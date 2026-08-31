//! # daygle-api
//!
//! HTTP REST API and embedded GUI serving for Daygle DNS, built on
//! [`axum`]/[`tower`].
//!
//! Endpoints:
//!
//! | Method   | Path                              | Purpose |
//! |----------|-----------------------------------|---------|
//! | `GET`    | `/api/status`                     | server status |
//! | `GET`    | `/api/metrics`                    | runtime metrics |
//! | `GET`    | `/api/logs?limit=N`               | recent log entries |
//! | `GET`    | `/api/config`                     | effective configuration |
//! | `POST`   | `/api/config/reload`              | re-read the config file (live reload) |
//! | `GET`    | `/api/zones`                      | list zones |
//! | `POST`   | `/api/zones`                      | create a zone |
//! | `DELETE` | `/api/zones/:id`                  | delete a zone |
//! | `GET`    | `/api/zones/:id/records`          | list records |
//! | `PUT`    | `/api/zones/:id/records`          | upsert a record |
//! | `DELETE` | `/api/zones/:id/records/:rid`     | delete a record |
//! | `POST`   | `/api/zones/:id/sign`             | DNSSEC-sign a zone |
//! | `POST`   | `/api/zones/:id/unsign`           | remove DNSSEC signing |
//! | `POST`   | `/api/zones/import`               | import a BIND zone file |
//! | `GET`    | `/api/split-horizon`              | list split-horizon networks and entries |
//! | `POST`   | `/api/split-horizon/networks`     | create/update a network (by name) |
//! | `DELETE` | `/api/split-horizon/networks/:name` | delete a network |
//! | `POST`   | `/api/split-horizon/entries`      | create a split-horizon entry |
//! | `PUT`    | `/api/split-horizon/entries/:id`  | update a split-horizon entry |
//! | `POST`   | `/api/split-horizon/entries/:id/move` | move an entry up/down in its domain's order |
//! | `DELETE` | `/api/split-horizon/entries/:id`  | delete a split-horizon entry |
//! | `POST`   | `/api/cache/clear`                | flush the recursive cache |
//!
//! Mutating endpoints require a `Authorization: Bearer <token>` header when
//! [`daygle_dns_core::config::ApiSettings::api_token`] is configured.
//!
//! The [`AppState`] holds the effective configuration and the recursive
//! resolver in `ArcSwap` containers so the live-reload machinery can publish
//! new values without locking or restarting.

mod handlers;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_core::config::DaygleConfig;
use daygle_dns_core::{LogStore, Metrics};
use daygle_dns_policy::BlocklistSourceManager;
use daygle_dns_recursive::RecursiveResolver;
use parking_lot::Mutex;

/// A live login session: the authenticated username, its role and expiry.
#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub role: daygle_dns_core::config::Role,
    pub expires_at: SystemTime,
}

/// In-memory login-session store (tokens are 128-bit random hex).
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    /// Insert a fresh session for `username`, valid for `ttl`.
    pub fn create(
        &self,
        username: &str,
        role: daygle_dns_core::config::Role,
        ttl: Duration,
    ) -> String {
        let token = new_token();
        self.sessions.lock().insert(
            token.clone(),
            Session {
                username: username.to_string(),
                role,
                expires_at: SystemTime::now() + ttl,
            },
        );
        token
    }

    /// Return the session for a token if it exists and is unexpired.
    /// Expired sessions are pruned lazily on access.
    pub fn verify(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock();
        prune_expired(&mut sessions);
        sessions.get(token).cloned()
    }

    /// Remove a session (logout). Returns whether it existed.
    pub fn revoke(&self, token: &str) -> bool {
        self.sessions.lock().remove(token).is_some()
    }
}

fn prune_expired(sessions: &mut HashMap<String, Session>) {
    let now = SystemTime::now();
    sessions.retain(|_, s| s.expires_at > now);
}

/// Generate a 128-bit random hex token (from OS entropy via rand's
/// thread-local generator; collision probability is negligible).
fn new_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect()
}

/// Shared state for the API and the DNS dispatcher.
///
/// `config` and `resolver` are atomic-swap containers so the live-reload
/// machinery can publish updates that every in-flight request observes.
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<AuthorityCatalog>,
    pub resolver: Arc<ArcSwapOption<RecursiveResolver>>,
    pub metrics: Arc<Metrics>,
    pub logs: Arc<LogStore>,
    pub config: Arc<ArcSwap<DaygleConfig>>,
    pub policy: Arc<ArcSwap<daygle_dns_policy::PolicyEngine>>,
    /// Advanced Blocking groups (per-client allow/block policies). Shared with
    /// the dispatcher; rebuilt and swapped in place when a group changes.
    pub advanced_blocking: Arc<ArcSwap<daygle_dns_policy::AdvancedBlocking>>,
    /// Remote blocklist source manager; `None` when no sources are configured.
    pub blocklist_sources: Option<Arc<BlocklistSourceManager>>,
    pub started_at: Instant,
    /// Path of the config file to re-read on `POST /api/config/reload`.
    pub config_path: Option<Arc<PathBuf>>,
    /// Notify handle that wakes the config-file watcher for an immediate
    /// reload; `None` when live reload is unavailable.
    pub reload_notify: Option<Arc<tokio::sync::Notify>>,
    /// Login sessions (only meaningful when `api.users` is configured).
    pub sessions: Arc<SessionStore>,
    /// Hook that rebinds DNS listeners after a settings change; `None` when
    /// the caller does not support live listener rebinding.
    pub request_dns_rebuild: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Dashboard time-series + top-N tables.
    pub stats: Arc<daygle_dns_core::stats::QueryStats>,
}

/// Build the API router (REST endpoints plus the embedded GUI).
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(handlers::status))
        .route("/metrics", get(handlers::metrics))
        .route("/stats", get(handlers::stats))
        .route("/logs", get(handlers::logs))
        .route(
            "/config",
            get(handlers::config)
                .put(handlers::update_settings)
                .post(handlers::reload_config),
        )
        .route("/auth/login", post(handlers::auth_login))
        .route("/auth/logout", post(handlers::auth_logout))
        .route("/auth/me", get(handlers::auth_me))
        .route("/zones", get(handlers::list_zones).post(handlers::create_zone))
        .route("/zones/import", post(handlers::import_zone))
        .route("/zones/{id}", delete(handlers::delete_zone))
        .route(
            "/zones/{id}/records",
            get(handlers::list_records).put(handlers::upsert_record),
        )
        .route(
            "/zones/{id}/records/{rid}/disabled",
            put(handlers::set_record_disabled),
        )
        .route("/zones/{id}/export", get(handlers::export_zone))
        .route("/zones/{id}/records/{rid}", delete(handlers::delete_record))
        .route("/zones/{id}/sign", post(handlers::sign_zone))
        .route("/zones/{id}/unsign", post(handlers::unsign_zone))
        .route("/cache/clear", post(handlers::clear_cache))
        .route("/split-horizon", get(handlers::get_split_horizon))
        .route(
            "/split-horizon/networks",
            post(handlers::upsert_split_horizon_network),
        )
        .route(
            "/split-horizon/networks/{name}",
            delete(handlers::delete_split_horizon_network),
        )
        .route(
            "/split-horizon/entries",
            post(handlers::create_split_horizon_entry),
        )
        .route(
            "/split-horizon/entries/{id}",
            put(handlers::update_split_horizon_entry)
                .delete(handlers::delete_split_horizon_entry),
        )
        .route(
            "/split-horizon/entries/{id}/move",
            post(handlers::move_split_horizon_entry),
        )
        .route(
            "/policy/blocklist/sources",
            get(handlers::blocklist_sources).post(handlers::refresh_blocklist_sources),
        )
        .route("/policy/blocking/test", post(handlers::test_blocking))
        .route(
            "/policy/blocking",
            get(handlers::list_blocking_groups).post(handlers::upsert_blocking_group),
        )
        .route(
            "/policy/blocking/{id}",
            delete(handlers::delete_blocking_group),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    let mut app = Router::new().nest("/api", api);

    if state.config.load().api.gui_enabled {
        app = app
            .route("/", get(handlers::gui_index))
            .route("/{*path}", get(handlers::gui_asset));
    }

    app
}

/// Authorization for API calls.
///
/// - `POST /api/auth/login` is always open (it *is* the login).
/// - When `api.users` is configured, **every** endpoint requires a valid
///   session token (from login) or the static `api_token` — the console is
///   fully authenticated, like Technitium.
/// - Otherwise (legacy `api_token` mode): GET/OPTIONS stay open, mutating
///   methods require the `api_token` Bearer header when one is configured.
async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // Within the nested router axum strips the `/api` prefix, so match both
    // the full and stripped forms of the login path.
    let path = req.uri().path();
    let is_login = path == "/api/auth/login" || path == "/auth/login";
    if is_login || req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }

    let config = state.config.load();
    let users_configured = !config.api.users.is_empty();
    let static_token = config.api.api_token.trim().to_string();
    drop(config);

    if !users_configured && static_token.is_empty() {
        // No auth configured at all: open access (development mode).
        return next.run(req).await;
    }

    let bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();

    // A static api_token always authorizes (backwards compatible).
    if !static_token.is_empty() && bearer == static_token {
        return next.run(req).await;
    }

    // When users are configured, a valid login session is required for every
    // method. In legacy token-only mode, GETs stay open.
    if users_configured {
        if let Some(session) = state.sessions.verify(&bearer) {
            // `viewer` accounts are read-only: any state-changing method is
            // rejected with 403 even though the session itself is valid.
            let mutating = !matches!(
                *req.method(),
                axum::http::Method::GET | axum::http::Method::HEAD
            );
            if mutating && session.role == daygle_dns_core::config::Role::Viewer {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "error": "read-only account: mutations require the admin role",
                    })),
                )
                    .into_response();
            }
            return next.run(req).await;
        }
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "authentication required",
                "login": true,
            })),
        )
            .into_response();
    }

    if req.method() == axum::http::Method::GET {
        return next.run(req).await;
    }

    (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
}
