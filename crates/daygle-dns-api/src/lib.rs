//! # daygle-api
//!
//! HTTP REST API and embedded GUI serving for Daygle DNS, built on
//! [`axum`]/[`tower`].
//!
//! Endpoints:
//!
//! | Method   | Path                              | Purpose |
//! |----------|-----------------------------------|---------|
//! | `GET`    | `/api/health`                     | unauthenticated liveness (used by the in-place updater) |
//! | `GET`    | `/api/status`                     | server status |
//! | `GET`    | `/api/metrics`                    | runtime metrics |
//! | `GET`    | `/api/logs?limit=N`               | recent log entries |
//! | `GET`    | `/api/config`                     | effective configuration |
//! | `POST`   | `/api/config/reload`              | re-read the config file (live reload) |
//! | `GET`    | `/api/zones`                      | list zones |
//! | `POST`   | `/api/zones`                      | create a primary or secondary zone |
//! | `GET`    | `/api/zones/defaults`             | SOA defaults a new zone would get |
//! | `DELETE` | `/api/zones/:id`                  | delete a zone |
//! | `PUT`    | `/api/zones/:id/soa`              | edit a primary zone's SOA metadata |
//! | `GET`    | `/api/zones/:id/records`          | list records |
//! | `PUT`    | `/api/zones/:id/records`          | upsert a record |
//! | `PUT`    | `/api/zones/:id/records/:rid`     | replace a record in place |
//! | `DELETE` | `/api/zones/:id/records/:rid`     | delete a record |
//! | `POST`   | `/api/auth/password`              | signed-in user rotates their own password |
//! | `PUT`    | `/api/auth/preferences`           | signed-in user sets their own date/time display |
//! | `GET`    | `/api/users`                      | list console accounts (hashes redacted) |
//! | `POST`   | `/api/users`                      | create a console account |
//! | `PATCH`  | `/api/users/:username`            | reset password / change role / enable-disable |
//! | `DELETE` | `/api/users/:username`            | delete a console account |
//! | `POST`   | `/api/zones/:id/sign`             | DNSSEC-sign a zone |
//! | `POST`   | `/api/zones/:id/unsign`           | remove DNSSEC signing |
//! | `POST`   | `/api/zones/import`               | import a BIND zone file |
//! |          |                                  | `POST /api/zones` accepts SOA/import/master options for the GUI |
//! | `GET`    | `/api/networks`                   | list named networks and what uses each |
//! | `POST`   | `/api/networks`                   | add, change or rename a named network |
//! | `DELETE` | `/api/networks/:name`             | delete an unused named network |
//! | `GET`    | `/api/split-horizon`              | list the named networks and split-horizon entries |
//! | `POST`   | `/api/split-horizon/networks`     | add or change a named network (older form of `/api/networks`) |
//! | `DELETE` | `/api/split-horizon/networks/:name` | delete an unused named network |
//! | `POST`   | `/api/split-horizon/entries`      | create a split-horizon entry |
//! | `PUT`    | `/api/split-horizon/entries/:id`  | update a split-horizon entry |
//! | `POST`   | `/api/split-horizon/entries/:id/move` | move an entry up/down in its domain's order |
//! | `DELETE` | `/api/split-horizon/entries/:id`  | delete a split-horizon entry |
//! | `GET`    | `/api/cache`                      | recursive cache status |
//! | `POST`   | `/api/cache/clear`                | flush the recursive cache |
//! | `POST`   | `/api/cache/flush`                | flush one name from the cache |
//! | `GET`    | `/api/local-root`                 | local root zone (RFC 8806) status |
//! | `GET`    | `/api/resolver`                   | resolver dashboard counters |
//! | `POST`   | `/api/local-root/refresh`         | check for a newer root zone now |
//! | `GET`    | `/api/policy/blocklist/sources`   | list remote blocklist sources and their status |
//! | `POST`   | `/api/policy/blocklist/sources`   | force an immediate refresh of every source |
//! | `PUT`    | `/api/policy/blocklist/sources`   | replace the configured sources (console CRUD) |
//! | `GET`    | `/api/policy/blocklist/sources/validate` | probe a URL and validate / auto-detect its format |
//! | `GET`    | `/api/ai/status`                  | AI scanner configuration and per-status counts |
//! | `GET`    | `/api/ai/verdicts`                | paginated per-domain AI verdicts |
//! | `POST`   | `/api/ai/override`                | allow-exempt or clear overrides for a domain |
//! | `POST`   | `/api/ai/rescan`                  | wake the scanner for an immediate cycle |
//! | `GET`    | `/api/ai/model-status`            | installed AI model files (size, sha256) + update-run state |
//! | `POST`   | `/api/ai/update-models`           | begin a models-only update from the latest release |
//!
//! Auth endpoints: `POST /api/auth/login`, `POST /api/auth/logout`,
//! `GET /api/auth/me`, plus the one-time first-run setup
//! (`GET/POST /api/auth/setup`). Console authentication is on by default
//! (`api.auth_required = true`): every endpoint requires a session token
//! (or the legacy static `api_token`); see `require_auth` below.
//!
//! The [`AppState`] holds the effective configuration and the recursive
//! resolver in `ArcSwap` containers so the live-reload machinery can publish
//! new values without locking or restarting.

pub mod acme;
pub mod alerts;
mod audit;
mod handlers;
mod networks;
mod update;

// The release-cache warmer is spawned by the binary next to the ACME
// renewals; `update` itself stays internal.
pub use update::refresh_release_forever;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_authoritative::SecondaryRefresher;
use daygle_dns_core::config::DaygleConfig;
use daygle_dns_core::{LogStore, Metrics};
use daygle_dns_policy::BlocklistSourceManager;
use daygle_dns_recursive::RecursiveResolver;
use parking_lot::Mutex;

/// Who a request is from: a login session, or a personal API token.
#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub role: daygle_dns_core::config::Role,
    pub expires_at: SystemTime,
    /// The API token's id, when the request used one rather than a login.
    pub api_token: Option<String>,
}

/// Login sessions, kept in memory and (when given a store) in the
/// database, so signing in survives a restart. Only token hashes are kept.
/// Also recognises personal API tokens ([`SessionStore::authenticate`]).
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    store: Option<daygle_dns_authoritative::ZoneStore>,
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn from_unix(secs: i64) -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

impl SessionStore {
    /// A store whose sessions live in the database too: the unexpired ones
    /// saved by an earlier run are loaded.
    pub fn with_store(store: daygle_dns_authoritative::ZoneStore) -> Self {
        let loaded = store
            .load_sessions(unix(SystemTime::now()))
            .unwrap_or_else(|e| {
                tracing::warn!("cannot load saved login sessions: {e}");
                Vec::new()
            });
        let sessions = loaded
            .into_iter()
            .map(|s| {
                (
                    s.token_hash,
                    Session {
                        username: s.username,
                        role: s.role,
                        expires_at: from_unix(s.expires_at),
                        api_token: None,
                    },
                )
            })
            .collect();
        Self {
            sessions: Mutex::new(sessions),
            store: Some(store),
        }
    }

    fn persist(
        &self,
        what: &str,
        f: impl FnOnce(&daygle_dns_authoritative::ZoneStore) -> daygle_dns_core::Result<()>,
    ) {
        if let Some(store) = &self.store {
            if let Err(e) = f(store) {
                tracing::warn!("cannot {what} a login session in the database: {e}");
            }
        }
    }

    /// Insert a fresh session for `username`, valid for `ttl`.
    pub fn create(
        &self,
        username: &str,
        role: daygle_dns_core::config::Role,
        ttl: Duration,
    ) -> String {
        let token = new_token();
        let hash = daygle_dns_core::auth::hash_token(&token);
        let session = Session {
            username: username.to_string(),
            role,
            expires_at: SystemTime::now() + ttl,
            api_token: None,
        };
        self.persist("save", |store| {
            store.put_session(&daygle_dns_authoritative::store::StoredSession {
                token_hash: hash.clone(),
                username: username.to_string(),
                role,
                expires_at: unix(session.expires_at),
            })
        });
        self.sessions.lock().insert(hash, session);
        token
    }

    /// Return the login session for a token if it exists and is unexpired.
    /// Expired sessions are pruned lazily on access.
    pub fn verify(&self, token: &str) -> Option<Session> {
        if token.is_empty() {
            return None;
        }
        let mut sessions = self.sessions.lock();
        prune_expired(&mut sessions);
        sessions
            .get(&daygle_dns_core::auth::hash_token(token))
            .cloned()
    }

    /// Who presents `token`: a login session, or else a personal API token
    /// of an enabled account (read-only tokens act as viewers).
    pub fn authenticate(&self, token: &str) -> Option<Session> {
        if let Some(session) = self.verify(token) {
            return Some(session);
        }
        let store = self.store.as_ref()?;
        if !token.starts_with(API_TOKEN_PREFIX) {
            return None;
        }
        let found = store
            .find_api_token(&daygle_dns_core::auth::hash_token(token))
            .ok()
            .flatten()?;
        let now = unix(SystemTime::now());
        if found.expires_at != 0 && found.expires_at <= now {
            return None;
        }
        let user = store.get_console_user(&found.username).ok().flatten()?;
        if !user.enabled {
            return None;
        }
        let _ = store.touch_api_token(&found.id, now);
        Some(Session {
            username: user.username,
            role: if found.read_only {
                daygle_dns_core::config::Role::Viewer
            } else {
                user.role
            },
            expires_at: if found.expires_at == 0 {
                SystemTime::now() + Duration::from_secs(3600)
            } else {
                from_unix(found.expires_at)
            },
            api_token: Some(found.id),
        })
    }

    /// Remove a session (logout). Returns whether it existed.
    pub fn revoke(&self, token: &str) -> bool {
        let hash = daygle_dns_core::auth::hash_token(token);
        self.persist("delete", |store| store.delete_session(&hash));
        self.sessions.lock().remove(&hash).is_some()
    }

    /// Drop every session belonging to `username` (used when an account is
    /// disabled, deleted, or its password/role changes).
    pub fn revoke_user(&self, username: &str) {
        self.persist("delete", |store| store.delete_user_sessions(username, None));
        self.sessions.lock().retain(|_, s| s.username != username);
    }

    /// Like [`revoke_user`], but keeps `keep_token` alive - used by the
    /// self-service password change so the current device stays signed in
    /// while every other session is signed out.
    pub fn revoke_user_except(&self, username: &str, keep_token: &str) {
        let keep = daygle_dns_core::auth::hash_token(keep_token);
        self.persist("delete", |store| {
            store.delete_user_sessions(username, Some(&keep))
        });
        self.sessions
            .lock()
            .retain(|hash, s| s.username != username || *hash == keep);
    }
}

/// Personal API tokens start with this, so they are told apart from login
/// sessions (and recognisable if leaked).
pub const API_TOKEN_PREFIX: &str = "dgl_";

/// A new personal API token (256 random bits).
pub fn new_api_token() -> String {
    let random: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    format!("{API_TOKEN_PREFIX}{random}")
}

fn prune_expired(sessions: &mut HashMap<String, Session>) {
    let now = SystemTime::now();
    sessions.retain(|_, s| s.expires_at > now);
}

/// Failed-login throttle keyed by client address: after
/// [`LoginThrottle::MAX_FAILURES`] failures inside [`LoginThrottle::WINDOW`],
/// further attempts from that address are refused until the window lapses.
/// Keyed by address rather than username so a guesser cannot lock a real
/// admin out of their own account.
#[derive(Default)]
pub struct LoginThrottle {
    failures: Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>,
}

impl LoginThrottle {
    pub const MAX_FAILURES: u32 = 10;
    pub const WINDOW: Duration = Duration::from_secs(300);
    /// Bound on tracked addresses; expired entries are dropped past it.
    const MAX_TRACKED: usize = 10_000;

    /// Seconds until `ip` may try again, or `None` when it is not throttled.
    pub fn retry_after(&self, ip: std::net::IpAddr) -> Option<u64> {
        let failures = self.failures.lock();
        let (count, since) = failures.get(&ip)?;
        let elapsed = since.elapsed();
        (*count >= Self::MAX_FAILURES && elapsed < Self::WINDOW)
            .then(|| (Self::WINDOW - elapsed).as_secs().max(1))
    }

    /// Record a failed attempt from `ip`.
    pub fn record_failure(&self, ip: std::net::IpAddr) {
        let mut failures = self.failures.lock();
        if failures.len() >= Self::MAX_TRACKED {
            failures.retain(|_, (_, since)| since.elapsed() < Self::WINDOW);
        }
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= Self::WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    /// Forget `ip`'s failures (after a successful login).
    pub fn clear(&self, ip: std::net::IpAddr) {
        self.failures.lock().remove(&ip);
    }
}

/// Generate a 128-bit random hex token (from OS entropy via rand's
/// thread-local generator; collision probability is negligible).
fn new_token() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// Callback that applies a saved configuration to server-side state.
pub type ApplyRuntime = Arc<dyn Fn(&DaygleConfig) + Send + Sync>;

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
    /// Runtime secondary-zone refresher, used by the zone form to apply master
    /// changes without requiring a process restart.
    pub secondary_refresher: Option<Arc<SecondaryRefresher>>,
    /// Health checks on failover records.
    pub health: Option<Arc<daygle_dns_authoritative::HealthMonitor>>,
    /// The local root zone (RFC 8806): settings changes, status and
    /// on-demand refresh.
    pub local_root: Arc<daygle_dns_authoritative::LocalRoot>,
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
    /// Per-client failed-login counter backing the login brute-force guard.
    pub login_throttle: Arc<LoginThrottle>,
    /// Hook that rebinds DNS listeners after a settings change; `None` when
    /// the caller does not support live listener rebinding.
    pub request_dns_rebuild: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Held while a handler reads, changes and publishes the configuration
    /// (shared with the config-file reload), so two saves landing together
    /// cannot silently overwrite each other's change.
    pub config_write: Arc<tokio::sync::Mutex<()>>,
    /// Applies a saved configuration to the server-side parts the API cannot
    /// reach itself (the recursive lookup admission limit); `None` in
    /// API-only setups.
    pub apply_runtime: Option<ApplyRuntime>,
    /// Reconfigure the web console's HTTP/HTTPS listeners (Settings ->
    /// General). `None` when the API runs without a server (tests).
    pub web_apply: Option<WebApplyFn>,
    /// Dashboard time-series + top-N tables.
    pub stats: Arc<daygle_dns_core::stats::QueryStats>,
    /// AI subsystem (verdict store, scanner handles); `None` when the
    /// `[ai]` section is disabled. All `/api/ai/...` endpoints read through
    /// this handle.
    pub ai: Option<Arc<daygle_dns_ml::AiEngine>>,
    /// Certificates from an ACME CA: HTTP-01 answers and issues running.
    pub acme: Arc<acme::Acme>,
    /// Response policy zones; `None` when the API runs without a server.
    pub rpz: Option<Arc<daygle_dns_authoritative::rpz::RpzManager>>,
}

/// Build the API router (REST endpoints plus the embedded GUI).
/// Moves the web console's listeners to new [`WebSettings`]: binds new
/// ports and loads the certificate first, and on any failure changes
/// nothing and returns the reason.
///
/// [`WebSettings`]: daygle_dns_core::config::WebSettings
pub type WebApplyFn = Arc<
    dyn Fn(
            daygle_dns_core::config::WebSettings,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(handlers::status))
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics))
        .route("/metrics/prometheus", get(handlers::metrics_prometheus))
        .route("/stats", get(handlers::stats))
        .route("/logs", get(handlers::logs))
        .route(
            "/querylogs",
            get(handlers::query_logs).delete(handlers::clear_query_logs),
        )
        .route("/ai/status", get(handlers::ai_status))
        .route("/ai/verdicts", get(handlers::ai_verdicts))
        .route("/ai/override", post(handlers::ai_override))
        .route("/ai/overrides", get(handlers::ai_overrides))
        .route("/ai/rescan", post(handlers::ai_rescan))
        .route("/ai/model-status", get(handlers::ai_model_status))
        .route("/ai/update-models", post(handlers::ai_update_models))
        .route(
            "/config",
            get(handlers::config)
                .put(handlers::update_settings)
                .post(handlers::reload_config),
        )
        .route("/auth/login", post(handlers::auth_login))
        .route("/auth/logout", post(handlers::auth_logout))
        .route("/auth/me", get(handlers::auth_me))
        .route("/auth/preferences", put(handlers::auth_set_preferences))
        .route("/auth/password", post(handlers::auth_change_password))
        .route(
            "/auth/tokens",
            get(handlers::list_api_tokens).post(handlers::create_api_token),
        )
        .route("/auth/tokens/{id}", delete(handlers::delete_api_token))
        .route("/auth/two-factor", get(handlers::two_factor_status))
        .route("/auth/two-factor/setup", post(handlers::two_factor_setup))
        .route("/auth/two-factor/enable", post(handlers::two_factor_enable))
        .route(
            "/auth/two-factor/recovery-codes",
            post(handlers::two_factor_new_recovery_codes),
        )
        .route(
            "/auth/two-factor/disable",
            post(handlers::two_factor_disable),
        )
        .route(
            "/auth/setup",
            get(handlers::auth_setup_status).post(handlers::auth_setup),
        )
        .route(
            "/users",
            get(handlers::list_users).post(handlers::create_user),
        )
        .route(
            "/users/{username}",
            patch(handlers::update_user).delete(handlers::delete_user),
        )
        .route(
            "/users/{username}/two-factor",
            delete(handlers::reset_user_two_factor),
        )
        .route(
            "/certificates",
            get(handlers::list_certificates).post(handlers::create_certificate),
        )
        .route("/certificates/{name}", delete(handlers::delete_certificate))
        .route(
            "/certificates/acme",
            post(handlers::request_acme_certificate),
        )
        .route(
            "/certificates/{name}/renew",
            post(handlers::renew_acme_certificate),
        )
        .route(
            "/acme",
            get(handlers::get_acme_settings).put(handlers::put_acme_settings),
        )
        .route(
            "/zones",
            get(handlers::list_zones).post(handlers::create_zone),
        )
        .route("/zones/import", post(handlers::import_zone))
        .route("/zones/defaults", get(handlers::zone_defaults_handler))
        .route("/zones/{id}", delete(handlers::delete_zone))
        .route("/zones/{id}/enabled", put(handlers::set_zone_enabled))
        .route("/zones/{id}/soa", put(handlers::update_zone_soa))
        .route(
            "/zones/{id}/records",
            get(handlers::list_records).put(handlers::upsert_record),
        )
        .route(
            "/zones/{id}/records/{rid}/disabled",
            put(handlers::set_record_disabled),
        )
        .route(
            "/zones/{id}/records/{rid}/health",
            put(handlers::set_health_check).delete(handlers::delete_health_check),
        )
        .route("/health-checks", get(handlers::list_health_checks))
        .route("/zones/{id}/export", get(handlers::export_zone))
        .route(
            "/zones/{id}/records/{rid}",
            put(handlers::replace_record).delete(handlers::delete_record),
        )
        .route("/zones/{id}/sign", post(handlers::sign_zone))
        .route("/zones/{id}/unsign", post(handlers::unsign_zone))
        .route("/cache", get(handlers::cache_status))
        .route("/cache/clear", post(handlers::clear_cache))
        .route("/cache/flush", post(handlers::flush_cache_name))
        .route("/local-root", get(handlers::local_root_status))
        .route("/resolver", get(handlers::resolver_stats))
        .route("/local-root/refresh", post(handlers::local_root_refresh))
        .route(
            "/networks",
            get(networks::list_networks).post(networks::save_network),
        )
        .route("/networks/{name}", delete(networks::delete_network))
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
            put(handlers::update_split_horizon_entry).delete(handlers::delete_split_horizon_entry),
        )
        .route(
            "/split-horizon/entries/{id}/move",
            post(handlers::move_split_horizon_entry),
        )
        .route(
            "/policy/blocklist/sources",
            get(handlers::blocklist_sources)
                .post(handlers::refresh_blocklist_sources)
                .put(handlers::replace_blocklist_sources),
        )
        .route(
            "/policy/blocklist/sources/validate",
            get(handlers::validate_blocklist_source),
        )
        .route("/policy/blocking/test", post(handlers::test_blocking))
        .route("/alerts/test", post(handlers::test_alert))
        .route(
            "/rpz",
            get(handlers::rpz_status).post(handlers::rpz_refresh),
        )
        .route("/rpz/test", post(handlers::rpz_test))
        .route(
            "/policy/blocking",
            get(handlers::list_blocking_groups).post(handlers::upsert_blocking_group),
        )
        .route(
            "/policy/blocking/{id}",
            delete(handlers::delete_blocking_group),
        )
        .route(
            "/policy/blocking/{id}/move",
            post(handlers::move_blocking_group),
        )
        .route("/backup", get(handlers::download_backup))
        .route(
            "/backup/restore",
            get(handlers::pending_restore)
                .post(handlers::stage_restore)
                .delete(handlers::cancel_restore)
                // Backups with query logs can be large.
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .route("/update", get(handlers::update_info))
        .route("/update/status", get(handlers::update_status))
        .route("/update/start", post(handlers::update_start))
        .route("/update/check", post(handlers::update_check))
        .route("/update/dismiss", post(handlers::update_dismiss))
        .route("/update/preflight", get(handlers::update_preflight))
        .route("/audit", get(handlers::audit_log))
        // Inside the authorization layer: refused requests are not recorded.
        .layer(middleware::from_fn_with_state(state.clone(), audit::audit))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state.clone());

    // ACME HTTP-01 challenge answers: open, outside the API, on every
    // listener (the CA connects over plain HTTP on port 80).
    let mut app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(handlers::acme_http_challenge),
        )
        .with_state(state.clone())
        .nest("/api", api);

    if state.config.load().api.gui_enabled {
        app = app
            .route("/", get(handlers::gui_index))
            .route("/{*path}", get(handlers::gui_asset));
    }

    app.layer(cors_layer(state.config.clone()))
        .layer(middleware::map_response(security_headers))
}

/// CORS for `api.cors_origins`. The allow-list is read from the live config
/// on every request, so a console edit applies without a restart; an empty
/// list (the default) emits no CORS headers, i.e. same-origin only. `*`
/// allows any origin (credentials travel as a bearer header, not cookies).
fn cors_layer(config: Arc<ArcSwap<DaygleConfig>>) -> tower_http::cors::CorsLayer {
    use tower_http::cors::{AllowOrigin, CorsLayer};
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let Ok(origin) = origin.to_str() else {
                return false;
            };
            config
                .load()
                .api
                .cors_origins
                .iter()
                .any(|allowed| allowed == "*" || allowed.trim_end_matches('/') == origin)
        }))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
}

/// Content Security Policy for the console: everything from this origin
/// only. Session tokens live in the browser's local storage, so any script
/// injected into the page could read them; this keeps injected markup from
/// loading or running script from anywhere else. Inline styles stay allowed
/// (the Svelte bundle sets `style` attributes).
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; \
    object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// Baseline hardening headers for the console and API: forbid framing
/// (clickjacking) and MIME sniffing, keep URLs out of cross-site referrers,
/// and restrict where the console may load code from.
async fn security_headers(mut response: Response) -> Response {
    use axum::http::{header, HeaderValue};
    let headers = response.headers_mut();
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("same-origin"));
    response
}

/// `GET` endpoints that still need the admin role: they make the server
/// reach out (fetch an arbitrary URL, probe GitHub, write a probe file), so
/// read-only accounts - and the legacy open-GET token mode - must not be
/// able to trigger them. Matched on both the full and nested path forms.
fn is_privileged_read(path: &str) -> bool {
    let path = path.strip_prefix("/api").unwrap_or(path);
    matches!(
        path,
        "/policy/blocklist/sources/validate"
            | "/update/preflight"
            | "/backup"
            | "/backup/restore"
            | "/audit"
    )
}

/// Authorization for API calls.
///
/// - `POST /api/auth/login` and the one-time `POST /api/auth/setup` are
///   always open (they *are* the login).
/// - `GET /api/health` is always open: the in-place updater probes it after a
///   restart to confirm the service is serving HTTP, with no credentials.
/// - Console auth is **on by default**: every endpoint requires a valid
///   session token (from login) or the static `api_token`. With no `users`
///   configured yet, `/api/auth/setup` reports that first-run setup is
///   pending and `POST /api/auth/setup` creates the first admin account.
/// - `api.auth_required = false` restores the fully-open development mode.
/// - A static `api_token` alone keeps its legacy GETs-open/mutations-tokened
///   behavior.
/// - A few `GET`s are privileged (see [`is_privileged_read`]) and are
///   treated like mutations: admin role or the static token.
async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // Within the nested router axum strips the `/api` prefix, so match both
    // the full and stripped forms of the login paths.
    let path = req.uri().path();
    let is_auth_path = path == "/api/auth/login"
        || path == "/auth/login"
        || path == "/api/auth/setup"
        || path == "/auth/setup"
        || path == "/api/health"
        || path == "/health";
    if is_auth_path || req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }

    let config = state.config.load();
    let static_token = config.api.api_token.trim().to_string();
    let auth_required = config.api.auth_required;
    drop(config);
    // Console accounts live in the database; config-file `[[api.users]]`
    // entries are only a seed imported at startup. A failed read counts as
    // "configured" so a database error can never open the API.
    let users_configured = state
        .catalog
        .store()
        .count_console_users()
        .map_or(true, |n| n > 0);

    if !users_configured && static_token.is_empty() && !auth_required {
        // Auth explicitly disabled (`api.auth_required = false`): open access.
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
    if !static_token.is_empty()
        && daygle_dns_core::auth::constant_time_eq(bearer.as_bytes(), static_token.as_bytes())
    {
        return next.run(req).await;
    }
    let privileged_read = is_privileged_read(path);

    // When users are configured, a valid login session is required for every
    // method. In legacy token-only mode, GETs stay open.
    if users_configured {
        if let Some(session) = state.sessions.authenticate(&bearer) {
            // `viewer` accounts are read-only: any state-changing method is
            // rejected with 403 even though the session itself is valid.
            let mutating = privileged_read
                || !matches!(
                    *req.method(),
                    axum::http::Method::GET | axum::http::Method::HEAD
                );
            // The self-service password change and two-factor settings are
            // mutations on the caller's own credentials (the handlers
            // re-verify the password), and display preferences only change
            // the caller's own view, so read-only accounts may use them.
            let own_path = path.strip_prefix("/api").unwrap_or(path);
            let is_own_account_change = matches!(own_path, "/auth/password" | "/auth/preferences")
                || own_path.starts_with("/auth/two-factor")
                || own_path.starts_with("/auth/tokens");
            if mutating
                && session.role == daygle_dns_core::config::Role::Viewer
                && !is_own_account_change
            {
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

    // First-run mode: auth is required but no accounts exist yet. Only
    // `/api/auth/setup` (open above) can bootstrap the console; everything
    // else is 401 with `setup: true` so the GUI shows the setup screen.
    if auth_required {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "initial setup required",
                "login": true,
                "setup": true,
            })),
        )
            .into_response();
    }

    if req.method() == axum::http::Method::GET && !privileged_read {
        return next.run(req).await;
    }

    (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
}
