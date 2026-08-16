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
//! | `DELETE` | `/api/split-horizon/entries/:id`  | delete a split-horizon entry |
//! | `POST`   | `/api/cache/clear`                | flush the recursive cache |
//!
//! Mutating endpoints require a `Authorization: Bearer <token>` header when
//! [`daygle_core::config::ApiSettings::api_token`] is configured.
//!
//! The [`AppState`] holds the effective configuration and the recursive
//! resolver in `ArcSwap` containers so the live-reload machinery can publish
//! new values without locking or restarting.

mod handlers;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use daygle_authoritative::AuthorityCatalog;
use daygle_core::config::DaygleConfig;
use daygle_core::{LogStore, Metrics};
use daygle_policy::BlocklistSourceManager;
use daygle_recursive::RecursiveResolver;

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
    pub policy: Arc<ArcSwap<daygle_policy::PolicyEngine>>,
    /// Remote blocklist source manager; `None` when no sources are configured.
    pub blocklist_sources: Option<Arc<BlocklistSourceManager>>,
    pub started_at: Instant,
    /// Path of the config file to re-read on `POST /api/config/reload`.
    pub config_path: Option<Arc<PathBuf>>,
    /// Notify handle that wakes the config-file watcher for an immediate
    /// reload; `None` when live reload is unavailable.
    pub reload_notify: Option<Arc<tokio::sync::Notify>>,
}

/// Build the API router (REST endpoints plus the embedded GUI).
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(handlers::status))
        .route("/metrics", get(handlers::metrics))
        .route("/logs", get(handlers::logs))
        .route("/config", get(handlers::config).post(handlers::reload_config))
        .route("/zones", get(handlers::list_zones).post(handlers::create_zone))
        .route("/zones/import", post(handlers::import_zone))
        .route("/zones/{id}", delete(handlers::delete_zone))
        .route(
            "/zones/{id}/records",
            get(handlers::list_records).put(handlers::upsert_record),
        )
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
            "/policy/blocklist/sources",
            get(handlers::blocklist_sources).post(handlers::refresh_blocklist_sources),
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

/// Bearer-token authorization for mutating methods.
async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == axum::http::Method::GET || req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let configured = state.config.load().api.api_token.trim().to_string();
    if configured.is_empty() {
        return next.run(req).await;
    }
    let authorized = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v) == configured)
        .unwrap_or(false);

    if authorized {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
    }
}
