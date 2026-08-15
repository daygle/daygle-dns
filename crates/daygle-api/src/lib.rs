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
//! | `GET`    | `/api/zones`                      | list zones |
//! | `POST`   | `/api/zones`                      | create a zone |
//! | `DELETE` | `/api/zones/:id`                  | delete a zone |
//! | `GET`    | `/api/zones/:id/records`          | list records |
//! | `PUT`    | `/api/zones/:id/records`          | upsert a record |
//! | `DELETE` | `/api/zones/:id/records/:rid`     | delete a record |
//! | `POST`   | `/api/zones/:id/sign`             | DNSSEC-sign a zone |
//! | `POST`   | `/api/zones/:id/unsign`           | remove DNSSEC signing |
//! | `POST`   | `/api/zones/import`               | import a BIND zone file |
//! | `POST`   | `/api/cache/clear`                | flush the recursive cache |
//!
//! Mutating endpoints require a `Authorization: Bearer <token>` header when
//! [`daygle_core::config::ApiSettings::api_token`] is configured.

mod handlers;

use std::sync::Arc;
use std::time::Instant;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use daygle_authoritative::AuthorityCatalog;
use daygle_core::config::DaygleConfig;
use daygle_core::{LogStore, Metrics};
use daygle_recursive::RecursiveResolver;

/// Shared state for the API and the DNS dispatcher.
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<AuthorityCatalog>,
    pub resolver: Option<Arc<RecursiveResolver>>,
    pub metrics: Arc<Metrics>,
    pub logs: Arc<LogStore>,
    pub config: Arc<DaygleConfig>,
    pub started_at: Instant,
}

/// Build the API router (REST endpoints plus the embedded GUI).
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(handlers::status))
        .route("/metrics", get(handlers::metrics))
        .route("/logs", get(handlers::logs))
        .route("/config", get(handlers::config))
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    let mut app = Router::new().nest("/api", api);

    if state.config.api.gui_enabled {
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
    let configured = state.config.api.api_token.trim();
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
