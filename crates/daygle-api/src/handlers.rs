//! HTTP handlers for the REST API.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use daygle_core::VERSION;
use serde::{Deserialize, Serialize};

use crate::AppState;

/// A uniform error response body.
#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

fn map_err(e: daygle_core::error::DaygleError) -> Response {
    let status = match &e {
        daygle_core::error::DaygleError::NotFound(_) => StatusCode::NOT_FOUND,
        daygle_core::error::DaygleError::AlreadyExists(_) => StatusCode::CONFLICT,
        daygle_core::error::DaygleError::InvalidRecord(_)
        | daygle_core::error::DaygleError::InvalidPolicy(_)
        | daygle_core::error::DaygleError::Config(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, e.to_string())
}

// ---- Status / metrics / logs / config -----------------------------------

pub async fn status(State(state): State<AppState>) -> Response {
    let zones = match state.catalog.store().count_zones() {
        Ok(n) => n,
        Err(e) => return map_err(e),
    };
    let records = match state.catalog.store().count_records() {
        Ok(n) => n,
        Err(e) => return map_err(e),
    };
    Json(serde_json::json!({
        "version": VERSION,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "zones": zones,
        "records": records,
        "recursion": state.resolver.is_some(),
        "dnssec": state.config.recursive.dnssec_validate,
        "dot_enabled": state.config.dot.enabled,
        "api_enabled": state.config.api.enabled,
    }))
    .into_response()
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    Json(state.metrics.snapshot()).into_response()
}

#[derive(Deserialize)]
pub struct LogsQuery {
    limit: Option<usize>,
}

pub async fn logs(
    State(state): State<AppState>,
    Query(query): Query<LogsQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(200).min(10_000);
    Json(state.logs.tail(limit)).into_response()
}

pub async fn config(State(state): State<AppState>) -> Response {
    Json((&*state.config).clone()).into_response()
}

// ---- Zones --------------------------------------------------------------

#[derive(Serialize)]
struct ZoneView {
    #[serde(flatten)]
    zone: daygle_authoritative::model::Zone,
    dnssec: bool,
}

pub async fn list_zones(State(state): State<AppState>) -> Response {
    let zones = match state.catalog.store().list_zones() {
        Ok(z) => z,
        Err(e) => return map_err(e),
    };
    let views = zones
        .into_iter()
        .map(|zone| {
            let dnssec = state
                .catalog
                .store()
                .get_signing_key(&zone.id)
                .map(|k| k.is_some())
                .unwrap_or(false);
            ZoneView { zone, dnssec }
        })
        .collect::<Vec<_>>();
    Json(views).into_response()
}

pub async fn create_zone(
    State(state): State<AppState>,
    Json(input): Json<ZoneInput>,
) -> Response {
    match state.catalog.store().create_zone(&input) {
        Ok(zone) => {
            let _ = state.catalog.reload();
            (StatusCode::CREATED, Json(zone)).into_response()
        }
        Err(e) => map_err(e),
    }
}

pub async fn delete_zone(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().delete_zone(&id) {
        Ok(true) => {
            let _ = state.catalog.reload();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => map_err(e),
    }
}

pub async fn import_zone(
    State(state): State<AppState>,
    Json(input): Json<ImportRequest>,
) -> Response {
    let zone_input = ZoneInput {
        name: input.name.clone(),
        ..Default::default()
    };
    let zone = match state.catalog.store().create_zone(&zone_input) {
        Ok(z) => z,
        Err(e) => return map_err(e),
    };
    let records = match daygle_authoritative::parse::parse_zone_file(&input.text) {
        Ok(r) => r,
        Err(e) => {
            let _ = state.catalog.store().delete_zone(&zone.id);
            return map_err(e);
        }
    };
    if let Err(e) = state.catalog.store().replace_records(&zone.id, &records) {
        let _ = state.catalog.store().delete_zone(&zone.id);
        return map_err(e);
    }
    if let Err(e) = state.catalog.reload() {
        return map_err(e);
    }
    (StatusCode::CREATED, Json(zone)).into_response()
}

#[derive(Deserialize)]
pub struct ImportRequest {
    name: String,
    text: String,
}

// ---- Records ------------------------------------------------------------

pub async fn list_records(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().list_records(&id) {
        Ok(records) => Json(records).into_response(),
        Err(e) => map_err(e),
    }
}

pub async fn upsert_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<RecordInput>,
) -> Response {
    match state.catalog.store().upsert_record(&id, &input) {
        Ok(record) => {
            let _ = state.catalog.reload();
            Json(record).into_response()
        }
        Err(e) => map_err(e),
    }
}

pub async fn delete_record(
    State(state): State<AppState>,
    Path((id, rid)): Path<(String, String)>,
) -> Response {
    match state.catalog.store().delete_record(&rid) {
        Ok(true) => {
            let _ = state.catalog.store().bump_serial(&id);
            let _ = state.catalog.reload();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => map_err(e),
    }
}

// ---- DNSSEC -------------------------------------------------------------

pub async fn sign_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.catalog.sign_zone(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_err(e),
    }
}

pub async fn unsign_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.catalog.unsign_zone(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_err(e),
    }
}

// ---- Cache --------------------------------------------------------------

pub async fn clear_cache(State(state): State<AppState>) -> Response {
    if let Some(resolver) = &state.resolver {
        resolver.clear_cache();
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---- GUI ----------------------------------------------------------------

pub async fn gui_index() -> Response {
    serve_gui("")
}

pub async fn gui_asset(Path(path): Path<String>) -> Response {
    serve_gui(&path)
}

fn serve_gui(path: &str) -> Response {
    match daygle_gui::lookup(path) {
        Some(asset) => {
            let headers = [(header::CONTENT_TYPE, asset.content_type)];
            (headers, asset.bytes).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
