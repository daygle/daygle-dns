//! HTTP handlers for the REST API.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygle_dns_authoritative::model::{
    MoveDirection, RecordInput, SplitHorizonEntryInput, SplitHorizonNetworkInput, ZoneInput,
};
use daygle_dns_authoritative::store::MoveResult;
use daygle_dns_core::VERSION;
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

fn map_err(e: daygle_dns_core::error::DaygleError) -> Response {
    let status = match &e {
        daygle_dns_core::error::DaygleError::NotFound(_) => StatusCode::NOT_FOUND,
        daygle_dns_core::error::DaygleError::AlreadyExists(_) => StatusCode::CONFLICT,
        daygle_dns_core::error::DaygleError::InvalidRecord(_)
        | daygle_dns_core::error::DaygleError::InvalidPolicy(_)
        | daygle_dns_core::error::DaygleError::Config(_) => StatusCode::BAD_REQUEST,
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
    let config = state.config.load_full();
    Json(serde_json::json!({
        "version": VERSION,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "zones": zones,
        "records": records,
        "recursion": state.resolver.load_full().is_some(),
        "dnssec": config.recursive.dnssec_validate,
        "dot_enabled": config.dot.enabled,
        "doq_enabled": config.doq.enabled,
        "users_configured": !config.api.users.is_empty(),
        "api_enabled": config.api.enabled,
        "blocklist_sources": config.policy.blocklist_sources.len(),
        "remote_blocklist_domains": state.policy.load_full().remote_blocklist_len(),
    }))
    .into_response()
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    Json(state.metrics.snapshot()).into_response()
}

/// Dashboard statistics: time-series over a window plus top-N tables.
/// `?window=1h` (default), `6h` or `24h`.
#[derive(Deserialize)]
pub struct StatsQuery {
    window: Option<String>,
}

pub async fn stats(
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
) -> Response {
    let window_minutes = match query.window.as_deref() {
        Some("1h") | None => 60,
        Some("6h") => 360,
        Some("24h") => 1440,
        Some(other) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown window '{other}' (use 1h, 6h or 24h)"),
            );
        }
    };
    Json(serde_json::json!({
        "window": window_minutes,
        "series": state.stats.series(window_minutes),
        "top_clients": state.stats.top_clients(10),
        "top_domains": state.stats.top_domains(10),
        "top_blocked": state.stats.top_blocked(10),
    }))
    .into_response()
}

/// Per-source status for remote blocklist sources.
pub async fn blocklist_sources(State(state): State<AppState>) -> Response {
    let Some(manager) = &state.blocklist_sources else {
        return error_response(
            StatusCode::NOT_FOUND,
            "no blocklist sources configured (add [[policy.blocklist_sources]])",
        );
    };
    // The refresher is spawned even with an empty source list, so an empty
    // manager still means "nothing configured" - report 404 so the console
    // shows setup guidance instead of an empty table.
    if manager.is_empty() {
        return error_response(
            StatusCode::NOT_FOUND,
            "no blocklist sources configured (add [[policy.blocklist_sources]])",
        );
    }
    let sources: Vec<serde_json::Value> = manager
        .status()
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "url": s.url,
                "enabled": s.enabled,
                "format": format!("{:?}", s.format).to_ascii_lowercase(),
                "refresh_secs": s.refresh_secs,
                "last_fetch": s.last_fetch.map(|t| t.elapsed().as_secs()),
                "domains": s.domains,
                "last_error": s.last_error,
            })
        })
        .collect();
    Json(serde_json::json!({
        "sources": sources,
        "total_domains": state.policy.load_full().remote_blocklist_len(),
    }))
    .into_response()
}

/// Force an immediate refresh of every remote blocklist source.
pub async fn refresh_blocklist_sources(State(state): State<AppState>) -> Response {
    let Some(manager) = &state.blocklist_sources else {
        return error_response(
            StatusCode::NOT_FOUND,
            "no blocklist sources configured (add [[policy.blocklist_sources]])",
        );
    };
    if manager.is_empty() {
        return error_response(
            StatusCode::NOT_FOUND,
            "no blocklist sources configured (add [[policy.blocklist_sources]])",
        );
    }
    match manager.refresh_all().await {
        Ok(Some(list)) => {
            let mut engine = state.policy.load_full().as_ref().clone();
            engine.set_remote_blocklist(list);
            state.policy.store(Arc::new(engine));
            let total = state.policy.load_full().remote_blocklist_len();
            Json(serde_json::json!({
                "refreshed": true,
                "total_domains": total,
            }))
            .into_response()
        }
        Ok(None) => Json(serde_json::json!({"refreshed": true, "total_domains": 0})).into_response(),
        Err(e) => error_response(StatusCode::BAD_GATEWAY, format!("refresh failed: {e}")),
    }
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
    // Redact secrets before serving: password hashes and the static API
    // token must never round-trip to the browser, not even for admins (the
    // values are only ever written, never echoed back).
    let mut value = match serde_json::to_value(state.config.load_full().as_ref().clone()) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot serialize config: {e}"),
            );
        }
    };
    if let Some(api) = value.get_mut("api").and_then(|a| a.as_object_mut()) {
        let token = api.get("api_token").and_then(|t| t.as_str()).unwrap_or("");
        api.insert(
            "api_token".to_string(),
            serde_json::json!(if token.is_empty() { "" } else { "[redacted]" }),
        );
        if let Some(users) = api.get_mut("users").and_then(|u| u.as_array_mut()) {
            for user in users.iter_mut() {
                if let Some(obj) = user.as_object_mut() {
                    obj.insert("password_hash".to_string(), serde_json::json!("[redacted]"));
                }
            }
        }
    }
    axum::Json(value).into_response()
}

/// Re-read the configuration file and apply policy/upstream/listener changes
/// immediately.
pub async fn reload_config(State(state): State<AppState>) -> Response {
    if state.config_path.is_none() || state.reload_notify.is_none() {
        return error_response(
            StatusCode::CONFLICT,
            "live reload is unavailable (no config file or reload disabled)",
        );
    }
    // Wake the watcher; it performs the actual reload and reports failures in
    // the logs. The re-read is asynchronous by design.
    state.reload_notify.as_ref().unwrap().notify_waiters();
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "reload requested" })),
    )
        .into_response()
}

// ---- Zones --------------------------------------------------------------

#[derive(Serialize)]
struct ZoneView {
    #[serde(flatten)]
    zone: daygle_dns_authoritative::model::Zone,
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
    let records = match daygle_dns_authoritative::parse::parse_zone_file(&input.text) {
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
    // The zone id (`_zone_id`) only scopes the route; `delete_record` bumps the
    // zone serial in its own transaction, so no separate bump is needed here.
    Path((_zone_id, rid)): Path<(String, String)>,
) -> Response {
    match state.catalog.store().delete_record(&rid) {
        Ok(true) => {
            let _ = state.catalog.reload();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => map_err(e),
    }
}

/// Body for the per-record enable/disable toggle (Technitium-style staging:
/// a disabled record stays in the zone for later re-enable but stops being
/// served).
#[derive(Deserialize)]
pub struct RecordDisabledInput {
    disabled: bool,
}

/// `PUT /api/zones/{id}/records/{rid}/disabled` - stage or re-enable a
/// single record without deleting it. The zone serial is bumped and the
/// catalog reloaded, so the change is live immediately.
pub async fn set_record_disabled(
    State(state): State<AppState>,
    Path((_zone_id, rid)): Path<(String, String)>,
    axum::Json(input): axum::Json<RecordDisabledInput>,
) -> Response {
    match state.catalog.store().set_record_disabled(&rid, input.disabled) {
        Ok(true) => {
            let _ = state.catalog.reload();
            Json(serde_json::json!({ "id": rid, "disabled": input.disabled })).into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => map_err(e),
    }
}

/// `GET /api/zones/{id}/export` - the zone as a BIND-style zone file
/// (`text/plain`), including SOA and every record. Disabled records are
/// included as `; disabled:` comments, so an export doubles as a full-zone
/// backup that round-trips through the import endpoint.
pub async fn export_zone(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().export_zone_file(&id) {
        Ok(text) => {
            let name = state
                .catalog
                .store()
                .get_zone(&id)
                .ok()
                .flatten()
                .map(|z| z.name)
                .unwrap_or_else(|| "zone".to_string());
            let filename = format!("attachment; filename=\"{}.zone\"", name);
            let headers = [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CONTENT_DISPOSITION, filename.as_str()),
            ];
            (headers, text).into_response()
        }
        Err(e) => map_err(e),
    }
}

// ---- Advanced blocking --------------------------------------------------

/// Rebuild the shared Advanced Blocking engine from the stored groups and
/// publish it to the dispatcher. Best-effort: a store read failure leaves the
/// previous engine in place and is logged.
fn rebuild_advanced_blocking(state: &AppState) {
    match state.catalog.store().list_blocking_groups() {
        Ok(groups) => state
            .advanced_blocking
            .store(Arc::new(daygle_dns_policy::AdvancedBlocking::build(&groups))),
        Err(e) => tracing::warn!("failed to rebuild advanced blocking: {e}"),
    }
}

/// Reject invalid regex patterns before they reach the store, so a bad pattern
/// is a clear 400 rather than a rule silently dropped at engine-build time.
fn validate_group_regexes(input: &daygle_dns_core::blocking::BlockingGroupInput) -> Result<(), String> {
    for pattern in input.allow_regex.iter().chain(input.block_regex.iter()) {
        daygle_dns_policy::validate_regex(pattern)
            .map_err(|e| format!("invalid regex '{pattern}': {e}"))?;
    }
    Ok(())
}

/// `GET /api/policy/blocking` - list all Advanced Blocking groups.
pub async fn list_blocking_groups(State(state): State<AppState>) -> Response {
    match state.catalog.store().list_blocking_groups() {
        Ok(groups) => Json(groups).into_response(),
        Err(e) => map_err(e),
    }
}

/// `POST /api/policy/blocking` - create a group, or update the one with the
/// same name. The dispatcher's blocking engine is rebuilt immediately.
pub async fn upsert_blocking_group(
    State(state): State<AppState>,
    Json(input): Json<daygle_dns_core::blocking::BlockingGroupInput>,
) -> Response {
    if let Err(msg) = validate_group_regexes(&input) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    match state.catalog.store().upsert_blocking_group(&input) {
        Ok(group) => {
            rebuild_advanced_blocking(&state);
            Json(group).into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `DELETE /api/policy/blocking/{id}` - remove a group and rebuild the engine.
pub async fn delete_blocking_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().delete_blocking_group(&id) {
        Ok(true) => {
            rebuild_advanced_blocking(&state);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "blocking group not found"),
        Err(e) => map_err(e),
    }
}

/// Body for the Advanced Blocking tester.
#[derive(Deserialize)]
pub struct BlockingTestInput {
    /// Client IP to evaluate as.
    client: String,
    /// Domain to test.
    domain: String,
}

/// `POST /api/policy/blocking/test` - evaluate a `{client, domain}` pair
/// against the live blocking groups and report whether (and why) it is
/// blocked, so an operator can verify rules before relying on them.
pub async fn test_blocking(
    State(state): State<AppState>,
    Json(input): Json<BlockingTestInput>,
) -> Response {
    let client: IpAddr = match input.client.trim().parse() {
        Ok(ip) => ip,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "client must be an IP address")
        }
    };
    let domain = input.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let (blocked, action, reason) = match state.advanced_blocking.load().evaluate(client, &domain) {
        Some(d) => (true, d.action.as_str().to_string(), d.reason),
        None => (
            false,
            "allow".to_string(),
            "no group blocked this query".to_string(),
        ),
    };
    Json(serde_json::json!({
        "client": client.to_string(),
        "domain": domain,
        "blocked": blocked,
        "action": action,
        "reason": reason,
    }))
    .into_response()
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

// ---- Split horizon ------------------------------------------------------

/// All split-horizon networks and domain entries.
pub async fn get_split_horizon(State(state): State<AppState>) -> Response {
    let networks = match state.catalog.store().list_split_horizon_networks() {
        Ok(n) => n,
        Err(e) => return map_err(e),
    };
    let entries = match state.catalog.store().list_split_horizon_entries() {
        Ok(e) => e,
        Err(e) => return map_err(e),
    };
    Json(serde_json::json!({ "networks": networks, "entries": entries })).into_response()
}

/// Create a network, or update the CIDRs of an existing one (matched by name).
pub async fn upsert_split_horizon_network(
    State(state): State<AppState>,
    Json(input): Json<SplitHorizonNetworkInput>,
) -> Response {
    match state.catalog.store().upsert_split_horizon_network(&input) {
        Ok(network) => {
            let _ = state.catalog.reload();
            Json(network).into_response()
        }
        Err(e) => map_err(e),
    }
}

pub async fn delete_split_horizon_network(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    match state.catalog.store().delete_split_horizon_network(&name) {
        Ok(true) => {
            let _ = state.catalog.reload();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "network not found"),
        Err(e) => map_err(e),
    }
}

/// Create a split-horizon entry (appended after existing entries for the
/// same domain; first match wins).
pub async fn create_split_horizon_entry(
    State(state): State<AppState>,
    Json(input): Json<SplitHorizonEntryInput>,
) -> Response {
    match state.catalog.store().create_split_horizon_entry(&input) {
        Ok(entry) => {
            let _ = state.catalog.reload();
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(e) => map_err(e),
    }
}

pub async fn update_split_horizon_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<SplitHorizonEntryInput>,
) -> Response {
    match state.catalog.store().update_split_horizon_entry(&id, &input) {
        Ok(Some(entry)) => {
            let _ = state.catalog.reload();
            Json(entry).into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "entry not found"),
        Err(e) => map_err(e),
    }
}

pub async fn delete_split_horizon_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().delete_split_horizon_entry(&id) {
        Ok(true) => {
            let _ = state.catalog.reload();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "entry not found"),
        Err(e) => map_err(e),
    }
}

/// Body for `POST /api/split-horizon/entries/{id}/move`.
#[derive(Deserialize)]
pub struct MoveSplitHorizonEntryInput {
    direction: MoveDirection,
}

/// Move an entry one position up or down within its domain's ordering.
/// Returns `{"moved": true}` when the entry was swapped, `{"moved": false}`
/// when it is already at the edge, and 404 when the entry does not exist.
pub async fn move_split_horizon_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<MoveSplitHorizonEntryInput>,
) -> Response {
    match state
        .catalog
        .store()
        .move_split_horizon_entry(&id, input.direction)
    {
        Ok(MoveResult::Moved) => {
            let _ = state.catalog.reload();
            Json(serde_json::json!({ "moved": true })).into_response()
        }
        Ok(MoveResult::AtBoundary) => {
            Json(serde_json::json!({ "moved": false })).into_response()
        }
        Ok(MoveResult::NotFound) => error_response(StatusCode::NOT_FOUND, "entry not found"),
        Err(e) => map_err(e),
    }
}

// ---- Cache --------------------------------------------------------------

pub async fn clear_cache(State(state): State<AppState>) -> Response {
    if let Some(resolver) = state.resolver.load_full() {
        resolver.clear_cache();
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---- Auth ----------------------------------------------------------------

/// Login request body.
#[derive(Deserialize)]
pub struct LoginInput {
    username: String,
    password: String,
}

/// `POST /api/auth/login` - verify username/password against `api.users`
/// and return a session token. Always open (unauthenticated by definition).
pub async fn auth_login(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<LoginInput>,
) -> Response {
    let config = state.config.load_full();
    let user = config
        .api
        .users
        .iter()
        .find(|u| u.username == input.username.trim());

    // Constant-ish response time: verify against a dummy hash when the user
    // does not exist so timing cannot enumerate accounts.
    let ok = match user {
        Some(u) => daygle_dns_core::auth::verify_password(&input.password, &u.password_hash),
        None => {
            let _ = daygle_dns_core::auth::verify_password(
                &input.password,
                "pbkdf2-sha256$210000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            );
            false
        }
    };

    if !ok {
        state
            .logs
            .push(
                daygle_dns_core::LogLevel::Warn,
                "api",
                format!("failed login attempt for user '{}'", input.username),
            );
        return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
    }

    let ttl = Duration::from_secs(config.api.session_ttl_secs.max(60));
    let role = user
        .map(|u| u.role)
        .unwrap_or(daygle_dns_core::config::Role::Admin);
    let token = state.sessions.create(
        user.map(|u| u.username.as_str()).unwrap_or(""),
        role,
        ttl,
    );
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("user '{}' logged in", input.username),
    );
    Json(serde_json::json!({
        "token": token,
        "username": input.username,
        "role": role.as_str(),
        "expires_in_secs": ttl.as_secs(),
    }))
    .into_response()
}

/// `POST /api/auth/logout` - revoke the presented session token.
pub async fn auth_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = bearer_token(&headers).unwrap_or_default();
    state.sessions.revoke(&token);
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /api/auth/me` - identity of the presented session.
pub async fn auth_me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = bearer_token(&headers).unwrap_or_default();
    match state.sessions.verify(&token) {
        Some(session) => Json(serde_json::json!({
            "username": session.username,
            "role": session.role.as_str(),
            "expires_at_secs": session
                .expires_at
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }))
        .into_response(),
        None => error_response(StatusCode::UNAUTHORIZED, "not authenticated"),
    }
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// ---- Settings update -----------------------------------------------------

/// Partial update of the editable settings. `None` fields are left unchanged.
/// Applied to the live config, validated, persisted to the config file, and
/// (when listeners are affected) DNS listeners are rebound.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsUpdate {
    pub server: Option<ServerUpdate>,
    pub recursive: Option<RecursiveUpdate>,
    pub dot: Option<ListenerUpdate>,
    pub doh: Option<DohUpdate>,
    pub doq: Option<ListenerUpdate>,
    pub api: Option<ApiUpdate>,
    pub policy: Option<PolicyUpdate>,
}

/// Partial update for policy-engine settings surfaced in the console (only the
/// fields the UI edits; blocklists/rules are managed through their own APIs).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub filter_aaaa: Option<bool>,
    pub filter_aaaa_except: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerUpdate {
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub udp_enabled: Option<bool>,
    pub tcp_enabled: Option<bool>,
    pub reload_enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursiveUpdate {
    pub enabled: Option<bool>,
    pub upstreams: Option<Vec<String>>,
    pub dnssec_validate: Option<bool>,
    pub prefetch_enabled: Option<bool>,
    pub prefetch_ttl_fraction_pct: Option<u32>,
    pub prefetch_min_queries: Option<u32>,
    pub serve_stale_secs: Option<u64>,
}

/// Fields shared by the DoT and DoQ listeners.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerUpdate {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
    pub self_signed: Option<bool>,
    pub server_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohUpdate {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
    pub self_signed: Option<bool>,
    pub server_name: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiUpdate {
    pub gui_enabled: Option<bool>,
    pub cors_origins: Option<Vec<String>>,
}

/// `PUT /api/config` - apply a partial settings update.
///
/// The merged configuration is validated first (invalid input is rejected
/// with 400 and nothing changes), stored in the live `ArcSwap`, persisted to
/// the config file, and the DNS listeners are rebuilt when needed.
pub async fn update_settings(
    State(state): State<AppState>,
    axum::Json(update): axum::Json<SettingsUpdate>,
) -> Response {
    let old_config = (*state.config.load_full()).clone();
    let mut config = old_config.clone();
    let mut listeners_affected = false;

    if let Some(s) = &update.server {
        if let Some(v) = &s.listen {
            config.server.listen = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = s.port {
            config.server.port = v;
            listeners_affected = true;
        }
        if let Some(v) = s.udp_enabled {
            config.server.udp_enabled = v;
            listeners_affected = true;
        }
        if let Some(v) = s.tcp_enabled {
            config.server.tcp_enabled = v;
            listeners_affected = true;
        }
        if let Some(v) = s.reload_enabled {
            config.server.reload_enabled = v;
        }
    }
    if let Some(r) = &update.recursive {
        if let Some(v) = r.enabled {
            config.recursive.enabled = v;
        }
        if let Some(v) = &r.upstreams {
            config.recursive.upstreams = v.clone();
        }
        if let Some(v) = r.dnssec_validate {
            config.recursive.dnssec_validate = v;
        }
        if let Some(v) = r.prefetch_enabled {
            config.recursive.prefetch_enabled = v;
        }
        if let Some(v) = r.prefetch_ttl_fraction_pct {
            config.recursive.prefetch_ttl_fraction_pct = v;
        }
        if let Some(v) = r.prefetch_min_queries {
            config.recursive.prefetch_min_queries = v;
        }
        if let Some(v) = r.serve_stale_secs {
            config.recursive.serve_stale_secs = v;
        }
    }
    if let Some(d) = &update.dot {
        if let Some(v) = d.enabled {
            config.dot.enabled = v;
            listeners_affected = true;
        }
        if let Some(v) = d.port {
            config.dot.port = v;
            listeners_affected = true;
        }
        if let Some(v) = d.self_signed {
            config.dot.self_signed = v;
        }
        if let Some(v) = &d.server_name {
            config.dot.server_name = v.clone();
        }
    }
    if let Some(d) = &update.doh {
        if let Some(v) = d.enabled {
            config.doh.enabled = v;
            listeners_affected = true;
        }
        if let Some(v) = d.port {
            config.doh.port = v;
            listeners_affected = true;
        }
        if let Some(v) = d.self_signed {
            config.doh.self_signed = v;
        }
        if let Some(v) = &d.server_name {
            config.doh.server_name = v.clone();
        }
        if let Some(v) = &d.endpoint {
            config.doh.endpoint = v.clone();
        }
    }
    if let Some(d) = &update.doq {
        if let Some(v) = d.enabled {
            config.doq.enabled = v;
            listeners_affected = true;
        }
        if let Some(v) = d.port {
            config.doq.port = v;
            listeners_affected = true;
        }
        if let Some(v) = d.self_signed {
            config.doq.self_signed = v;
        }
        if let Some(v) = &d.server_name {
            config.doq.server_name = v.clone();
        }
    }
    if let Some(a) = &update.api {
        if let Some(v) = a.gui_enabled {
            config.api.gui_enabled = v;
        }
        if let Some(v) = &a.cors_origins {
            config.api.cors_origins = v.clone();
        }
    }
    let mut policy_changed = false;
    if let Some(p) = &update.policy {
        if let Some(v) = p.filter_aaaa {
            config.policy.filter_aaaa = v;
            policy_changed = true;
        }
        if let Some(v) = &p.filter_aaaa_except {
            config.policy.filter_aaaa_except = v.clone();
            policy_changed = true;
        }
    }

    // Validate before applying anything. A validation failure is rejected
    // only when this update introduces a *new* error: if the pre-update
    // configuration already failed validation the same way (possible for
    // hand-managed config files), the update itself is not at fault and is
    // still applied.
    if let Err(e) = config.validate() {
        let pre_existing = old_config
            .validate()
            .err()
            .map(|old| old.to_string() == e.to_string())
            .unwrap_or(false);
        if !pre_existing {
            return map_err(e);
        }
        state.logs.warn(
            "api",
            format!("settings applied despite pre-existing validation error: {e}"),
        );
    }

    // Persist to the config file when we know its path. The whole document
    // is rewritten (comments in an edited file are not preserved; the
    // example file documents every option).
    if let Some(path) = &state.config_path {
        match config.to_toml() {
            Ok(text) => {
                if let Err(e) = std::fs::write(path.as_ref(), text) {
                    state.logs.error(
                        "api",
                        format!("failed to persist settings to {}: {e}", path.display()),
                    );
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "applied in memory but failed to persist to the config file",
                    );
                }
            }
            Err(e) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("cannot serialize config: {e}"),
                );
            }
        }
    }

    // Publish live, then ask for a listener rebuild when needed.
    state.config.store(Arc::new(config.clone()));
    if listeners_affected {
        if let Some(rebuild) = &state.request_dns_rebuild {
            rebuild();
        }
    }
    // Rebuild the policy engine so a Filter-AAAA change applies immediately,
    // regardless of whether the config-file watcher is enabled.
    if policy_changed {
        match daygle_dns_policy::build_engine(&config.policy) {
            Ok(engine) => state.policy.store(Arc::new(engine)),
            Err(e) => tracing::warn!("policy rebuild after settings update failed: {e}"),
        }
    }
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        "settings updated via the console".to_string(),
    );
    Json((*state.config.load_full()).clone()).into_response()
}

// ---- GUI ----------------------------------------------------------------

pub async fn gui_index() -> Response {
    serve_gui("")
}

pub async fn gui_asset(Path(path): Path<String>) -> Response {
    serve_gui(&path)
}

fn serve_gui(path: &str) -> Response {
    match daygle_dns_gui::lookup(path) {
        Some(asset) => {
            let headers = [
                (header::CONTENT_TYPE, asset.content_type),
                (header::CACHE_CONTROL, asset.cache_control()),
            ];
            (headers, asset.bytes).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
