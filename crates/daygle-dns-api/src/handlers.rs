//! HTTP handlers for the REST API.

use std::net::IpAddr;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygle_dns_authoritative::model::{
    MoveDirection, RecordInput, SplitHorizonEntryInput, SplitHorizonNetworkInput, ZoneInput,
};
use chrono::Datelike;
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

/// Whether `url` is an HTTP(S) URL. Blocklist sources are fetched over
/// HTTP(S), so anything else (e.g. `file://`) would only fail later with a
/// confusing transport error.
fn is_http_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Validate `new` before applying a runtime settings update. Only errors the
/// update *introduces* reject it: if the pre-update configuration already
/// failed validation the same way (possible for hand-managed config files),
/// the update itself is not at fault and is still applied.
fn validate_config_update(
    state: &AppState,
    old: &daygle_dns_core::config::DaygleConfig,
    new: &daygle_dns_core::config::DaygleConfig,
    what: &str,
) -> std::result::Result<(), Response> {
    if let Err(e) = new.validate() {
        let pre_existing = old
            .validate()
            .err()
            .map(|old_err| old_err.to_string() == e.to_string())
            .unwrap_or(false);
        if !pre_existing {
            return Err(map_err(e));
        }
        state
            .logs
            .warn("api", format!("{what} applied despite pre-existing validation error: {e}"));
    }
    Ok(())
}

/// Persist `config` to the config file when its path is known. The whole
/// document is rewritten (comments in an edited file are not preserved; the
/// example file documents every option).
///
/// No longer used: console-managed settings live in the database overlay
/// (`runtime_settings`); the file is bootstrap-only.
#[allow(dead_code)]
fn persist_config(
    state: &AppState,
    config: &daygle_dns_core::config::DaygleConfig,
) -> std::result::Result<(), (StatusCode, String)> {
    let Some(path) = &state.config_path else {
        return Ok(());
    };
    match config.to_toml() {
        Ok(text) => {
            if let Err(e) = std::fs::write(path.as_ref(), text) {
                state.logs.error(
                    "api",
                    format!("failed to persist config to {}: {e}", path.display()),
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "not applied: failed to persist to the config file".to_string(),
                ));
            }
            Ok(())
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot serialize config: {e}"),
        )),
    }
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
        "setup_pending": setup_pending(&state),
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

/// Body for `PUT /api/policy/blocklist/sources`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSourcesInput {
    /// The complete desired source list; replaces whatever is configured.
    pub sources: Vec<daygle_dns_core::config::BlocklistSourceConfig>,
}

/// `PUT /api/policy/blocklist/sources` - replace the configured remote
/// blocklist sources (add / edit / remove through the console).
///
/// The new list is validated, persisted to the config file and applied live:
/// the running source manager swaps its list and immediately refetches every
/// enabled source in the background, so a saved source starts blocking (or
/// unblocking) within seconds and the change survives a restart.
///
/// Removing the last source (or disabling all of them) clears the remote
/// blocklist right away, matching a fresh install with no sources.
pub async fn replace_blocklist_sources(
    State(state): State<AppState>,
    Json(input): Json<BlocklistSourcesInput>,
) -> Response {
    let Some(manager) = &state.blocklist_sources else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blocklist manager is unavailable; cannot apply sources",
        );
    };

    // Per-source sanity checks with clear messages, before full validation.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for source in &input.sources {
        let name = source.name.trim();
        if name.is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "blocklist source name must not be empty");
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("duplicate blocklist source name '{name}'"),
            );
        }
        if !is_http_url(&source.url) {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("source '{name}': URL must start with http:// or https://"),
            );
        }
    }

    let old_config = (*state.config.load_full()).clone();
    let mut config = old_config.clone();
    config.policy.blocklist_sources = input.sources.clone();

    if let Err(response) = validate_config_update(&state, &old_config, &config, "blocklist sources") {
        return response;
    }
    // Blocklist sources are console-managed runtime settings: store them in
    // the DB overlay (the config file is no longer rewritten).
    if let Err(e) = state
        .catalog
        .store()
        .put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(&config))
    {
        return map_err(e);
    }

    state.config.store(Arc::new(config));
    manager.set_sources(input.sources.clone());

    let any_enabled = input.sources.iter().any(|s| s.enabled);
    if input.sources.is_empty() || !any_enabled {
        // Nothing left to fetch: drop the remote blocklist immediately so
        // previously blocked domains start resolving again.
        let mut engine = state.policy.load_full().as_ref().clone();
        engine.set_remote_blocklist(daygle_dns_policy::Blocklist::new());
        state.policy.store(Arc::new(engine));
    } else {
        // Refetch in the background so the response is fast. A result is
        // applied only if the source list did not change again while the
        // fetch was in flight, so a stale response can never overwrite a
        // newer configuration.
        let manager = manager.clone();
        let policy = state.policy.clone();
        tokio::spawn(async move {
            let expected = manager.sources();
            match manager.refresh_all().await {
                Ok(Some(list)) => {
                    if manager.sources() != expected {
                        return; // superseded by a newer edit
                    }
                    let mut engine = policy.load_full().as_ref().clone();
                    engine.set_remote_blocklist(list);
                    policy.store(Arc::new(engine));
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "blocklist refresh after source edit failed"),
            }
        });
    }

    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!(
            "blocklist sources updated via the console ({} source{})",
            input.sources.len(),
            if input.sources.len() == 1 { "" } else { "s" }
        ),
    );
    Json(serde_json::json!({
        "applied": true,
        "sources": input.sources.len(),
        "total_domains": state.policy.load_full().remote_blocklist_len(),
    }))
    .into_response()
}

/// Query for `GET /api/policy/blocklist/sources/validate`.
#[derive(Deserialize)]
pub struct BlocklistValidateQuery {
    /// The URL to probe.
    url: String,
    /// Declared format: `domains`, `hosts` or `adblock`. Empty or `auto`
    /// auto-detects the format from the content.
    format: Option<String>,
}

/// `GET /api/policy/blocklist/sources/validate` - fetch a candidate source
/// URL and check that it really is the declared blocklist format (or detect
/// the format when `format=auto`), *without* saving it.
///
/// The verdict is returned with HTTP 200 as `{ok, format, domains, sample}`
/// (or `{ok: false, reason}` when the content does not parse / match the
/// declared format); transport failures are 502 and bad input is 400, so the
/// console can distinguish "wrong content" from "unreachable URL".
pub async fn validate_blocklist_source(
    State(state): State<AppState>,
    Query(query): Query<BlocklistValidateQuery>,
) -> Response {
    let url = query.url.trim();
    if !is_http_url(url) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "URL must start with http:// or https://",
        );
    }
    let requested = match query.format.as_deref().unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "" | "auto" | "detect" => None,
        "domains" => Some(daygle_dns_core::config::BlocklistFormat::Domains),
        "hosts" => Some(daygle_dns_core::config::BlocklistFormat::Hosts),
        "adblock" => Some(daygle_dns_core::config::BlocklistFormat::Adblock),
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown format '{other}' (use domains, hosts, adblock or auto)"),
            );
        }
    };
    let Some(manager) = &state.blocklist_sources else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "blocklist client is unavailable",
        );
    };
    let text = match manager.fetch_text(url).await {
        Ok(t) => t,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!("cannot fetch {url}: {e}"),
            );
        }
    };

    let fmt_name = |f: daygle_dns_core::config::BlocklistFormat| {
        format!("{f:?}").to_ascii_lowercase()
    };
    let verdict = |format: daygle_dns_core::config::BlocklistFormat| {
        let domains = daygle_dns_policy::parse_blocklist(&text, format);
        let sample: Vec<String> = domains.iter().take(5).cloned().collect();
        serde_json::json!({
            "ok": !domains.is_empty(),
            "format": fmt_name(format),
            "domains": domains.len(),
            "sample": sample,
            "reason": if domains.is_empty() {
                serde_json::Value::String(format!(
                    "fetched OK but found no domains - the content does not look like a {} list",
                    fmt_name(format)
                ))
            } else {
                serde_json::Value::Null
            },
        })
    };

    let detected = daygle_dns_policy::detect_blocklist_format(&text);
    let response = match requested {
        Some(format) => {
            // A source whose content clearly reads as another format is a
            // mistake (e.g. an adblock filter saved as `hosts`), even when the
            // declared parser would extract junk from it.
            if let Some(detected) = detected {
                if detected != format {
                    return Json(serde_json::json!({
                        "ok": false,
                        "format": fmt_name(format),
                        "domains": 0,
                        "reason": format!(
                            "the content looks like a {} list, not {} - pick the right format or use auto",
                            fmt_name(detected),
                            fmt_name(format)
                        ),
                    }))
                    .into_response();
                }
            }
            verdict(format)
        }
        None => match detected {
            Some(format) => verdict(format),
            None => serde_json::json!({
                "ok": false,
                "format": "auto",
                "domains": 0,
                "reason": "could not recognize the content as a domains list, hosts file or adblock filter",
            }),
        },
    };
    Json(response).into_response()
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

// ---- Query logs (searchable SQLite-backed per-query history) ---------------

#[derive(Deserialize)]
pub struct QueryLogsQuery {
    client: Option<String>,
    qname: Option<String>,
    qtype: Option<String>,
    protocol: Option<String>,
    outcome: Option<String>,
    rcode: Option<String>,
    from: Option<String>,
    to: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
    /// `csv` streams the full filtered result set as a download instead of a
    /// JSON page.
    format: Option<String>,
}

fn query_log_filter(query: &QueryLogsQuery) -> daygle_dns_authoritative::QueryLogFilter {
    daygle_dns_authoritative::QueryLogFilter {
        client: query.client.clone(),
        qname: query.qname.clone(),
        qtype: query.qtype.clone(),
        protocol: query.protocol.clone(),
        outcome: query.outcome.clone(),
        rcode: query.rcode.clone(),
        from: query.from.clone(),
        to: query.to.clone(),
        page: query.page,
        per_page: query.per_page,
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// `GET /api/querylogs` - search the query log. JSON by default; `?format=csv`
/// streams every matching row (no pagination) as a CSV download.
pub async fn query_logs(
    State(state): State<AppState>,
    Query(query): Query<QueryLogsQuery>,
) -> Response {
    if query.format.as_deref() == Some("csv") {
        // Export: the full filtered set, capped sanely so a huge retention
        // window cannot produce an unbounded response.
        let mut filter = query_log_filter(&query);
        filter.page = Some(1);
        filter.per_page = Some(10_000);
        let rows = match state.catalog.store().search_query_logs(&filter) {
            Ok((rows, _)) => rows,
            Err(e) => return map_err(e),
        };
        let mut csv = String::from("timestamp,client,qname,qtype,protocol,outcome,rcode,elapsed_ms\n");
        for r in &rows {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                csv_escape(&r.ts),
                csv_escape(&r.client),
                csv_escape(&r.qname),
                csv_escape(&r.qtype),
                csv_escape(&r.protocol),
                csv_escape(&r.outcome),
                r.rcode.as_deref().map(csv_escape).unwrap_or_default(),
                r.elapsed_ms,
            ));
        }
        let headers = [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"query-logs.csv\"",
            ),
        ];
        return (headers, csv).into_response();
    }

    match state
        .catalog
        .store()
        .search_query_logs(&query_log_filter(&query))
    {
        Ok((rows, total)) => Json(serde_json::json!({
            "entries": rows,
            "total": total,
            "page": query.page.unwrap_or(1).max(1),
            "per_page": query.per_page.unwrap_or(50).clamp(1, 500),
        }))
        .into_response(),
        Err(e) => map_err(e),
    }
}

/// `DELETE /api/querylogs` - clear the whole query log.
pub async fn clear_query_logs(State(state): State<AppState>) -> Response {
    match state.catalog.store().clear_query_logs() {
        Ok(deleted) => {
            state.logs.push(
                daygle_dns_core::LogLevel::Info,
                "api",
                format!("query log cleared ({deleted} entries)"),
            );
            Json(serde_json::json!({"deleted": deleted})).into_response()
        }
        Err(e) => map_err(e),
    }
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
    state.reload_notify.as_ref().expect("reload_notify checked above").notify_waiters();
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
    zone_type: &'static str,
    masters: Vec<String>,
    refresh_secs: Option<u64>,
}

pub async fn list_zones(State(state): State<AppState>) -> Response {
    let zones = match state.catalog.store().list_zones() {
        Ok(z) => z,
        Err(e) => return map_err(e),
    };
    let secondary = match state.catalog.store().list_secondary() {
        Ok(items) => items
            .into_iter()
            .map(|item| (item.zone_id.clone(), item))
            .collect::<std::collections::HashMap<_, _>>(),
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
            if let Some(item) = secondary.get(&zone.id) {
                ZoneView {
                    zone,
                    dnssec,
                    zone_type: "secondary",
                    masters: item.masters.clone(),
                    refresh_secs: Some(item.refresh_secs),
                }
            } else {
                ZoneView {
                    zone,
                    dnssec,
                    zone_type: "primary",
                    masters: Vec::new(),
                    refresh_secs: None,
                }
            }
        })
        .collect::<Vec<_>>();
    Json(views).into_response()
}

/// Payload used by the GUI's Add Zone form. `zone_type` currently accepts
/// `primary` or `secondary`; the other zone kinds need recursive forwarding or
/// catalog-specific behavior and are intentionally not represented as hosted
/// zones yet.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateZoneInput {
    pub name: String,
    #[serde(default = "default_zone_type")]
    pub zone_type: String,
    pub primary_ns: Option<String>,
    pub admin_mailbox: Option<String>,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>,
    /// Generate an RFC 1912-style YYYYMMDDnn serial for this new zone.
    #[serde(default)]
    pub serial_date_scheme: bool,
    /// Optional BIND zone-file contents. SOA metadata is imported when present.
    pub import_text: Option<String>,
    /// Master addresses for a secondary zone.
    #[serde(default)]
    pub masters: Vec<String>,
    /// Secondary refresh interval in seconds.
    pub refresh_secs: Option<u64>,
}

fn default_zone_type() -> String {
    "primary".to_string()
}

/// Canonicalize a policy domain list the same way the policy engine consumes it:
/// trimmed, trailing-dot removed, lowercased, and deduplicated.
/// Other DNS identifiers (zone names, TSIG key names, secondary-zone names) are
/// likewise normalized at their own boundaries, so the stored config reflects the
/// canonical form rather than whatever casing the last editor used.
fn normalize_policy_domains(items: &[String]) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for raw in items {
        let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if !d.is_empty() {
            let _ = out.insert(d);
        }
    }
    out.into_iter().collect()
}

/// Canonicalize recursive upstream entries before storing them.
/// Upstream entries are not DNS domain policies, but they are identifiers that
/// should be stored in a stable form (empty entries stripped, outer whitespace
/// trimmed). Transport/TLS schemes remain case-sensitive and are left as-is.
fn normalize_recursive_upstreams(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn date_serial() -> u32 {
    let now = chrono::Utc::now();
    (now.year() as u32) * 10_000 + now.month() * 100 + now.day()
}

fn imported_soa(records: &[RecordInput]) -> Option<(String, String, u32, u32, u32, u32, u32)> {
    let record = records.iter().find(|record| record.rtype.eq_ignore_ascii_case("SOA"))?;
    let fields: Vec<&str> = record.content.split_whitespace().collect();
    if fields.len() < 7 {
        return None;
    }
    Some((
        fields[0].to_string(),
        fields[1].to_string(),
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
        fields[4].parse().ok()?,
        fields[5].parse().ok()?,
        fields[6].parse().ok()?,
    ))
}

pub async fn create_zone(
    State(state): State<AppState>,
    Json(input): Json<CreateZoneInput>,
) -> Response {
    let zone_type = input.zone_type.trim().to_ascii_lowercase();
    if zone_type != "primary" && zone_type != "secondary" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "zone type must be primary or secondary",
        );
    }

    let mut imported_records: Option<Vec<RecordInput>> = None;
    let imported_soa = if let Some(text) = input.import_text.as_deref() {
        if text.trim().is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "imported zone file is empty");
        }
        let records = match daygle_dns_authoritative::parse::parse_zone_file(text) {
            Ok(records) => records,
            Err(e) => return map_err(e),
        };
        let soa = imported_soa(&records);
        imported_records = Some(records.into_iter().filter(|r| r.rtype != "SOA").collect());
        soa
    } else {
        None
    };

    let secondary_input = if zone_type == "secondary" {
        if input.masters.is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "secondary zones require at least one master server");
        }
        for master in &input.masters {
            if let Err(e) = daygle_dns_core::config::parse_master_addr(master) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid secondary master '{master}': {e}"),
                );
            }
        }
        let refresh_secs = input.refresh_secs.unwrap_or(3600);
        if refresh_secs == 0 {
            return error_response(StatusCode::BAD_REQUEST, "secondary refresh interval must be greater than zero");
        }
        Some(daygle_dns_core::config::SecondaryZoneConfig {
            name: input.name.trim().trim_end_matches('.').to_ascii_lowercase(),
            masters: input.masters.clone(),
            refresh_secs,
            enabled: true,
            tsig_key: String::new(),
        })
    } else {
        None
    };

    let mut zone_input = ZoneInput {
        name: input.name.clone(),
        primary_ns: input.primary_ns.clone(),
        admin_mailbox: input.admin_mailbox.clone(),
        serial: input.serial,
        refresh: input.refresh,
        retry: input.retry,
        expire: input.expire,
        minimum: input.minimum,
    };
    if let Some((primary_ns, admin_mailbox, serial, refresh, retry, expire, minimum)) = imported_soa {
        zone_input.primary_ns.get_or_insert(primary_ns);
        zone_input.admin_mailbox.get_or_insert(admin_mailbox);
        zone_input.serial.get_or_insert(serial);
        zone_input.refresh.get_or_insert(refresh);
        zone_input.retry.get_or_insert(retry);
        zone_input.expire.get_or_insert(expire);
        zone_input.minimum.get_or_insert(minimum);
    }
    if input.serial_date_scheme {
        zone_input.serial = Some(date_serial().saturating_mul(100).saturating_add(1));
    }

    let zone = match state.catalog.store().create_zone(&zone_input) {
        Ok(zone) => zone,
        Err(e) => return map_err(e),
    };
    if let Some(records) = imported_records.as_deref() {
        if let Err(e) = state.catalog.store().replace_records(&zone.id, records) {
            let _ = state.catalog.store().delete_zone(&zone.id);
            return map_err(e);
        }
    }
    let old_config = (*state.config.load_full()).clone();
    let mut new_config = old_config.clone();        if let Some(secondary) = &secondary_input {
            new_config.authoritative.secondary_zones.push(secondary.clone());
            if let Err(response) = validate_config_update(&state, &old_config, &new_config, "secondary zone") {
                let _ = state.catalog.store().delete_zone(&zone.id);
                return response;
            }
            if let Err(e) = state.catalog.store().set_secondary(
                &zone.id,
                &secondary.masters,
                secondary.refresh_secs,
            ) {
                let _ = state.catalog.store().delete_zone(&zone.id);
                return map_err(e);
            }
            state.config.store(Arc::new(new_config));
            if let Some(refresher) = &state.secondary_refresher {
                refresher.set_zone(secondary.clone());
            }
        }

    if let Err(e) = state.catalog.reload() {
        let _ = state.catalog.store().delete_zone(&zone.id);
        return map_err(e);
    }
    (StatusCode::CREATED, Json(zone)).into_response()
}

pub async fn delete_zone(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let existing = match state.catalog.store().get_zone(&id) {
        Ok(Some(zone)) => zone,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => return map_err(e),
    };
    let secondary = match state.catalog.store().list_secondary() {
        Ok(items) => items.into_iter().find(|item| item.zone_id == id),
        Err(e) => return map_err(e),
    };
    let old_config = (*state.config.load_full()).clone();
    let mut new_config = old_config.clone();
    if secondary.is_some() {
        new_config.authoritative.secondary_zones.retain(|z| {
            !z.name.eq_ignore_ascii_case(&existing.name)
        });
        if let Err(response) = validate_config_update(&state, &old_config, &new_config, "zone deletion") {
            return response;
        }
    }

    match state.catalog.store().delete_zone(&id) {
        Ok(true) => {
            if secondary.is_some() {
                state.config.store(Arc::new(new_config));
                if let Some(refresher) = &state.secondary_refresher {
                    refresher.remove_zone(&existing.name);
                }
            }
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

/// Body for `PUT /api/zones/{id}/soa` - edit the SOA metadata of a primary
/// zone. Every field is optional: omitted fields keep their current value.
/// `serial` sets the serial explicitly; otherwise, when `bump_serial` is
/// true the serial is incremented automatically so downstream secondaries
/// and zone transfers pick up the change. `bump_serial` wins over `serial`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateZoneSoaInput {
    pub primary_ns: Option<String>,
    pub admin_mailbox: Option<String>,
    pub serial: Option<u32>,
    #[serde(default)]
    pub bump_serial: bool,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>,
}

pub async fn update_zone_soa(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<UpdateZoneSoaInput>,
) -> Response {
    let current = match state.catalog.store().get_zone(&id) {
        Ok(Some(zone)) => zone,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => return map_err(e),
    };
    if let Some(response) = reject_secondary_mutation(&state, &id) {
        return response;
    }

    // SOA values are only meaningful when non-empty / non-zero.
    let require_non_empty = |raw: Option<String>, label: &str| match raw {
        Some(value) => {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                Err(format!("{label} cannot be empty"))
            } else {
                Ok(trimmed)
            }
        }
        None => Ok(String::new()),
    };
    let require_positive = |value: Option<u32>, label: &str| match value {
        Some(v) if v > 0 => Ok(v),
        Some(_) => Err(format!("{label} must be greater than zero")),
        None => Ok(0),
    };
    let primary_ns = match require_non_empty(input.primary_ns, "primary nameserver") {
        Ok(v) if v.is_empty() => current.primary_ns,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let admin_mailbox = match require_non_empty(input.admin_mailbox, "administrator mailbox") {
        Ok(v) if v.is_empty() => current.admin_mailbox,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let refresh = match require_positive(input.refresh, "refresh") {
        Ok(v) if v == 0 => current.refresh,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let retry = match require_positive(input.retry, "retry") {
        Ok(v) if v == 0 => current.retry,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let expire = match require_positive(input.expire, "expire") {
        Ok(v) if v == 0 => current.expire,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let minimum = match require_positive(input.minimum, "minimum TTL") {
        Ok(v) if v == 0 => current.minimum,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };

    let serial = if input.bump_serial {
        current.serial // rewritten by bump_serial below
    } else {
        input.serial.unwrap_or(current.serial)
    };

    if let Err(e) = state.catalog.store().set_zone_soa(
        &id,
        &primary_ns,
        &admin_mailbox,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    ) {
        return map_err(e);
    }
    if input.bump_serial {
        if let Err(e) = state.catalog.store().bump_serial(&id) {
            return map_err(e);
        }
    }

    let _ = state.catalog.reload();
    match state.catalog.store().get_zone(&id) {
        Ok(Some(zone)) => Json(zone).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => map_err(e),
    }
}

pub async fn list_records(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.catalog.store().list_records(&id) {
        Ok(records) => Json(records).into_response(),
        Err(e) => map_err(e),
    }
}

fn reject_secondary_mutation(state: &AppState, zone_id: &str) -> Option<Response> {
    match state.catalog.store().list_secondary() {
        Ok(items) if items.iter().any(|item| item.zone_id == zone_id) => Some(error_response(
            StatusCode::CONFLICT,
            "secondary zones are read-only",
        )),
        _ => None,
    }
}

pub async fn upsert_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<RecordInput>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &id) {
        return response;
    }
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
    // The zone id (`zone_id`) scopes the route and enforces secondary read-only
    // semantics; `delete_record` bumps the serial in its own transaction.
    Path((zone_id, rid)): Path<(String, String)>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &zone_id) {
        return response;
    }
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
    Path((zone_id, rid)): Path<(String, String)>,
    axum::Json(input): axum::Json<RecordDisabledInput>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &zone_id) {
        return response;
    }
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
    let (blocked, action, reason, group) = match state.advanced_blocking.load().evaluate(client, &domain) {
        Some(d) => (true, d.action.as_str().to_string(), d.reason, d.group),
        None => (false, "allow".to_string(), "no group blocked this query".to_string(), None),
    };
    Json(serde_json::json!({
        "client": client.to_string(),
        "domain": domain,
        "blocked": blocked,
        "action": action,
        "reason": reason,
        "group": group,
    }))
    .into_response()
}

// ---- DNSSEC -------------------------------------------------------------

pub async fn sign_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &id) {
        return response;
    }
    match state.catalog.sign_zone(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_err(e),
    }
}

pub async fn unsign_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &id) {
        return response;
    }
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

/// Current recursive cache configuration and runtime counters.
pub async fn cache_status(State(state): State<AppState>) -> Response {
    let resolver = state.resolver.load_full();
    let metrics = state.metrics.snapshot();
    Json(serde_json::json!({
        "enabled": resolver.is_some(),
        "capacity": resolver.as_ref().map(|r| r.cache_size()).unwrap_or(0),
        "tracked_names": resolver.as_ref().map(|r| r.tracked_names()).unwrap_or(0),
        "hits": metrics.cache_hits,
        "misses": metrics.cache_misses,
        "prefetch_enabled": state.config.load().recursive.prefetch_enabled,
        "serve_stale_secs": state.config.load().recursive.serve_stale_secs,
    }))
    .into_response()
}

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

/// `POST /api/auth/login` - verify username/password against the console
/// accounts in the database and return a session token. Always open
/// (unauthenticated by definition).
pub async fn auth_login(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<LoginInput>,
) -> Response {
    let user = match state.catalog.store().get_console_user(input.username.trim()) {
        Ok(user) => user,
        Err(e) => return map_err(e),
    };

    // Constant-ish response time: verify against a dummy hash when the user
    // does not exist (or is disabled, which is not disclosed) so timing
    // cannot enumerate accounts.
    let dummy_hash = "pbkdf2-sha256$210000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let ok = match user.as_ref() {
        Some(u) if u.enabled => {
            daygle_dns_core::auth::verify_password(&input.password, &u.password_hash)
        }
        _ => {
            let _ = daygle_dns_core::auth::verify_password(&input.password, dummy_hash);
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

    let user = user.expect("checked above");
    let ttl = Duration::from_secs(state.config.load().api.session_ttl_secs.max(60));
    let token = state.sessions.create(&user.username, user.role, ttl);
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("user '{}' logged in", user.username),
    );
    Json(serde_json::json!({
        "token": token,
        "username": user.username,
        "role": user.role.as_str(),
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

// ---- Self-service password change ---------------------------------------

/// Body of `POST /api/auth/password`.
#[derive(Deserialize)]
pub struct ChangePasswordInput {
    current_password: String,
    new_password: String,
}

/// `POST /api/auth/password` - the signed-in user rotates their own password.
///
/// Requires the current password. Every other session of the account is
/// revoked; the session that performed the change stays signed in.
/// Available to `viewer` accounts too (it is their own credential).
pub async fn auth_change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<ChangePasswordInput>,
) -> Response {
    let token = bearer_token(&headers).unwrap_or_default();
    let session = match state.sessions.verify(&token) {
        Some(s) => s,
        None => return error_response(StatusCode::UNAUTHORIZED, "not authenticated"),
    };
    let store = state.catalog.store();
    let user = match store.get_console_user(&session.username) {
        Ok(u) => u,
        Err(e) => return map_err(e),
    };
    let Some(user) = user else {
        return error_response(StatusCode::NOT_FOUND, "account no longer exists");
    };
    if !user.enabled {
        return error_response(StatusCode::FORBIDDEN, "account is disabled");
    }
    if !daygle_dns_core::auth::verify_password(&input.current_password, &user.password_hash) {
        state.logs.push(
            daygle_dns_core::LogLevel::Warn,
            "api",
            format!("failed password change for user '{}'", session.username),
        );
        return error_response(StatusCode::UNAUTHORIZED, "current password is incorrect");
    }
    if input.new_password.chars().count() < 8 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new password must be at least 8 characters",
        );
    }
    if input.new_password == input.current_password {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new password must differ from the current password",
        );
    }

    if let Err(e) =
        store.set_console_user_password(&session.username, &daygle_dns_core::auth::hash_password(&input.new_password))
    {
        return map_err(e);
    }
    // Other devices are signed out; this session survives.
    state.sessions.revoke_user_except(&session.username, &token);
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("user '{}' changed their password", session.username),
    );
    StatusCode::NO_CONTENT.into_response()
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// ---- First-run setup -----------------------------------------------------

/// Whether the one-time admin setup is pending: console auth is on, no
/// user accounts exist in the database yet, and no legacy static `api_token`
/// is configured (token-only mode manages auth itself, no setup step).
fn setup_pending(state: &AppState) -> bool {
    let config = state.config.load();
    let users = state.catalog.store().list_console_users().unwrap_or_default();
    config.api.auth_required && users.is_empty() && config.api.api_token.trim().is_empty()
}

/// `GET /api/auth/setup` - is the one-time admin setup still pending?
/// Open endpoint: it only reports a boolean, and must answer before any
/// account exists to bootstrap the GUI.
pub async fn auth_setup_status(State(state): State<AppState>) -> Response {
    let config = state.config.load_full();
    Json(serde_json::json!({
        "setup_pending": setup_pending(&state),
        "auth_required": config.api.auth_required,
        "token_auth": !config.api.api_token.trim().is_empty(),
    }))
    .into_response()
}

/// Body of `POST /api/auth/setup`.
#[derive(Deserialize)]
pub struct SetupInput {
    username: String,
    password: String,
}

/// `POST /api/auth/setup` - one-time creation of the first admin account.
///
/// Open endpoint (it runs before any account exists, which is the point).
/// It refuses to run once any user is configured or when console auth is
/// disabled. On success the account is persisted to the config file and a
/// session for it is returned, so the GUI lands straight in the console.
pub async fn auth_setup(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<SetupInput>,
) -> Response {
    let config = state.config.load_full();
    let existing = match state.catalog.store().list_console_users() {
        Ok(users) => users,
        Err(e) => return map_err(e),
    };
    if !existing.is_empty() {
        return error_response(
            StatusCode::CONFLICT,
            "setup already completed: an account exists; sign in instead",
        );
    }
    if !config.api.auth_required {
        return error_response(
            StatusCode::CONFLICT,
            "console authentication is disabled; enable api.auth_required first",
        );
    }
    if !config.api.api_token.trim().is_empty() {
        return error_response(
            StatusCode::CONFLICT,
            "auth is managed by a static api_token; remove it to use console accounts",
        );
    }
    drop(config);

    let username = input.username.trim().to_string();
    if username.is_empty() || username.len() > 64 || username.contains(char::is_whitespace) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "username must be 1-64 characters with no whitespace",
        );
    }
    if input.password.chars().count() < 8 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        );
    }

    let password_hash = daygle_dns_core::auth::hash_password(&input.password);
    if let Err(e) = state.catalog.store().create_console_user(
        &username,
        &daygle_dns_authoritative::ConsoleUserInput {
            password_hash,
            role: daygle_dns_core::config::Role::Admin,
            enabled: true,
        },
    ) {
        return map_err(e);
    }

    let ttl = Duration::from_secs(state.config.load().api.session_ttl_secs.max(60));
    let token = state.sessions.create(&username, daygle_dns_core::config::Role::Admin, ttl);
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("initial admin account '{username}' created via console setup"),
    );
    Json(serde_json::json!({
        "token": token,
        "username": username,
        "role": "admin",
        "expires_in_secs": ttl.as_secs(),
    }))
    .into_response()
}

// ---- Console user management (admin only) --------------------------------

/// Guards against demoting, disabling, or deleting the last enabled admin
/// account, which would permanently lock the console.
fn last_admin_guard(store: &daygle_dns_authoritative::ZoneStore, target: &str) -> Result<(), Response> {
    let user = match store.get_console_user(target).map_err(map_err)? {
        Some(u) => u,
        None => return Err(error_response(StatusCode::NOT_FOUND, "user not found")),
    };
    if user.role == daygle_dns_core::config::Role::Admin && user.enabled {
        let enabled_admins = store.count_enabled_admins().map_err(map_err)?;
        if enabled_admins <= 1 {
            return Err(error_response(
                StatusCode::CONFLICT,
                "cannot remove the last enabled admin account",
            ));
        }
    }
    Ok(())
}

fn validate_username_password(username: &str, password: &str) -> Option<Response> {
    if username.is_empty() || username.len() > 64 || username.contains(char::is_whitespace) {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            "username must be 1-64 characters with no whitespace",
        ));
    }
    if password.chars().count() < 8 {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        ));
    }
    None
}

/// `GET /api/users` - list console accounts (password hashes redacted).
pub async fn list_users(State(state): State<AppState>) -> Response {
    match state.catalog.store().list_console_users() {
        Ok(users) => Json(serde_json::json!(
            users.iter().map(|u| u.redacted()).collect::<Vec<_>>()
        ))
        .into_response(),
        Err(e) => map_err(e),
    }
}

/// Body of `POST /api/users`.
#[derive(Deserialize)]
pub struct CreateUserInput {
    username: String,
    password: String,
    role: Option<String>,
}

/// `POST /api/users` - create a console account (admin role by default).
pub async fn create_user(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<CreateUserInput>,
) -> Response {
    let username = input.username.trim().to_string();
    if let Some(resp) = validate_username_password(&username, &input.password) {
        return resp;
    }
    let role = match input.role.as_deref() {
        None | Some("admin") => daygle_dns_core::config::Role::Admin,
        Some("viewer") => daygle_dns_core::config::Role::Viewer,
        Some(other) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("unknown role '{other}'"))
        }
    };
    let store = state.catalog.store();
    let existing = match store.get_console_user(&username) {
        Ok(u) => u,
        Err(e) => return map_err(e),
    };
    if existing.is_some() {
        return error_response(StatusCode::CONFLICT, "username already exists");
    }
    let user = match store.create_console_user(
        &username,
        &daygle_dns_authoritative::ConsoleUserInput {
            password_hash: daygle_dns_core::auth::hash_password(&input.password),
            role,
            enabled: true,
        },
    ) {
        Ok(u) => u,
        Err(e) => return map_err(e),
    };
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("console account '{username}' created"),
    );
    Json(serde_json::json!(user.redacted())).into_response()
}

/// Body of `PATCH /api/users/{username}`.
#[derive(Deserialize, Default)]
pub struct UpdateUserInput {
    password: Option<String>,
    role: Option<String>,
    enabled: Option<bool>,
}

/// `PATCH /api/users/{username}` - reset a password, change a role, or
/// enable/disable an account. Changes to passwords, roles, or the enabled
/// flag revoke that account's live sessions.
pub async fn update_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    axum::Json(input): axum::Json<UpdateUserInput>,
) -> Response {
    let username = username.trim().to_string();
    let store = state.catalog.store();
    let existing = match store.get_console_user(&username) {
        Ok(u) => u,
        Err(e) => return map_err(e),
    };
    if existing.is_none() {
        return error_response(StatusCode::NOT_FOUND, "user not found");
    }

    if let Some(password) = &input.password {
        if let Some(resp) = validate_username_password(&username, password) {
            return resp;
        }
    }
    let new_role = match input.role.as_deref() {
        None => None,
        Some("admin") => Some(daygle_dns_core::config::Role::Admin),
        Some("viewer") => Some(daygle_dns_core::config::Role::Viewer),
        Some(other) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("unknown role '{other}'"))
        }
    };

    // Demotion to viewer on the last admin is the same lockout risk as a
    // deletion, so it goes through the same guard.
    if new_role == Some(daygle_dns_core::config::Role::Viewer)
        || input.enabled == Some(false)
    {
        if let Err(resp) = last_admin_guard(store, &username) {
            return resp;
        }
    }

    if let Some(password) = &input.password {
        if let Err(e) =
            store.set_console_user_password(&username, &daygle_dns_core::auth::hash_password(password))
        {
            return map_err(e);
        }
    }
    if let Some(role) = new_role {
        if let Err(e) = store.set_console_user_role(&username, role) {
            return map_err(e);
        }
    }
    if let Some(enabled) = input.enabled {
        if let Err(e) = store.set_console_user_enabled(&username, enabled) {
            return map_err(e);
        }
    }

    // The stored credentials/permissions changed: kill the account's live
    // sessions so the change takes effect immediately.
    if input.password.is_some() || new_role.is_some() || input.enabled.is_some() {
        state.sessions.revoke_user(&username);
    }
    let user = match store.get_console_user(&username) {
        Ok(u) => u.expect("existence checked above"),
        Err(e) => return map_err(e),
    };
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("console account '{username}' updated"),
    );
    Json(serde_json::json!(user.redacted())).into_response()
}

/// `DELETE /api/users/{username}` - remove a console account. The last
/// enabled admin cannot be deleted.
pub async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Response {
    let username = username.trim().to_string();
    let store = state.catalog.store();
    if let Err(resp) = last_admin_guard(store, &username) {
        return resp;
    }
    let deleted = match store.delete_console_user(&username) {
        Ok(d) => d,
        Err(e) => return map_err(e),
    };
    if !deleted {
        return error_response(StatusCode::NOT_FOUND, "user not found");
    }
    state.sessions.revoke_user(&username);
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("console account '{username}' deleted"),
    );
    StatusCode::NO_CONTENT.into_response()
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
    pub allowlist: Option<Vec<String>>,
    pub blocklist: Option<Vec<String>>,
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
    pub cache_size: Option<usize>,
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
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohUpdate {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
    pub self_signed: Option<bool>,
    pub server_name: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
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
        if let Some(v) = r.cache_size {
            config.recursive.cache_size = v;
        }
        if let Some(v) = &r.upstreams {
            config.recursive.upstreams = normalize_recursive_upstreams(v);
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
        if let Some(v) = &d.cert_path {
            config.dot.cert_path = v.clone();
        }
        if let Some(v) = &d.key_path {
            config.dot.key_path = v.clone();
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
        if let Some(v) = &d.cert_path {
            config.doh.cert_path = v.clone();
        }
        if let Some(v) = &d.key_path {
            config.doh.key_path = v.clone();
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
        if let Some(v) = &d.cert_path {
            config.doq.cert_path = v.clone();
        }
        if let Some(v) = &d.key_path {
            config.doq.key_path = v.clone();
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
        if let Some(v) = &p.allowlist {
            config.policy.allowlist = normalize_policy_domains(v);
            policy_changed = true;
        }
        if let Some(v) = &p.blocklist {
            config.policy.blocklist = normalize_policy_domains(v);
            policy_changed = true;
        }
        if let Some(v) = p.filter_aaaa {
            config.policy.filter_aaaa = v;
            policy_changed = true;
        }
        if let Some(v) = &p.filter_aaaa_except {
            config.policy.filter_aaaa_except = normalize_policy_domains(v);
            policy_changed = true;
        }
    }

    // Validate before applying anything: only errors this update introduces
    // reject it (a pre-existing failure on a hand-managed file is kept).
    if let Err(response) = validate_config_update(&state, &old_config, &config, "settings") {
        return response;
    }

    // Persist the DB-owned runtime settings to the database, then publish
    // live. (The config file is no longer rewritten: it holds bootstrap
    // values only, and the DB overlay wins over it on every boot.)
    if let Err(e) = state
        .catalog
        .store()
        .put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(&config))
    {
        return map_err(e);
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
            Ok(mut engine) => {
                // Rebuilding static policy must not discard domains already
                // fetched from remote sources; the source refresher owns that
                // portion and will replace it only when a refresh completes.
                if let Some(remote) = state.policy.load_full().remote_blocklist_snapshot() {
                    engine.set_remote_blocklist(remote.as_ref().clone());
                }
                state.policy.store(Arc::new(engine));
            }
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
