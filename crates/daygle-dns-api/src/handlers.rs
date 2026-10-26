//! HTTP handlers for the REST API.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Datelike;
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

pub(crate) fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

pub(crate) fn map_err(e: daygle_dns_core::error::DaygleError) -> Response {
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

/// Longest password accepted anywhere. Far above any real passphrase; it
/// only bounds the work (and memory) an unauthenticated request can cause.
const MAX_PASSWORD_LEN: usize = 1024;

/// Concurrent PBKDF2 computations. Each takes a CPU core for a noticeable
/// time (210k iterations), so bound them: a login flood then queues here
/// instead of starving the DNS listeners of CPU.
static PASSWORD_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Run a PBKDF2 job on the blocking pool (never on an async worker thread,
/// where it would stall every task scheduled there, DNS included).
async fn password_work<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    let _permit = password_permit().await;
    run_password_job(job).await
}

/// A slot for one PBKDF2 computation (see [`PASSWORD_WORK`]).
async fn password_permit() -> tokio::sync::SemaphorePermit<'static> {
    PASSWORD_WORK
        .acquire()
        .await
        .expect("password semaphore is never closed")
}

/// Run a PBKDF2 job on the blocking pool; the caller holds a permit.
async fn run_password_job<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(job)
        .await
        .expect("password hashing task panicked")
}

/// [`daygle_dns_core::auth::hash_password`] off the async runtime.
async fn hash_password(password: &str) -> String {
    let password = password.to_string();
    password_work(move || daygle_dns_core::auth::hash_password(&password)).await
}

/// Shorten attacker-controlled text before it is written to the in-memory
/// log ring (an unauthenticated login may carry megabytes in `username`).
fn log_safe(value: &str) -> String {
    const MAX: usize = 64;
    let mut out: String = value
        .chars()
        .take(MAX)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if value.chars().count() > MAX {
        out.push_str("...");
    }
    out
}

/// Serialize a configuration for the browser with secrets removed: password
/// hashes, the static API token and TSIG shared secrets are write-only and
/// never echoed back, not even to admins (viewers can read this endpoint, and
/// a TSIG secret authorizes zone transfers and dynamic updates).
fn redacted_config_json(
    config: &daygle_dns_core::config::DaygleConfig,
) -> std::result::Result<serde_json::Value, serde_json::Error> {
    let mut value = serde_json::to_value(config)?;
    if let Some(keys) = value
        .get_mut("authoritative")
        .and_then(|a| a.get_mut("tsig_keys"))
        .and_then(|k| k.as_array_mut())
    {
        for key in keys.iter_mut().filter_map(|k| k.as_object_mut()) {
            key.insert("secret".to_string(), serde_json::json!("[redacted]"));
        }
    }
    if let Some(api) = value.get_mut("api").and_then(|a| a.as_object_mut()) {
        let token = api.get("api_token").and_then(|t| t.as_str()).unwrap_or("");
        let redacted = if token.is_empty() { "" } else { "[redacted]" };
        api.insert("api_token".to_string(), serde_json::json!(redacted));
        if let Some(users) = api.get_mut("users").and_then(|u| u.as_array_mut()) {
            for user in users.iter_mut() {
                if let Some(obj) = user.as_object_mut() {
                    obj.insert("password_hash".to_string(), serde_json::json!("[redacted]"));
                }
            }
        }
    }
    Ok(value)
}

fn config_response(config: &daygle_dns_core::config::DaygleConfig) -> Response {
    match redacted_config_json(config) {
        Ok(value) => Json(value).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot serialize config: {e}"),
        ),
    }
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
///
/// Compares on the [`DaygleError::kind`] discriminant instead of the full
/// `Display` string so cosmetic changes to error messages (paths, line
/// numbers, capitalization) cannot make the comparison silently disagree.
// The Err variant carries a full axum `Response`; boxing it would churn every
// call site for no real gain.
#[allow(clippy::result_large_err)]
pub(crate) fn validate_config_update(
    state: &AppState,
    old: &daygle_dns_core::config::DaygleConfig,
    new: &daygle_dns_core::config::DaygleConfig,
    what: &str,
) -> std::result::Result<(), Response> {
    if let Err(e) = new.validate() {
        // Only the identical error counts as pre-existing: every config error
        // shares one kind, so comparing kinds let any new error through
        // whenever the old config had an unrelated problem.
        let pre_existing = old
            .validate()
            .err()
            .map(|old_err| old_err.to_string() == e.to_string())
            .unwrap_or(false);
        if !pre_existing {
            return Err(map_err(e));
        }
        state.logs.warn(
            "api",
            format!("{what} applied despite pre-existing validation error: {e}"),
        );
    }
    Ok(())
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
    // Update availability for the dashboard's banner: a pure cache read
    // (only the background warmer touches GitHub, at the configured
    // interval), skipped entirely while update checks are disabled.
    let release = if state.config.load().updates.enabled {
        run_blocking(crate::update::release_comparison).await
    } else {
        None
    };
    Json(serde_json::json!({
        "version": VERSION,
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "zones": zones,
        "records": records,
        "recursion": state.resolver.load_full().is_some(),
        // "recursive" or "forwarding" while recursion is enabled, else null.
        "resolution_mode": state.resolver.load_full().map(|r| r.mode()),
        "recursion_access": config.recursive.recursion_access,
        // Whether a verified local root zone (RFC 8806) is in use.
        "local_root": state.local_root.status().serving,
        "dnssec": config.recursive.dnssec_validate,
        "dot_enabled": config.dot.enabled,
        "doh_enabled": config.doh.enabled,
        "doq_enabled": config.doq.enabled,
        "users_configured": state
            .catalog
            .store()
            .count_console_users()
            .is_ok_and(|n| n > 0),
        "setup_pending": setup_pending(&state),
        "api_enabled": config.api.enabled,
        // Update availability (both null on hosts that cannot self-update):
        // the dashboard shows a banner with a link to the Update page.
        "update_available": release.as_ref().map(|r| r.outdated),
        "latest_release": release.as_ref().map(|r| r.latest.clone()),
        "blocklist_sources": config.policy.blocklist_sources.len(),
        "remote_blocklist_domains": state.policy.load_full().remote_blocklist_len(),
    }))
    .into_response()
}

/// Public liveness endpoint, deliberately exempt from `require_auth` so the
/// in-place updater can verify a restarted service is serving HTTP without
/// carrying credentials. Exposes no configuration or zone data.
pub async fn health() -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "version": VERSION,
        // Entry bundle embedded in this build's console, compared by the
        // running console against its own bundle to offer a reload when the
        // server was updated while a page stayed open.
        "console_build": daygle_dns_gui::entry_bundle_name(),
    }))
    .into_response()
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    Json(state.metrics.snapshot()).into_response()
}

/// `GET /api/metrics/prometheus` - every counter in the Prometheus text
/// format, for scraping (authorize with a read-only API token).
pub async fn metrics_prometheus(State(state): State<AppState>) -> Response {
    let zones = state
        .catalog
        .store()
        .list_zones()
        .map(|z| z.len())
        .unwrap_or(0);
    let text = state.metrics.render_prometheus(&[
        daygle_dns_core::metrics::Gauge {
            name: "uptime_seconds",
            help: "Seconds since the server started.",
            value: state.started_at.elapsed().as_secs_f64().floor(),
        },
        daygle_dns_core::metrics::Gauge {
            name: "zones",
            help: "Zones served by this server.",
            value: zones as f64,
        },
    ]);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

/// Dashboard statistics: time-series over a window plus top-N tables.
/// `?window=1h` (default), `6h` or `24h`.
#[derive(Deserialize)]
pub struct StatsQuery {
    window: Option<String>,
}

pub async fn stats(State(state): State<AppState>, Query(query): Query<StatsQuery>) -> Response {
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
                "scope": s.scope,
                "refresh_secs": s.refresh_secs,
                "last_fetch": s.last_fetch.map(|t| t.elapsed().as_secs()),
                "last_fetch_at": s
                    .last_fetch_at
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
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
    /// Sources renamed in this edit (old name -> new name), so the client
    /// groups that select them follow the rename.
    #[serde(default)]
    pub renames: std::collections::HashMap<String, String>,
}

/// `PUT /api/policy/blocklist/sources` - replace the configured remote
/// blocklist sources (add / edit / remove through the console).
///
/// The new list is validated, persisted to the database and applied live:
/// `set_sources` wakes the background refresher (reload.rs), which rebuilds
/// the remote blocklist from per-source caches and fetches anything new or
/// changed, so a saved source starts blocking (or unblocking) within seconds
/// and the change survives a restart.
///
/// Removing the last source (or disabling all of them) clears the remote
/// blocklist right away, matching a fresh install with no sources.
pub async fn replace_blocklist_sources(
    State(state): State<AppState>,
    Json(input): Json<BlocklistSourcesInput>,
) -> Response {
    let _config_write = state.config_write.lock().await;
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
            return error_response(
                StatusCode::BAD_REQUEST,
                "blocklist source name must not be empty",
            );
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

    if let Err(response) = validate_config_update(&state, &old_config, &config, "blocklist sources")
    {
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
        // Nothing left to fetch: drop the remote blocklists (everyone's and
        // the DoT listener's) immediately so previously blocked domains
        // start resolving again.
        daygle_dns_policy::publish_source_lists(&state.policy, None, None);
    }
    // For one or more enabled sources, `set_sources` above already woke the
    // background refresher, which rebuilds the remote blocklist from the
    // per-source caches and fetches anything new or changed.

    // Client groups follow renamed sources and drop removed ones.
    if let Err(e) = retarget_group_blocklists(&state, &input.sources, &input.renames) {
        return map_err(e);
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

/// Point client groups' selected blocklists at the new source list: a renamed
/// source keeps its groups, and a removed one is dropped from them.
fn retarget_group_blocklists(
    state: &AppState,
    sources: &[daygle_dns_core::config::BlocklistSourceConfig],
    renames: &std::collections::HashMap<String, String>,
) -> daygle_dns_core::error::Result<()> {
    let renames: std::collections::HashMap<String, &String> = renames
        .iter()
        .map(|(old, new)| (old.to_ascii_lowercase(), new))
        .collect();
    let mut changed = false;
    for group in state.catalog.store().list_blocking_groups()? {
        let mut kept: Vec<String> = Vec::new();
        for name in &group.blocklists {
            let name = renames
                .get(&name.to_ascii_lowercase())
                .map_or(name, |new| *new);
            let current = sources.iter().find(|s| s.name.eq_ignore_ascii_case(name));
            if let Some(source) = current {
                if !kept.contains(&source.name) {
                    kept.push(source.name.clone());
                }
            }
        }
        if kept != group.blocklists {
            state.catalog.store().upsert_blocking_group(
                &daygle_dns_core::blocking::BlockingGroupInput {
                    id: Some(group.id.clone()),
                    name: group.name.clone(),
                    enabled: group.enabled,
                    clients: group.clients.clone(),
                    allow: group.allow.clone(),
                    block: group.block.clone(),
                    allow_regex: group.allow_regex.clone(),
                    block_regex: group.block_regex.clone(),
                    blocklists: kept,
                    response: group.response.clone(),
                    ai_blocking: group.ai_blocking,
                },
            )?;
            changed = true;
        }
    }
    if changed {
        rebuild_advanced_blocking(state);
    }
    Ok(())
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
    let requested = match query
        .format
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "auto" | "detect" => None,
        "domains" => Some(daygle_dns_core::config::BlocklistFormat::Domains),
        "wildcard" => Some(daygle_dns_core::config::BlocklistFormat::Wildcard),
        "hosts" => Some(daygle_dns_core::config::BlocklistFormat::Hosts),
        "adblock" => Some(daygle_dns_core::config::BlocklistFormat::Adblock),
        "rpz" => Some(daygle_dns_core::config::BlocklistFormat::Rpz),
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "unknown format '{other}' (use domains, wildcard, hosts, adblock, rpz or auto)"
                ),
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
            return error_response(StatusCode::BAD_GATEWAY, format!("cannot fetch {url}: {e}"));
        }
    };

    let fmt_name =
        |f: daygle_dns_core::config::BlocklistFormat| format!("{f:?}").to_ascii_lowercase();
    let verdict = |format: daygle_dns_core::config::BlocklistFormat| {
        let domains = daygle_dns_policy::parse_blocklist(&text, format);
        let sample: Vec<String> = domains
            .iter()
            .filter(|d| {
                format != daygle_dns_core::config::BlocklistFormat::Wildcard || !d.starts_with("*.")
            })
            .take(5)
            .cloned()
            .collect();
        serde_json::json!({
            "ok": !domains.is_empty(),
            "format": fmt_name(format),
            "domains": daygle_dns_policy::domain_count(&domains, format),
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

    let detected = daygle_dns_policy::detect_blocklist_format_at(url, &text);
    let response = match requested {
        Some(format) => {
            // A source whose content clearly reads as another format is a
            // mistake (e.g. an adblock filter saved as `hosts`), even when the
            // declared parser would extract junk from it. A plain list of
            // names reads the same either way, so `domains` and `wildcard`
            // are the user's call.
            use daygle_dns_core::config::BlocklistFormat::{Domains, Wildcard};
            let plain = |f| matches!(f, Domains | Wildcard);
            if let Some(detected) = detected {
                if detected != format && !(plain(detected) && plain(format)) {
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
        Ok(list) => {
            // The DoT-scoped set too: it used to wait for the next scheduled
            // cycle, which may be hours away.
            daygle_dns_policy::publish_source_lists(
                &state.policy,
                Some(Arc::new(list)),
                manager.dot_blocklist(),
            );
            let total = state.policy.load_full().remote_blocklist_len();
            Json(serde_json::json!({
                "refreshed": true,
                "total_domains": total,
            }))
            .into_response()
        }
        Err(e) => error_response(StatusCode::BAD_GATEWAY, format!("refresh failed: {e}")),
    }
}

#[derive(Deserialize)]
pub struct LogsQuery {
    limit: Option<usize>,
}

pub async fn logs(State(state): State<AppState>, Query(query): Query<LogsQuery>) -> Response {
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

/// Which end of a time range a bound is.
#[derive(Clone, Copy)]
enum Bound {
    From,
    To,
}

/// Turn a `from`/`to` query bound into the form the stored timestamps
/// compare against. Rows store `Utc::now().to_rfc3339()` text and the store
/// compares it as a string, so a bound must be UTC with the same `+00:00`
/// layout: a local time such as `09:00+11:00` must become `22:00` the day
/// before. Accepts RFC 3339 with any offset, or a bare
/// `YYYY-MM-DDTHH:MM[:SS]` taken as UTC. `to` covers its whole last second.
fn query_log_bound(raw: &str, bound: Bound) -> Result<String, String> {
    use chrono::{DateTime, NaiveDateTime, Utc};
    let raw = raw.trim();
    let utc: DateTime<Utc> = match DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S")
            .or_else(|_| NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M"))
            .map(|n| n.and_utc())
            .map_err(|_| format!("'{raw}' is not a date and time (expected RFC 3339)"))?,
    };
    let second = utc.format("%Y-%m-%dT%H:%M:%S");
    Ok(match bound {
        // Every stored row in this second (with or without a fraction)
        // sorts at or after the bare second.
        Bound::From => second.to_string(),
        // ...and before this, which outranks any fraction or offset text.
        Bound::To => format!("{second}.999999999+99:99"),
    })
}

fn query_log_filter(
    query: &QueryLogsQuery,
) -> Result<daygle_dns_authoritative::QueryLogFilter, String> {
    let bound = |value: &Option<String>, which| {
        value
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .map(|v| query_log_bound(v, which))
            .transpose()
    };
    // Clients are logged in canonical form (2001:db8::1); match however
    // the address was typed (expanded, upper case, IPv4-mapped).
    let client = query.client.as_deref().map(|c| {
        c.trim()
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_canonical().to_string())
            .unwrap_or_else(|_| c.trim().to_string())
    });
    Ok(daygle_dns_authoritative::QueryLogFilter {
        client,
        qname: query.qname.clone(),
        qtype: query.qtype.clone(),
        protocol: query.protocol.clone(),
        outcome: query.outcome.clone(),
        rcode: query.rcode.clone(),
        from: bound(&query.from, Bound::From)?,
        to: bound(&query.to, Bound::To)?,
        page: query.page,
        per_page: query.per_page,
    })
}

/// Escape one CSV field (RFC 4180). Fields a spreadsheet would evaluate as a
/// formula (`=`, `+`, `-`, `@`, tab, CR) get a leading `'`: query names are
/// client-controlled, and an export is typically opened in a spreadsheet.
fn csv_escape(value: &str) -> String {
    let guarded;
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        guarded = format!("'{value}");
        guarded.as_str()
    } else {
        value
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// `GET /api/ai/verdicts` query params.
#[derive(Debug, Default, serde::Deserialize)]
pub struct AiVerdictsQuery {
    /// Optional status filter (`pending`, `classified`, `skipped`).
    status: Option<String>,
    /// Optional domain substring search.
    q: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
}

/// `POST /api/ai/override` body.
#[derive(Debug, serde::Deserialize)]
pub struct AiOverrideBody {
    pub domain: String,
    /// `allow` installs an AI-exempt override; `clear` removes it.
    pub action: String,
    /// Optional justification, shown in the console.
    #[serde(default)]
    pub reason: String,
}

/// `GET /api/querylogs` - search the query log. JSON by default; `?format=csv`
/// streams every matching row (no pagination) as a CSV download.
pub async fn query_logs(
    State(state): State<AppState>,
    Query(query): Query<QueryLogsQuery>,
) -> Response {
    let filter = match query_log_filter(&query) {
        Ok(filter) => filter,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    if query.format.as_deref() == Some("csv") {
        // Export: the full filtered set, capped sanely so a huge retention
        // window cannot produce an unbounded response.
        let mut filter = filter;
        filter.page = Some(1);
        filter.per_page = Some(daygle_dns_authoritative::ZoneStore::QUERY_LOG_MAX_EXPORT);
        let rows = match state.catalog.store().export_query_logs(&filter) {
            Ok((rows, _)) => rows,
            Err(e) => return map_err(e),
        };
        let mut csv =
            String::from("timestamp,client,qname,qtype,protocol,outcome,rcode,elapsed_ms\n");
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

    match state.catalog.store().search_query_logs(&filter) {
        Ok((rows, total)) => Json(serde_json::json!({
            "entries": rows,
            "total": total,
            "page": query.page.unwrap_or(1).max(1),
            "per_page": query
                .per_page
                .unwrap_or(50)
                .clamp(1, daygle_dns_authoritative::ZoneStore::QUERY_LOG_MAX_PAGE),
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

// ── AI subsystem (`[ai]` section of the config) ─────────────────────────────
//
// Every endpoint 404s when the AI subsystem is disabled, mirroring how the
// blocklist-source endpoints treat an empty configuration.

fn ai_engine(state: &AppState) -> Option<Arc<daygle_dns_ml::AiEngine>> {
    state.ai.clone()
}

/// `GET /api/ai/status` - scanner configuration and per-status counts.
pub async fn ai_status(State(state): State<AppState>) -> Response {
    let Some(ai) = ai_engine(&state) else {
        return map_err(daygle_dns_ml::ai_disabled_error());
    };
    let settings = ai.settings.load();
    let statuses = match ai.store.status_counts() {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let blockable = match ai.blockable_counts() {
        Ok(counts) => counts,
        Err(e) => return map_err(e),
    };
    let snapshot = ai.snapshot().load();
    Json(serde_json::json!({
        "enabled": settings.enabled,
        "mode": match settings.mode {
            daygle_dns_core::config::AiMode::Train => "train",
            daygle_dns_core::config::AiMode::Enforce => "enforce",
        },
        // The pipeline actually running (a missing model file falls back to
        // the heuristic rules whatever `model_path` says).
        "backend": ai.backend_name(),
        "workers": settings.workers,
        "scan_interval_secs": settings.scan_interval_secs,
        "expire_check_secs": settings.expire_check_secs,
        "confidence_floor": settings.confidence_floor,
        "category_ttl_secs": settings.category_ttl_secs,
        "threat_ttl_secs": settings.threat_ttl_secs,
        "block_threshold": settings.block_threshold,
        "auto_block_categories": settings.auto_block_categories,
        "backend_categories": ai.backend_categories(),
        "status_counts": serde_json::Map::from_iter(
            statuses
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::from(v))),
        ),
        // Domains that qualify for auto-blocking, by category: blocked in
        // enforce mode, what would be blocked in train mode.
        "blockable_counts": blockable,
        "snapshot_len": snapshot.len(),
    }))
    .into_response()
}

/// `GET /api/ai/verdicts?page=&per_page=&status=` - paginated verdict list.
pub async fn ai_verdicts(
    State(state): State<AppState>,
    Query(query): Query<AiVerdictsQuery>,
) -> Response {
    let Some(ai) = ai_engine(&state) else {
        return map_err(daygle_dns_ml::ai_disabled_error());
    };
    let per_page = query.per_page.unwrap_or(50).clamp(1, 500);
    let page = query.page.unwrap_or(1).max(1);
    match ai.store.list_verdicts(
        query.status.as_deref(),
        query.q.as_deref(),
        per_page,
        (page - 1).saturating_mul(per_page),
    ) {
        Ok((rows, total)) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "entries": rows.iter().map(|r| serde_json::json!({
                    "domain": r.domain,
                    "category": r.category,
                    "severity": r.severity,
                    "status": r.status,
                    "confidence": r.confidence,
                    "backend": r.backend,
                    "evidence": r.evidence,
                    "observations": r.observations,
                    "overridden": r.overridden,
                    "classified_at": chrono::DateTime::<chrono::Utc>::from_timestamp(r.classified_at, 0)
                        .map(|t| t.to_rfc3339()),
                    "expires_at": chrono::DateTime::<chrono::Utc>::from_timestamp(r.expires_at, 0)
                        .map(|t| t.to_rfc3339()),
                }))
                .collect::<Vec<_>>(),
                "total": total,
                "per_page": per_page,
                "page": page,
            })),
        )
            .into_response(),
        Err(e) => map_err(e),
    }
}

/// `POST /api/ai/override` - `{"domain": "x", "action": "allow" | "clear"}`.
pub async fn ai_override(
    State(state): State<AppState>,
    Json(body): Json<AiOverrideBody>,
) -> Response {
    let Some(ai) = ai_engine(&state) else {
        return map_err(daygle_dns_ml::ai_disabled_error());
    };
    let domain = body.domain.trim().trim_matches('.').to_ascii_lowercase();
    let domain_ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !domain_ok {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "enter a valid domain name, such as news.example.com"
            })),
        )
            .into_response();
    }
    match body.action.as_str() {
        "allow" => match ai.set_allow_override(&domain, &body.reason) {
            Ok(()) => {
                state.logs.push(
                    daygle_dns_core::LogLevel::Info,
                    "api",
                    format!("AI override: '{domain}' is now AI-exempt"),
                );
                Json(serde_json::json!({"domain": domain, "action": "allow"})).into_response()
            }
            Err(e) => map_err(e),
        },
        "clear" => match ai.clear_override(&domain) {
            Ok(true) => {
                state.logs.push(
                    daygle_dns_core::LogLevel::Info,
                    "api",
                    format!("AI override cleared for '{domain}'"),
                );
                Json(serde_json::json!({"domain": domain, "action": "clear"})).into_response()
            }
            Ok(false) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no override exists"})),
            )
                .into_response(),
            Err(e) => map_err(e),
        },
        other => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown action '{other}' (expected allow or clear)")
            })),
        )
            .into_response(),
    }
}

/// `GET /api/ai/overrides` - the exempted domains (an exemption also covers
/// subdomains), newest first.
pub async fn ai_overrides(State(state): State<AppState>) -> Response {
    let Some(ai) = ai_engine(&state) else {
        return map_err(daygle_dns_ml::ai_disabled_error());
    };
    match ai.store.list_overrides() {
        Ok(rows) => Json(serde_json::json!({
            "overrides": rows.iter().map(|o| serde_json::json!({
                "domain": o.domain,
                "action": o.action,
                "reason": o.reason,
                "created_at": chrono::DateTime::<chrono::Utc>::from_timestamp(o.created_at, 0)
                    .map(|t| t.to_rfc3339()),
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => map_err(e),
    }
}

/// `POST /api/ai/rescan` - wake the scanner for an immediate cycle.
pub async fn ai_rescan(State(state): State<AppState>) -> Response {
    let Some(ai) = ai_engine(&state) else {
        return map_err(daygle_dns_ml::ai_disabled_error());
    };
    ai.trigger_rescan();
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        "AI rescan requested".to_string(),
    );
    Json(serde_json::json!({"requested": true})).into_response()
}

pub async fn config(State(state): State<AppState>) -> Response {
    config_response(&state.config.load_full())
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
    state
        .reload_notify
        .as_ref()
        .expect("reload_notify checked above")
        .notify_waiters();
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "reload requested" })),
    )
        .into_response()
}

/// `GET /api/update` - host-level information relevant to upgrading the server.
///
/// The canonical update path for this project is the one-line installer
/// (`install.sh`). It fetches the latest source, rebuilds the `daygle-dns`
/// binary, installs it in place, preserves the existing configuration, zones,
/// certificates and database, and restarts the service when systemd is in use.
///
/// On Linux hosts that look like a real install (systemd unit, binary under
/// `/usr/local/bin`, or a config under `/etc/`) with `git` + `cargo` present,
/// `can_update` is `true` and the console offers `POST /api/update/start` to
/// run the same steps in place. Elsewhere this endpoint is guidance-only and
/// tells the operator to run the `update_command` on the host.
pub async fn update_info(State(state): State<AppState>) -> Response {
    let install_script = "https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh";
    let has_config_file = state.config_path.is_some();
    let config_dir = config_dir(&state);
    // Spawns processes (`sh`, `curl` with multi-second timeouts) and reads
    // files: keep it off the async workers.
    // Whether automatic checks are on. They warm the release cache at the
    // configured cadence; the release data below is always a pure cache
    // read, so it is surfaced even with checks off - a manual `Check Now`
    // then populates it (and the Update page explains the state).
    let release_checks_on = state.config.load().updates.enabled;
    let (has_systemd, can_update, gates, release, update_state, checked_ago) =
        run_blocking(move || {
            let dir = config_dir.as_deref();
            (
                std::path::Path::new("/etc/systemd/system/daygle-dns.service").is_file(),
                crate::update::can_update(dir),
                crate::update::gates(dir),
                // Latest-release comparison (cache only, never touches GitHub):
                // only resolved on hosts that can self-update, so dev/non-Linux
                // consoles get nulls.
                crate::update::release_comparison(),
                crate::update::read_state(),
                crate::update::latest_release_age_secs(),
            )
        })
        .await;

    Json(serde_json::json!({
        "version": VERSION,
        "install_script": install_script,
        "has_config_file": has_config_file,
        "has_systemd": has_systemd,
        "can_update": can_update,
        "gates": gates,
        "latest_release": release.as_ref().map(|r| r.latest.clone()),
        "updater_outdated": release.as_ref().map(|r| r.outdated),
        "updater_bootstrap_required": release.as_ref().map(|r| r.bootstrap_required),
        "update_command": format!("curl -fsSL {install_script} | sh"),
        "preserves": ["configuration", "zones", "certificates", "database"],
        "note": "Update Now runs this same installer on the host: the latest release is built from source and installed in place, preserving configuration, zones, certificates and the database, and re-provisions the systemd update service. The command shown here is the manual equivalent.",
        "state": update_state,
        "checks_enabled": release_checks_on,
        "check_interval_secs": state.config.load().updates.check_interval_secs,
        "latest_checked_secs_ago": checked_ago,
    }))
    .into_response()
}

/// `POST /api/update/check` - run one release check now (admin).
///
/// The Update page's "Check Now": fetches the latest published release
/// from GitHub on demand instead of waiting up to the full
/// `[updates].check_interval_secs` cycle for the background warmer, so a
/// freshly published release is visible immediately. Throttled server-side
/// (see [`crate::update::manual_release_check`]): every click is a request
/// off GitHub's unauthenticated budget, so a request inside the minute
/// window is answered from the cache with a retry hint. Automatic checks
/// being disabled does not block this - it is the explicit replacement
/// for them.
pub async fn update_check(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let can = run_blocking(move || crate::update::can_update(config_dir.as_deref())).await;
    if !can {
        return error_response(
            StatusCode::CONFLICT,
            "this host cannot self-update, so there is nothing to check",
        );
    }
    let (check, comparison) = run_blocking(|| {
        let check = crate::update::manual_release_check();
        (check, crate::update::release_comparison())
    })
    .await;
    Json(serde_json::json!({
        "latest_release": check.latest,
        "updater_outdated": comparison.as_ref().map(|r| r.outdated),
        "updater_bootstrap_required": comparison.as_ref().map(|r| r.bootstrap_required),
        "checked_now": check.checked_now,
        "fetched": check.fetched_now,
        "retry_after_secs": check.retry_after_secs,
    }))
    .into_response()
}

/// Directory of the config file, used by the updater's install-evidence
/// checks.
fn config_dir(state: &AppState) -> Option<std::path::PathBuf> {
    state
        .config_path
        .as_deref()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
}

/// Run blocking host work (process spawns, file I/O) on the blocking pool.
async fn run_blocking<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(job)
        .await
        .expect("blocking update task panicked")
}

fn start_error_response(e: crate::update::StartError) -> Response {
    let status = match e {
        crate::update::StartError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    };
    error_response(status, e.to_string())
}

/// `GET /api/update/status` - progress of an in-place update (polls safe).
///
/// Returns the updater's state snapshot plus a tail of its output so the
/// console can show live progress. Status is read from the shared temp-dir
/// state file, so a poll after the server restarts still reports the outcome
/// of the run that just restarted it.
pub async fn update_status(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let (can_update, gates, update_state, log) = run_blocking(move || {
        let dir = config_dir.as_deref();
        (
            crate::update::can_update(dir),
            crate::update::gates(dir),
            crate::update::read_state(),
            crate::update::log_tail(8192),
        )
    })
    .await;
    Json(serde_json::json!({
        "version": VERSION,
        "can_update": can_update,
        "gates": gates,
        "state": update_state,
        "log": log,
    }))
    .into_response()
}

/// `POST /api/update/start` - begin an in-place update (admin only).
///
/// Only available when the host qualifies (see [`crate::update::can_update`]).
/// The updater runs detached, then hands the privileged step to the root
/// systemd update service, which restarts the server - so a `202` only means
/// the update began; follow `/api/update/status` for progress and to detect
/// the restart.
pub async fn update_start(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let Ok(exe) = std::env::current_exe() else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot locate the running binary",
        );
    };
    match run_blocking(move || crate::update::start(&exe, config_dir.as_deref())).await {
        Ok(pid) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "started": true, "pid": pid })),
        )
            .into_response(),
        Err(e) => start_error_response(e),
    }
}

/// `POST /api/update/dismiss` - clear the recorded update-run state (admin
/// only) so the console stops showing the last `done`/`error` result.
/// Refused while a run is active.
pub async fn update_dismiss() -> Response {
    match run_blocking(crate::update::clear_state).await {
        Ok(()) => Json(serde_json::json!({ "dismissed": true })).into_response(),
        Err(e) => start_error_response(e),
    }
}

/// `GET /api/update/preflight` - run health checks before starting an update
/// (admin only: it probes the network and the staging directory).
///
/// Returns structured results indicating whether an update can proceed, with
/// specific fix instructions for any detected issues. This allows the console
/// to show actionable guidance before the user attempts an update.
pub async fn update_preflight(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let result = run_blocking(move || crate::update::preflight(config_dir.as_deref())).await;
    Json(result).into_response()
}

/// `GET /api/ai/model-status` - the installed AI model files (present, size,
/// sha256), for the console's AI page. Shares the update run state so an
/// in-flight model update can be followed from there too.
pub async fn ai_model_status(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let (dir, files, update_state) = run_blocking(move || {
        let (dir, files) = crate::update::model_status(config_dir.as_deref());
        (dir, files, crate::update::read_state())
    })
    .await;
    Json(serde_json::json!({
        "models_dir": dir.as_ref().map(|d| d.display().to_string()),
        "files": files,
        "state": update_state,
    }))
    .into_response()
}

/// `POST /api/ai/update-models` - begin a models-only update: download the
/// `daygle-dns-models.tar.gz` bundle from the latest release and hand it to
/// the privileged apply service, which installs the model files and restarts
/// the server. A `202` only means the update began; poll
/// `GET /api/ai/model-status` (which embeds the shared update-state) until
/// `done`/`error`.
pub async fn ai_update_models(State(state): State<AppState>) -> Response {
    let config_dir = config_dir(&state);
    let Ok(exe) = std::env::current_exe() else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot locate the running binary",
        );
    };
    match run_blocking(move || crate::update::start_models(&exe, config_dir.as_deref())).await {
        Ok(pid) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "started": true, "pid": pid })),
        )
            .into_response(),
        Err(e) => start_error_response(e),
    }
}

// ---- Zones --------------------------------------------------------------

#[derive(Serialize)]
struct ZoneView {
    #[serde(flatten)]
    zone: daygle_dns_authoritative::model::Zone,
    dnssec: bool,
    /// Whether a signed zone uses NSEC3 rather than NSEC.
    nsec3: bool,
    /// The DS records the parent zone must publish for a signed zone (one
    /// per active key, so two during a key rollover).
    ds: Vec<String>,
    zone_type: &'static str,
    /// The consumed catalog zone that added this zone, if any.
    catalog: Option<String>,
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
    let catalog_members = match state.catalog.store().catalog_members() {
        Ok(m) => m,
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
            let nsec3 = dnssec && state.catalog.store().zone_nsec3(&zone.id).unwrap_or(false);
            let catalog = catalog_members.get(&zone.id).cloned();
            let ds = if dnssec {
                state.catalog.ds_records(&zone.id).unwrap_or_default()
            } else {
                Vec::new()
            };
            if let Some(item) = secondary.get(&zone.id) {
                ZoneView {
                    zone,
                    dnssec,
                    nsec3,
                    ds,
                    zone_type: "secondary",
                    catalog,
                    masters: item.masters.clone(),
                    refresh_secs: Some(item.refresh_secs),
                }
            } else {
                ZoneView {
                    zone,
                    dnssec,
                    nsec3,
                    ds,
                    zone_type: "primary",
                    catalog,
                    masters: Vec::new(),
                    refresh_secs: None,
                }
            }
        })
        .collect::<Vec<_>>();
    Json(views).into_response()
}

/// The SOA defaults a new zone gets, with where each came from.
pub(crate) struct ZoneDefaults {
    pub primary_ns: Option<String>,
    /// `setting`, `hostname` or `none`.
    pub primary_ns_source: &'static str,
    pub admin_mailbox: Option<String>,
    /// `setting`, `admin_email` or `none`.
    pub admin_mailbox_source: &'static str,
    /// The mailbox as an email address, when that reading is unambiguous.
    pub admin_email: Option<String>,
}

/// Resolve the SOA defaults for new zones: the Settings values when set,
/// else this server's host name and the first administrator's email.
pub(crate) fn zone_defaults(state: &AppState) -> ZoneDefaults {
    let config = state.config.load_full();
    let configured_ns = config.authoritative.default_primary_ns.trim();
    let (primary_ns, primary_ns_source) = if !configured_ns.is_empty() {
        let ns = if configured_ns.ends_with('.') {
            configured_ns.to_string()
        } else {
            format!("{configured_ns}.")
        };
        (Some(ns), "setting")
    } else {
        match daygle_dns_core::config::detect_server_name() {
            Some(name) => (Some(name), "hostname"),
            None => (None, "none"),
        }
    };
    let configured_mailbox = config.authoritative.default_admin_mailbox.trim();
    let (admin_mailbox, admin_email, admin_mailbox_source) = if !configured_mailbox.is_empty() {
        let rname = daygle_dns_core::config::mailbox_to_rname(configured_mailbox)
            .unwrap_or_else(|_| configured_mailbox.to_string());
        let email = daygle_dns_core::config::rname_to_email(&rname);
        (Some(rname), email, "setting")
    } else {
        let email = state.catalog.store().first_admin_email().ok().flatten();
        match email
            .as_deref()
            .map(daygle_dns_core::config::mailbox_to_rname)
        {
            Some(Ok(rname)) if !rname.is_empty() => (Some(rname), email, "admin_email"),
            _ => (None, None, "none"),
        }
    };
    ZoneDefaults {
        primary_ns,
        primary_ns_source,
        admin_mailbox,
        admin_mailbox_source,
        admin_email,
    }
}

/// `GET /api/zones/defaults` - the SOA values a new zone would get, so the
/// console can pre-fill Add Zone and explain empty Settings fields.
pub async fn zone_defaults_handler(State(state): State<AppState>) -> Response {
    let d = zone_defaults(&state);
    Json(serde_json::json!({
        "primary_ns": d.primary_ns,
        "primary_ns_source": d.primary_ns_source,
        "admin_mailbox": d.admin_mailbox,
        "admin_mailbox_source": d.admin_mailbox_source,
        "admin_email": d.admin_email,
        // What an empty setting falls back to, whatever is set now.
        "server_name": daygle_dns_core::config::detect_server_name(),
        "first_admin_email": state.catalog.store().first_admin_email().ok().flatten(),
    }))
    .into_response()
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
    /// Default SOA contact mailbox for zones created by this request; when
    /// not provided the API falls back to the server's
    /// `authoritative.default_admin_mailbox` setting.
    #[serde(default)]
    pub default_admin_mailbox: Option<String>,
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

/// Canonicalize CIDR network allow-lists (AXFR and dynamic-update networks).
fn normalize_policy_networks(items: &[String]) -> Vec<String> {
    normalize_recursive_upstreams(items)
}

/// Canonicalize NOTIFY targets (`IP`, `IP:port`, `[IPv6]:port`).
fn normalize_notify_targets(items: &[String]) -> Vec<String> {
    normalize_recursive_upstreams(items)
}

fn date_serial() -> u32 {
    let now = chrono::Utc::now();
    (now.year() as u32) * 10_000 + now.month() * 100 + now.day()
}

fn imported_soa(records: &[RecordInput]) -> Option<(String, String, u32, u32, u32, u32, u32)> {
    let record = records
        .iter()
        .find(|record| record.rtype.eq_ignore_ascii_case("SOA"))?;
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
    let _config_write = state.config_write.lock().await;
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
            return error_response(
                StatusCode::BAD_REQUEST,
                "secondary zones require at least one master server",
            );
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
            return error_response(
                StatusCode::BAD_REQUEST,
                "secondary refresh interval must be greater than zero",
            );
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

    // People type email addresses; the SOA wants the RNAME form.
    let admin_mailbox = match input
        .admin_mailbox
        .clone()
        .or_else(|| input.default_admin_mailbox.clone())
        .map(|m| daygle_dns_core::config::mailbox_to_rname(&m))
        .transpose()
    {
        Ok(m) => m.filter(|m| !m.is_empty()),
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let mut zone_input = ZoneInput {
        name: input.name.clone(),
        primary_ns: input.primary_ns.clone(),
        admin_mailbox,
        serial: input.serial,
        refresh: input.refresh,
        retry: input.retry,
        expire: input.expire,
        minimum: input.minimum,
    };
    let has_imported_soa = imported_soa.is_some();
    if let Some((primary_ns, admin_mailbox, serial, refresh, retry, expire, minimum)) = imported_soa
    {
        zone_input.primary_ns.get_or_insert(primary_ns);
        zone_input.admin_mailbox.get_or_insert(admin_mailbox);
        zone_input.serial.get_or_insert(serial);
        zone_input.refresh.get_or_insert(refresh);
        zone_input.retry.get_or_insert(retry);
        zone_input.expire.get_or_insert(expire);
        zone_input.minimum.get_or_insert(minimum);
    }
    // No explicit nameserver or mailbox, and the imported zone file carried
    // no SOA: use the server's defaults (Settings, else this server's host
    // name and the first administrator's email), else the store's
    // ns1.<zone>. / admin.<zone>. fallbacks.
    if !has_imported_soa {
        let defaults = zone_defaults(&state);
        if zone_input.primary_ns.is_none() {
            zone_input.primary_ns = defaults.primary_ns;
        }
        if zone_input.admin_mailbox.is_none() {
            zone_input.admin_mailbox = defaults.admin_mailbox;
        }
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
    let mut new_config = old_config.clone();
    if let Some(secondary) = &secondary_input {
        new_config
            .authoritative
            .secondary_zones
            .push(secondary.clone());
        if let Err(response) =
            validate_config_update(&state, &old_config, &new_config, "secondary zone")
        {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneEnabledInput {
    enabled: bool,
}

/// `PUT /api/zones/{id}/enabled` - stop or resume serving a zone while
/// retaining its records and metadata.
pub async fn set_zone_enabled(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::Json(input): axum::Json<ZoneEnabledInput>,
) -> Response {
    match state.catalog.store().set_zone_enabled(&id, input.enabled) {
        Ok(true) => {
            if let Err(e) = state.catalog.reload() {
                return map_err(e);
            }
            match state.catalog.store().get_zone(&id) {
                Ok(Some(zone)) => Json(zone).into_response(),
                Ok(None) => error_response(StatusCode::NOT_FOUND, "zone not found"),
                Err(e) => map_err(e),
            }
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => map_err(e),
    }
}

pub async fn delete_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let _config_write = state.config_write.lock().await;
    let existing = match state.catalog.store().get_zone(&id) {
        Ok(Some(zone)) => zone,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "zone not found"),
        Err(e) => return map_err(e),
    };
    let secondary = match state.catalog.store().list_secondary() {
        Ok(items) => items.into_iter().find(|item| item.zone_id == id),
        Err(e) => return map_err(e),
    };
    match state.catalog.store().catalog_members() {
        Ok(members) => {
            if let Some(catalog) = members.get(&id) {
                return error_response(
                    StatusCode::CONFLICT,
                    format!(
                        "{} was added by the catalog zone {catalog}: remove it from the catalog, or stop following the catalog",
                        existing.name
                    ),
                );
            }
        }
        Err(e) => return map_err(e),
    }
    let old_config = (*state.config.load_full()).clone();
    let mut new_config = old_config.clone();
    if secondary.is_some() {
        new_config
            .authoritative
            .secondary_zones
            .retain(|z| !z.name.eq_ignore_ascii_case(&existing.name));
        if let Err(response) =
            validate_config_update(&state, &old_config, &new_config, "zone deletion")
        {
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
    let admin_mailbox = match require_non_empty(input.admin_mailbox, "administrator mailbox")
        .and_then(|v| daygle_dns_core::config::mailbox_to_rname(&v))
    {
        Ok(v) if v.is_empty() => current.admin_mailbox,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let refresh = match require_positive(input.refresh, "refresh") {
        Ok(0) => current.refresh,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let retry = match require_positive(input.retry, "retry") {
        Ok(0) => current.retry,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let expire = match require_positive(input.expire, "expire") {
        Ok(0) => current.expire,
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let minimum = match require_positive(input.minimum, "minimum TTL") {
        Ok(0) => current.minimum,
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

pub async fn list_records(State(state): State<AppState>, Path(id): Path<String>) -> Response {
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

/// Replace an existing record in place (the console's Edit action). Unlike
/// the collection `PUT`, which always adds a record, this keeps the record's
/// id so editing never leaves the old value behind.
pub async fn replace_record(
    State(state): State<AppState>,
    Path((zone_id, rid)): Path<(String, String)>,
    Json(input): Json<RecordInput>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &zone_id) {
        return response;
    }
    match state.catalog.store().replace_record(&zone_id, &rid, &input) {
        Ok(Some(record)) => {
            let _ = state.catalog.reload();
            Json(record).into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "record not found"),
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
    match state
        .catalog
        .store()
        .set_record_disabled(&rid, input.disabled)
    {
        Ok(true) => {
            let _ = state.catalog.reload();
            Json(serde_json::json!({ "id": rid, "disabled": input.disabled })).into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => map_err(e),
    }
}

// ---- Health checks (failover records) ----------------------------------

/// The health check to put on a record (the record comes from the path).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckInput {
    pub kind: String,
    pub port: u16,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_health_interval")]
    pub interval_secs: u32,
}

fn default_health_interval() -> u32 {
    30
}

/// `GET /api/health-checks` - every health check, with its record and
/// whether it is passing.
pub async fn list_health_checks(State(state): State<AppState>) -> Response {
    match &state.health {
        Some(health) => Json(health.status()).into_response(),
        None => Json(Vec::<()>::new()).into_response(),
    }
}

/// `PUT /api/zones/{id}/records/{rid}/health` - add or change the health
/// check on an A or AAAA record.
pub async fn set_health_check(
    State(state): State<AppState>,
    Path((zone_id, rid)): Path<(String, String)>,
    axum::Json(input): axum::Json<HealthCheckInput>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &zone_id) {
        return response;
    }
    let record = match state.catalog.store().get_record(&rid) {
        Ok(Some(r)) if r.zone_id == zone_id => r,
        Ok(_) => return error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => return map_err(e),
    };
    if !matches!(record.rtype.as_str(), "A" | "AAAA") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "only A and AAAA records can be health-checked",
        );
    }
    let mut check = daygle_dns_authoritative::model::HealthCheck {
        record_id: rid.clone(),
        kind: input.kind,
        port: input.port,
        path: input.path,
        host: input.host,
        interval_secs: input.interval_secs,
    };
    if let Err(msg) = check.validate() {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    if let Err(e) = state.catalog.store().set_health_check(&check) {
        return map_err(e);
    }
    let _ = state.catalog.reload();
    if let Some(health) = &state.health {
        health.recheck(&rid);
    }
    Json(check).into_response()
}

/// `DELETE /api/zones/{id}/records/{rid}/health` - stop checking a record
/// (it is served again whatever its state).
pub async fn delete_health_check(
    State(state): State<AppState>,
    Path((zone_id, rid)): Path<(String, String)>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &zone_id) {
        return response;
    }
    match state.catalog.store().get_record(&rid) {
        Ok(Some(r)) if r.zone_id == zone_id => {}
        Ok(_) => return error_response(StatusCode::NOT_FOUND, "record not found"),
        Err(e) => return map_err(e),
    }
    match state.catalog.store().delete_health_check(&rid) {
        Ok(true) => {
            let mut unhealthy = (*state.catalog.unhealthy()).clone();
            unhealthy.remove(&rid);
            if state.catalog.set_unhealthy(unhealthy).is_ok() {
                let _ = state.catalog.reload();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "the record has no health check"),
        Err(e) => map_err(e),
    }
}

/// `GET /api/zones/{id}/export` - the zone as a BIND-style zone file
/// (`text/plain`), including SOA and every record. Disabled records are
/// included as `; disabled:` comments, so an export doubles as a full-zone
/// backup that round-trips through the import endpoint.
pub async fn export_zone(State(state): State<AppState>, Path(id): Path<String>) -> Response {
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

// ---- Backup and restore --------------------------------------------------

/// A scratch file next to the database (or in the system temp directory
/// for an in-memory one), removed when dropped.
struct ScratchFile(std::path::PathBuf);

impl ScratchFile {
    fn new(database: &str, purpose: &str) -> Self {
        let name = format!(
            "daygle-dns-{purpose}-{}-{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        );
        let dir = std::path::Path::new(database)
            .parent()
            .filter(|p| database != ":memory:" && !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        Self(dir.join(name))
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Deserialize)]
pub struct BackupQuery {
    #[serde(default)]
    query_logs: bool,
}

/// `GET /api/backup[?query_logs=true]` - download a backup of the database
/// (admin only: it holds private keys and password hashes).
pub async fn download_backup(
    State(state): State<AppState>,
    Query(query): Query<BackupQuery>,
) -> Response {
    let config = state.config.load_full();
    let database = config.authoritative.database.clone();
    let ai_database = daygle_dns_ml::database_path(&config.ai, &database);
    let store = state.catalog.store().clone();
    let made = tokio::task::spawn_blocking(move || {
        let scratch = ScratchFile::new(&database, "backup");
        store.backup_to(&scratch.0, query.query_logs, Some(&ai_database))?;
        Ok::<_, daygle_dns_core::error::DaygleError>(std::fs::read(&scratch.0)?)
    })
    .await;
    match made {
        Ok(Ok(bytes)) => {
            let filename = format!(
                "attachment; filename=\"daygle-dns-backup-{}.db\"",
                chrono::Local::now().format("%Y%m%d-%H%M")
            );
            state.logs.info(
                "backup",
                format!("backup downloaded ({} bytes)", bytes.len()),
            );
            (
                [
                    (header::CONTENT_TYPE, "application/vnd.sqlite3"),
                    (header::CONTENT_DISPOSITION, filename.as_str()),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                bytes,
            )
                .into_response()
        }
        Ok(Err(e)) => map_err(e),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `GET /api/backup/restore` - the restore waiting for a restart, if any.
pub async fn pending_restore(State(state): State<AppState>) -> Response {
    let database = state.config.load().authoritative.database.clone();
    Json(serde_json::json!({
        "pending": daygle_dns_authoritative::backup::pending_restore(&database),
    }))
    .into_response()
}

/// `POST /api/backup/restore` (the backup file as the body) - check the
/// backup and stage it to replace the database on the next restart.
pub async fn stage_restore(State(state): State<AppState>, body: axum::body::Bytes) -> Response {
    let database = state.config.load().authoritative.database.clone();
    if database == ":memory:" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "this server runs on an in-memory database, which cannot be restored",
        );
    }
    let staged = tokio::task::spawn_blocking(move || {
        let scratch = ScratchFile::new(&database, "upload");
        std::fs::write(&scratch.0, &body)?;
        daygle_dns_authoritative::backup::stage_restore(&database, &scratch.0)
    })
    .await;
    match staged {
        Ok(Ok(info)) => {
            state.logs.info(
                "backup",
                "restore staged: it replaces the database when the server restarts".to_string(),
            );
            Json(serde_json::json!({ "pending": info })).into_response()
        }
        Ok(Err(e)) => map_err(e),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `DELETE /api/backup/restore` - drop the staged restore.
pub async fn cancel_restore(State(state): State<AppState>) -> Response {
    let database = state.config.load().authoritative.database.clone();
    match daygle_dns_authoritative::backup::cancel_restore(&database) {
        Ok(true) => {
            state
                .logs
                .info("backup", "staged restore cancelled".to_string());
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "no restore is staged"),
        Err(e) => map_err(e),
    }
}

// ---- Advanced blocking --------------------------------------------------

/// Rebuild the shared Advanced Blocking engine from the stored groups and
/// publish it to the dispatcher. Best-effort: a store read failure leaves the
/// previous engine in place and is logged.
pub(crate) fn rebuild_advanced_blocking(state: &AppState) {
    match state.catalog.store().list_blocking_groups() {
        Ok(groups) => {
            let groups = state.config.load().resolve_blocking_groups(groups);
            state
                .advanced_blocking
                .store(Arc::new(daygle_dns_policy::AdvancedBlocking::build(
                    &groups,
                    state.advanced_blocking.load().lists(),
                )))
        }
        Err(e) => tracing::warn!("failed to rebuild advanced blocking: {e}"),
    }
}

/// Reject invalid regex patterns before they reach the store, so a bad pattern
/// is a clear 400 rather than a rule silently dropped at engine-build time.
fn validate_group_regexes(
    input: &daygle_dns_core::blocking::BlockingGroupInput,
) -> Result<(), String> {
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
    Json(mut input): Json<daygle_dns_core::blocking::BlockingGroupInput>,
) -> Response {
    if let Err(msg) = validate_group_regexes(&input) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    // Client networks are addresses or names of configured networks.
    let config = state.config.load_full();
    if let Some(entry) = input
        .clients
        .iter()
        .find(|c| !config.is_network_entry(c.trim()) && !daygle_dns_policy::is_listener_keyword(c))
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "'{}' is not a network, an address, a network name, or a listener name (DoT, DoH, DoQ)",
                entry.trim()
            ),
        );
    }
    // Selected blocklists must name configured sources; store each under the
    // source's own spelling.
    let mut blocklists: Vec<String> = Vec::new();
    for name in &input.blocklists {
        let Some(source) = config
            .policy
            .blocklist_sources
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name.trim()))
        else {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("no blocklist source named '{}'", name.trim()),
            );
        };
        if !blocklists.contains(&source.name) {
            blocklists.push(source.name.clone());
        }
    }
    input.blocklists = blocklists;
    match state.catalog.store().upsert_blocking_group(&input) {
        Ok(group) => {
            rebuild_advanced_blocking(&state);
            Json(group).into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `POST /api/policy/blocking/{id}/move` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveGroupInput {
    /// `up` or `down`.
    pub direction: String,
}

/// `POST /api/policy/blocking/{id}/move` - move a group one place up or down
/// in the evaluation order (the first matching group decides).
pub async fn move_blocking_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<MoveGroupInput>,
) -> Response {
    let delta = match input.direction.as_str() {
        "up" => -1,
        "down" => 1,
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("direction must be 'up' or 'down', not '{other}'"),
            )
        }
    };
    match state.catalog.store().move_blocking_group(&id, delta) {
        Ok(true) => {
            rebuild_advanced_blocking(&state);
            match state.catalog.store().list_blocking_groups() {
                Ok(groups) => Json(groups).into_response(),
                Err(e) => map_err(e),
            }
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "blocking group not found"),
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
    /// Encrypted listener to evaluate as (`dot`, `doh` or `doq`, matching
    /// the special client-list entries); omitted for plain DNS. Optional so
    /// existing console calls keep working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listener: Option<String>,
}

/// `POST /api/policy/blocking/test` - evaluate a `{client, domain}` pair
/// against the live blocking groups and report whether (and why) it is
/// blocked, so an operator can verify rules before relying on them.
pub async fn test_blocking(
    State(state): State<AppState>,
    Json(input): Json<BlockingTestInput>,
) -> Response {
    // Queries reach the policy with IPv4-mapped sources unmapped; test the
    // same address the resolver would see.
    let client: IpAddr = match input.client.trim().parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "client must be an IP address"),
    };
    let domain = input
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let listener = input
        .listener
        .as_deref()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| daygle_dns_policy::advanced::LISTENER_KEYWORDS.contains(&l.as_str()))
        .map(|l| match l.as_str() {
            "dot" => "dot",
            "doh" => "doh",
            _ => "doq",
        });
    // The resolver skips client-group blocking for allowlisted names.
    let allowlisted = state.policy.load().is_allowlisted(&domain);
    let groups = state.advanced_blocking.load();
    let verdict = if allowlisted {
        None
    } else {
        groups.evaluate(client, &domain, listener)
    };
    // Whether the AI may auto-block this client's queries, and which group
    // decided that (none: the client is in no group).
    let (ai_blocking, ai_group) = groups.ai_blocking(client, listener);
    let ai_group = ai_group.map(str::to_string);
    let (blocked, action, reason, group) = match verdict {
        Some(d) => (true, d.action.as_str().to_string(), d.reason, d.group),
        None => (
            false,
            "allow".to_string(),
            if allowlisted {
                "domain is on the allowlist".to_string()
            } else {
                "no group blocked this query".to_string()
            },
            None,
        ),
    };
    Json(serde_json::json!({
        "client": client.to_string(),
        "domain": domain,
        "blocked": blocked,
        "action": action,
        "reason": reason,
        "group": group,
        "ai_blocking": ai_blocking,
        "ai_group": ai_group,
    }))
    .into_response()
}

// ---- DNSSEC -------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SignZoneBody {
    /// Prove non-existence with NSEC3 (`true`) or NSEC (`false`); absent
    /// keeps the zone's current choice.
    nsec3: Option<bool>,
}

pub async fn sign_zone(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<SignZoneBody>>,
) -> Response {
    if let Some(response) = reject_secondary_mutation(&state, &id) {
        return response;
    }
    let nsec3 = body.and_then(|Json(b)| b.nsec3);
    match state.catalog.sign_zone_with(&id, nsec3) {
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

/// The named networks (Settings -> Networks) and the split-horizon entries.
pub async fn get_split_horizon(State(state): State<AppState>) -> Response {
    let networks: Vec<serde_json::Value> = state
        .config
        .load()
        .all_networks()
        .into_iter()
        .map(|n| serde_json::json!({ "id": n.name, "name": n.name, "cidrs": n.cidrs }))
        .collect();
    let entries = match state.catalog.store().list_split_horizon_entries() {
        Ok(e) => e,
        Err(e) => return map_err(e),
    };
    Json(serde_json::json!({ "networks": networks, "entries": entries })).into_response()
}

/// Add a named network, or change the addresses of one (matched by name).
/// The older form of `POST /api/networks`, kept for API clients.
pub async fn upsert_split_horizon_network(
    State(state): State<AppState>,
    Json(input): Json<SplitHorizonNetworkInput>,
) -> Response {
    let existing = state
        .config
        .load()
        .networks
        .iter()
        .find(|n| n.name.eq_ignore_ascii_case(input.name.trim()))
        .cloned();
    crate::networks::save_network(
        State(state),
        Json(crate::networks::NetworkInput {
            original_name: existing.as_ref().map(|n| n.name.clone()),
            name: input.name,
            cidrs: input.cidrs,
            description: existing.map(|n| n.description).unwrap_or_default(),
        }),
    )
    .await
}

/// Delete an unused named network (older form of `DELETE /api/networks`).
pub async fn delete_split_horizon_network(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    crate::networks::delete_network(State(state), Path(name)).await
}

/// Reject a split-horizon entry naming a network that does not exist (it
/// would never match).
fn check_entry_networks(state: &AppState, input: &SplitHorizonEntryInput) -> Option<Response> {
    state
        .config
        .load()
        .resolve_networks(&input.networks)
        .err()
        .map(|e| error_response(StatusCode::BAD_REQUEST, e))
}

/// Create a split-horizon entry (appended after existing entries for the
/// same domain; first match wins).
pub async fn create_split_horizon_entry(
    State(state): State<AppState>,
    Json(input): Json<SplitHorizonEntryInput>,
) -> Response {
    if let Some(response) = check_entry_networks(&state, &input) {
        return response;
    }
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
    if let Some(response) = check_entry_networks(&state, &input) {
        return response;
    }
    match state
        .catalog
        .store()
        .update_split_horizon_entry(&id, &input)
    {
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
        Ok(MoveResult::AtBoundary) => Json(serde_json::json!({ "moved": false })).into_response(),
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
        // "recursive" or "forwarding": recursive mode cannot flush one name
        // from the recursor's own cache.
        "mode": resolver.as_ref().map(|r| r.mode()),
        "capacity": resolver.as_ref().map(|r| r.cache_size()).unwrap_or(0),
        "tracked_names": resolver.as_ref().map(|r| r.tracked_names()).unwrap_or(0),
        "hits": metrics.cache_hits,
        "misses": metrics.cache_misses,
        "prefetch_enabled": state.config.load().recursive.prefetch_enabled,
        "serve_stale_secs": state.config.load().recursive.serve_stale_secs,
    }))
    .into_response()
}

/// `GET /api/resolver` - the resolver dashboard: how lookups were routed
/// and how they ended, a latency histogram, the DNSSEC share and the
/// outbound connections by transport (counters since the server started).
pub async fn resolver_stats(State(state): State<AppState>) -> Response {
    let config = state.config.load_full();
    let resolver = state.resolver.load_full();
    let metrics = &state.metrics;
    let local_root = state.local_root.status();
    Json(serde_json::json!({
        "enabled": resolver.is_some(),
        "mode": resolver.as_ref().map(|r| r.mode()),
        "dnssec_validation": config.recursive.dnssec_validate,
        "opportunistic_encryption": resolver
            .as_ref()
            .is_some_and(|r| r.opportunistic_encryption()),
        "local_root": {
            "enabled": local_root.enabled,
            "serving": local_root.serving,
            "serial": local_root.serial,
        },
        "client_policies": config
            .recursive
            .client_policies
            .iter()
            .filter(|p| p.enabled)
            .count(),
        "conditional_zones": config.recursive.conditional_zones.len(),
        "stub_zones": config.authoritative.stub_zones.len(),
        "queries": metrics.get(&metrics.recursive),
        "dnssec_validated": metrics.get(&metrics.dnssec_validated),
        "stats": metrics.resolver.snapshot(),
    }))
    .into_response()
}

/// `GET /api/local-root` - the local root zone (RFC 8806): whether it is
/// enabled and served, its serial and size, and the last refresh outcome.
pub async fn local_root_status(State(state): State<AppState>) -> Response {
    Json(state.local_root.status()).into_response()
}

/// `POST /api/local-root/refresh` - check the sources for a newer root zone
/// now instead of waiting for the SOA refresh interval.
pub async fn local_root_refresh(State(state): State<AppState>) -> Response {
    if !state.config.load_full().recursive.local_root.enabled {
        return error_response(StatusCode::CONFLICT, "the local root zone is not enabled");
    }
    state.local_root.refresh_now();
    StatusCode::ACCEPTED.into_response()
}

/// `POST /api/cache/flush` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlushNameInput {
    pub name: String,
    /// One record type (`"A"`, `"AAAA"`, ...); omitted flushes the common
    /// types.
    #[serde(default, rename = "type")]
    pub record_type: Option<String>,
}

/// `POST /api/cache/flush` - remove one name from the resolver caches.
/// `complete` is false when recursive mode still holds its own copy (the
/// recursor has no per-entry removal; flush the whole cache for that).
pub async fn flush_cache_name(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<FlushNameInput>,
) -> Response {
    let Some(resolver) = state.resolver.load_full() else {
        return error_response(
            StatusCode::CONFLICT,
            "recursion is disabled, so there is no cache",
        );
    };
    if input.name.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "name is required");
    }
    let record_type = input
        .record_type
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match resolver.flush_name(&input.name, record_type) {
        Ok(complete) => Json(serde_json::json!({
            "name": input.name.trim(),
            "complete": complete,
        }))
        .into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
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
    /// The authenticator app's code (or a recovery code) for an account
    /// with two-factor login.
    #[serde(default)]
    code: String,
}

/// `POST /api/auth/login` - verify username/password against the console
/// accounts in the database and return a session token. Always open
/// (unauthenticated by definition).
pub async fn auth_login(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    axum::Json(input): axum::Json<LoginInput>,
) -> Response {
    let client_ip = client_ip_of(connect_info);
    let throttled = |state: &AppState| throttled_response(state, client_ip);
    if let Some(resp) = throttled(&state) {
        return resp;
    }
    if input.username.len() > 256 || input.password.len() > MAX_PASSWORD_LEN {
        return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
    }
    let user = match state
        .catalog
        .store()
        .get_console_user(input.username.trim())
    {
        Ok(user) => user,
        Err(e) => return map_err(e),
    };

    // Constant-ish response time: verify against a dummy hash when the user
    // does not exist (or is disabled, which is not disclosed) so timing
    // cannot enumerate accounts.
    let dummy_hash = "pbkdf2-sha256$210000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let stored_hash = match user.as_ref() {
        Some(u) if u.enabled => Some(u.password_hash.clone()),
        _ => None,
    };
    // Check the throttle again once this attempt has its PBKDF2 slot. Many
    // concurrent attempts all pass the check above before any of them has
    // failed; they queue for the slots, so re-checking here bounds a burst
    // to the permits in flight instead of letting every queued guess run.
    // The slot is held until this attempt's outcome is recorded below.
    let _permit = password_permit().await;
    if let Some(resp) = throttled(&state) {
        return resp;
    }
    let password = input.password.clone();
    let ok = run_password_job(move || match stored_hash {
        Some(hash) => daygle_dns_core::auth::verify_password(&password, &hash),
        None => {
            let _ = daygle_dns_core::auth::verify_password(&password, dummy_hash);
            false
        }
    })
    .await;

    if !ok {
        if let Some(ip) = client_ip {
            state.login_throttle.record_failure(ip);
        }
        state.logs.push(
            daygle_dns_core::LogLevel::Warn,
            "api",
            format!(
                "failed login attempt for user '{}'{}",
                log_safe(&input.username),
                client_ip
                    .map(|ip| format!(" from {ip}"))
                    .unwrap_or_default()
            ),
        );
        crate::audit::record_sign_in(
            &state,
            "/auth/login",
            input.username.trim(),
            client_ip,
            "Failed sign-in",
            401,
        );
        return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
    }
    let user = user.expect("checked above");

    // Two-factor login: the password was right, now the code. A wrong code
    // counts as a failed login, and the throttle is only cleared once both
    // pass, so codes cannot be guessed at full speed.
    if let Err(response) = check_two_factor(&state, &user.username, &input.code, client_ip) {
        if !input.code.trim().is_empty() {
            crate::audit::record_sign_in(
                &state,
                "/auth/login",
                &user.username,
                client_ip,
                "Failed sign-in (wrong two-factor code)",
                401,
            );
        }
        return response;
    }
    if let Some(ip) = client_ip {
        state.login_throttle.clear(ip);
    }
    if let Err(e) = state
        .catalog
        .store()
        .touch_console_user_login(&user.username)
    {
        return map_err(e);
    }

    let ttl = Duration::from_secs(state.config.load().api.session_ttl_secs.max(60));
    let token = state.sessions.create(&user.username, user.role, ttl);
    crate::audit::record_sign_in(
        &state,
        "/auth/login",
        &user.username,
        client_ip,
        "Signed in",
        200,
    );
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

#[derive(Deserialize)]
pub struct AuditQueryParams {
    before_id: Option<i64>,
    user: Option<String>,
    q: Option<String>,
    limit: Option<u32>,
}

/// `GET /api/audit` (admin) - the audit log, newest first.
pub async fn audit_log(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    let query = daygle_dns_authoritative::store::AuditQuery {
        before_id: params.before_id,
        username: params.user,
        text: params.q,
        limit: params.limit.unwrap_or(100),
    };
    match state.catalog.store().search_audit_log(&query) {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => map_err(e),
    }
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

/// `GET /api/auth/me` - identity of the presented session, with the
/// account's display preferences and the server's display defaults.
/// `preferences` is null for accounts defined in the config file, which
/// have nowhere to store them.
pub async fn auth_me(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let token = bearer_token(&headers).unwrap_or_default();
    match state.sessions.authenticate(&token) {
        Some(session) => {
            let preferences = state
                .catalog
                .store()
                .get_console_user(&session.username)
                .ok()
                .flatten()
                .map(|u| u.preferences);
            Json(serde_json::json!({
                "username": session.username,
                "role": session.role.as_str(),
                "expires_at_secs": session
                    .expires_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                "preferences": preferences,
                "display_defaults": state.config.load().display,
                // Signed in with a personal API token rather than a login.
                "api_token": session.api_token.is_some(),
            }))
            .into_response()
        }
        None => error_response(StatusCode::UNAUTHORIZED, "not authenticated"),
    }
}

/// `PUT /api/auth/preferences` - the signed-in user sets their own date and
/// time display preferences. An empty field means "use the server default".
/// Available to `viewer` accounts too (it only affects their own view).
pub async fn auth_set_preferences(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<daygle_dns_core::config::DisplaySettings>,
) -> Response {
    let token = bearer_token(&headers).unwrap_or_default();
    let Some(session) = state.sessions.verify(&token) else {
        return error_response(StatusCode::UNAUTHORIZED, "not authenticated");
    };
    let preferences = daygle_dns_core::config::DisplaySettings {
        time_zone: input.time_zone.trim().to_string(),
        date_format: input.date_format.trim().to_string(),
        time_format: input.time_format.trim().to_string(),
    };
    let store = state.catalog.store();
    match store.get_console_user(&session.username) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_response(
                StatusCode::CONFLICT,
                "accounts defined in the configuration file cannot store preferences",
            )
        }
        Err(e) => return map_err(e),
    }
    if let Err(e) = store.set_console_user_preferences(&session.username, &preferences) {
        return map_err(e);
    }
    Json(serde_json::json!({ "preferences": preferences })).into_response()
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
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
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
    if let Err(r) = confirm_password(
        &state,
        client_ip_of(connect_info),
        &user,
        &input.current_password,
        "a password change",
        "current password is incorrect",
    )
    .await
    {
        return r;
    }
    if input.new_password.chars().count() < 8 || input.new_password.len() > MAX_PASSWORD_LEN {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("new password must be 8-{MAX_PASSWORD_LEN} characters"),
        );
    }
    if input.new_password == input.current_password {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new password must differ from the current password",
        );
    }

    let new_hash = hash_password(&input.new_password).await;
    if let Err(e) = store.set_console_user_password(&session.username, &new_hash) {
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

// ---- Two-factor login -----------------------------------------------------

/// `401` asking for (another) two-factor code: `two_factor: true` tells the
/// console to show the code field.
fn two_factor_required(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": message, "two_factor": true })),
    )
        .into_response()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// For an account with two-factor login, check `code` (from the
/// authenticator app, or a recovery code, which is then used up). Accounts
/// without it pass.
#[allow(clippy::result_large_err)]
fn check_two_factor(
    state: &AppState,
    username: &str,
    code: &str,
    client_ip: Option<IpAddr>,
) -> Result<(), Response> {
    let store = state.catalog.store();
    let two_factor = store
        .get_two_factor(username)
        .map_err(map_err)?
        .filter(|t| !t.secret.is_empty());
    let Some(two_factor) = two_factor else {
        return Ok(());
    };
    let code = code.trim();
    if code.is_empty() {
        return Err(two_factor_required(
            "enter the code from your authenticator app",
        ));
    }
    let recovery = daygle_dns_core::totp::is_recovery_code(code);
    let accepted = if recovery {
        store.use_two_factor_recovery_code(
            username,
            &daygle_dns_core::totp::hash_recovery_code(code),
        )
    } else {
        match daygle_dns_core::totp::verify(
            &two_factor.secret,
            code,
            unix_now(),
            two_factor.last_step,
        ) {
            Some(step) => store.use_two_factor_step(username, step),
            None => Ok(false),
        }
    }
    .map_err(map_err)?;
    let from = client_ip
        .map(|ip| format!(" from {ip}"))
        .unwrap_or_default();
    if !accepted {
        if let Some(ip) = client_ip {
            state.login_throttle.record_failure(ip);
        }
        state.logs.push(
            daygle_dns_core::LogLevel::Warn,
            "api",
            format!("wrong two-factor code for user '{username}'{from}"),
        );
        return Err(two_factor_required(
            "that code is not right, or was already used",
        ));
    }
    if recovery {
        let left = store
            .get_two_factor(username)
            .ok()
            .flatten()
            .map_or(0, |t| t.recovery_hashes.len());
        state.logs.push(
            daygle_dns_core::LogLevel::Warn,
            "api",
            format!("user '{username}' signed in with a recovery code{from} ({left} left)"),
        );
    }
    Ok(())
}

/// The signed-in account (a login session, not an API token), for the
/// self-service credential endpoints.
#[allow(clippy::result_large_err)]
fn session_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<daygle_dns_authoritative::store::ConsoleUser, Response> {
    let token = bearer_token(headers).unwrap_or_default();
    let session = state.sessions.verify(&token).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "this needs a signed-in console account (not an API token)",
        )
    })?;
    match state.catalog.store().get_console_user(&session.username) {
        Ok(Some(user)) if user.enabled => Ok(user),
        Ok(Some(_)) => Err(error_response(StatusCode::FORBIDDEN, "account is disabled")),
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "account no longer exists",
        )),
        Err(e) => Err(map_err(e)),
    }
}

/// Build a recursive resolver from `resolved` (a config with its network
/// names resolved) on the blocking pool: a stub zone naming its servers by
/// host name is resolved with a blocking system lookup.
pub(crate) async fn build_resolver(
    state: &AppState,
    resolved: &daygle_dns_core::config::DaygleConfig,
) -> daygle_dns_core::error::Result<daygle_dns_recursive::RecursiveResolver> {
    let settings = resolved.recursive.clone();
    let stub_zones = resolved.authoritative.stub_zones.clone();
    let metrics = state.metrics.clone();
    let local_root = state.local_root.clone();
    tokio::task::spawn_blocking(move || {
        daygle_dns_recursive::RecursiveResolver::build(
            &settings,
            metrics,
            &stub_zones,
            Some(local_root),
        )
    })
    .await
    .map_err(|e| {
        daygle_dns_core::error::DaygleError::Internal(format!("resolver build task failed: {e}"))
    })?
}

/// `429` with `Retry-After` when `client_ip` is locked out by the failed
/// login throttle, else `None`.
fn throttled_response(state: &AppState, client_ip: Option<IpAddr>) -> Option<Response> {
    let retry = client_ip.and_then(|ip| state.login_throttle.retry_after(ip))?;
    let mut resp = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "too many failed login attempts; try again later",
    );
    if let Ok(value) = header::HeaderValue::from_str(&retry.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, value);
    }
    Some(resp)
}

/// The client address of a request (canonical, so IPv4-mapped IPv6 counts
/// as the IPv4 address it carries).
fn client_ip_of(
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
) -> Option<IpAddr> {
    connect_info.map(|axum::Extension(info)| info.0.ip().to_canonical())
}

/// Re-check a signed-in account's password (before a password or
/// two-factor change). A wrong password counts as a failed login for
/// `client_ip`, so a stolen session cannot be used to guess the password
/// at full speed; like a login, the throttle is re-checked once the
/// attempt holds its PBKDF2 slot. `what` names the change for the log.
#[allow(clippy::result_large_err)]
async fn confirm_password(
    state: &AppState,
    client_ip: Option<IpAddr>,
    user: &daygle_dns_authoritative::store::ConsoleUser,
    password: &str,
    what: &str,
    wrong: &str,
) -> Result<(), Response> {
    if let Some(resp) = throttled_response(state, client_ip) {
        return Err(resp);
    }
    let ok = if password.len() > MAX_PASSWORD_LEN {
        false
    } else {
        let _permit = password_permit().await;
        if let Some(resp) = throttled_response(state, client_ip) {
            return Err(resp);
        }
        let (password, hash) = (password.to_string(), user.password_hash.clone());
        run_password_job(move || daygle_dns_core::auth::verify_password(&password, &hash)).await
    };
    if !ok {
        if let Some(ip) = client_ip {
            state.login_throttle.record_failure(ip);
        }
        state.logs.push(
            daygle_dns_core::LogLevel::Warn,
            "api",
            format!("wrong password for {what} by user '{}'", user.username),
        );
        return Err(error_response(StatusCode::UNAUTHORIZED, wrong));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct PasswordInput {
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
pub struct CodeInput {
    #[serde(default)]
    code: String,
}

/// `GET /api/auth/two-factor` - whether the signed-in account uses
/// two-factor login, and how many recovery codes it has left.
pub async fn two_factor_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.catalog.store().get_two_factor(&user.username) {
        Ok(t) => {
            let t = t.unwrap_or_default();
            Json(serde_json::json!({
                "enabled": !t.secret.is_empty(),
                "recovery_codes_left": if t.secret.is_empty() { 0 } else { t.recovery_hashes.len() },
            }))
            .into_response()
        }
        Err(e) => map_err(e),
    }
}

/// `POST /api/auth/two-factor/setup` `{password}` - start setting up
/// two-factor login: a new secret, and the `otpauth://` URI for a QR code.
/// Nothing changes until `/enable` confirms a code.
pub async fn two_factor_setup(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<PasswordInput>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if let Err(r) = confirm_password(
        &state,
        client_ip_of(connect_info),
        &user,
        &input.password,
        "a two-factor change",
        "password is incorrect",
    )
    .await
    {
        return r;
    }
    let secret = daygle_dns_core::totp::generate_secret();
    if let Err(e) = state
        .catalog
        .store()
        .set_two_factor_pending(&user.username, &secret)
    {
        return map_err(e);
    }
    Json(serde_json::json!({
        "secret": secret,
        "uri": daygle_dns_core::totp::otpauth_uri("Daygle DNS", &user.username, &secret),
    }))
    .into_response()
}

/// `POST /api/auth/two-factor/enable` `{code}` - confirm the app works and
/// turn two-factor login on. Returns the recovery codes, shown only now.
pub async fn two_factor_enable(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<CodeInput>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let store = state.catalog.store();
    let pending = match store.get_two_factor(&user.username) {
        Ok(t) => t.map(|t| t.pending_secret).unwrap_or_default(),
        Err(e) => return map_err(e),
    };
    if pending.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "start two-factor setup first");
    }
    let Some(step) = daygle_dns_core::totp::verify(&pending, &input.code, unix_now(), 0) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "that code is not right: check the app's clock and try the newest code",
        );
    };
    let (codes, hashes) = daygle_dns_core::totp::generate_recovery_codes();
    if let Err(e) = store.enable_two_factor(&user.username, step, &hashes) {
        return map_err(e);
    }
    // Other devices must sign in again, now with a code.
    let token = bearer_token(&headers).unwrap_or_default();
    state.sessions.revoke_user_except(&user.username, &token);
    state.logs.info(
        "api",
        format!("user '{}' turned on two-factor login", user.username),
    );
    Json(serde_json::json!({ "recovery_codes": codes })).into_response()
}

/// `POST /api/auth/two-factor/recovery-codes` `{password}` - replace the
/// recovery codes (the old ones stop working).
pub async fn two_factor_new_recovery_codes(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<PasswordInput>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if let Err(r) = confirm_password(
        &state,
        client_ip_of(connect_info),
        &user,
        &input.password,
        "a two-factor change",
        "password is incorrect",
    )
    .await
    {
        return r;
    }
    if !user.two_factor {
        return error_response(StatusCode::BAD_REQUEST, "two-factor login is not on");
    }
    let (codes, hashes) = daygle_dns_core::totp::generate_recovery_codes();
    if let Err(e) = state
        .catalog
        .store()
        .set_two_factor_recovery(&user.username, &hashes)
    {
        return map_err(e);
    }
    state.logs.info(
        "api",
        format!("user '{}' made new recovery codes", user.username),
    );
    Json(serde_json::json!({ "recovery_codes": codes })).into_response()
}

/// `POST /api/auth/two-factor/disable` `{password}` - turn two-factor
/// login off for the signed-in account.
pub async fn two_factor_disable(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<PasswordInput>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if let Err(r) = confirm_password(
        &state,
        client_ip_of(connect_info),
        &user,
        &input.password,
        "a two-factor change",
        "password is incorrect",
    )
    .await
    {
        return r;
    }
    match state.catalog.store().disable_two_factor(&user.username) {
        Ok(was_on) => {
            if was_on {
                state.logs.push(
                    daygle_dns_core::LogLevel::Warn,
                    "api",
                    format!("user '{}' turned off two-factor login", user.username),
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => map_err(e),
    }
}

// ---- Personal API tokens ---------------------------------------------------

#[derive(Deserialize)]
pub struct ApiTokenInput {
    name: String,
    #[serde(default)]
    read_only: bool,
    /// Days until the token stops working; 0 or absent: never.
    #[serde(default)]
    expires_in_days: u32,
}

/// `GET /api/auth/tokens` - the signed-in account's API tokens.
pub async fn list_api_tokens(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.catalog.store().list_api_tokens(&user.username) {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e) => map_err(e),
    }
}

/// `POST /api/auth/tokens` `{name, read_only, expires_in_days}` - make an
/// API token for the signed-in account. The token is returned only now.
pub async fn create_api_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<ApiTokenInput>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let name = input.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "give the token a name (up to 64 characters)",
        );
    }
    if input.expires_in_days > 3650 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "a token can last at most 3650 days",
        );
    }
    let store = state.catalog.store();
    match store.list_api_tokens(&user.username) {
        Ok(tokens) if tokens.len() >= 50 => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "an account can have at most 50 API tokens: delete some first",
            )
        }
        Ok(_) => {}
        Err(e) => return map_err(e),
    }
    let now = unix_now() as i64;
    let secret = crate::new_api_token();
    let token = daygle_dns_authoritative::store::ApiToken {
        id: format!("{:016x}", rand::random::<u64>()),
        username: user.username.clone(),
        name: name.clone(),
        token_hash: daygle_dns_core::auth::hash_token(&secret),
        read_only: input.read_only || user.role == daygle_dns_core::config::Role::Viewer,
        created_at: now,
        last_used_at: 0,
        expires_at: if input.expires_in_days == 0 {
            0
        } else {
            now + i64::from(input.expires_in_days) * 86_400
        },
    };
    if let Err(e) = store.create_api_token(&token) {
        return map_err(e);
    }
    state.logs.info(
        "api",
        format!("user '{}' created API token '{name}'", user.username),
    );
    let mut body = serde_json::to_value(&token).expect("token serializes");
    body["token"] = serde_json::json!(secret);
    (StatusCode::CREATED, Json(body)).into_response()
}

/// `DELETE /api/auth/tokens/{id}` - revoke one of the signed-in account's
/// API tokens.
pub async fn delete_api_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.catalog.store().delete_api_token(&user.username, &id) {
        Ok(true) => {
            state.logs.info(
                "api",
                format!("user '{}' revoked an API token", user.username),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "no such token"),
        Err(e) => map_err(e),
    }
}

/// `DELETE /api/users/{username}/two-factor` (admin) - turn two-factor
/// login off for an account that lost its authenticator app and recovery
/// codes. It signs in with its password alone until it sets it up again.
pub async fn reset_user_two_factor(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Response {
    let store = state.catalog.store();
    match store.get_console_user(&username) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("user '{username}' not found"),
            )
        }
        Err(e) => return map_err(e),
    }
    match store.disable_two_factor(&username) {
        Ok(was_on) => {
            if was_on {
                state.sessions.revoke_user(&username);
                state.logs.push(
                    daygle_dns_core::LogLevel::Warn,
                    "api",
                    format!("two-factor login reset for user '{username}'"),
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => map_err(e),
    }
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
    let no_users = matches!(state.catalog.store().count_console_users(), Ok(0));
    config.api.auth_required && no_users && config.api.api_token.trim().is_empty()
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
    /// Optional display name for the initial admin account (stored as
    /// the profile `first_name`).
    #[serde(default)]
    pub first_name: String,
    /// Optional display surname for the initial admin account (stored as
    /// the profile `last_name`).
    #[serde(default)]
    pub last_name: String,
    /// Optional email for the initial admin account (stored as the
    /// profile `email`).
    #[serde(default)]
    pub email: String,
}

/// `POST /api/auth/setup` - one-time creation of the first admin account.
///
/// Open endpoint (it runs before any account exists, which is the point).
/// It refuses to run once any user is configured or when console auth is
/// disabled. On success the account is persisted to the database and a
/// session for it is returned, so the GUI lands straight in the console.
pub async fn auth_setup(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<SetupInput>,
) -> Response {
    // Serialize setup attempts: the "no account exists yet" check and the
    // account creation below must be atomic, or two racing requests could
    // each create an admin.
    static SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _setup = SETUP_LOCK.lock().await;
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
    if let Some(resp) = validate_username_password(&username, &input.password) {
        return resp;
    }

    let password_hash = hash_password(&input.password).await;
    if let Err(e) = state.catalog.store().create_console_user(
        &username,
        &daygle_dns_authoritative::ConsoleUserInput {
            password_hash,
            role: daygle_dns_core::config::Role::Admin,
            enabled: true,
            first_name: input.first_name.trim().to_string(),
            last_name: input.last_name.trim().to_string(),
            email: input.email.trim().to_string(),
        },
    ) {
        return map_err(e);
    }

    let ttl = Duration::from_secs(state.config.load().api.session_ttl_secs.max(60));
    let token = state
        .sessions
        .create(&username, daygle_dns_core::config::Role::Admin, ttl);
    crate::audit::record_sign_in(
        &state,
        "/auth/setup",
        &username,
        None,
        "Created the first administrator",
        200,
    );
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
// Err carries a full axum `Response` (see validate_config_update above).
#[allow(clippy::result_large_err)]
fn last_admin_guard(
    store: &daygle_dns_authoritative::ZoneStore,
    target: &str,
) -> Result<(), Response> {
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
    if password.chars().count() < 8 || password.len() > MAX_PASSWORD_LEN {
        return Some(error_response(
            StatusCode::BAD_REQUEST,
            format!("password must be 8-{MAX_PASSWORD_LEN} characters"),
        ));
    }
    None
}

/// `GET /api/users` - list console accounts (password hashes redacted).
pub async fn list_users(State(state): State<AppState>) -> Response {
    match state.catalog.store().list_console_users() {
        Ok(users) => Json(serde_json::json!(users
            .iter()
            .map(|u| u.redacted())
            .collect::<Vec<_>>()))
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
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
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
            return error_response(StatusCode::BAD_REQUEST, format!("unknown role '{other}'"))
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
    let password_hash = hash_password(&input.password).await;
    let user = match store.create_console_user(
        &username,
        &daygle_dns_authoritative::ConsoleUserInput {
            password_hash,
            role,
            enabled: true,
            first_name: input.first_name.unwrap_or_default().trim().to_string(),
            last_name: input.last_name.unwrap_or_default().trim().to_string(),
            email: input.email.unwrap_or_default().trim().to_string(),
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
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
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
            return error_response(StatusCode::BAD_REQUEST, format!("unknown role '{other}'"))
        }
    };

    // Demotion to viewer on the last admin is the same lockout risk as a
    // deletion, so it goes through the same guard.
    if new_role == Some(daygle_dns_core::config::Role::Viewer) || input.enabled == Some(false) {
        if let Err(resp) = last_admin_guard(store, &username) {
            return resp;
        }
    }

    if let Some(password) = &input.password {
        let password_hash = hash_password(password).await;
        if let Err(e) = store.set_console_user_password(&username, &password_hash) {
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
    if input.first_name.is_some() || input.last_name.is_some() || input.email.is_some() {
        let first = input.first_name.as_deref().map(str::trim);
        let last = input.last_name.as_deref().map(str::trim);
        let email = input.email.as_deref().map(str::trim);
        if let Err(e) = store.set_console_user_profile(&username, first, last, email) {
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
pub async fn delete_user(State(state): State<AppState>, Path(username): Path<String>) -> Response {
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
/// Applied to the live config, validated, persisted to the database, and
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
    pub authoritative: Option<AuthoritativeUpdate>,
    pub ai: Option<AiUpdate>,
    pub display: Option<DisplayUpdate>,
    pub web: Option<WebUpdate>,
    /// Replaces the whole `[syslog]` section.
    pub syslog: Option<daygle_dns_core::config::SyslogSettings>,
    /// Replaces the whole `[dns64]` section.
    pub dns64: Option<daygle_dns_core::config::Dns64Settings>,
    /// Replaces the whole `[ecs]` section.
    pub ecs: Option<daygle_dns_core::config::EcsSettings>,
    /// Replaces the whole `[updates]` section.
    pub updates: Option<daygle_dns_core::config::UpdateCheckSettings>,
}

/// Partial update for how the web console is served (HTTP and/or HTTPS).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebUpdate {
    pub http_enabled: Option<bool>,
    pub http_port: Option<u16>,
    pub https_enabled: Option<bool>,
    pub https_port: Option<u16>,
    /// A managed certificate name; empty means the generated self-signed
    /// `web-console` certificate.
    pub https_certificate: Option<String>,
    pub redirect_http: Option<bool>,
}

/// Partial update for the console's date and time display defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayUpdate {
    pub time_zone: Option<String>,
    pub date_format: Option<String>,
    pub time_format: Option<String>,
}

/// Partial update for authoritative-zone settings surfaced in the console.
/// Mirrors `daygle_dns_core::config::AuthoritativeUpdate` (the DB overlay
/// shape); kept separate so the HTTP API and persistence formats evolve
/// independently.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeUpdate {
    pub default_record_ttl: Option<u32>,
    pub default_primary_ns: Option<String>,
    /// Blank clears it (new zones then use `admin.<zone>.`).
    pub default_admin_mailbox: Option<String>,
    pub axfr_enabled: Option<bool>,
    pub axfr_networks: Option<Vec<String>>,
    pub allow_dynamic_updates: Option<bool>,
    pub update_networks: Option<Vec<String>>,
    pub notify_enabled: Option<bool>,
    pub notify_targets: Option<Vec<String>>,
    pub notify_listen_enabled: Option<bool>,
    /// Replaces the whole stub-zone list.
    pub stub_zones: Option<Vec<daygle_dns_core::config::StubZoneConfig>>,
    /// The catalog zone to publish; blank stops publishing it.
    pub catalog_zone: Option<String>,
    /// Replaces the whole list of consumed catalog zones.
    pub catalog_consumers: Option<Vec<daygle_dns_core::config::CatalogConsumerConfig>>,
}

/// Partial update for policy-engine settings surfaced in the console (only the
/// fields the UI edits; blocklists/rules are managed through their own APIs).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub allowlist: Option<Vec<String>>,
    /// Client networks always refused (addresses or network names).
    pub denied_networks: Option<Vec<String>>,
    /// Client networks that bypass the denied list (addresses or network names).
    pub allowed_networks: Option<Vec<String>>,
    pub blocklist: Option<Vec<String>>,
    pub filter_aaaa: Option<bool>,
    pub filter_aaaa_except: Option<Vec<String>>,
    pub cname_inspection: Option<bool>,
}

/// Partial update for the AI scanner (mirrors `AiSettings` fields; the
/// fields the console edits on the Settings page). Bounds and cross-field
/// invariants are enforced by `DaygleConfig::validate()` once applied.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiUpdate {
    pub enabled: Option<bool>,
    pub mode: Option<daygle_dns_core::config::AiMode>,
    /// Verdict-store database path; empty uses `ai.db` next to the zone DB.
    pub database: Option<String>,
    /// fastText model path; empty uses the built-in heuristic backend.
    pub model_path: Option<String>,
    pub workers: Option<u32>,
    pub scan_interval_secs: Option<u64>,
    pub expire_check_secs: Option<u64>,
    pub max_domains_per_scan: Option<u32>,
    pub auto_block_categories: Option<Vec<String>>,
    pub block_threshold: Option<f32>,
    pub confidence_floor: Option<f32>,
    pub category_ttl_secs: Option<u64>,
    pub threat_ttl_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerUpdate {
    pub listen: Option<String>,
    pub ipv6_only: Option<bool>,
    pub port: Option<u16>,
    pub udp_enabled: Option<bool>,
    pub tcp_enabled: Option<bool>,
    pub reload_enabled: Option<bool>,
    /// Load balancers trusted to send PROXY protocol headers (addresses or
    /// network names).
    pub proxy_protocol: Option<Vec<String>>,
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
    pub max_cache_ttl: Option<u32>,
    pub failure_cache_ttl: Option<u32>,
    pub max_concurrent_lookups: Option<usize>,
    /// Replaces the whole conditional-forwarder list.
    pub conditional_zones: Option<Vec<daygle_dns_core::config::ConditionalZoneConfig>>,
    pub mode: Option<daygle_dns_core::config::ResolutionMode>,
    pub recursion_access: Option<daygle_dns_core::config::RecursionAccess>,
    pub recursion_networks: Option<Vec<String>>,
    pub root_hints: Option<Vec<String>>,
    pub case_randomization: Option<bool>,
    pub rebinding_protection: Option<bool>,
    /// Local root zone (RFC 8806): `enabled` and `sources`.
    pub local_root: Option<daygle_dns_core::config::LocalRootSettings>,
    pub opportunistic_encryption: Option<bool>,
    pub outbound_ip_versions: Option<daygle_dns_core::config::IpVersions>,
    pub min_cache_ttl: Option<u32>,
    pub negative_cache_ttl: Option<u32>,
    pub use_system_config: Option<bool>,
    /// Replaces the whole client policy list.
    pub client_policies: Option<Vec<daygle_dns_core::config::ClientPolicyConfig>>,
}

/// Check that every forwarder list keeps a server of an IP version the
/// resolver may use: the default upstreams (unless the system resolver is
/// used), conditional forwarders and forwarding client policies.
fn check_outbound_servers(r: &daygle_dns_core::config::RecursiveSettings) -> Result<(), String> {
    let versions = r.outbound_ip_versions;
    if versions == daygle_dns_core::config::IpVersions::Both {
        return Ok(());
    }
    if r.effective_mode() == daygle_dns_core::config::ResolutionMode::Forwarding
        && !r.use_system_config
    {
        daygle_dns_recursive::parse_upstreams_for(&r.upstreams, versions)
            .map_err(|e| format!("upstreams: {e}"))?;
    }
    for zone in &r.conditional_zones {
        daygle_dns_recursive::parse_upstreams_for(&zone.upstreams, versions)
            .map_err(|e| format!("conditional forwarder '{}': {e}", zone.name))?;
    }
    for policy in r
        .client_policies
        .iter()
        .filter(|p| p.enabled && p.action == daygle_dns_core::config::ClientPolicyAction::Forward)
    {
        daygle_dns_recursive::parse_upstreams_for(&policy.upstreams, versions)
            .map_err(|e| format!("client policy '{}': {e}", policy.name))?;
    }
    Ok(())
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
    pub certificate: Option<String>,
    pub handshake_timeout_secs: Option<u64>,
    pub max_connections: Option<usize>,
    pub max_concurrent_streams: Option<usize>,
    /// QUIC idle timeout (DoQ only).
    pub idle_timeout_secs: Option<u64>,
    /// Client networks allowed to use this listener (addresses or network
    /// names); empty or absent means everyone.
    pub allowed_networks: Option<Vec<String>>,
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
    pub certificate: Option<String>,
    pub handshake_timeout_secs: Option<u64>,
    pub max_connections: Option<usize>,
    /// Client networks allowed to use this listener (addresses or network
    /// names); empty or absent means everyone.
    pub allowed_networks: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiUpdate {
    pub gui_enabled: Option<bool>,
    pub cors_origins: Option<Vec<String>>,
}

/// Stamp each client policy with the time it last changed, for the
/// console's Last Modified column. A policy with the same name whose
/// enabled/clients/action/upstreams are unchanged keeps its previous
/// stamp; a new, renamed or edited one gets the current time. The stamp
/// always comes from the server clock, never from the request.
fn stamp_client_policies(
    old: &[daygle_dns_core::config::ClientPolicyConfig],
    new: &mut [daygle_dns_core::config::ClientPolicyConfig],
) {
    let now = chrono::Utc::now().to_rfc3339();
    for policy in new {
        let previous = old.iter().find(|o| o.name == policy.name);
        let unchanged = previous.is_some_and(|o| {
            o.enabled == policy.enabled
                && o.clients == policy.clients
                && o.action == policy.action
                && o.upstreams == policy.upstreams
        });
        policy.modified_at = match previous {
            Some(p) if unchanged => p.modified_at.clone(),
            _ => Some(now.clone()),
        };
    }
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
    let _config_write = state.config_write.lock().await;
    let old_config = (*state.config.load_full()).clone();
    let mut config = old_config.clone();
    let mut listeners_affected = false;

    if let Some(s) = &update.server {
        if let Some(v) = &s.listen {
            config.server.listen = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = s.ipv6_only {
            config.server.ipv6_only = v;
            listeners_affected = true;
        }
        if let Some(v) = s.port {
            config.server.port = v;
            listeners_affected = true;
        }
        if let Some(v) = &s.proxy_protocol {
            config.server.proxy_protocol = normalize_policy_networks(v);
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
        if let Some(v) = r.max_cache_ttl {
            config.recursive.max_cache_ttl = v;
        }
        if let Some(v) = &r.conditional_zones {
            config.recursive.conditional_zones =
                daygle_dns_core::config::RecursiveUpdate::normalize_conditional_zones(v);
        }
        // Policy upstreams use the resolver's own syntax, which the config
        // validation cannot check: parse them here so a typo is a 400, not a
        // resolver rebuild that silently keeps the old policies.
        for policy in r.client_policies.iter().flatten() {
            if policy.action == daygle_dns_core::config::ClientPolicyAction::Forward {
                if let Err(e) = daygle_dns_recursive::parse_upstreams(&policy.upstreams) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("client policy '{}': {e}", policy.name.trim()),
                    );
                }
            }
        }
        daygle_dns_core::config::RecursiveUpdate {
            mode: r.mode,
            recursion_access: r.recursion_access,
            recursion_networks: r.recursion_networks.clone(),
            root_hints: r.root_hints.clone(),
            case_randomization: r.case_randomization,
            rebinding_protection: r.rebinding_protection,
            local_root: r.local_root.clone(),
            opportunistic_encryption: r.opportunistic_encryption,
            outbound_ip_versions: r.outbound_ip_versions,
            client_policies: r.client_policies.clone(),
            min_cache_ttl: r.min_cache_ttl,
            negative_cache_ttl: r.negative_cache_ttl,
            use_system_config: r.use_system_config,
            ..Default::default()
        }
        .apply_resolution(&mut config.recursive);
        if r.client_policies.is_some() {
            // The console's Last Modified column: stamp each policy with
            // when it last changed. Unchanged policies keep their stamp,
            // and anything sent in the request is ignored.
            stamp_client_policies(
                &old_config.recursive.client_policies,
                &mut config.recursive.client_policies,
            );
        }
        if let Some(v) = r.failure_cache_ttl {
            config.recursive.failure_cache_ttl = v;
        }
        if let Some(v) = r.max_concurrent_lookups {
            config.recursive.max_concurrent_lookups = v;
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
            listeners_affected = true;
        }
        if let Some(v) = &d.server_name {
            config.dot.server_name = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.cert_path {
            config.dot.cert_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.key_path {
            config.dot.key_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.certificate {
            config.dot.certificate = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = d.handshake_timeout_secs {
            config.dot.handshake_timeout_secs = v;
            listeners_affected = true;
        }
        if let Some(v) = d.max_connections {
            config.dot.max_connections = v;
            listeners_affected = true;
        }
        if let Some(v) = &d.allowed_networks {
            config.dot.allowed_networks = normalize_policy_networks(v);
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
            listeners_affected = true;
        }
        if let Some(v) = &d.server_name {
            config.doh.server_name = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.cert_path {
            config.doh.cert_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.key_path {
            config.doh.key_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.endpoint {
            config.doh.endpoint = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.certificate {
            config.doh.certificate = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = d.handshake_timeout_secs {
            config.doh.handshake_timeout_secs = v;
            listeners_affected = true;
        }
        if let Some(v) = d.max_connections {
            config.doh.max_connections = v;
            listeners_affected = true;
        }
        if let Some(v) = &d.allowed_networks {
            config.doh.allowed_networks = normalize_policy_networks(v);
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
            listeners_affected = true;
        }
        if let Some(v) = &d.server_name {
            config.doq.server_name = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.cert_path {
            config.doq.cert_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.key_path {
            config.doq.key_path = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = &d.certificate {
            config.doq.certificate = v.clone();
            listeners_affected = true;
        }
        if let Some(v) = d.max_connections {
            config.doq.max_connections = v;
            listeners_affected = true;
        }
        if let Some(v) = d.max_concurrent_streams {
            config.doq.max_concurrent_streams = v;
            listeners_affected = true;
        }
        if let Some(v) = d.idle_timeout_secs {
            config.doq.idle_timeout_secs = v;
            listeners_affected = true;
        }
        if let Some(v) = &d.allowed_networks {
            config.doq.allowed_networks = normalize_policy_networks(v);
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
    if let Some(dns64) = &update.dns64 {
        let dns64 = daygle_dns_core::config::Dns64Settings {
            prefix: dns64.prefix.trim().to_string(),
            clients: dns64
                .clients
                .iter()
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect(),
            ..dns64.clone()
        };
        if let Err(msg) = dns64.compile(&config.all_networks()) {
            return error_response(StatusCode::BAD_REQUEST, format!("dns64: {msg}"));
        }
        config.dns64 = dns64;
    }
    if let Some(ecs) = &update.ecs {
        let ecs = daygle_dns_core::config::EcsSettings {
            subnet: ecs.subnet.trim().to_string(),
            ..ecs.clone()
        };
        if let Err(msg) = ecs.compile() {
            return error_response(StatusCode::BAD_REQUEST, format!("ecs: {msg}"));
        }
        config.ecs = ecs;
    }
    if let Some(syslog) = &update.syslog {
        let syslog = daygle_dns_core::config::SyslogSettings {
            server: syslog.server.trim().to_string(),
            facility: syslog.facility.trim().to_string(),
            level: syslog.level.trim().to_string(),
            ..syslog.clone()
        };
        if let Err(msg) = syslog.check() {
            return error_response(StatusCode::BAD_REQUEST, format!("syslog: {msg}"));
        }
        config.syslog = syslog;
    }
    if let Some(updates) = &update.updates {
        config.updates = updates.clone();
    }
    if let Some(w) = &update.web {
        if let Some(v) = w.http_enabled {
            config.web.http_enabled = v;
        }
        if let Some(v) = w.http_port {
            config.web.http_port = v;
        }
        if let Some(v) = w.https_enabled {
            config.web.https_enabled = v;
        }
        if let Some(v) = w.https_port {
            config.web.https_port = v;
        }
        if let Some(v) = &w.https_certificate {
            config.web.https_certificate = v.trim().to_string();
        }
        if let Some(v) = w.redirect_http {
            config.web.redirect_http = v;
        }
        if let Err(msg) = config.web.check(config.api.port) {
            return error_response(StatusCode::BAD_REQUEST, msg);
        }
        // HTTPS with no certificate chosen: generate (once) a self-signed
        // one, kept as a managed certificate so it stays the same across
        // restarts and can be replaced on the Certificates page.
        if config.web.https_enabled && config.web.https_certificate.is_empty() {
            let name = daygle_dns_core::config::WEB_SELF_SIGNED_CERT;
            let exists = matches!(state.catalog.store().get_tls_certificate(name), Ok(Some(_)));
            if !exists {
                let server_name = daygle_dns_core::config::detect_server_name()
                    .map(|n| n.trim_end_matches('.').to_string())
                    .unwrap_or_else(|| "daygle.local".to_string());
                let (cert_pem, key_pem) =
                    match daygle_dns_dot::generate_self_signed_pem(&server_name) {
                        Ok(pair) => pair,
                        Err(e) => return map_err(e),
                    };
                let cert = daygle_dns_authoritative::TlsCertificate {
                    name: name.to_string(),
                    server_name,
                    cert_pem,
                    key_pem,
                    created_at: chrono::Utc::now().to_rfc3339(),
                };
                if let Err(e) = state.catalog.store().put_tls_certificate(&cert) {
                    return map_err(e);
                }
            }
            config.web.https_certificate = name.to_string();
        }
    }
    if let Some(d) = &update.display {
        if let Some(v) = &d.time_zone {
            config.display.time_zone = v.trim().to_string();
        }
        if let Some(v) = &d.date_format {
            config.display.date_format = v.clone();
        }
        if let Some(v) = &d.time_format {
            config.display.time_format = v.clone();
        }
    }
    let mut authoritative_changed = false;
    if let Some(a) = &update.authoritative {
        if let Some(v) = a.default_record_ttl {
            config.authoritative.default_record_ttl = v;
            authoritative_changed = true;
        }
        if let Some(v) = &a.default_primary_ns {
            // Normalize to the fully-qualified form so the SOA MNAME is
            // absolute regardless of whether the user typed the trailing
            // dot; blank clears it (new zones then use this server's name).
            let v = v.trim();
            config.authoritative.default_primary_ns = if v.is_empty() || v.ends_with('.') {
                v.to_string()
            } else {
                format!("{v}.")
            };
            authoritative_changed = true;
        }
        if let Some(v) = &a.default_admin_mailbox {
            // An email address or the SOA form; blank clears it (new zones
            // then use the first administrator's email).
            config.authoritative.default_admin_mailbox =
                match daygle_dns_core::config::mailbox_to_rname(v) {
                    Ok(m) => m,
                    Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
                };
            authoritative_changed = true;
        }
        if let Some(v) = a.axfr_enabled {
            config.authoritative.axfr_enabled = v;
            authoritative_changed = true;
        }
        if let Some(v) = &a.axfr_networks {
            config.authoritative.axfr_networks = normalize_policy_networks(v);
            authoritative_changed = true;
        }
        if let Some(v) = a.allow_dynamic_updates {
            config.authoritative.allow_dynamic_updates = v;
            authoritative_changed = true;
        }
        if let Some(v) = &a.update_networks {
            config.authoritative.update_networks = normalize_policy_networks(v);
            authoritative_changed = true;
        }
        if let Some(v) = a.notify_enabled {
            config.authoritative.notify_enabled = v;
            authoritative_changed = true;
        }
        if let Some(v) = &a.notify_targets {
            config.authoritative.notify_targets = normalize_notify_targets(v);
            authoritative_changed = true;
        }
        if let Some(v) = a.notify_listen_enabled {
            config.authoritative.notify_listen_enabled = v;
            authoritative_changed = true;
        }
        if let Some(v) = &a.stub_zones {
            config.authoritative.stub_zones =
                daygle_dns_core::config::AuthoritativeUpdate::normalize_stub_zones(v);
        }
        if let Some(v) = &a.catalog_zone {
            config.authoritative.catalog_zone = daygle_dns_core::config::normalize_zone_name(v);
        }
        if let Some(v) = &a.catalog_consumers {
            config.authoritative.catalog_consumers =
                daygle_dns_core::config::AuthoritativeUpdate::normalize_catalog_consumers(v);
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
        if let Some(v) = &p.denied_networks {
            config.policy.denied_networks = normalize_policy_networks(v);
            policy_changed = true;
        }
        if let Some(v) = &p.allowed_networks {
            config.policy.allowed_networks = normalize_policy_networks(v);
            policy_changed = true;
        }
        if let Some(v) = p.filter_aaaa {
            config.policy.filter_aaaa = v;
            policy_changed = true;
        }
        if let Some(v) = p.cname_inspection {
            config.policy.cname_inspection = v;
            policy_changed = true;
        }
        if let Some(v) = &p.filter_aaaa_except {
            config.policy.filter_aaaa_except = normalize_policy_domains(v);
            policy_changed = true;
        }
    }
    let mut ai_changed = false;
    if let Some(a) = &update.ai {
        if let Some(v) = a.enabled {
            config.ai.enabled = v;
            ai_changed = true;
        }
        if let Some(v) = a.mode {
            config.ai.mode = v;
            ai_changed = true;
        }
        if let Some(v) = &a.database {
            config.ai.database = v.trim().to_string();
            ai_changed = true;
        }
        if let Some(v) = &a.model_path {
            config.ai.model_path = v.trim().to_string();
            ai_changed = true;
        }
        if let Some(v) = a.workers {
            config.ai.workers = v;
            ai_changed = true;
        }
        if let Some(v) = a.scan_interval_secs {
            config.ai.scan_interval_secs = v;
            ai_changed = true;
        }
        if let Some(v) = a.expire_check_secs {
            config.ai.expire_check_secs = v;
            ai_changed = true;
        }
        if let Some(v) = a.max_domains_per_scan {
            config.ai.max_domains_per_scan = v;
            ai_changed = true;
        }
        if let Some(v) = &a.auto_block_categories {
            config.ai.auto_block_categories =
                daygle_dns_core::config::AiUpdate::normalize_categories(v.clone());
            ai_changed = true;
        }
        if let Some(v) = a.block_threshold {
            config.ai.block_threshold = v;
            ai_changed = true;
        }
        if let Some(v) = a.confidence_floor {
            config.ai.confidence_floor = v;
            ai_changed = true;
        }
        if let Some(v) = a.category_ttl_secs {
            config.ai.category_ttl_secs = v;
            ai_changed = true;
        }
        if let Some(v) = a.threat_ttl_secs {
            config.ai.threat_ttl_secs = v;
            ai_changed = true;
        }
    }

    // A selected console-managed certificate must exist in the store.
    for (label, name) in [
        ("DoT", &config.dot.certificate),
        ("DoH", &config.doh.certificate),
        ("DoQ", &config.doq.certificate),
        ("HTTPS", &config.web.https_certificate),
    ] {
        if !name.is_empty()
            && state
                .catalog
                .store()
                .get_tls_certificate(name)
                .map(|c| c.is_none())
                .unwrap_or(true)
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown certificate '{name}' selected for {label}"),
            );
        }
    }

    // Validate before applying anything: only errors this update introduces
    // reject it (a pre-existing failure on a hand-managed file is kept).
    if let Err(response) = validate_config_update(&state, &old_config, &config, "settings") {
        return response;
    }
    // Outbound IP Versions must leave every forwarder list someone to ask.
    if config.recursive != old_config.recursive {
        if let Err(e) = check_outbound_servers(&config.recursive) {
            return error_response(StatusCode::BAD_REQUEST, e);
        }
    }

    // Move the web listeners first: a port that cannot be bound or a
    // certificate that does not load rejects the whole update, so the
    // console is never left unreachable by a save.
    if old_config.web != config.web {
        if let Some(apply) = &state.web_apply {
            if let Err(msg) = apply(config.web.clone()).await {
                return error_response(StatusCode::BAD_REQUEST, msg);
            }
        }
    }

    // Build the replacement recursive resolver before anything is persisted
    // or published: a failed build rejects the save with 400 and nothing
    // changes, so the published config and the live resolver can never
    // diverge (a rebuild that failed after publishing used to silently keep
    // the previous resolver, and a later no-op save would never retry it
    // without a restart). Runtime components take the network names
    // resolved to addresses.
    let resolved = config.with_networks_resolved();
    let recursive_changed = old_config.recursive != config.recursive
        || old_config.authoritative.stub_zones != config.authoritative.stub_zones;
    let new_resolver = if recursive_changed && config.recursive.enabled {
        Some(match build_resolver(&state, &resolved).await {
            Ok(resolver) => resolver,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("recursive resolver rebuild failed: {e}"),
                );
            }
        })
    } else {
        None
    };

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

    // Publish live, then ask for a listener rebuild when needed (only when a
    // listener-relevant section really changed: a no-op save must not bounce
    // every socket).
    let listeners_affected = listeners_affected
        && (old_config.server != config.server
            || old_config.dot != config.dot
            || old_config.doh != config.doh
            || old_config.doq != config.doq);
    state.config.store(Arc::new(config.clone()));
    // Server-side knobs read from their own state rather than the config
    // (the recursive lookup limit): a console change otherwise waited for a
    // restart or a config-file reload.
    if let Some(apply) = &state.apply_runtime {
        apply(&config);
    }
    if listeners_affected {
        if let Some(rebuild) = &state.request_dns_rebuild {
            rebuild();
        }
    }
    state
        .local_root
        .set_settings(config.recursive.local_root_in_effect());
    // Swap in the resolver built before the save (or drop it when recursion
    // was disabled) so upstreams, cache settings, conditional forwarders,
    // stub zones and recursion access apply to live traffic immediately and
    // together with the published config. No rebuild here: anything that
    // needed building happened before the persist step (see above).
    if recursive_changed {
        state.resolver.store(new_resolver.map(Arc::new));
    }
    // Hot-swap the per-request authoritative gates (AXFR + dynamic-update
    // policy) so the change applies to in-flight DNS traffic immediately,
    // not just after a restart. NOTIFY hooks are startup-built and need a
    // restart; the persisted config already carries them.
    // The published catalog zone is rebuilt at once; consumed catalogs are
    // read from the live config by their refresh loop.
    if old_config.authoritative.catalog_zone != config.authoritative.catalog_zone {
        if let Err(e) = state
            .catalog
            .set_catalog_zone(&config.authoritative.catalog_zone)
        {
            state
                .logs
                .warn("api", format!("cannot publish the catalog zone: {e}"));
        }
    }
    if authoritative_changed {
        state.catalog.update_gate_settings(
            resolved.authoritative.axfr_enabled,
            resolved.authoritative.axfr_networks.clone(),
            resolved.authoritative.allow_dynamic_updates,
            resolved.authoritative.update_networks.clone(),
        );
    }
    // Rebuild the policy engine so a Filter-AAAA change applies immediately,
    // regardless of whether the config-file watcher is enabled.
    if policy_changed {
        match daygle_dns_policy::build_engine(&resolved.policy) {
            // Rebuilding static policy must not discard domains already
            // fetched from remote sources (and the DoT-scoped set): the
            // source refresher owns those, and the live engine's are kept.
            Ok(engine) => daygle_dns_policy::publish_rebuilt(&state.policy, engine),
            Err(e) => tracing::warn!("policy rebuild after settings update failed: {e}"),
        }
    }
    // Hot-apply AI settings on the running engine: the plugin and scanner
    // read the swapped settings atomically, so enable/mode/thresholds/TTLs
    // apply immediately and the block snapshot is rebuilt with the new
    // invariants. Enabling a server that started with `[ai]` disabled (and
    // model/database switches) needs the startup path to build the engine -
    // the persisted overlay makes it effective on the next restart.
    if ai_changed {
        match &state.ai {
            Some(ai) => {
                let backend_changed = old_config.ai.model_path != config.ai.model_path
                    || old_config.ai.database != config.ai.database;
                ai.settings.store(Arc::new(config.ai.clone()));
                ai.refresh_snapshot_now();
                ai.trigger_rescan();
                if backend_changed {
                    state.logs.warn(
                        "api",
                        "AI model or database path changed; restart to switch backends".to_string(),
                    );
                }
            }
            None => {
                state.logs.info(
                    "api",
                    "AI settings stored; the scanner activates on the next restart".to_string(),
                );
            }
        }
    }
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        "settings updated via the console".to_string(),
    );
    config_response(&state.config.load_full())
}

// ---- Managed TLS certificates --------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateInput {
    pub name: String,
    /// Subject name (used when generating a self-signed certificate; the CN/SAN).
    pub server_name: Option<String>,
    /// PEM certificate. Omit (together with `key_pem`) to generate self-signed.
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// PEM private key. Must accompany `cert_pem`.
    #[serde(default)]
    pub key_pem: Option<String>,
}

fn validate_certificate_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.starts_with('.')
        && !name.ends_with('.');
    if ok {
        Ok(())
    } else {
        Err(
            "name must be 1-64 characters using only letters, digits, '.', '_' or '-' (no leading/trailing dot)"
                .to_string(),
        )
    }
}

/// Which listeners currently reference a managed certificate (by name).
fn certificate_references(
    config: &daygle_dns_core::config::DaygleConfig,
) -> Vec<(String, &'static str)> {
    let mut refs = Vec::new();
    for (name, label) in [
        (&config.dot.certificate, "DoT"),
        (&config.doh.certificate, "DoH"),
        (&config.doq.certificate, "DoQ"),
    ] {
        if !name.is_empty() {
            refs.push((name.clone(), label));
        }
    }
    if config.web.https_enabled && !config.web.https_certificate.is_empty() {
        refs.push((config.web.https_certificate.clone(), "Web Console"));
    }
    refs
}

fn certificate_json(
    cert: &daygle_dns_authoritative::TlsCertificate,
    in_use: Vec<&'static str>,
) -> serde_json::Value {
    let stamp = |secs: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|t| t.to_rfc3339())
    };
    let mut value = serde_json::json!({
        "name": cert.name,
        "server_name": cert.server_name,
        "created_at": cert.created_at,
        "in_use": in_use,
    });
    // Details read from the certificate itself (null when it cannot be read).
    let details = daygle_dns_dot::describe_certificate(&cert.cert_pem).ok();
    value["subject"] = serde_json::json!(details.as_ref().map(|d| &d.subject));
    value["issuer"] = serde_json::json!(details.as_ref().map(|d| &d.issuer));
    value["self_signed"] = serde_json::json!(details.as_ref().map(|d| d.self_signed));
    value["names"] = serde_json::json!(details.as_ref().map(|d| &d.names));
    value["not_before"] = serde_json::json!(details.as_ref().and_then(|d| stamp(d.not_before)));
    value["not_after"] = serde_json::json!(details.as_ref().and_then(|d| stamp(d.not_after)));
    value
}

/// `GET /api/certificates` - list console-managed TLS certificates (metadata
/// only; PEM material is never returned to the GUI).
pub async fn list_certificates(State(state): State<AppState>) -> Response {
    let refs = certificate_references(&state.config.load_full());
    let store = state.catalog.store();
    let list = match store.list_tls_certificates() {
        Ok(list) => list,
        Err(e) => return map_err(e),
    };
    let mut acme: std::collections::BTreeMap<String, _> = match store.list_acme_certificates() {
        Ok(certs) => certs.into_iter().map(|c| (c.name.clone(), c)).collect(),
        Err(e) => return map_err(e),
    };
    let acme_json = |cert: &daygle_dns_authoritative::store::AcmeCertificate| {
        serde_json::json!({
            "domains": cert.domains,
            "challenge": cert.challenge,
            "status": if state.acme.is_issuing(&cert.name) { "pending" } else { cert.status.as_str() },
            "last_error": cert.last_error,
            "last_attempt": cert.last_attempt,
        })
    };
    let mut items: Vec<serde_json::Value> = list
        .iter()
        .map(|cert| {
            let in_use: Vec<&'static str> = refs
                .iter()
                .filter(|(name, _)| name == &cert.name)
                .map(|(_, label)| *label)
                .collect();
            let mut value = certificate_json(cert, in_use);
            value["acme"] = acme
                .remove(&cert.name)
                .as_ref()
                .map_or(serde_json::Value::Null, acme_json);
            value
        })
        .collect();
    // Requested but not issued yet.
    for cert in acme.values() {
        items.push(serde_json::json!({
            "name": cert.name,
            "server_name": cert.domains.first(),
            "created_at": null,
            "in_use": [],
            "subject": null,
            "issuer": null,
            "self_signed": null,
            "names": cert.domains,
            "not_before": null,
            "not_after": null,
            "acme": acme_json(cert),
        }));
    }
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Json(items).into_response()
}

/// `POST /api/certificates` - create (self-signed) or upload a TLS
/// certificate. Uploading with the same `name` replaces the existing entry;
/// listeners referencing the name are rebuilt so the new material applies.
pub async fn create_certificate(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<CertificateInput>,
) -> Response {
    let name = input.name.trim().to_string();
    if let Err(msg) = validate_certificate_name(&name) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    let server_name = input.server_name.unwrap_or_default().trim().to_string();

    let (cert_pem, key_pem, server_name) = match (input.cert_pem, input.key_pem) {
        (None, None) => {
            let sn = if server_name.is_empty() {
                "daygle.local".to_string()
            } else {
                server_name.clone()
            };
            match daygle_dns_dot::generate_self_signed_pem(&sn) {
                Ok((c, k)) => (c, k, sn),
                Err(e) => return map_err(e),
            }
        }
        (Some(cert_pem), Some(key_pem)) => {
            if let Err(e) = daygle_dns_dot::validate_pem_pair(&cert_pem, &key_pem) {
                return error_response(StatusCode::BAD_REQUEST, e.to_string());
            }
            (cert_pem, key_pem, server_name)
        }
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "provide cert_pem and key_pem together, or neither to generate a self-signed certificate",
            )
        }
    };

    // An ACME certificate is replaced by its CA, not by hand.
    match state.catalog.store().get_acme_certificate(&name) {
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                format!("certificate '{name}' comes from an ACME CA and renews itself; delete it first to replace it"),
            )
        }
        Ok(None) => {}
        Err(e) => return map_err(e),
    }
    let cert = daygle_dns_authoritative::TlsCertificate {
        name: name.clone(),
        server_name,
        cert_pem,
        key_pem,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Err(e) = install_certificate(&state, cert.clone()).await {
        return map_err(e);
    }

    let in_use: Vec<&'static str> = certificate_references(&state.config.load_full())
        .into_iter()
        .filter(|(n, _)| n == &name)
        .map(|(_, l)| l)
        .collect();
    Json(certificate_json(&cert, in_use)).into_response()
}

/// Store a certificate and refresh the listeners that use it, so a
/// replacement (an upload, or an ACME renewal) applies straight away.
pub(crate) async fn install_certificate(
    state: &AppState,
    cert: daygle_dns_authoritative::TlsCertificate,
) -> Result<(), daygle_dns_core::error::DaygleError> {
    let name = cert.name.clone();
    state.catalog.store().put_tls_certificate(&cert)?;
    let referenced = certificate_references(&state.config.load_full())
        .into_iter()
        .any(|(n, _)| n == name);
    if referenced {
        if let Some(rebuild) = &state.request_dns_rebuild {
            rebuild();
        }
        // The console's HTTPS listener picks the new pair up in place.
        let web = state.config.load_full().web.clone();
        if web.https_enabled && web.https_certificate == name {
            if let Some(apply) = &state.web_apply {
                if let Err(e) = apply(web).await {
                    tracing::warn!("web console certificate reload failed: {e}");
                }
            }
        }
    }
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!(
            "certificate '{name}' {}",
            if referenced {
                "updated (listeners rebuilt)"
            } else {
                "saved"
            }
        ),
    );
    Ok(())
}

// ---- ACME (Let's Encrypt) ---------------------------------------------------

/// `GET /.well-known/acme-challenge/{token}` - HTTP-01 challenge answers
/// while an ACME certificate is being issued.
pub async fn acme_http_challenge(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    match state.acme.http_response(&token) {
        Some(answer) => {
            ([(header::CONTENT_TYPE, "application/octet-stream")], answer).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /api/acme` - the ACME settings.
pub async fn get_acme_settings(State(state): State<AppState>) -> Response {
    let settings = crate::acme::settings(&state);
    Json(serde_json::json!({
        "settings": settings,
        "directory_url": settings.directory_url(),
        "lets_encrypt": crate::acme::LETS_ENCRYPT,
        "lets_encrypt_staging": crate::acme::LETS_ENCRYPT_STAGING,
    }))
    .into_response()
}

/// `PUT /api/acme` - save the ACME settings.
pub async fn put_acme_settings(
    State(state): State<AppState>,
    axum::Json(settings): axum::Json<crate::acme::AcmeSettings>,
) -> Response {
    let settings = crate::acme::AcmeSettings {
        email: settings.email.trim().to_string(),
        directory: settings.directory.trim().to_string(),
        ..settings
    };
    match crate::acme::save_settings(&state, &settings) {
        Ok(()) => get_acme_settings(State(state)).await,
        Err(e) => error_response(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
pub struct AcmeCertificateInput {
    name: String,
    domains: Vec<String>,
    #[serde(default)]
    challenge: String,
}

/// Start issuing an ACME certificate in the background.
fn spawn_acme_issue(state: &AppState, name: String) {
    let state = state.clone();
    tokio::spawn(async move {
        let _ = crate::acme::issue(&state, &name).await;
    });
}

/// `POST /api/certificates/acme` `{name, domains, challenge}` - request a
/// certificate from the ACME CA. Issuing runs in the background (`202`);
/// the certificate list shows how it went.
pub async fn request_acme_certificate(
    State(state): State<AppState>,
    axum::Json(input): axum::Json<AcmeCertificateInput>,
) -> Response {
    let name = input.name.trim().to_string();
    if let Err(msg) = validate_certificate_name(&name) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    let challenge = match input.challenge.trim() {
        "" | "http" => "http",
        "dns" => "dns",
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unknown challenge '{other}': use http or dns"),
            )
        }
    };
    let domains = match crate::acme::check_domains(&input.domains, challenge) {
        Ok(d) => d,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    if !crate::acme::settings(&state).agree_terms {
        return error_response(
            StatusCode::BAD_REQUEST,
            "accept the CA's terms of service in the Let's Encrypt settings first",
        );
    }
    let store = state.catalog.store();
    match (
        store.get_tls_certificate(&name),
        store.get_acme_certificate(&name),
    ) {
        (Ok(None), Ok(None)) => {}
        (Ok(_), Ok(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                format!("a certificate named '{name}' already exists"),
            )
        }
        (Err(e), _) | (_, Err(e)) => return map_err(e),
    }
    let cert = daygle_dns_authoritative::store::AcmeCertificate {
        name: name.clone(),
        domains,
        challenge: challenge.to_string(),
        status: "pending".to_string(),
        last_error: String::new(),
        last_attempt: 0,
    };
    if let Err(e) = store.put_acme_certificate(&cert) {
        return map_err(e);
    }
    spawn_acme_issue(&state, name);
    (StatusCode::ACCEPTED, Json(cert)).into_response()
}

/// `POST /api/certificates/{name}/renew` - renew an ACME certificate now.
pub async fn renew_acme_certificate(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    match state.catalog.store().get_acme_certificate(&name) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("'{name}' is not an ACME certificate"),
            )
        }
        Err(e) => return map_err(e),
    }
    if state.acme.is_issuing(&name) {
        return error_response(
            StatusCode::CONFLICT,
            format!("certificate '{name}' is already being requested"),
        );
    }
    spawn_acme_issue(&state, name);
    StatusCode::ACCEPTED.into_response()
}

/// `DELETE /api/certificates/{name}` - remove a managed certificate. A
/// certificate still selected by a listener cannot be deleted.
pub async fn delete_certificate(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    let name = name.trim().to_string();
    let in_use: Vec<&'static str> = certificate_references(&state.config.load_full())
        .into_iter()
        .filter(|(n, _)| n == &name)
        .map(|(_, l)| l)
        .collect();
    if !in_use.is_empty() {
        return error_response(
            StatusCode::CONFLICT,
            format!(
                "certificate '{name}' is in use by {}; change the listener first",
                in_use.join(" and ")
            ),
        );
    }
    match state.catalog.store().delete_tls_certificate(&name) {
        Ok(true) => {}
        Ok(false) => return error_response(StatusCode::NOT_FOUND, "certificate not found"),
        Err(e) => return map_err(e),
    }
    state.logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!("certificate '{name}' deleted"),
    );
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
