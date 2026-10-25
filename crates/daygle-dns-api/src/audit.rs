//! The audit log: every change made through the API (and every sign-in),
//! with who made it, how they were signed in, from where, and whether it
//! worked. Request bodies are never kept: they can hold passwords and keys.

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use daygle_dns_authoritative::store::AuditEntry;

use crate::AppState;

/// What a request did, in words. `path` has no `/api` prefix.
pub fn action_for(method: &Method, path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let m = method.as_str();
    let action = match (m, parts.as_slice()) {
        ("PUT", ["config"]) => "Changed settings",
        ("POST", ["config"]) => "Reloaded the config file",
        ("POST", ["zones"]) => "Created zone",
        ("POST", ["zones", "import"]) => "Imported zone",
        ("DELETE", ["zones", _]) => "Deleted zone",
        ("PUT", ["zones", _, "soa"]) => "Changed zone SOA",
        ("PUT", ["zones", _, "records"]) => "Added record",
        ("PUT", ["zones", _, "records", _]) => "Changed record",
        ("DELETE", ["zones", _, "records", _]) => "Deleted record",
        ("PUT", ["zones", _, "records", _, "disabled"]) => "Enabled or disabled record",
        ("PUT", ["zones", _, "records", _, "health"]) => "Set a record health check",
        ("DELETE", ["zones", _, "records", _, "health"]) => "Removed a record health check",
        ("POST", ["zones", _, "sign"]) => "Signed zone",
        ("POST", ["zones", _, "unsign"]) => "Unsigned zone",
        ("POST", ["users"]) => "Created user",
        ("PATCH", ["users", _]) => "Changed user",
        ("DELETE", ["users", _]) => "Deleted user",
        ("DELETE", ["users", _, "two-factor"]) => "Reset two-factor login",
        ("POST", ["certificates"]) => "Saved certificate",
        ("DELETE", ["certificates", _]) => "Deleted certificate",
        ("POST", ["certificates", "acme"]) => "Requested certificate",
        ("POST", ["certificates", _, "renew"]) => "Renewed certificate",
        ("PUT", ["acme"]) => "Changed Let's Encrypt settings",
        ("POST", ["auth", "logout"]) => "Signed out",
        ("POST", ["auth", "password"]) => "Changed own password",
        ("PUT", ["auth", "preferences"]) => "Changed own display preferences",
        ("POST", ["auth", "two-factor", "setup"]) => "Started two-factor setup",
        ("POST", ["auth", "two-factor", "enable"]) => "Turned on two-factor login",
        ("POST", ["auth", "two-factor", "disable"]) => "Turned off two-factor login",
        ("POST", ["auth", "two-factor", "recovery-codes"]) => "Made new recovery codes",
        ("POST", ["auth", "tokens"]) => "Created API token",
        ("DELETE", ["auth", "tokens", _]) => "Revoked API token",
        ("GET", ["backup"]) => "Downloaded backup",
        ("POST", ["backup", "restore"]) => "Staged a restore",
        ("DELETE", ["backup", "restore"]) => "Cancelled the restore",
        ("POST", ["cache", "clear"]) => "Flushed the cache",
        ("POST", ["cache", "flush"]) => "Flushed a name from the cache",
        ("DELETE", ["querylogs"]) => "Cleared the query log",
        ("POST", ["policy", "blocklist", "sources"]) => "Refreshed blocklists",
        ("PUT", ["policy", "blocklist", "sources"]) => "Changed blocklist sources",
        ("POST", ["policy", "blocking"]) => "Saved blocking group",
        ("DELETE", ["policy", "blocking", _]) => "Deleted blocking group",
        ("POST", ["policy", "blocking", _, "move"]) => "Reordered blocking groups",
        ("POST", ["split-horizon", "networks"]) => "Saved split-horizon network",
        ("DELETE", ["split-horizon", "networks", _]) => "Deleted split-horizon network",
        ("POST", ["split-horizon", "entries"]) => "Created split-horizon entry",
        ("PUT", ["split-horizon", "entries", _]) => "Changed split-horizon entry",
        ("DELETE", ["split-horizon", "entries", _]) => "Deleted split-horizon entry",
        ("POST", ["split-horizon", "entries", _, "move"]) => "Reordered split-horizon entries",
        ("POST", ["ai", "override"]) => "Changed an AI override",
        ("POST", ["ai", "rescan"]) => "Started an AI rescan",
        ("POST", ["ai", "update-models"]) => "Updated the AI models",
        ("POST", ["local-root", "refresh"]) => "Refreshed the local root zone",
        ("POST", ["update", "start"]) => "Started a server update",
        _ => return format!("{m} {path}"),
    };
    action.to_string()
}

/// Requests that change nothing worth recording, or that record
/// themselves (sign-in and first-run setup know the username).
fn skipped(method: &Method, path: &str) -> bool {
    let changes = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let notable_read = path == "/backup";
    (!changes && !notable_read)
        || matches!(
            path,
            "/auth/login"
                | "/auth/setup"
                | "/policy/blocking/test"
                | "/update/dismiss"
                | "/update/check"
        )
}

/// Who a request is from, and how they signed in: `session`, `api_token`,
/// `static_token`, or `open` (authentication turned off).
fn identify(state: &AppState, req: &Request) -> (String, &'static str) {
    let bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if let Some(session) = state.sessions.authenticate(bearer) {
        let via = if session.api_token.is_some() {
            "api_token"
        } else {
            "session"
        };
        return (session.username, via);
    }
    let static_token = state.config.load().api.api_token.trim().to_string();
    if !static_token.is_empty()
        && daygle_dns_core::auth::constant_time_eq(bearer.as_bytes(), static_token.as_bytes())
    {
        return ("api_token".to_string(), "static_token");
    }
    (String::new(), "open")
}

fn client_of(req: &Request) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_canonical().to_string())
        .unwrap_or_default()
}

/// Write one entry (failures only reach the server log: auditing must not
/// break the request it records).
pub fn record(state: &AppState, entry: AuditEntry) {
    if let Err(e) = state.catalog.store().add_audit_entry(&entry) {
        tracing::warn!("cannot write the audit log: {e}");
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Record a sign-in attempt (from the login and setup handlers, which
/// know the username). `path` is the endpoint without `/api`.
pub fn record_sign_in(
    state: &AppState,
    path: &str,
    username: &str,
    client: Option<std::net::IpAddr>,
    action: &str,
    status: u16,
) {
    record(
        state,
        AuditEntry {
            id: 0,
            ts: now(),
            username: username.chars().take(64).collect(),
            via: "password".to_string(),
            client: client.map(|c| c.to_string()).unwrap_or_default(),
            action: action.to_string(),
            method: "POST".to_string(),
            path: format!("/api{path}"),
            status,
        },
    );
}

/// Middleware: record every change made through the API once it has run.
/// Sits inside the authorization layer, so refused requests never get here.
pub async fn audit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    // Inside the `/api` router the prefix is already stripped.
    let path = req.uri().path().to_string();
    let path = path
        .strip_prefix("/api")
        .map(str::to_string)
        .unwrap_or(path);
    let full_path = format!("/api{path}");
    if skipped(&method, &path) {
        return next.run(req).await;
    }
    let (username, via) = identify(&state, &req);
    let client = client_of(&req);
    let response = next.run(req).await;
    record(
        &state,
        AuditEntry {
            id: 0,
            ts: now(),
            username,
            via: via.to_string(),
            client,
            action: action_for(&method, &path),
            method: method.to_string(),
            path: full_path,
            status: response.status().as_u16(),
        },
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_read_well_and_fall_back_to_the_request() {
        assert_eq!(action_for(&Method::PUT, "/config"), "Changed settings");
        assert_eq!(
            action_for(&Method::DELETE, "/zones/abc/records/def"),
            "Deleted record"
        );
        assert_eq!(action_for(&Method::GET, "/backup"), "Downloaded backup");
        assert_eq!(
            action_for(&Method::POST, "/something/new"),
            "POST /something/new"
        );
        assert!(skipped(&Method::GET, "/zones"));
        assert!(!skipped(&Method::GET, "/backup"));
        assert!(skipped(&Method::POST, "/auth/login"));
        assert!(!skipped(&Method::POST, "/zones"));
    }
}
