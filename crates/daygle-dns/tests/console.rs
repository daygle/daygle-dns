//! Integration tests: console login (users + sessions), settings update
//! (`PUT /api/config`), and DNS-over-QUIC (RFC 9250) end to end.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use chrono::Datelike;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::DaygleConfig;
use daygle_dns_core::hash_password;
use daygle_dns::BoundServer;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use rustls_pki_types::pem::PemObject;
use serde_json::json;

/// Spawn a server with console users configured (admin / secret).
/// Low PBKDF2 iterations keep logins fast; verification uses the stored
/// count, so this is safe.
async fn spawn_with_users(dir: &tempfile::TempDir, config_path: Option<PathBuf>) -> BoundServer {
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    // Real (validated) ports: settings updates re-validate the merged
    // config, which must mirror a production-loaded file.
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();
    cfg.api.users = vec![daygle_dns_core::config::ApiUser {
        username: "admin".to_string(),
        password_hash: hash_password("secret"),
        role: daygle_dns_core::config::Role::Admin,
    }];
    bind_with_config(cfg, config_path).await
}

/// Spawn a server with an admin and a read-only viewer account.
/// Low PBKDF2 iterations keep logins fast; verification uses the stored
/// count, so this is safe.
async fn spawn_with_roles(dir: &tempfile::TempDir) -> BoundServer {
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();
    let low = |pw: &str| daygle_dns_core::auth::hash_password_with(pw, 100);
    cfg.api.users = vec![
        daygle_dns_core::config::ApiUser {
            username: "admin".to_string(),
            password_hash: low("secret"),
            role: daygle_dns_core::config::Role::Admin,
        },
        daygle_dns_core::config::ApiUser {
            username: "auditor".to_string(),
            password_hash: low("watch"),
            role: daygle_dns_core::config::Role::Viewer,
        },
    ];
    spawn(cfg).await
}

/// Login and return the token + role from the response (plus the raw
/// response when `expect_status` is given, for negative tests).
async fn login_status(addr: std::net::SocketAddr, username: &str, password: &str) -> u16 {
    reqwest::Client::new()
        .post(api_url(addr, "/api/auth/login"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Login and return the token + role from the response.
async fn login(addr: std::net::SocketAddr, username: &str, password: &str) -> (String, String) {
    let resp = reqwest::Client::new()
        .post(api_url(addr, "/api/auth/login"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login as {username} failed");
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["token"].as_str().unwrap().to_string(),
        body["role"].as_str().unwrap().to_string(),
    )
}

/// Like `common::spawn` but optionally with a config file path so settings
/// updates can be persisted.
async fn bind_with_config(cfg: DaygleConfig, path: Option<PathBuf>) -> BoundServer {
    if let Some(path) = path {
        daygle_dns::bind_with(Arc::new(cfg), Some(path))
            .await
            .expect("server should bind")
    } else {
        spawn(cfg).await
    }
}

fn api_url(addr: std::net::SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

/// Probe a free TCP port (bind + drop). Used so the settings test's config
/// passes full validation, mirroring a production-loaded config.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn console_users_live_in_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_with_users(&dir, None).await;
    let client = reqwest::Client::new();
    let base = api_url(server.api_addr, "");
    let (token, role) = login(server.api_addr, "admin", "secret").await;
    assert_eq!(role, "admin");

    // The config-seeded account is listed, with its hash redacted.
    let resp = client
        .get(format!("{base}/api/users"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let users: serde_json::Value = resp.json().await.unwrap();
    let admin = users.as_array().unwrap().iter().find(|u| u["username"] == "admin").unwrap();
    assert_eq!(admin["password_hash"], json!("[redacted]"));

    // Create a viewer and an extra admin through the API.
    for (name, user_role) in [("auditor", "viewer"), ("root2", "admin")] {
        let resp = client
            .post(format!("{base}/api/users"))
            .bearer_auth(&token)
            .json(&json!({ "username": name, "password": "long-enough-pw", "role": user_role }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create {name}");
    }
    // Duplicate and weak-password creates are rejected.
    assert_eq!(
        client
            .post(format!("{base}/api/users"))
            .bearer_auth(&token)
            .json(&json!({ "username": "auditor", "password": "long-enough-pw" }))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        client
            .post(format!("{base}/api/users"))
            .bearer_auth(&token)
            .json(&json!({ "username": "shorty", "password": "tiny" }))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // The new accounts can actually log in with their roles.
    let (_, auditor_role) = login(server.api_addr, "auditor", "long-enough-pw").await;
    assert_eq!(auditor_role, "viewer");

    // Disabling an account revokes its sessions and blocks login.
    let resp = client
        .patch(format!("{base}/api/users/auditor"))
        .bearer_auth(&token)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(login_status(server.api_addr, "auditor", "long-enough-pw").await, 401);

    // Re-enable, then reset the password: the old one stops working.
    let resp = client
        .patch(format!("{base}/api/users/auditor"))
        .bearer_auth(&token)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .patch(format!("{base}/api/users/auditor"))
        .bearer_auth(&token)
        .json(&json!({ "password": "rotated-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(login_status(server.api_addr, "auditor", "long-enough-pw").await, 401);
    let _ = login(server.api_addr, "auditor", "rotated-password").await;

    // The last enabled admin is protected: with two admins, deleting one
    // works, but deleting the remaining one is refused.
    let resp = client
        .delete(format!("{base}/api/users/root2"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(login_status(server.api_addr, "root2", "long-enough-pw").await, 401);
    let resp = client
        .delete(format!("{base}/api/users/admin"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    // ... and demotion is guarded the same way.
    let resp = client
        .patch(format!("{base}/api/users/admin"))
        .bearer_auth(&token)
        .json(&json!({ "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Deleted accounts cannot log in.
    assert_eq!(login_status(server.api_addr, "root2", "long-enough-pw").await, 401);

    shutdown(server).await;
}

#[tokio::test]
async fn user_can_rotate_their_own_password() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_with_users(&dir, None).await;
    let client = reqwest::Client::new();
    let base = api_url(server.api_addr, "");

    // Two sessions for the same account (two "devices").
    let (token_a, _) = login(server.api_addr, "admin", "secret").await;
    let (token_b, _) = login(server.api_addr, "admin", "secret").await;

    // Wrong current password is rejected.
    let resp = client
        .post(format!("{base}/api/auth/password"))
        .bearer_auth(&token_a)
        .json(&json!({ "current_password": "wrong", "new_password": "new-secret-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Short and unchanged new passwords are rejected.
    let resp = client
        .post(format!("{base}/api/auth/password"))
        .bearer_auth(&token_a)
        .json(&json!({ "current_password": "secret", "new_password": "tiny" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = client
        .post(format!("{base}/api/auth/password"))
        .bearer_auth(&token_a)
        .json(&json!({ "current_password": "secret", "new_password": "secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The rotation succeeds and keeps the calling session alive.
    let resp = client
        .post(format!("{base}/api/auth/password"))
        .bearer_auth(&token_a)
        .json(&json!({ "current_password": "secret", "new_password": "new-secret-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client
        .get(format!("{base}/api/auth/me"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "calling session stays signed in");

    // The other session of the same account is revoked...
    let resp = client
        .get(format!("{base}/api/auth/me"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "other sessions are signed out");

    // ... the old password no longer works...
    assert_eq!(login_status(server.api_addr, "admin", "secret").await, 401);

    // ... and the new one does. A viewer may rotate their own password too.
    let resp = client
        .post(format!("{base}/api/users"))
        .bearer_auth(&token_a)
        .json(&json!({ "username": "auditor", "password": "watch-secret", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (viewer_token, _) = login(server.api_addr, "auditor", "watch-secret").await;
    let resp = client
        .post(format!("{base}/api/auth/password"))
        .bearer_auth(&viewer_token)
        .json(&json!({ "current_password": "watch-secret", "new_password": "watch-secret-2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "viewer can rotate their own password");
    let _ = login(server.api_addr, "auditor", "watch-secret-2").await;

    shutdown(server).await;
}

#[tokio::test]
async fn first_run_setup_creates_admin_and_locks_the_console() {
    let dir = tempfile::tempdir().unwrap();
    // Default config (auth_required defaults to true, no users, no token)
    // written to a file so the setup can persist the account and a restarted
    // process can load it back. The console is locked and setup is pending.
    let cfg_path = dir.path().join("daygle-dns.toml");
    std::fs::write(&cfg_path, DaygleConfig::default().to_toml().expect("serialize")).unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();
    // Simulate a fresh install: auth back on (base_config opts out for the
    // other tests), no users, no token.
    cfg.api.auth_required = true;
    let server = bind_with_config(cfg, Some(cfg_path.clone())).await;
    let client = reqwest::Client::new();
    let base = api_url(server.api_addr, "");

    // Everything is locked, and 401 bodies point the GUI at setup.
    let resp = reqwest::get(format!("{base}/api/status")).await.unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["login"], json!(true));
    assert_eq!(body["setup"], json!(true));

    // The setup status is public and reports pending; login is not possible.
    let resp = reqwest::get(format!("{base}/api/auth/setup")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["setup_pending"], json!(true));

    let resp = client
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "username": "admin", "password": "whatever" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Short passwords are rejected.
    let resp = client
        .post(format!("{base}/api/auth/setup"))
        .json(&json!({ "username": "admin", "password": "short" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Completing setup returns a session for the new admin.
    let resp = client
        .post(format!("{base}/api/auth/setup"))
        .json(&json!({ "username": "admin", "password": "first-run-secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "setup body: {}", resp.text().await.unwrap_or_default());
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(created["username"], json!("admin"));
    assert_eq!(created["role"], json!("admin"));
    let token = created["token"].as_str().unwrap().to_string();

    // The session authorizes reads and mutations immediately.
    let resp = client
        .get(format!("{base}/api/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{base}/api/zones"))
        .bearer_auth(&token)
        .json(&json!({ "name": "setup.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Setup is one-time: a second attempt is refused.
    let resp = client
        .post(format!("{base}/api/auth/setup"))
        .json(&json!({ "username": "evil", "password": "second-attempt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // The account survives a restart: the new process (which loads the
    // persisted file) enforces login and accepts the created credentials.
    shutdown(server).await;
    let mut cfg = DaygleConfig::load(&cfg_path).expect("reload persisted config");
    // Keep the test's ephemeral ports/database; the persisted file only
    // supplies the (now DB-backed) account plus auth settings.
    cfg.server.listen = "127.0.0.1".to_string();
    cfg.server.port = free_tcp_port();
    cfg.api.listen = "127.0.0.1".to_string();
    cfg.api.port = free_tcp_port();
    cfg.dot.enabled = false;
    cfg.doh.enabled = false;
    cfg.doq.enabled = false;
    cfg.recursive.enabled = false;
    cfg.recursive.use_system_config = false;
    cfg.authoritative.database = dir.path().join("daygle-dns.db").to_string_lossy().into_owned();
    let server = bind_with_config(cfg, Some(cfg_path)).await;
    let resp = reqwest::get(api_url(server.api_addr, "/api/status")).await.unwrap();
    assert_eq!(resp.status(), 401);
    let (token, role) = login(server.api_addr, "admin", "first-run-secret").await;
    assert_eq!(role, "admin");
    let resp = reqwest::Client::new()
        .get(api_url(server.api_addr, "/api/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    shutdown(server).await;
}

#[tokio::test]
async fn auth_can_be_disabled_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();
    cfg.api.auth_required = false;
    let server = spawn(cfg).await;

    // The opt-out serves the console open, and no setup is pending.
    let resp = reqwest::get(api_url(server.api_addr, "/api/status")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = reqwest::get(api_url(server.api_addr, "/api/auth/setup")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["setup_pending"], json!(false));

    // The setup endpoint refuses to run while auth is disabled.
    let resp = reqwest::Client::new()
        .post(api_url(server.api_addr, "/api/auth/setup"))
        .json(&json!({ "username": "admin", "password": "not-used-here" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    shutdown(server).await;
}

#[tokio::test]
async fn login_flow_full_auth() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_with_users(&dir, None).await;

    // With users configured, read endpoints require authentication.
    let resp = reqwest::get(api_url(server.api_addr, "/api/status"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["login"], json!(true));

    // Wrong password is rejected.
    let resp = reqwest::Client::new()
        .post(api_url(server.api_addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Correct credentials issue a token.
    let resp = reqwest::Client::new()
        .post(api_url(server.api_addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": "secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "login body: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    // The token authorizes reads and mutations.
    let client = reqwest::Client::new();
    let resp = client
        .get(api_url(server.api_addr, "/api/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(api_url(server.api_addr, "/api/zones"))
        .bearer_auth(&token)
        .json(&json!({ "name": "login.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // `GET /api/auth/me` identifies the session.
    let resp = client
        .get(api_url(server.api_addr, "/api/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let me: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(me["username"], json!("admin"));

    // Logout revokes the session.
    client
        .post(api_url(server.api_addr, "/api/auth/logout"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let resp = client
        .get(api_url(server.api_addr, "/api/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    shutdown(server).await;
}

#[tokio::test]
async fn static_api_token_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.api.api_token = "legacy-token".to_string();
    let server = spawn(cfg).await;

    // Legacy mode: GETs stay open, mutations need the static token.
    let resp = reqwest::get(api_url(server.api_addr, "/api/status"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = reqwest::Client::new()
        .post(api_url(server.api_addr, "/api/zones"))
        .json(&json!({ "name": "x.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = reqwest::Client::new()
        .post(api_url(server.api_addr, "/api/zones"))
        .bearer_auth("legacy-token")
        .json(&json!({ "name": "x.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    shutdown(server).await;
}

#[tokio::test]
async fn db_settings_survive_restart_and_win_over_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("daygle-dns.toml");
    std::fs::write(
        &cfg_path,
        DaygleConfig::default().to_toml().expect("serialize"),
    )
    .unwrap();
    let server = spawn_with_users(&dir, Some(cfg_path.clone())).await;
    let client = reqwest::Client::new();
    let (token, _) = login(server.api_addr, "admin", "secret").await;

    // Change a runtime setting through the console.
    let resp = client
        .put(api_url(server.api_addr, "/api/config"))
        .bearer_auth(&token)
        .json(&json!({ "recursive": { "cache_size": 12345 } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    shutdown(server).await;

    // Edit the FILE to a different value, as a hand-edit would.
    let mut file_cfg = DaygleConfig::load(&cfg_path).unwrap();
    file_cfg.recursive.cache_size = 999;
    std::fs::write(&cfg_path, file_cfg.to_toml().unwrap()).unwrap();

    // Restart. The DB overlay must win: 12345, not the file's 999.
    let server = spawn_with_users(&dir, Some(cfg_path.clone())).await;
    let client = reqwest::Client::new();
    let (token, _) = login(server.api_addr, "admin", "secret").await;
    let cfg = client
        .get(api_url(server.api_addr, "/api/config"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(cfg["recursive"]["cache_size"], json!(12345));

    shutdown(server).await;
}

#[tokio::test]
async fn settings_update_applies_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("daygle-dns.toml");
    std::fs::write(
        &cfg_path,
        DaygleConfig::default().to_toml().expect("serialize"),
    )
    .unwrap();

    let server = spawn_with_users(&dir, Some(cfg_path.clone())).await;
    let client = reqwest::Client::new();

    // Login.
    let resp = client
        .post(api_url(server.api_addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": "secret" }))
        .send()
        .await
        .unwrap();
    let token: String = resp.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .into();

    // Update recursion + DoQ settings through the console.
    let resp = client
        .put(api_url(server.api_addr, "/api/config"))
        .bearer_auth(&token)
        .json(&json!({
            "recursive": {
                "dnssec_validate": true,
                "serve_stale_secs": 1800,
            },
            "doq": { "enabled": true },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "body: {}", resp.text().await.unwrap());
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["recursive"]["dnssec_validate"], json!(true));
    assert_eq!(updated["recursive"]["serve_stale_secs"], json!(1800));
    assert_eq!(updated["doq"]["enabled"], json!(true));

    // The update was persisted to the DATABASE (the config file is
    // bootstrap-only now) and re-applies on a fresh boot.
    let store = daygle_dns_authoritative::ZoneStore::open(
        dir.path().join("daygle-dns.db").to_string_lossy().as_ref(),
    )
    .unwrap();
    let overlay = store
        .get_runtime_settings::<daygle_dns_core::config::RuntimeSettings>()
        .unwrap()
        .expect("runtime settings should be stored");
    drop(store);
    let mut from_file = DaygleConfig::load(&cfg_path).expect("persisted config should parse");
    overlay.apply_to(&mut from_file);
    assert!(from_file.recursive.dnssec_validate);
    assert_eq!(from_file.recursive.serve_stale_secs, 1800);
    assert!(from_file.doq.enabled);

    // The config file itself was NOT rewritten by the console save: its
    // serve-stale value is still the file's default, not the console's 1800.
    assert_ne!(
        DaygleConfig::load(&cfg_path).unwrap().recursive.serve_stale_secs,
        1800
    );

    // A genuinely new validation error is rejected and nothing changes.
    let resp = client
        .put(api_url(server.api_addr, "/api/config"))
        .bearer_auth(&token)
        .json(&json!({ "recursive": { "prefetch_ttl_fraction_pct": 0 } }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "body: {}",
        resp.text().await.unwrap_or_default()
    );
    let after = client
        .get(api_url(server.api_addr, "/api/config"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_ne!(after["recursive"]["prefetch_ttl_fraction_pct"], json!(0));

    shutdown(server).await;
}

#[tokio::test]
async fn zone_form_creates_primary_import_and_secondary_zones() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();
    let server = spawn(cfg).await;
    let client = reqwest::Client::new();
    let base = api_url(server.api_addr, "");

    let primary = client
        .post(format!("{base}/api/zones"))
        .json(&json!({
            "name": "imported.test",
            "zone_type": "primary",
            "primary_ns": "ns1.imported.test.",
            "admin_mailbox": "admin.imported.test.",
            "serial": 42,
            "refresh": 1800,
            "retry": 300,
            "expire": 86400,
            "minimum": 60,
            "import_text": "$ORIGIN imported.test.\n$TTL 300\n@ IN SOA ns1.imported.test. admin.imported.test. 99 3600 600 86400 300\n@ IN NS ns1.imported.test.\nns1 IN A 192.0.2.10\n"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(primary.status(), 201, "primary body: {}", primary.text().await.unwrap_or_default());
    let primary: serde_json::Value = client
        .get(format!("{base}/api/zones"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let imported = primary
        .as_array()
        .unwrap()
        .iter()
        .find(|zone| zone["name"] == "imported.test")
        .unwrap();
    assert_eq!(imported["zone_type"], json!("primary"));
    assert_eq!(imported["serial"], json!(42));

    let records: Vec<serde_json::Value> = client
        .get(format!("{base}/api/zones/{}/records", imported["id"].as_str().unwrap()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(records.iter().any(|record| record["rtype"] == "A"));

    let date_based = client
        .post(format!("{base}/api/zones"))
        .json(&json!({ "name": "dated.test", "serial_date_scheme": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(date_based.status(), 201);
    let dated: serde_json::Value = date_based.json().await.unwrap();
    let today = chrono::Utc::now();
    let date_prefix = (today.year() as u32) * 10_000 + today.month() * 100 + today.day();
    let serial = dated["serial"].as_u64().unwrap() as u32;
    assert!((date_prefix * 100 + 1..=date_prefix * 100 + 99).contains(&serial));

    let secondary = client
        .post(format!("{base}/api/zones"))
        .json(&json!({
            "name": "branch.test",
            "zone_type": "secondary",
            "masters": ["192.0.2.10", "192.0.2.11:5353"],
            "refresh_secs": 600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(secondary.status(), 201, "secondary body: {}", secondary.text().await.unwrap_or_default());

    let zones: Vec<serde_json::Value> = client
        .get(format!("{base}/api/zones"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let branch = zones.iter().find(|zone| zone["name"] == "branch.test").unwrap();
    assert_eq!(branch["zone_type"], json!("secondary"));
    assert_eq!(branch["masters"], json!(["192.0.2.10", "192.0.2.11:5353"]));
    assert_eq!(branch["refresh_secs"], json!(600));

    let mutation = client
        .put(format!("{base}/api/zones/{}/records", branch["id"].as_str().unwrap()))
        .json(&json!({ "name": "host", "rtype": "A", "content": "192.0.2.20" }))
        .send()
        .await
        .unwrap();
    assert_eq!(mutation.status(), 409);

    shutdown(server).await;
}

#[tokio::test]
async fn viewer_role_is_read_only_and_secrets_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_with_roles(&dir).await;
    let client = reqwest::Client::new();
    let base = api_url(server.api_addr, "");

    // Login reports the role, and `/auth/me` echoes it.
    let (viewer_token, role) = login(server.api_addr, "auditor", "watch").await;
    assert_eq!(role, "viewer");
    let me: serde_json::Value = client
        .get(format!("{base}/api/auth/me"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["role"], json!("viewer"));

    // Reads are allowed...
    let resp = client
        .get(format!("{base}/api/status"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{base}/api/stats"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let stats: serde_json::Value = resp.json().await.unwrap();
    assert!(stats.get("series").is_some());

    // ...but every mutating method is rejected with 403.
    let resp = client
        .post(format!("{base}/api/zones"))
        .bearer_auth(&viewer_token)
        .json(&json!({ "name": "viewer.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .put(format!("{base}/api/config"))
        .bearer_auth(&viewer_token)
        .json(&json!({ "recursive": { "enabled": false } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .post(format!("{base}/api/cache/clear"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Admin keeps full access.
    let (admin_token, role) = login(server.api_addr, "admin", "secret").await;
    assert_eq!(role, "admin");
    let resp = client
        .post(format!("{base}/api/zones"))
        .bearer_auth(&admin_token)
        .json(&json!({ "name": "admin.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Secrets are redacted in GET /api/config for every authenticated user.
    let cfg_json: serde_json::Value = client
        .get(format!("{base}/api/config"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let users = cfg_json["api"]["users"].as_array().unwrap();
    for u in users {
        assert_eq!(u["password_hash"], json!("[redacted]"), "hash leaked");
    }

    shutdown(server).await;
}

#[tokio::test]
async fn stats_endpoint_tracks_served_queries() {
    let dir = tempfile::tempdir().unwrap();
    let zone_db = dir.path().join("daygle-dns.db");
    let mut cfg = base_config(&zone_db);
    cfg.server.port = free_tcp_port();
    cfg.api.port = free_tcp_port();

    // One authoritative zone + record, in the database the server opens.
    let store = daygle_dns_authoritative::ZoneStore::open(&zone_db.to_string_lossy()).unwrap();
    let catalog = Arc::new(
        daygle_dns_authoritative::AuthorityCatalog::new(
            store,
            daygle_dns_core::config::AuthoritativeSettings::default(),
        )
        .unwrap(),
    );
    let zone = catalog
        .store()
        .create_zone(&ZoneInput { name: "stats.test".to_string(), ..Default::default() })
        .unwrap();
    catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.7".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    catalog.reload().unwrap();
    drop(catalog);

    let server = spawn(cfg).await;

    // Serve a handful of queries from two "clients".
    for _ in 0..3 {
        udp_query(server.udp_addr.unwrap(), "host.stats.test.", RecordType::A).await;
    }
    udp_query(server.udp_addr.unwrap(), "other.stats.test.", RecordType::A).await;

    let client = reqwest::Client::new();
    let stats: serde_json::Value = client
        .get(api_url(server.api_addr, "/api/stats?window=1h"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let total: u64 = stats["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["queries"].as_u64().unwrap_or(0))
        .sum();
    assert!(total >= 4, "expected >= 4 recorded queries, got {total}");
    assert_eq!(stats["series"].as_array().unwrap().len(), 60);

    let top_domains: Vec<&str> = stats["top_domains"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["key"].as_str())
        .collect();
    assert!(top_domains.contains(&"host.stats.test"), "top domains: {top_domains:?}");
    let top_clients: Vec<&str> = stats["top_clients"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["key"].as_str())
        .collect();
    assert!(top_clients.iter().any(|k| k.starts_with("127.0.0.1")), "{top_clients:?}");

    shutdown(server).await;
}

#[tokio::test]
async fn doq_query_end_to_end() {
    use quinn::Connection as QuinnConnection;

    let dir = tempfile::tempdir().unwrap();
    // The zone lives in the same database the server will open, so the
    // dispatcher can answer authoritatively (recursion is disabled in the
    // test config; an unknown name would be refused).
    let zone_db = dir.path().join("daygle-dns.db");
    let mut cfg = base_config(&zone_db);
    cfg.dot.enabled = false;
    cfg.doq.enabled = true;
    cfg.doq.listen = "127.0.0.1".to_string();
    cfg.doq.port = 0;
    cfg.doq.server_name = "daygle.test".to_string();
    // Local cert paths inside the temp dir.
    cfg.doq.cert_path = dir
        .path()
        .join("doq.crt")
        .to_string_lossy()
        .into_owned();
    cfg.doq.key_path = dir
        .path()
        .join("doq.key")
        .to_string_lossy()
        .into_owned();

    // Authoritative zone with one record.
    let store = daygle_dns_authoritative::ZoneStore::open(
        &zone_db.to_string_lossy(),
    )
    .unwrap();
    let catalog = Arc::new(
        daygle_dns_authoritative::AuthorityCatalog::new(
            store,
            daygle_dns_core::config::AuthoritativeSettings::default(),
        )
        .unwrap(),
    );
    let zone = catalog
        .store()
        .create_zone(&ZoneInput {
            name: "doq.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.10".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    catalog.reload().unwrap();
    drop(catalog);

    let server = spawn(cfg).await;
    let doq_addr = server.doq_addr.expect("DoQ should be bound");

    // QUIC client that trusts the generated self-signed certificate by
    // loading it as a root.
    let cert_path = dir.path().join("doq.crt");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::<'_>::pem_file_iter(&cert_path)
        .expect("open cert")
    {
        roots.add(cert.expect("parse cert")).expect("add root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn: QuinnConnection = endpoint
        .connect(doq_addr, "daygle.test")
        .unwrap()
        .await
        .expect("quic connect");

    // RFC 9250 §4.2: one bidirectional stream per query; messages carry a
    // 2-octet length prefix exactly like DNS-over-TCP; §4.2.1: message ID 0.
    let (mut send, mut recv) = conn.open_bi().await.expect("open stream");
    let query = {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_utf8("host.doq.test.").unwrap(),
            RecordType::A,
        ));
        msg.to_vec().unwrap()
    };
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    send.write_all(&framed).await.expect("send query");
    send.finish().unwrap();

    let response = recv.read_to_end(64 * 1024).await.expect("read response");
    assert!(response.len() >= 2, "response must carry a length prefix");
    let (len_bytes, body) = response.split_at(2);
    let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    assert_eq!(len, body.len(), "length prefix must match the message");
    let msg = Message::from_vec(body).expect("decode response");
    assert_eq!(
        msg.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    let answer = msg
        .answers
        .first()
        .map(|r| r.data.to_string())
        .expect("answer present");
    assert_eq!(answer, "192.0.2.10");

    // A second query on a new stream over the same connection works.
    let (mut send, mut recv) = conn.open_bi().await.expect("open second stream");
    let query2 = {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_utf8("host.doq.test.").unwrap(),
            RecordType::AAAA,
        ));
        msg.to_vec().unwrap()
    };
    let mut framed2 = Vec::with_capacity(query2.len() + 2);
    framed2.extend_from_slice(&(query2.len() as u16).to_be_bytes());
    framed2.extend_from_slice(&query2);
    send.write_all(&framed2).await.expect("send query");
    send.finish().unwrap();
    let response2 = recv.read_to_end(64 * 1024).await.expect("read response");
    let (len2, body2) = response2.split_at(2);
    let len2 = u16::from_be_bytes([len2[0], len2[1]]) as usize;
    assert_eq!(len2, body2.len());
    let msg2 = Message::from_vec(body2).unwrap();
    assert_eq!(
        msg2.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );

    shutdown(server).await;
}

#[tokio::test]
async fn gui_cache_headers_allow_upgrades_without_hard_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_with_users(&dir, None).await;
    let base = api_url(server.api_addr, "");

    // The HTML shell is served at a stable URL, so it is revalidated on
    // every load: after an upgrade the embedded shell references new hashed
    // bundles, and a browser holding a stale shell would request assets the
    // new binary no longer carries.
    let resp = reqwest::get(format!("{base}/"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap().to_str().unwrap(),
        "no-cache"
    );
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));

    // The hashed entry bundle the shell references is immutable-cached.
    let shell = resp.text().await.unwrap();
    let src = shell
        .split("src=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("index.html references an entry script");
    assert!(src.starts_with("/assets/"), "expected a hashed Vite asset, got {src}");
    let resp = reqwest::get(format!("{base}{src}")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap().to_str().unwrap(),
        "public, max-age=31536000, immutable"
    );

    shutdown(server).await;
}

// Keep unused helpers referenced.
#[allow(unused_imports)]
use common as _;
