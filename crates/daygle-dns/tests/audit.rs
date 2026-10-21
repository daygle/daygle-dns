//! Integration test: the audit log records sign-ins and changes, with who
//! made them and how, and only admins can read it.

mod common;

use common::*;
use serde_json::{json, Value};

#[tokio::test]
async fn changes_and_sign_ins_are_audited() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.api.auth_required = true;
    let server = spawn(cfg).await;
    let client = reqwest::Client::new();
    let api = format!("http://{}/api", server.api_addr);
    let created: Value = client
        .post(format!("{api}/auth/setup"))
        .json(&json!({ "username": "admin", "password": "first-run-secret" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin = created["token"].as_str().unwrap().to_string();

    // A failed and a successful sign-in, a change, a refused change, a
    // read (not recorded) and a change made with an API token.
    let login = |password: &str| {
        client
            .post(format!("{api}/auth/login"))
            .json(&json!({ "username": "admin", "password": password }))
            .send()
    };
    assert_eq!(login("wrong-password").await.unwrap().status(), 401);
    assert_eq!(login("first-run-secret").await.unwrap().status(), 200);
    let resp = client
        .post(format!("{api}/zones"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "audited.test" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = client
        .post(format!("{api}/zones"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "audited.test" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
    client
        .get(format!("{api}/zones"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap();
    let token: Value = client
        .post(format!("{api}/auth/tokens"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "script" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["token"].as_str().unwrap().to_string();
    client
        .post(format!("{api}/cache/clear"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    let entries: Value = client
        .get(format!("{api}/audit"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = entries.as_array().unwrap();
    let actions: Vec<(&str, &str, i64)> = entries
        .iter()
        .rev()
        .map(|e| {
            (
                e["action"].as_str().unwrap(),
                e["via"].as_str().unwrap(),
                e["status"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        actions,
        [
            ("Created the first administrator", "password", 200),
            ("Failed sign-in", "password", 401),
            ("Signed in", "password", 200),
            ("Created zone", "session", 201),
            ("Created zone", "session", 409),
            ("Created API token", "session", 201),
            ("Flushed the cache", "api_token", 204),
        ],
        "{entries:?}"
    );
    assert!(entries.iter().all(|e| e["username"] == json!("admin")));
    assert!(entries.iter().any(|e| e["client"] == json!("127.0.0.1")));
    assert!(entries
        .iter()
        .all(|e| e["path"].as_str().unwrap().starts_with("/api/")));

    // Filters, and admins only.
    let zones: Value = client
        .get(format!("{api}/audit?q=zone"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zones.as_array().unwrap().len(), 2);
    let resp = client
        .post(format!("{api}/users"))
        .bearer_auth(&admin)
        .json(&json!({ "username": "watcher", "password": "watcher-pass", "role": "viewer" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let viewer: Value = client
        .post(format!("{api}/auth/login"))
        .json(&json!({ "username": "watcher", "password": "watcher-pass" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .get(format!("{api}/audit"))
        .bearer_auth(viewer["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    shutdown(server).await;
}
