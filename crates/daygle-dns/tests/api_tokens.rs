//! Integration test: login sessions survive a restart, and personal API
//! tokens authorize scripts (read-only ones only read) until revoked.

mod common;

use common::*;
use serde_json::{json, Value};

async fn status(client: &reqwest::Client, api: &str, token: &str) -> u16 {
    client
        .get(format!("{api}/status"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn sessions_persist_and_api_tokens_work() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let config = || {
        let mut cfg = base_config(&db);
        cfg.api.auth_required = true;
        cfg
    };
    let server = spawn(config()).await;
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
    let session = created["token"].as_str().unwrap().to_string();
    let other: Value = client
        .post(format!("{api}/auth/login"))
        .json(&json!({ "username": "admin", "password": "first-run-secret" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other = other["token"].as_str().unwrap().to_string();

    // Tokens for a script: one that can change things, one that only reads.
    let make = |name: &str, read_only: bool| {
        client
            .post(format!("{api}/auth/tokens"))
            .bearer_auth(&session)
            .json(&json!({ "name": name, "read_only": read_only }))
            .send()
    };
    let rw: Value = make("deploy", false).await.unwrap().json().await.unwrap();
    let rw = rw["token"].as_str().unwrap().to_string();
    assert!(rw.starts_with("dgl_"));
    let ro_body: Value = make("monitoring", true)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ro = ro_body["token"].as_str().unwrap().to_string();
    assert_eq!(make("", false).await.unwrap().status(), 400);

    assert_eq!(status(&client, &api, &rw).await, 200);
    let create_zone = |token: &str, name: &str| {
        client
            .post(format!("{api}/zones"))
            .bearer_auth(token.to_string())
            .json(&json!({ "name": name }))
            .send()
    };
    assert!(create_zone(&rw, "script.test")
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(status(&client, &api, &ro).await, 200);
    assert_eq!(create_zone(&ro, "nope.test").await.unwrap().status(), 403);
    // A token cannot make more tokens or change the account's login.
    let resp = client
        .post(format!("{api}/auth/tokens"))
        .bearer_auth(&rw)
        .json(&json!({ "name": "child" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let me: Value = client
        .get(format!("{api}/auth/me"))
        .bearer_auth(&ro)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["api_token"], json!(true));
    assert_eq!(me["role"], json!("viewer"));
    // Prometheus scrapes with a read-only token.
    let resp = client
        .get(format!("{api}/metrics/prometheus"))
        .bearer_auth(&ro)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    let text = resp.text().await.unwrap();
    assert!(text.contains("# TYPE daygle_dns_queries_total counter"));
    assert!(text.contains("daygle_dns_zones 1"));
    assert_eq!(
        client
            .get(format!("{api}/metrics/prometheus"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // A made-up token does nothing.
    assert_eq!(status(&client, &api, "dgl_0000").await, 401);

    // The list shows them (never the secret), with use recorded.
    let list: Value = client
        .get(format!("{api}/auth/tokens"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(list
        .iter()
        .all(|t| t.get("token").is_none() && t.get("token_hash").is_none()));
    assert!(list
        .iter()
        .any(|t| t["name"] == json!("deploy") && t["last_used_at"].as_i64().unwrap() > 0));

    // Signing out ends that session only.
    client
        .post(format!("{api}/auth/logout"))
        .bearer_auth(&other)
        .send()
        .await
        .unwrap();
    assert_eq!(status(&client, &api, &other).await, 401);
    shutdown(server).await;

    // After a restart the session and tokens still work; the signed-out
    // session stays signed out.
    let server = spawn(config()).await;
    let api = format!("http://{}/api", server.api_addr);
    assert_eq!(status(&client, &api, &session).await, 200);
    assert_eq!(status(&client, &api, &other).await, 401);
    assert_eq!(status(&client, &api, &rw).await, 200);

    // Revoking a token stops it.
    let id = ro_body["id"].as_str().unwrap();
    let resp = client
        .delete(format!("{api}/auth/tokens/{id}"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(status(&client, &api, &ro).await, 401);
    shutdown(server).await;
}
