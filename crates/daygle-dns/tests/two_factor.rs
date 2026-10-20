//! Integration test: two-factor console login with an authenticator app
//! code or a recovery code, and an admin resetting it.

mod common;

use common::*;
use daygle_dns_core::totp;
use serde_json::{json, Value};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn login(client: &reqwest::Client, api: &str, code: &str) -> (u16, Value) {
    let resp = client
        .post(format!("{api}/auth/login"))
        .json(&json!({ "username": "admin", "password": "first-run-secret", "code": code }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn two_factor_login_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.api.auth_required = true;
    let server = spawn(cfg).await;
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{api}/auth/setup"))
        .json(&json!({ "username": "admin", "password": "first-run-secret" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"].as_str().unwrap().to_string();
    let post = |path: &str, body: Value| {
        client
            .post(format!("{api}{path}"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };

    let status: Value = client
        .get(format!("{api}/auth/two-factor"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["enabled"], json!(false));

    // Setting up needs the password; enabling needs a right code.
    let resp = post("/auth/two-factor/setup", json!({ "password": "wrong" }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let setup: Value = post(
        "/auth/two-factor/setup",
        json!({ "password": "first-run-secret" }),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(setup["uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/Daygle+DNS:admin?"));
    // Not on yet: the password alone still signs in.
    assert_eq!(login(&client, &api, "").await.0, 200);
    let resp = post("/auth/two-factor/enable", json!({ "code": "000000" }))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let enabled_at = now();
    let first_code = totp::code_for(&secret, enabled_at).unwrap();
    let enabled: Value = post("/auth/two-factor/enable", json!({ "code": first_code }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let recovery: Vec<String> = serde_json::from_value(enabled["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), totp::RECOVERY_CODES);

    // The password alone now asks for a code; wrong codes are refused.
    let (status, body) = login(&client, &api, "").await;
    assert_eq!(status, 401);
    assert_eq!(body["two_factor"], json!(true));
    assert_eq!(login(&client, &api, "123456").await.0, 401);
    // The code used to turn it on cannot be used again; the next one works,
    // once.
    assert_eq!(login(&client, &api, &first_code).await.0, 401);
    let next = totp::code_for(&secret, enabled_at + totp::STEP_SECS).unwrap();
    assert_eq!(login(&client, &api, &next).await.0, 200);
    assert_eq!(login(&client, &api, &next).await.0, 401);
    // A recovery code works once, written any way.
    let upper = recovery[0].to_uppercase();
    assert_eq!(login(&client, &api, &upper).await.0, 200);
    assert_eq!(login(&client, &api, &recovery[0]).await.0, 401);

    // The admin's user list shows it, and an admin can reset it.
    let users: Value = client
        .get(format!("{api}/users"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == json!("admin"))
        .unwrap();
    assert_eq!(admin["two_factor"], json!(true));
    // A fresh session (the reset signs the account's sessions out).
    let fresh = login(&client, &api, &recovery[1]).await.1["token"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!("{api}/users/admin/two-factor"))
        .bearer_auth(&fresh)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(login(&client, &api, "").await.0, 200);
    shutdown(server).await;
}
