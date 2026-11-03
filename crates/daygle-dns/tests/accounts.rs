//! Integration test: DNS accounts. A device that reaches DoT as
//! `<client id>.<accounts.domain>` (or DoH at `/dns-query/<client id>`) is
//! recognised as its account: filtering groups that name the account apply
//! to it wherever it connects from, the query log names it, and with
//! `accounts.require` encrypted queries without a known account are refused.

mod common;

use std::path::Path;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{json, Value};

/// A certificate for `acct.test` and `*.acct.test`, written to `dir`.
fn wildcard_certificate(dir: &Path) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["acct.test".to_string(), "*.acct.test".to_string()])
            .unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = dir.join("wildcard.crt");
    let key_path = dir.join("wildcard.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

async fn api(server: &daygle_dns::BoundServer, method: &str, path: &str, body: Value) -> Value {
    let url = format!("http://{}/api{path}", server.api_addr);
    let client = reqwest::Client::new();
    let request = match method {
        "POST" => client.post(&url).json(&body),
        "PUT" => client.put(&url).json(&body),
        _ => client.get(&url),
    };
    let resp = request.send().await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(status.is_success(), "{method} {path}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

#[tokio::test]
async fn accounts_are_recognised_filtered_logged_and_required() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = wildcard_certificate(dir.path());
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    for (enabled, cert_path, key_path) in [
        (
            &mut config.dot.enabled,
            &mut config.dot.cert_path,
            &mut config.dot.key_path,
        ),
        (
            &mut config.doh.enabled,
            &mut config.doh.cert_path,
            &mut config.doh.key_path,
        ),
    ] {
        *enabled = true;
        *cert_path = cert.clone();
        *key_path = key.clone();
    }
    config.dot.self_signed = false;
    config.doh.self_signed = false;
    config.accounts.domain = "acct.test".to_string();
    let server = spawn(config).await;

    // games.test resolves (it is hosted here) unless a group blocks it.
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "games.test".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "@".into(),
                rtype: "A".into(),
                content: "192.0.2.80".into(),
                ttl: 60,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    // An account, and a group that blocks games.test for it only.
    let kid = api(
        &server,
        "POST",
        "/accounts",
        json!({ "name": "Kid", "client_id": "kid1" }),
    )
    .await;
    assert_eq!(kid["hostname"], "kid1.acct.test");
    assert_eq!(kid["doh_path"], "/dns-query/kid1");
    api(
        &server,
        "POST",
        "/policy/blocking",
        json!({ "name": "Kids", "clients": ["account:kid"], "block": ["games.test"] }),
    )
    .await;

    let dot = server.dot_addr.unwrap();
    let cert_path = Path::new(&cert);
    let ask = |sni: &'static str| async move {
        dot_query(dot, sni, cert_path, "games.test.", RecordType::A).await
    };
    // As the account (from anywhere): blocked. Without it: answered.
    assert_eq!(
        ask("kid1.acct.test").await.response_code,
        ResponseCode::NXDomain
    );
    let anonymous = ask("acct.test").await;
    assert_eq!(first_answer(&anonymous).as_deref(), Some("192.0.2.80"));
    let unknown = ask("nobody.acct.test").await;
    assert_eq!(first_answer(&unknown).as_deref(), Some("192.0.2.80"));

    // DoH: the client ID in the URL path.
    let doh = server.doh_addr.unwrap();
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("games.test.").unwrap(),
        RecordType::A,
    ));
    let https = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // lgtm
        .build()
        .unwrap();
    let doh_ask = |path: &'static str| {
        let https = https.clone();
        let body = query.to_vec().unwrap();
        async move {
            let resp = https
                .post(format!("https://{doh}{path}")) // lgtm
                .header("Content-Type", "application/dns-message")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            Message::from_vec(&resp.bytes().await.unwrap()).unwrap()
        }
    };
    assert_eq!(
        doh_ask("/dns-query/kid1").await.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        doh_ask("/dns-query").await.response_code,
        ResponseCode::NoError
    );

    // The query log names the account (the writer batches: poll).
    let mut logged = Value::Null;
    for _ in 0..100 {
        logged = api(&server, "GET", "/querylogs?account=Kid", Value::Null).await;
        if logged["total"].as_u64().unwrap_or(0) >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let entries = logged["entries"].as_array().unwrap();
    assert!(entries.len() >= 2, "{logged}");
    assert!(entries.iter().all(|e| e["account"] == "Kid"), "{logged}");

    // The account was seen.
    let mut seen = false;
    for _ in 0..100 {
        let list = api(&server, "GET", "/accounts", Value::Null).await;
        if list["accounts"][0]["last_seen_at"].is_string() {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(seen, "last_seen_at was never set");

    // The blocking tester evaluates as an account when told to.
    let as_kid = api(
        &server,
        "POST",
        "/policy/blocking/test",
        json!({ "client": "203.0.113.9", "domain": "games.test", "account": "kid" }),
    )
    .await;
    assert_eq!(as_kid["blocked"], true, "{as_kid}");
    let as_nobody = api(
        &server,
        "POST",
        "/policy/blocking/test",
        json!({ "client": "203.0.113.9", "domain": "games.test" }),
    )
    .await;
    assert_eq!(as_nobody["blocked"], false, "{as_nobody}");

    // Required: no account, or an unknown or disabled one, is refused.
    api(
        &server,
        "PUT",
        "/config",
        json!({ "accounts": { "domain": "acct.test", "require": true } }),
    )
    .await;
    assert_eq!(ask("acct.test").await.response_code, ResponseCode::Refused);
    assert_eq!(
        ask("nobody.acct.test").await.response_code,
        ResponseCode::Refused
    );
    assert_eq!(
        ask("kid1.acct.test").await.response_code,
        ResponseCode::NXDomain
    );
    let id = kid["id"].as_str().unwrap();
    api(
        &server,
        "PUT",
        &format!("/accounts/{id}"),
        json!({ "name": "Kid", "enabled": false }),
    )
    .await;
    assert_eq!(
        ask("kid1.acct.test").await.response_code,
        ResponseCode::Refused
    );
    // Plain DNS cannot carry an account and is not affected.
    let plain = udp_query(server.udp_addr.unwrap(), "games.test.", RecordType::A).await;
    assert_eq!(first_answer(&plain).as_deref(), Some("192.0.2.80"));

    shutdown(server).await;
}
