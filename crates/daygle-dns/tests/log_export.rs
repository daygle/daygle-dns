//! Integration test: with `[log_export]` turned on in Settings, answered
//! queries are POSTed as JSON (NDJSON or an array) to an HTTP endpoint,
//! with the configured Authorization header, which the API never shows.

mod common;

use std::time::Duration;

use axum::http::HeaderMap;
use common::*;
use hickory_proto::rr::RecordType;
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// One request the collector received: its headers and body.
type Received = (HeaderMap, String);

/// A log collector that accepts every POST and hands it to the test.
async fn collector() -> (String, mpsc::UnboundedReceiver<Received>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/ingest",
        axum::routing::post(move |headers: HeaderMap, body: String| {
            let tx = tx.clone();
            async move {
                let _ = tx.send((headers, body));
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/ingest"), rx)
}

async fn put_export(api: &str, settings: Value) -> reqwest::StatusCode {
    reqwest::Client::new()
        .put(format!("{api}/config"))
        .json(&json!({ "log_export": settings }))
        .send()
        .await
        .unwrap()
        .status()
}

/// The exported queries, from requests received within a few seconds,
/// until one names `qname`.
async fn wait_for_query(rx: &mut mpsc::UnboundedReceiver<Received>, qname: &str) -> Received {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let got = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("no export arrived in time")
            .expect("collector stopped");
        if got.1.contains(qname) {
            return got;
        }
    }
}

#[tokio::test]
async fn queries_are_exported_to_an_http_endpoint() {
    let (url, mut rx) = collector().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let api = format!("http://{}/api", server.api_addr);
    let udp = server.udp_addr.unwrap();

    // Bad settings are refused.
    assert_eq!(
        put_export(&api, json!({ "enabled": true, "url": "" })).await,
        400
    );
    assert_eq!(
        put_export(&api, json!({ "enabled": true, "url": "ftp://x.example" })).await,
        400
    );
    assert_eq!(
        put_export(
            &api,
            json!({ "enabled": true, "url": url, "format": "xml" })
        )
        .await,
        400
    );

    // NDJSON, with an Authorization header.
    assert_eq!(
        put_export(
            &api,
            json!({
                "enabled": true,
                "url": url,
                "authorization": "Bearer s3cret",
                "flush_secs": 1,
            })
        )
        .await,
        200
    );
    // The secret is never shown, and saving the placeholder keeps it.
    let config: Value = reqwest::get(format!("{api}/config"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["log_export"]["authorization"], "[redacted]");
    assert_eq!(
        put_export(
            &api,
            json!({
                "enabled": true,
                "url": url,
                "authorization": "[redacted]",
                "flush_secs": 1,
            })
        )
        .await,
        200
    );

    udp_query(udp, "exported-one.example.", RecordType::A).await;
    let (headers, body) = wait_for_query(&mut rx, "exported-one.example").await;
    assert_eq!(headers["authorization"], "Bearer s3cret");
    assert_eq!(headers["content-type"], "application/x-ndjson");
    let line = body
        .lines()
        .find(|l| l.contains("exported-one.example"))
        .unwrap();
    let event: Value = serde_json::from_str(line).unwrap();
    assert_eq!(event["client"], "127.0.0.1");
    assert_eq!(event["qtype"], "A");
    assert_eq!(event["protocol"], "udp");
    assert_eq!(event["rcode"], "REFUSED");
    assert!(event["time"].as_str().unwrap().ends_with('Z'));

    // A JSON array, without the header once it is cleared.
    assert_eq!(
        put_export(
            &api,
            json!({ "enabled": true, "url": url, "format": "json", "flush_secs": 1 })
        )
        .await,
        200
    );
    udp_query(udp, "exported-two.example.", RecordType::AAAA).await;
    let (headers, body) = wait_for_query(&mut rx, "exported-two.example").await;
    assert!(headers.get("authorization").is_none());
    assert_eq!(headers["content-type"], "application/json");
    let events: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert!(events.iter().any(|e| e["qtype"] == "AAAA"));

    // The console's test button sends one sample query.
    let response = reqwest::Client::new()
        .post(format!("{api}/log-export/test"))
        .json(&json!({ "log_export": { "url": url, "format": "ndjson" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let (_, body) = wait_for_query(&mut rx, "test.daygle-dns.invalid").await;
    assert!(body.contains("\"outcome\":\"test\""), "{body}");

    let status: Value = reqwest::get(format!("{api}/log-export"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status["sent"].as_u64().unwrap() >= 2, "{status}");
    assert_eq!(status["last_error"], Value::Null);

    // Switched off: nothing more is sent.
    assert_eq!(
        put_export(&api, json!({ "enabled": false, "url": url })).await,
        200
    );
    udp_query(udp, "not-exported.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    while let Ok((_, body)) = rx.try_recv() {
        assert!(!body.contains("not-exported.example"), "{body}");
    }
    shutdown(server).await;
}
