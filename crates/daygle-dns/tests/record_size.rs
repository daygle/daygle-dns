//! Integration test: a record that cannot be encoded into one DNS message is
//! refused when it is written, instead of failing a zone transfer later.

mod common;

use common::*;
use daygle_dns_authoritative::model::ZoneInput;
use serde_json::{json, Value};

/// `count` quoted strings of `size` characters: TXT RDATA of a known size.
fn txt_rdata(count: usize, size: usize) -> String {
    let string = "x".repeat(size);
    (0..count)
        .map(|_| format!("\"{string}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
async fn a_record_too_large_for_one_dns_message_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let zone_id = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "size.test".to_string(),
            ..Default::default()
        })
        .unwrap()
        .id;

    // 300 strings of 250 characters is about 75 KB of TXT RDATA, past what a
    // single DNS message can carry.
    let resp = client
        .put(format!("{base}/zones/{zone_id}/records"))
        .json(&json!({
            "name": "big",
            "rtype": "TXT",
            "content": txt_rdata(300, 250),
            "ttl": 300,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains("one DNS message"), "{error}");

    // A large TXT that still fits is accepted, so the check is the message
    // limit rather than the size of a reasonable record.
    let resp = client
        .put(format!("{base}/zones/{zone_id}/records"))
        .json(&json!({
            "name": "large",
            "rtype": "TXT",
            "content": txt_rdata(20, 250),
            "ttl": 300,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The refused record was never stored, so nothing answers for it.
    let records: Value = client
        .get(format!("{base}/zones/{zone_id}/records"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = records
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert!(names.iter().any(|n| n.starts_with("large")), "{names:?}");
    assert!(!names.iter().any(|n| n.starts_with("big")), "{names:?}");

    shutdown(server).await;
}
