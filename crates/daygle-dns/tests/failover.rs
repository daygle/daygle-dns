//! Integration test: health-checked failover records. A failing primary is
//! left out of answers in favour of the backup, and comes back when its
//! check passes again.

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{HealthCheck, RecordInput, ZoneInput};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use serde_json::{json, Value};

fn addresses(msg: &Message) -> Vec<String> {
    let mut out: Vec<String> = msg
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

async fn wait_for(udp: std::net::SocketAddr, want: &[&str]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let got = addresses(&udp_query(udp, "www.failover.test.", RecordType::A).await);
        if got == want {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "still {got:?}, want {want:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn answers_fail_over_to_healthy_records() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let udp = server.udp_addr.unwrap();
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "failover.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    let add = |content: &str, priority: u16| {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "www".to_string(),
                    rtype: "A".to_string(),
                    content: content.to_string(),
                    ttl: 30,
                    priority,
                    disabled: false,
                },
            )
            .unwrap()
    };
    let primary = add("127.0.0.1", 0);
    let backup = add("127.0.0.2", 10);

    // Each address runs the checked service.
    let primary_service = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = primary_service.local_addr().unwrap().port();
    let _backup_service = tokio::net::TcpListener::bind(("127.0.0.2", port))
        .await
        .unwrap();
    for record in [&primary, &backup] {
        store
            .set_health_check(&HealthCheck {
                record_id: record.id.clone(),
                kind: "tcp".to_string(),
                port,
                path: String::new(),
                host: String::new(),
                interval_secs: 1,
            })
            .unwrap();
    }
    server.catalog.reload().unwrap();

    // Both up: only the primary.
    wait_for(udp, &["127.0.0.1"]).await;

    // The primary's service stops: the backup takes over.
    drop(primary_service);
    wait_for(udp, &["127.0.0.2"]).await;

    // The status says why.
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let checks: Value = client
        .get(format!("{api}/health-checks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let primary_status = checks
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["record_id"] == primary.id.as_str())
        .unwrap();
    assert_eq!(primary_status["healthy"], false);
    assert!(primary_status["last_error"]
        .as_str()
        .unwrap()
        .contains("connection"));

    // It comes back: so does the primary.
    let _primary_service = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    wait_for(udp, &["127.0.0.1"]).await;

    // Through the API: bad checks are refused; removing the checks serves
    // both records again.
    let health = |id: &str| format!("{api}/zones/{}/records/{id}/health", zone.id);
    let resp = client
        .put(health(&primary.id))
        .json(&json!({ "kind": "tcp", "port": port, "interval_secs": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = client
        .put(health(&primary.id))
        .json(&json!({ "kind": "http", "port": 80, "path": "health" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let saved: Value = resp.json().await.unwrap();
    assert_eq!(saved["path"], "/health");
    assert_eq!(saved["interval_secs"], 30);
    for id in [&primary.id, &backup.id] {
        let resp = client.delete(health(id)).send().await.unwrap();
        assert_eq!(resp.status(), 204);
    }
    wait_for(udp, &["127.0.0.1", "127.0.0.2"]).await;

    shutdown(server).await;
}
