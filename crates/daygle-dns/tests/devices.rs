//! Integration test: device names (by hand, and from reverse DNS) for the
//! clients in the query log.

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::rr::RecordType;

async fn devices(client: &reqwest::Client, base: &str) -> Vec<serde_json::Value> {
    let body: serde_json::Value = client
        .get(format!("{base}/devices?hours=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["devices"].as_array().cloned().unwrap_or_default()
}

fn device<'a>(list: &'a [serde_json::Value], address: &str) -> Option<&'a serde_json::Value> {
    list.iter().find(|d| d["address"] == address)
}

#[tokio::test]
async fn devices_are_named_by_hand_and_from_reverse_dns() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.logging.query_db_enabled = true;
    let server = spawn(config).await;
    let store = server.catalog.store();
    let reverse = store
        .create_zone(&ZoneInput {
            name: "0.0.127.in-addr.arpa".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &reverse.id,
            &RecordInput {
                name: "2".to_string(),
                rtype: "PTR".to_string(),
                content: "printer.home.arpa.".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.unwrap();
    for source in [[127, 0, 0, 1], [127, 0, 0, 2]] {
        udp_query_from(source.into(), udp, "example.test.", RecordType::A).await;
    }
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // The query log is written in the background.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let list = loop {
        let list = devices(&client, &base).await;
        if device(&list, "127.0.0.1").is_some() && device(&list, "127.0.0.2").is_some() {
            break list;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "clients not listed: {list:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let printer = device(&list, "127.0.0.2").unwrap();
    assert_eq!(printer["name"], "printer.home.arpa");
    assert_eq!(printer["source"], "reverse_dns");
    assert_eq!(device(&list, "127.0.0.1").unwrap()["name"], "");

    // A name by hand wins, and can be cleared again.
    let put = |body: serde_json::Value| {
        client
            .put(format!("{base}/devices/name"))
            .json(&body)
            .send()
    };
    let resp = put(serde_json::json!({"address": "127.0.0.2", "name": "Office Printer"}))
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = put(serde_json::json!({"address": "127.0.0.1", "name": " Kids-iPad "}))
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let list = devices(&client, &base).await;
    let printer = device(&list, "127.0.0.2").unwrap();
    assert_eq!(
        (&printer["name"], &printer["source"]),
        (&"Office Printer".into(), &"manual".into())
    );
    assert_eq!(device(&list, "127.0.0.1").unwrap()["name"], "Kids-iPad");

    put(serde_json::json!({"address": "127.0.0.2", "name": ""}))
        .await
        .unwrap();
    let list = devices(&client, &base).await;
    assert_eq!(device(&list, "127.0.0.2").unwrap()["source"], "reverse_dns");

    // Bad input is refused.
    for body in [
        serde_json::json!({"address": "not-an-ip", "name": "x"}),
        serde_json::json!({"address": "127.0.0.1", "mac": "zz", "name": "x"}),
        serde_json::json!({"address": "127.0.0.1", "name": "x".repeat(64)}),
    ] {
        assert_eq!(put(body).await.unwrap().status(), 400);
    }
    shutdown(server).await;
}
