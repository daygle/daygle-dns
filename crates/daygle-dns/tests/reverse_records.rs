//! Integration test: the record API keeps PTR records in step with A and
//! AAAA records (`update_ptr`), creating the reverse zone on request
//! (`create_reverse_zone`).

mod common;

use common::*;
use hickory_proto::rr::RecordType;
use serde_json::{json, Value};

async fn ptr(udp: std::net::SocketAddr, name: &str) -> Option<String> {
    first_answer(&udp_query(udp, name, RecordType::PTR).await)
}

#[tokio::test]
async fn ptr_records_follow_their_address_records() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let udp = server.udp_addr.unwrap();

    let zone: Value = client
        .post(format!("{base}/zones"))
        .json(&json!({"name": "lan.example"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let zone_id = zone["id"].as_str().unwrap().to_string();
    let record =
        |content: &str| json!({"name": "dns", "rtype": "A", "content": content, "ttl": 300});

    // No reverse zone yet: without create_reverse_zone the PTR is skipped.
    let body: Value = client
        .put(format!("{base}/zones/{zone_id}/records?update_ptr=true"))
        .json(&record("192.168.20.5"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        body["reverse"]["problem"]
            .as_str()
            .unwrap()
            .contains("no hosted reverse zone"),
        "{body}"
    );
    let rid = body["id"].as_str().unwrap().to_string();

    // Saving again with create_reverse_zone creates 20.168.192.in-addr.arpa.
    let body: Value = client
        .put(format!(
            "{base}/zones/{zone_id}/records/{rid}?update_ptr=true&create_reverse_zone=true"
        ))
        .json(&record("192.168.20.5"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["reverse"]["zone_created"], "20.168.192.in-addr.arpa",
        "{body}"
    );
    assert_eq!(body["reverse"]["added"][0], "5.20.168.192.in-addr.arpa");
    assert_eq!(
        ptr(udp, "5.20.168.192.in-addr.arpa.").await.as_deref(),
        Some("dns.lan.example.")
    );

    // A new address moves the PTR.
    let body: Value = client
        .put(format!(
            "{base}/zones/{zone_id}/records/{rid}?update_ptr=true"
        ))
        .json(&record("192.168.20.6"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["reverse"]["removed"][0], "5.20.168.192.in-addr.arpa",
        "{body}"
    );
    assert_eq!(body["reverse"]["added"][0], "6.20.168.192.in-addr.arpa");
    assert_eq!(ptr(udp, "5.20.168.192.in-addr.arpa.").await, None);
    assert_eq!(
        ptr(udp, "6.20.168.192.in-addr.arpa.").await.as_deref(),
        Some("dns.lan.example.")
    );

    // Another name on the same address leaves the existing PTR alone.
    let body: Value = client
        .put(format!("{base}/zones/{zone_id}/records?update_ptr=true"))
        .json(&json!({"name": "alias", "rtype": "A", "content": "192.168.20.6", "ttl": 300}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        body["reverse"]["problem"]
            .as_str()
            .unwrap()
            .contains("dns.lan.example"),
        "{body}"
    );
    let alias_id = body["id"].as_str().unwrap().to_string();
    // Deleting that one does not remove the PTR of the other name.
    let resp = client
        .delete(format!(
            "{base}/zones/{zone_id}/records/{alias_id}?update_ptr=true"
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["reverse"]["removed"], json!([]), "{body}");
    assert!(ptr(udp, "6.20.168.192.in-addr.arpa.").await.is_some());

    // Disabling the record takes its PTR away; enabling brings it back.
    let toggle = |disabled: bool| {
        client
            .put(format!(
                "{base}/zones/{zone_id}/records/{rid}/disabled?update_ptr=true"
            ))
            .json(&json!({ "disabled": disabled }))
            .send()
    };
    let body: Value = toggle(true).await.unwrap().json().await.unwrap();
    assert_eq!(
        body["reverse"]["removed"][0], "6.20.168.192.in-addr.arpa",
        "{body}"
    );
    assert_eq!(ptr(udp, "6.20.168.192.in-addr.arpa.").await, None);
    let body: Value = toggle(false).await.unwrap().json().await.unwrap();
    assert_eq!(
        body["reverse"]["added"][0], "6.20.168.192.in-addr.arpa",
        "{body}"
    );
    assert!(ptr(udp, "6.20.168.192.in-addr.arpa.").await.is_some());

    // Deleting the record removes its PTR; without the option it is a 204.
    let body: Value = client
        .delete(format!(
            "{base}/zones/{zone_id}/records/{rid}?update_ptr=true"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["reverse"]["removed"][0], "6.20.168.192.in-addr.arpa",
        "{body}"
    );
    assert_eq!(ptr(udp, "6.20.168.192.in-addr.arpa.").await, None);

    // Without update_ptr, nothing changes (and the response is the record).
    let body: Value = client
        .put(format!("{base}/zones/{zone_id}/records"))
        .json(&record("192.168.20.7"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body.get("reverse").is_none(), "{body}");
    assert_eq!(ptr(udp, "7.20.168.192.in-addr.arpa.").await, None);
    let resp = client
        .delete(format!(
            "{base}/zones/{zone_id}/records/{}",
            body["id"].as_str().unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    shutdown(server).await;
}
