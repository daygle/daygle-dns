//! Integration test: named networks are live links. A setting that names a
//! network (here DNS64's client list) follows the network when it changes,
//! without the setting being edited; a network in use cannot be deleted; an
//! unknown name is refused.

mod common;

use common::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use serde_json::{json, Value};

fn aaaa_answers(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_changed_network_applies_to_every_setting_that_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream(
        &dir.path().join("upstream.db"),
        "v4only.test",
        "198.51.100.9",
    )
    .await;

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // LAN covers the test client (loopback), so DNS64 serves it.
    let resp = client
        .post(format!("{api}/networks"))
        .json(&json!({ "name": "LAN", "cidrs": ["127.0.0.1"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // DNS64 names LAN; the setting itself is never edited again below.
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({
            "dns64": { "enabled": true, "prefix": "2001:db8:64::/96", "clients": ["LAN"] }
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(aaaa_answers(&msg), ["2001:db8:64::c633:6409"]);

    // Move LAN away from the client: DNS64 stops serving it at once.
    let resp = client
        .post(format!("{api}/networks"))
        .json(&json!({ "original_name": "LAN", "name": "LAN", "cidrs": ["10.0.0.0/8"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(aaaa_answers(&msg).is_empty());

    // The setting still names LAN, and LAN is used, so it cannot be deleted.
    let config: Value = client
        .get(format!("{api}/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["dns64"]["clients"], json!(["LAN"]));
    let resp = client
        .delete(format!("{api}/networks/LAN"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["used_by"], json!(["DNS64"]));

    // Moving it back restores the answers.
    let resp = client
        .post(format!("{api}/networks"))
        .json(&json!({ "original_name": "LAN", "name": "LAN", "cidrs": ["127.0.0.0/8"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(aaaa_answers(&msg), ["2001:db8:64::c633:6409"]);

    // A name that is not a network is refused, and nothing changes.
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({
            "dns64": { "enabled": true, "prefix": "2001:db8:64::/96", "clients": ["Office"] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(aaaa_answers(&msg), ["2001:db8:64::c633:6409"]);
}
