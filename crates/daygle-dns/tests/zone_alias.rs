//! Integration test: zone aliases. A zone's records answer under each of
//! its aliases (owner names moved into the alias, data unchanged), with
//! NXDOMAIN and NODATA as in the zone, and aliases cannot clash with hosted
//! zones or with each other.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use serde_json::{json, Value};

fn record(name: &str, rtype: &str, content: &str) -> RecordInput {
    RecordInput {
        name: name.into(),
        rtype: rtype.into(),
        content: content.into(),
        ttl: 300,
        priority: 0,
        disabled: false,
    }
}

async fn put_aliases(api: &str, zone: &str, aliases: &[&str]) -> (reqwest::StatusCode, Value) {
    let response = reqwest::Client::new()
        .put(format!("{api}/zones/{zone}/aliases"))
        .json(&json!({ "aliases": aliases }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn zones_answer_under_their_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let api = format!("http://{}/api", server.api_addr);
    let udp = server.udp_addr.unwrap();
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "brand.test".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.10"))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("@", "MX", "10 mail.brand.test."))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("shop", "CNAME", "www.brand.test."))
        .unwrap();
    let other = store
        .create_zone(&ZoneInput {
            name: "other.test".into(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();

    // Not served before it is set up.
    let msg = udp_query(udp, "www.brand-alias.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    let (status, body) = put_aliases(&api, &zone.id, &["Brand-Alias.test.", "brand.example"]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body[0]["name"], "brand-alias.test");
    assert_eq!(body[1]["name"], "brand.example");

    let msg = udp_query(udp, "www.brand-alias.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.authoritative);
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].name.to_ascii(), "www.brand-alias.test.");
    assert_eq!(msg.answers[0].data.to_string(), "192.0.2.10");

    // Apex records, with the data unchanged.
    let msg = udp_query(udp, "brand.example.", RecordType::MX).await;
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].data.to_string(), "10 mail.brand.test.");
    // The SOA is the alias's own.
    let msg = udp_query(udp, "brand.example.", RecordType::SOA).await;
    assert_eq!(msg.answers[0].name.to_ascii(), "brand.example.");

    // NXDOMAIN and NODATA as in the zone.
    let msg = udp_query(udp, "nope.brand-alias.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    let msg = udp_query(udp, "www.brand-alias.test.", RecordType::TXT).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());

    // A change to the zone shows under the alias.
    store
        .upsert_record(&zone.id, &record("api", "A", "192.0.2.20"))
        .unwrap();
    server.catalog.reload().unwrap();
    let msg = udp_query(udp, "api.brand.example.", RecordType::A).await;
    assert_eq!(msg.answers[0].data.to_string(), "192.0.2.20");

    // Clashes are refused.
    let (status, _) = put_aliases(&api, &zone.id, &["other.test"]).await;
    assert_eq!(status, 409, "a hosted zone");
    let (status, _) = put_aliases(&api, &other.id, &["brand.example"]).await;
    assert_eq!(status, 409, "another zone's alias");
    let (status, _) = put_aliases(&api, &zone.id, &["sub.brand.test"]).await;
    assert_eq!(status, 400, "inside the zone");
    let (status, _) = put_aliases(&api, &zone.id, &["test"]).await;
    assert_eq!(status, 400, "above the zone");
    let (status, _) = put_aliases(&api, &zone.id, &["1.168.192.in-addr.arpa"]).await;
    assert_eq!(status, 400, "a reverse zone");
    let err = store
        .create_zone(&ZoneInput {
            name: "brand.example".into(),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("alias"), "{err}");

    let aliases: Value = reqwest::get(format!("{api}/zone-aliases"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(aliases.as_array().unwrap().len(), 2);
    assert_eq!(aliases[0]["zone_id"], zone.id.as_str());

    // Removing an alias stops it being served; deleting the zone removes
    // the rest.
    let (status, _) = put_aliases(&api, &zone.id, &["brand.example"]).await;
    assert_eq!(status, 200);
    let msg = udp_query(udp, "www.brand-alias.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);
    assert!(store.delete_zone(&zone.id).unwrap());
    server.catalog.reload().unwrap();
    assert!(store.list_zone_aliases().unwrap().is_empty());
    let msg = udp_query(udp, "www.brand.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);
    shutdown(server).await;
}
