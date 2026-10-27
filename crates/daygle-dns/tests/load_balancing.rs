//! Integration test: weighted A/AAAA records. Each answer holds one of the
//! weighted addresses, picked in proportion to the weights; a weight of 0
//! takes an address out, and signed zones are served whole.

mod common;

use std::collections::HashMap;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use serde_json::json;

fn addresses(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0.to_string()),
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

fn record(name: &str, rtype: &str, content: &str) -> RecordInput {
    RecordInput {
        name: name.into(),
        rtype: rtype.into(),
        content: content.into(),
        ttl: 60,
        priority: 0,
        disabled: false,
    }
}

async fn put_weight(api: &str, zone: &str, record: &str, weight: u32) -> reqwest::StatusCode {
    reqwest::Client::new()
        .put(format!("{api}/zones/{zone}/records/{record}/weight"))
        .json(&json!({ "weight": weight }))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn weighted_records_share_the_answers() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let api = format!("http://{}/api", server.api_addr);
    let udp = server.udp_addr.unwrap();
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "lb.test".into(),
            ..Default::default()
        })
        .unwrap();
    let heavy = store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.1"))
        .unwrap();
    let light = store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.2"))
        .unwrap();
    let drained = store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.3"))
        .unwrap();
    let v6 = store
        .upsert_record(&zone.id, &record("www", "AAAA", "2001:db8::1"))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("www", "AAAA", "2001:db8::2"))
        .unwrap();
    let mx = store
        .upsert_record(&zone.id, &record("@", "MX", "10 mail.lb.test."))
        .unwrap();
    server.catalog.reload().unwrap();

    // No weights: the whole RRset.
    let mut all = addresses(&udp_query(udp, "www.lb.test.", RecordType::A).await);
    all.sort();
    assert_eq!(all, ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);

    assert_eq!(put_weight(&api, &zone.id, &heavy.id, 3).await, 200);
    assert_eq!(put_weight(&api, &zone.id, &light.id, 1).await, 200);
    // Only A and AAAA records take a weight, up to 10000.
    assert_eq!(put_weight(&api, &zone.id, &mx.id, 1).await, 400);
    assert_eq!(put_weight(&api, &zone.id, &heavy.id, 10_001).await, 400);
    assert_eq!(put_weight(&api, &zone.id, "nope", 1).await, 404);
    let weights: HashMap<String, u32> = reqwest::get(format!("{api}/record-weights"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(weights.get(&heavy.id), Some(&3));
    assert_eq!(weights.get(&light.id), Some(&1));
    assert_eq!(weights.get(&drained.id), None);

    // One address per answer, in proportion to the weights; the address
    // without a weight takes no share.
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..400 {
        let got = addresses(&udp_query(udp, "WWW.lb.test.", RecordType::A).await);
        assert_eq!(got.len(), 1, "{got:?}");
        *counts.entry(got[0].clone()).or_default() += 1;
    }
    let heavy_n = counts.get("192.0.2.1").copied().unwrap_or(0);
    let light_n = counts.get("192.0.2.2").copied().unwrap_or(0);
    assert_eq!(counts.get("192.0.2.3"), None, "{counts:?}");
    assert!(light_n > 40 && heavy_n > 2 * light_n, "{counts:?}");

    // The AAAA RRset has no weights: served whole.
    assert_eq!(
        addresses(&udp_query(udp, "www.lb.test.", RecordType::AAAA).await).len(),
        2
    );
    assert_eq!(put_weight(&api, &zone.id, &v6.id, 5).await, 200);
    assert_eq!(
        addresses(&udp_query(udp, "www.lb.test.", RecordType::AAAA).await),
        ["2001:db8::1"]
    );

    // Weight 0 removes it from load balancing.
    assert_eq!(put_weight(&api, &zone.id, &v6.id, 0).await, 200);
    assert_eq!(
        addresses(&udp_query(udp, "www.lb.test.", RecordType::AAAA).await).len(),
        2
    );
    shutdown(server).await;
}

#[tokio::test]
async fn signed_zones_serve_weighted_rrsets_whole() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.authoritative.dnssec_enabled = true;
    let server = spawn(cfg).await;
    let api = format!("http://{}/api", server.api_addr);
    let udp = server.udp_addr.unwrap();
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "signed-lb.test".into(),
            ..Default::default()
        })
        .unwrap();
    let one = store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.1"))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("www", "A", "192.0.2.2"))
        .unwrap();
    assert_eq!(put_weight(&api, &zone.id, &one.id, 1).await, 200);
    server.catalog.sign_zone(&zone.id).unwrap();
    let got = addresses(&udp_query(udp, "www.signed-lb.test.", RecordType::A).await);
    assert_eq!(got.len(), 2, "signed RRsets are not split: {got:?}");
    shutdown(server).await;
}
