//! Integration test: AUTOPTR records make up PTR answers for addresses in a
//! reverse zone that have no PTR record of their own, for IPv4 and IPv6,
//! and are refused where they cannot work.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn record(name: &str, rtype: &str, content: &str, ttl: u32) -> RecordInput {
    RecordInput {
        name: name.into(),
        rtype: rtype.into(),
        content: content.into(),
        ttl,
        priority: 0,
        disabled: false,
    }
}

#[tokio::test]
async fn auto_ptr_answers_addresses_without_a_ptr() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.authoritative.dnssec_enabled = true;
    let server = spawn(cfg).await;
    let udp = server.udp_addr.unwrap();
    let store = server.catalog.store();

    let v4 = store
        .create_zone(&ZoneInput {
            name: "168.192.in-addr.arpa".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(&v4.id, &record("@", "AUTOPTR", "ip-{ip}.home.arpa", 300))
        .unwrap();
    // A sub-range with its own template, and a host with a real PTR.
    store
        .upsert_record(&v4.id, &record("5", "AUTOPTR", "Guest-{ip}.home.arpa.", 60))
        .unwrap();
    store
        .upsert_record(&v4.id, &record("1.1", "PTR", "router.home.arpa.", 3600))
        .unwrap();
    let v6 = store
        .create_zone(&ZoneInput {
            name: "8.b.d.0.1.0.0.2.ip6.arpa".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(&v6.id, &record("@", "AUTOPTR", "{ip}.v6.home.arpa", 120))
        .unwrap();
    server.catalog.reload().unwrap();

    let ptr = |msg: &hickory_proto::op::Message| -> Vec<(u32, String)> {
        msg.answers
            .iter()
            .map(|r| (r.ttl, r.data.to_string()))
            .collect()
    };

    let msg = udp_query(udp, "47.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.authoritative);
    assert_eq!(ptr(&msg), [(300, "ip-192-168-1-47.home.arpa.".to_string())]);

    let msg = udp_query(udp, "9.5.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(
        ptr(&msg),
        [(60, "guest-192-168-5-9.home.arpa.".to_string())]
    );

    // A real PTR record wins.
    let msg = udp_query(udp, "1.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(ptr(&msg), [(3600, "router.home.arpa.".to_string())]);

    // Names that are not a single address are left to the zone.
    let msg = udp_query(udp, "1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert!(msg.answers.is_empty());

    let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
    let msg = udp_query(udp, name, RecordType::PTR).await;
    assert_eq!(
        ptr(&msg),
        [(120, "2001-db8-0-0-0-0-0-1.v6.home.arpa.".to_string())]
    );

    // AUTOPTR records belong in reverse zones and need {ip}; one per name.
    let forward = store
        .create_zone(&ZoneInput {
            name: "home.arpa.test".into(),
            ..Default::default()
        })
        .unwrap();
    let err = store
        .upsert_record(&forward.id, &record("@", "AUTOPTR", "ip-{ip}.lan", 60))
        .unwrap_err()
        .to_string();
    assert!(err.contains("reverse zone"), "{err}");
    let err = store
        .upsert_record(&v4.id, &record("7", "AUTOPTR", "host.lan", 60))
        .unwrap_err()
        .to_string();
    assert!(err.contains("{ip}"), "{err}");
    let err = store
        .upsert_record(&v4.id, &record("@", "AUTOPTR", "other-{ip}.lan", 60))
        .unwrap_err()
        .to_string();
    assert!(err.contains("already has an AUTOPTR"), "{err}");
    let err = store
        .upsert_record(&v4.id, &record("8", "AUTOPTR", "-{ip}.lan", 60))
        .unwrap_err()
        .to_string();
    assert!(err.contains("host name"), "{err}");

    // The made-up answers cannot be signed.
    let err = server.catalog.sign_zone(&v4.id).unwrap_err().to_string();
    assert!(err.contains("AUTOPTR"), "{err}");

    // Not part of zone transfers.
    let export = store.export_zone_file(&v4.id).unwrap();
    assert!(export.contains("AUTOPTR"), "kept in exports: {export}");
    let (_, transferred) = server
        .catalog
        .transfer_records("168.192.in-addr.arpa")
        .unwrap()
        .unwrap();
    assert_eq!(
        transferred
            .iter()
            .filter(|r| r.record_type() == RecordType::PTR)
            .count(),
        1
    );
    shutdown(server).await;
}
