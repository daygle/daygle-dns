//! Integration test: authoritative responses over UDP and TCP, plus policy
//! blocking.

mod common;

use common::*;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use daygle_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn config_with_zone(db: &std::path::Path, upstream: Option<String>) -> DaygleConfig {
    let mut cfg = base_config(db);
    if let Some(up) = upstream {
        cfg.recursive.enabled = true;
        cfg.recursive.use_system_config = false;
        cfg.recursive.upstreams = vec![up];
        cfg.recursive.dnssec_validate = false;
    }
    cfg
}

#[tokio::test]
async fn serves_authoritative_a_record_over_udp() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let config = config_with_zone(&db, None);

    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "example.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.42".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;

    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.42"));
    assert_eq!(server.metrics.snapshot().authoritative, 1);

    shutdown(server).await;
}

#[tokio::test]
async fn serves_authoritative_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let server = spawn(config_with_zone(&db, None)).await;

    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tcp.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "AAAA".to_string(),
                content: "2001:db8::1".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let tcp = server.tcp_addr.expect("TCP is enabled");
    let msg = tcp_query(tcp, "host.tcp.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("2001:db8::1"));

    shutdown(server).await;
}

#[tokio::test]
async fn policy_blocklist_returns_nxdomain() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let mut config = base_config(&db);
    config.policy.blocklist = vec!["*.ads.example".to_string()];

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "banner.ads.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    assert_eq!(server.metrics.snapshot().blocked, 1);

    // Unmatched names still get a normal (REFUSED, no recursion) response.
    let ok = udp_query(udp, "example.com.", RecordType::A).await;
    assert_eq!(ok.response_code, ResponseCode::Refused);

    shutdown(server).await;
}
