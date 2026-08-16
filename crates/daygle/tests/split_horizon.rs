//! Integration test: split-horizon synthetic answers over UDP.
//!
//! Split-horizon runs after policy but before the authoritative catalog, so
//! internal clients see internal addresses even for hosted zones. Test
//! clients always originate from loopback (127.0.0.1), so a network covering
//! 127.0.0.0/8 stands in for the "internal" side.

mod common;

use common::*;
use daygle_authoritative::model::{
    RecordInput, SplitHorizonEntryInput, SplitHorizonNetworkInput, ZoneInput,
};
use daygle_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn config_with_zone(db: &std::path::Path) -> DaygleConfig {
    base_config(db)
}

fn zone_with_www(store: &daygle_authoritative::ZoneStore, zone_name: &str, ip: &str) {
    let zone = store
        .create_zone(&ZoneInput {
            name: zone_name.to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: ip.to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
}

#[tokio::test]
async fn matching_client_gets_synthetic_answer_over_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    // Hosted zone: www.example.test -> 192.0.2.42 (public view).
    zone_with_www(store, "example.test", "192.0.2.42");

    // Split horizon: clients on the loopback network see 10.0.0.5 instead.
    store
        .upsert_split_horizon_network(&SplitHorizonNetworkInput {
            name: "LAN".to_string(),
            cidrs: vec!["127.0.0.0/8".to_string()],
        })
        .unwrap();
    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec!["LAN".to_string()],
            ips: vec!["10.0.0.5".to_string()],
            ttl: 30,
            disabled: false,
        })
        .unwrap();
    // A catch-all for a *different* domain must not affect example.test.
    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "other.example.test".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.9".to_string()],
            ttl: 30,
            disabled: false,
        })
        .unwrap();

    server.catalog.reload().unwrap();
    let udp = server.udp_addr.expect("UDP is enabled");

    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("10.0.0.5"));
    assert_eq!(server.metrics.snapshot().split_horizon, 1);

    shutdown(server).await;
}

#[tokio::test]
async fn non_matching_client_falls_through_to_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    zone_with_www(store, "example.test", "192.0.2.42");

    // The VPN network does not contain the loopback test client.
    store
        .upsert_split_horizon_network(&SplitHorizonNetworkInput {
            name: "VPN".to_string(),
            cidrs: vec!["10.8.0.0/24".to_string()],
        })
        .unwrap();
    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec!["VPN".to_string()],
            ips: vec!["10.0.0.5".to_string()],
            ttl: 30,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;

    // Not on the VPN: the authoritative answer is served untouched.
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.42"));
    assert_eq!(server.metrics.snapshot().split_horizon, 0);

    shutdown(server).await;
}

#[tokio::test]
async fn catch_all_entry_serves_both_families() {
    // An entry with no networks matches every client. Recursion is disabled,
    // so without the catch-all these queries would be REFUSED; with it the
    // synthetic answers come back.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "intranet.example.com".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.5".to_string(), "fd00::5".to_string()],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");

    let a = udp_query(udp, "intranet.example.com.", RecordType::A).await;
    assert_eq!(a.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&a).as_deref(), Some("10.0.0.5"));

    let aaaa = udp_query(udp, "intranet.example.com.", RecordType::AAAA).await;
    assert_eq!(aaaa.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&aaaa).as_deref(), Some("fd00::5"));

    assert_eq!(server.metrics.snapshot().split_horizon, 2);

    shutdown(server).await;
}

#[tokio::test]
async fn ipv4_only_entry_does_not_swallow_aaaa_queries() {
    // An IPv4-only entry must fall through (to authoritative here) for AAAA
    // queries rather than answering NODATA/NXDOMAIN.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    zone_with_www(store, "example.test", "192.0.2.42");
    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.5".to_string()],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");

    let a = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&a).as_deref(), Some("10.0.0.5"));

    let aaaa = udp_query(udp, "www.example.test.", RecordType::AAAA).await;
    assert_eq!(aaaa.response_code, ResponseCode::NoError);
    // No AAAA record exists in the zone; authoritative answers NoError/NODATA.
    assert!(aaaa.answers.is_empty());
    assert_eq!(server.metrics.snapshot().split_horizon, 1);

    shutdown(server).await;
}
