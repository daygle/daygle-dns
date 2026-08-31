//! Integration test: split-horizon synthetic answers over UDP.
//!
//! Split-horizon runs after policy but before the authoritative catalog, so
//! internal clients see internal addresses even for hosted zones. Test
//! clients always originate from loopback (127.0.0.1), so a network covering
//! 127.0.0.0/8 stands in for the "internal" side.

mod common;

use common::*;
use daygle_dns_authoritative::model::{
    MoveDirection, RecordInput, SplitHorizonEntryInput, SplitHorizonNetworkInput,
    SplitHorizonRecord, ZoneInput,
};
use daygle_dns_authoritative::store::MoveResult;
use daygle_dns_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn config_with_zone(db: &std::path::Path) -> DaygleConfig {
    base_config(db)
}

fn zone_with_www(store: &daygle_dns_authoritative::ZoneStore, zone_name: &str, ip: &str) {
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
    let db = dir.path().join("daygle-dns.db");
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
            records: vec![],
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
            records: vec![],
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
    let db = dir.path().join("daygle-dns.db");
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
            records: vec![],
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
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "intranet.example.com".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.5".to_string(), "fd00::5".to_string()],
            records: vec![],
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
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    zone_with_www(store, "example.test", "192.0.2.42");
    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.5".to_string()],
            records: vec![],
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

#[tokio::test]
async fn reorder_changes_which_view_wins() {
    // Two entries for the same domain: an all-clients fallback created first
    // and an internal view behind it. Until the internal view is moved up,
    // the fallback answers everyone (including the loopback client); after
    // the move the loopback client gets the internal address.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    store
        .upsert_split_horizon_network(&SplitHorizonNetworkInput {
            name: "LAN".to_string(),
            cidrs: vec!["127.0.0.0/8".to_string()],
        })
        .unwrap();
    let public = store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec![],
            ips: vec!["203.0.113.1".to_string()],
            records: vec![],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    let internal = store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "www.example.test".to_string(),
            networks: vec!["LAN".to_string()],
            ips: vec!["10.0.0.5".to_string()],
            records: vec![],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.expect("UDP is enabled");

    // Fallback is first: the loopback client (in LAN) still gets the public
    // address because the catch-all matches first.
    let before = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&before).as_deref(), Some("203.0.113.1"));

    // Move the internal view to the front of its domain and reload.
    assert_eq!(
        store
            .move_split_horizon_entry(&internal.id, MoveDirection::Up)
            .unwrap(),
        MoveResult::Moved
    );
    server.catalog.reload().unwrap();

    let after = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&after).as_deref(), Some("10.0.0.5"));

    // The fallback is now last, so moving it back up restores the original
    // behaviour: the catch-all answers first again.
    assert_eq!(
        store
            .move_split_horizon_entry(&public.id, MoveDirection::Up)
            .unwrap(),
        MoveResult::Moved
    );
    server.catalog.reload().unwrap();
    let restored = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&restored).as_deref(), Some("203.0.113.1"));

    shutdown(server).await;
}

#[tokio::test]
async fn split_horizon_serves_mx_txt_srv_records() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "mail.example.test".to_string(),
            networks: vec![],
            ips: vec![],
            records: vec![
                SplitHorizonRecord {
                    rtype: "MX".to_string(),
                    content: "10 mailhost.example.test.".to_string(),
                },
                SplitHorizonRecord {
                    rtype: "TXT".to_string(),
                    content: "\"v=spf1 -all\"".to_string(),
                },
                SplitHorizonRecord {
                    rtype: "SRV".to_string(),
                    content: "0 5 5060 sip.example.test.".to_string(),
                },
            ],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.expect("UDP is enabled");

    let mx = udp_query(udp, "mail.example.test.", RecordType::MX).await;
    assert_eq!(mx.response_code, ResponseCode::NoError);
    assert_eq!(mx.answers.len(), 1);
    assert_eq!(mx.answers[0].record_type(), RecordType::MX);
    assert!(mx.answers[0].data.to_string().contains("10 mailhost.example.test"));

    let txt = udp_query(udp, "mail.example.test.", RecordType::TXT).await;
    assert_eq!(txt.answers.len(), 1);
    assert_eq!(txt.answers[0].record_type(), RecordType::TXT);
    assert!(txt.answers[0].data.to_string().contains("v=spf1 -all"));

    let srv = udp_query(udp, "mail.example.test.", RecordType::SRV).await;
    assert_eq!(srv.answers.len(), 1);
    assert_eq!(srv.answers[0].record_type(), RecordType::SRV);
    assert!(srv.answers[0].data.to_string().contains("5060"));

    // The entry has no A record: an A query falls through (REFUSED, since
    // recursion is off) instead of getting a bogus answer.
    let a = udp_query(udp, "mail.example.test.", RecordType::A).await;
    assert_eq!(a.response_code, ResponseCode::Refused);
    assert!(a.answers.is_empty());

    assert_eq!(server.metrics.snapshot().split_horizon, 3);

    shutdown(server).await;
}

#[tokio::test]
async fn split_horizon_cname_answers_all_types() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db)).await;
    let store = server.catalog.store();

    store
        .create_split_horizon_entry(&SplitHorizonEntryInput {
            domain: "alias.example.test".to_string(),
            networks: vec![],
            ips: vec![],
            records: vec![SplitHorizonRecord {
                rtype: "CNAME".to_string(),
                content: "target.example.test.".to_string(),
            }],
            ttl: 60,
            disabled: false,
        })
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.expect("UDP is enabled");

    // An A query at a CNAME name gets the CNAME record (RFC 1034 §3.6.2).
    let a = udp_query(udp, "alias.example.test.", RecordType::A).await;
    assert_eq!(a.response_code, ResponseCode::NoError);
    assert_eq!(a.answers.len(), 1);
    assert_eq!(a.answers[0].record_type(), RecordType::CNAME);
    assert!(a.answers[0].data.to_string().contains("target.example.test"));

    let cname = udp_query(udp, "alias.example.test.", RecordType::CNAME).await;
    assert_eq!(cname.answers.len(), 1);
    assert_eq!(cname.answers[0].record_type(), RecordType::CNAME);

    assert_eq!(server.metrics.snapshot().split_horizon, 2);

    shutdown(server).await;
}
