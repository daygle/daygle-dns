//! Integration tests: AXFR/IXFR zone transfer serving and secondary zone
//! replication from a master.

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_authoritative::XfrClient;
use daygle_dns_core::config::{DaygleConfig, SecondaryZoneConfig};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A minimal TCP client that sends a raw DNS query with a length prefix and
/// reads a single response message (used to assert transfer responses).
async fn tcp_transfer_query(addr: std::net::SocketAddr, name: &str, rtype: RecordType) -> Message {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect TCP");
    let mut msg = Message::new(0x2222, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_utf8(name).expect("valid name"), rtype));
    let bytes = msg.to_vec().expect("encode query");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.expect("write query");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.expect("read body");
    Message::from_vec(&resp).expect("decode response")
}

fn config_with_axfr(db: &std::path::Path, axfr: bool, networks: Vec<String>) -> DaygleConfig {
    let mut cfg = base_config(db);
    cfg.authoritative.axfr_enabled = axfr;
    cfg.authoritative.axfr_networks = networks;
    cfg
}

/// Seed a zone with an A and an MX record on a bound server.
async fn seed_zone(server: &daygle_dns::BoundServer, name: &str) -> String {
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: name.to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.10".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "@".to_string(),
                rtype: "MX".to_string(),
                content: "10 mail.example.test.".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    zone.id
}

#[tokio::test]
async fn axfr_serves_full_zone_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_axfr(&db, true, vec![])).await;
    seed_zone(&server, "example.test").await;

    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_transfer_query(tcp, "example.test.", RecordType::AXFR).await;

    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert!(resp.authoritative);
    // First and last answers are the SOA; the zone data is in between.
    assert!(
        resp.answers.len() >= 3,
        "expected SOA + records + SOA, got {}",
        resp.answers.len()
    );
    assert_eq!(resp.answers.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(resp.answers.last().unwrap().record_type(), RecordType::SOA);

    let rdatas: Vec<String> = resp.answers.iter().map(|r| r.data.to_string()).collect();
    assert!(rdatas.iter().any(|d| d == "192.0.2.10"), "missing A record");
    assert!(
        rdatas.iter().any(|d| d.starts_with("10 mail.example.test")),
        "missing MX record"
    );

    shutdown(server).await;
}

#[tokio::test]
async fn ixfr_returns_full_zone() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_axfr(&db, true, vec![])).await;
    seed_zone(&server, "ixfr.test").await;

    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_transfer_query(tcp, "ixfr.test.", RecordType::IXFR).await;

    // IXFR answered with a full transfer (always valid per RFC 1995).
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert!(resp.answers.len() >= 3);
    assert_eq!(resp.answers.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(resp.answers.last().unwrap().record_type(), RecordType::SOA);

    shutdown(server).await;
}

#[tokio::test]
async fn axfr_refused_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_axfr(&db, false, vec![])).await;
    seed_zone(&server, "locked.test").await;

    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_transfer_query(tcp, "locked.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

#[tokio::test]
async fn axfr_acl_restricts_clients() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // Only 10.0.0.0/8 may transfer; 127.0.0.1 must be refused.
    let server = spawn(config_with_axfr(&db, true, vec!["10.0.0.0/8".to_string()])).await;
    seed_zone(&server, "acl.test").await;

    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_transfer_query(tcp, "acl.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

/// End-to-end secondary replication: a master serves AXFR; a secondary pulls
/// the zone, serves it, then picks up a change.
#[tokio::test]
async fn secondary_replicates_zone_from_master() {
    let dir = tempfile::tempdir().unwrap();

    // Master: hosts example.test with AXFR enabled, plaintext TCP on.
    let master_db = dir.path().join("master.db");
    let master = spawn(config_with_axfr(&master_db, true, vec![])).await;
    seed_zone(&master, "repl.test").await;
    let master_tcp = master.tcp_addr.expect("master TCP enabled");

    // Secondary: replicates repl.test from the master every second.
    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.secondary_zones = vec![SecondaryZoneConfig {
        name: "repl.test".to_string(),
        masters: vec![master_tcp.to_string()],
        refresh_secs: 1,
        enabled: true,
        tsig_key: String::new(),
    }];
    let secondary = spawn(config).await;

    // The refresher runs immediately on startup; poll until the secondary
    // serves the A record pulled from the master.
    let udp = secondary.udp_addr.expect("secondary UDP enabled");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut answer = None;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "www.repl.test.", RecordType::A).await;
        if msg.response_code == ResponseCode::NoError {
            answer = first_answer(&msg);
            if answer.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(answer.as_deref(), Some("192.0.2.10"));

    // Change the master: add a TXT record (single-chunk value so the
    // transferred content round-trips exactly) and bump the serial.
    let store = master.catalog.store();
    let zone = store.find_zone_by_name("repl.test").unwrap().unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "TXT".to_string(),
                content: "\"hello-from-master\"".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    store.bump_serial(&zone.id).unwrap();
    master.catalog.reload().unwrap();

    // The secondary should pick up the TXT within a refresh interval.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut saw_txt = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "www.repl.test.", RecordType::TXT).await;
        if let Some(txt) = first_answer(&msg) {
            if txt == "hello-from-master" {
                saw_txt = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(saw_txt, "secondary did not pick up the master's update");

    shutdown(secondary).await;
    shutdown(master).await;
}

/// The transfer client used directly against a running master.
#[tokio::test]
async fn xfr_client_transfers_zone() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_axfr(&db, true, vec![])).await;
    seed_zone(&server, "client.test").await;

    let tcp = server.tcp_addr.expect("TCP enabled");
    let client = XfrClient::new(Duration::from_secs(5));

    let zone: Name = "client.test.".parse().unwrap();
    let soa = client.query_soa(tcp, &zone).await.expect("SOA query");
    assert!(soa.is_some(), "master should answer SOA");

    let records = client.axfr(tcp, &zone).await.expect("AXFR");
    assert!(records.len() >= 3, "full zone expected, got {}", records.len());
    assert_eq!(records.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(records.last().unwrap().record_type(), RecordType::SOA);
    assert!(
        records
            .iter()
            .any(|r| r.data.to_string() == "192.0.2.10"),
        "A record missing from transfer"
    );

    shutdown(server).await;
}
