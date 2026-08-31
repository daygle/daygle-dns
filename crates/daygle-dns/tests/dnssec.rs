//! Integration tests: DNSSEC maintenance - a signed zone serves its DNSKEY
//! with RRSIGs, and automatic rollover transitions are observable over the
//! wire: two DNSKEYs while double-signing, the old key stays published while
//! retired, then only the new key remains. The zone stays signed throughout.

mod common;

use std::time::Duration;

use common::*;
use daygle_core::config::DaygleConfig;
use daygle_authoritative::DnssecMaintenance;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::RecordType;

/// DNSSEC config with 1-day rollover thresholds so backdated keys drive the
/// full state machine inside the test. The spawned maintenance task's
/// interval is long enough to stay idle; rollover steps are invoked manually
/// for determinism.
fn dnssec_config(db: &std::path::Path) -> DaygleConfig {
    let mut cfg = base_config(db);
    cfg.authoritative.dnssec_enabled = true;
    cfg.authoritative.dnssec_sig_validity_days = 14;
    cfg.authoritative.dnssec_rollover_days = 1;
    cfg.authoritative.dnssec_rollover_overlap_days = 1;
    cfg.authoritative.dnssec_rollover_retire_days = 1;
    cfg.authoritative.dnssec_maintenance_secs = 3600;
    cfg
}

/// Query over UDP with the DO bit set (EDNS), so answers carry RRSIGs.
async fn udp_query_do(addr: std::net::SocketAddr, name: &str, rtype: RecordType) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let mut msg = query_message(name, rtype);
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    msg.set_edns(edns);
    let bytes = msg.to_vec().expect("encode query");
    socket.send_to(&bytes, addr).await.expect("send query");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("timeout waiting for response")
        .expect("receive response");
    Message::from_vec(&buf[..n]).expect("decode response")
}

fn dnskey_count(msg: &Message) -> usize {
    msg.answers
        .iter()
        .filter(|r| r.record_type() == RecordType::DNSKEY)
        .count()
}

fn rrsig_count(msg: &Message) -> usize {
    msg.answers
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
        .count()
}

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
    server.catalog.reload().unwrap();
    zone.id
}

/// Run one rollover pass against the server's store + catalog.
fn pass_rollover(server: &daygle_dns::BoundServer) {
    let settings = server.catalog.settings().clone();
    let maintenance = DnssecMaintenance::new(
        server.catalog.store().clone(),
        server.catalog.clone(),
        &settings,
    );
    maintenance.process_rollover().unwrap();
}

/// A signed zone serves its DNSKEY, and the RRset is signed.
#[tokio::test]
async fn signed_zone_serves_dnskey_and_rrsigs() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(dnssec_config(&db)).await;
    let zone_id = seed_zone(&server, "signed.test").await;
    server.catalog.sign_zone(&zone_id).unwrap();

    let udp = server.udp_addr.expect("UDP enabled");
    let reply = udp_query_do(udp, "signed.test.", RecordType::DNSKEY).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert_eq!(dnskey_count(&reply), 1, "one DNSKEY expected");
    assert!(rrsig_count(&reply) >= 1, "DNSKEY RRset must be signed");

    // The served DNSKEY flags mark it as a zone-signing key.
    let dnskey = reply
        .answers
        .iter()
        .find(|r| r.record_type() == RecordType::DNSKEY)
        .unwrap();
    match &dnskey.data {
        hickory_proto::rr::RData::DNSSEC(
            hickory_proto::dnssec::rdata::DNSSECRData::DNSKEY(key),
        ) => {
            assert!(key.zone_key(), "zone key flag expected");
            assert!(key.secure_entry_point(), "SEP (KSK) flag expected");
        }
        other => panic!("unexpected DNSKEY rdata: {other:?}"),
    }

    // Plain A answers still work alongside DNSSEC.
    let reply = udp_query(udp, "www.signed.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.10"));

    shutdown(server).await;
}

/// Rollover over the wire: two DNSKEYs during double-signing, the old key
/// stays published while retired, then only the new key remains - and the
/// zone stays signed at every step.
#[tokio::test]
async fn rollover_transitions_are_served() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(dnssec_config(&db)).await;
    let store = server.catalog.store();
    let zone_id = seed_zone(&server, "roll.test").await;
    let udp = server.udp_addr.expect("UDP enabled");

    // The first key is backdated 2 days (past the 1-day rollover threshold)
    // and the zone is signed with it.
    let (algorithm, der) = daygle_authoritative::generate_signing_key().unwrap();
    store
        .store_signing_key_created(
            &zone_id,
            algorithm,
            &der,
            chrono::Utc::now() - chrono::Duration::hours(48),
        )
        .unwrap();
    server.catalog.reload().unwrap();

    // Baseline: one DNSKEY, signed.
    let reply = udp_query_do(udp, "roll.test.", RecordType::DNSKEY).await;
    assert_eq!(dnskey_count(&reply), 1);
    assert!(rrsig_count(&reply) >= 1);

    // Pass 1: new key generated -> two DNSKEYs published (double-signing).
    pass_rollover(&server);
    let reply = udp_query_do(udp, "roll.test.", RecordType::DNSKEY).await;
    assert_eq!(dnskey_count(&reply), 2, "pre-publish: both keys served");
    assert!(rrsig_count(&reply) >= 1);

    // Pass 2: old key retired -> still two DNSKEYs (grace publication),
    // signed by the surviving key.
    pass_rollover(&server);
    let reply = udp_query_do(udp, "roll.test.", RecordType::DNSKEY).await;
    assert_eq!(dnskey_count(&reply), 2, "retired key stays published");
    assert!(rrsig_count(&reply) >= 1);

    // Age the retired key past the delete threshold and advance once more:
    // only the new key remains, and the zone keeps serving signed answers.
    let old_key = store
        .list_signing_keys(&zone_id)
        .unwrap()
        .into_iter()
        .find(|k| k.is_retired())
        .unwrap();
    store
        .set_key_created_at(&old_key.id, chrono::Utc::now() - chrono::Duration::hours(96))
        .unwrap();
    pass_rollover(&server);
    let reply = udp_query_do(udp, "roll.test.", RecordType::DNSKEY).await;
    assert_eq!(dnskey_count(&reply), 1, "old key fully removed");
    assert!(rrsig_count(&reply) >= 1);

    // Exactly one active key remains.
    let stored = store.list_signing_keys(&zone_id).unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].is_active());

    shutdown(server).await;
}
