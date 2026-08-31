//! Integration test: RFC 2136 dynamic updates (UPDATE) with write-through to
//! SQLite and immediate catalog reload.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use daygle_core::config::DaygleConfig;
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

fn config_with_updates(db: &std::path::Path) -> DaygleConfig {
    let mut cfg = base_config(db);
    cfg.authoritative.allow_dynamic_updates = true;
    cfg
}

/// Build an UPDATE message targeting `zone` with the given prerequisites and
/// updates.
fn update_message(zone: &str, prereqs: Vec<Record>, updates: Vec<Record>) -> Message {
    let mut msg = Message::new(0x2a01, MessageType::Query, OpCode::Update);
    msg.add_zone(Query::query(
        Name::from_utf8(zone).expect("valid zone name"),
        RecordType::SOA,
    ));
    for prereq in prereqs {
        msg.add_pre_requisite(prereq);
    }
    for update in updates {
        msg.add_update(update);
    }
    msg
}

/// Send a message over plaintext UDP and return the response.
async fn udp_send(addr: SocketAddr, msg: &Message) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let bytes = msg.to_vec().expect("encode message");
    socket.send_to(&bytes, addr).await.expect("send message");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("timeout waiting for response")
        .expect("receive response");
    Message::from_vec(&buf[..n]).expect("decode response")
}

fn add_a_record(name: &str, ip: [u8; 4], ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_utf8(name).expect("valid name"),
        ttl,
        RData::A(A(ip.into())),
    )
}

fn delete_rrset(name: &str, rtype: RecordType) -> Record {
    let mut record = Record::from_rdata(
        Name::from_utf8(name).expect("valid name"),
        0,
        RData::Update0(rtype),
    );
    record.dns_class = DNSClass::ANY;
    record
}

/// Prerequisite "name is not in use" (class NONE, type ANY).
fn prereq_name_not_in_use(name: &str) -> Record {
    let mut record = Record::from_rdata(
        Name::from_utf8(name).expect("valid name"),
        0,
        RData::Update0(RecordType::ANY),
    );
    record.dns_class = DNSClass::NONE;
    record
}

/// Prerequisite "RRset exists (value independent)" (class ANY, type `rtype`).
fn prereq_rrset_exists(name: &str, rtype: RecordType) -> Record {
    let mut record = Record::from_rdata(
        Name::from_utf8(name).expect("valid name"),
        0,
        RData::Update0(rtype),
    );
    record.dns_class = DNSClass::ANY;
    record
}

async fn setup_zone(server: &daygle_dns::BoundServer, name: &str) -> String {
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: name.to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();
    zone.id
}

#[tokio::test]
async fn update_adds_record_and_answers_live() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    let zone_id = setup_zone(&server, "upd.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // Add host.upd.test A 192.0.2.99, guarded by "name is not in use".
    let msg = update_message(
        "upd.test.",
        vec![prereq_name_not_in_use("host.upd.test.")],
        vec![add_a_record("host.upd.test.", [192, 0, 2, 99], 300)],
    );
    let resp = udp_send(udp, &msg).await;
    assert_eq!(resp.response_code, ResponseCode::NoError);

    // The record is immediately served authoritatively.
    let query = udp_query(udp, "host.upd.test.", RecordType::A).await;
    assert_eq!(query.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&query).as_deref(), Some("192.0.2.99"));

    // The serial was bumped by the update.
    let zone = server.catalog.store().get_zone(&zone_id).unwrap().unwrap();
    assert!(zone.serial > 1);

    shutdown(server).await;
}

#[tokio::test]
async fn update_prerequisite_failures_return_rcodes() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    setup_zone(&server, "prereq.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // Add the record first (no prereqs).
    let add = update_message(
        "prereq.test.",
        vec![],
        vec![add_a_record("box.prereq.test.", [192, 0, 2, 10], 60)],
    );
    assert_eq!(udp_send(udp, &add).await.response_code, ResponseCode::NoError);

    // "Name is not in use" now fails with YXDOMAIN.
    let again = update_message(
        "prereq.test.",
        vec![prereq_name_not_in_use("box.prereq.test.")],
        vec![add_a_record("box.prereq.test.", [192, 0, 2, 11], 60)],
    );
    assert_eq!(udp_send(udp, &again).await.response_code, ResponseCode::YXDomain);

    // "RRset exists" for an absent name fails with NXRRSet.
    let missing = update_message(
        "prereq.test.",
        vec![prereq_rrset_exists("ghost.prereq.test.", RecordType::A)],
        vec![add_a_record("ghost.prereq.test.", [192, 0, 2, 12], 60)],
    );
    assert_eq!(
        udp_send(udp, &missing).await.response_code,
        ResponseCode::NXRRSet
    );

    // The failed updates left nothing behind.
    let query = udp_query(udp, "ghost.prereq.test.", RecordType::A).await;
    assert_eq!(query.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn update_delete_rrset_and_persistence_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    let zone_id = setup_zone(&server, "persist.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // Seed a record through the API path (store) and one through UPDATE.
    server
        .catalog
        .store()
        .upsert_record(
            &zone_id,
            &RecordInput {
                name: "seed.persist.test".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.1".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let add = update_message(
        "persist.test.",
        vec![],
        vec![add_a_record("dyn.persist.test.", [192, 0, 2, 77], 300)],
    );
    assert_eq!(udp_send(udp, &add).await.response_code, ResponseCode::NoError);
    let q = udp_query(udp, "dyn.persist.test.", RecordType::A).await;
    assert_eq!(first_answer(&q).as_deref(), Some("192.0.2.77"));

    // Delete dyn.persist.test A RRset; seed.persist.test must survive.
    let del = update_message(
        "persist.test.",
        vec![],
        vec![delete_rrset("dyn.persist.test.", RecordType::A)],
    );
    assert_eq!(udp_send(udp, &del).await.response_code, ResponseCode::NoError);
    let gone = udp_query(udp, "dyn.persist.test.", RecordType::A).await;
    assert_eq!(gone.response_code, ResponseCode::NXDomain);
    let kept = udp_query(udp, "seed.persist.test.", RecordType::A).await;
    assert_eq!(first_answer(&kept).as_deref(), Some("192.0.2.1"));

    // Add dyn.persist.test again so it exists in the DB when we restart.
    let re_add = update_message(
        "persist.test.",
        vec![prereq_name_not_in_use("dyn.persist.test.")],
        vec![add_a_record("dyn.persist.test.", [192, 0, 2, 77], 300)],
    );
    assert_eq!(udp_send(udp, &re_add).await.response_code, ResponseCode::NoError);

    shutdown(server).await;

    // The dynamically added record persists in SQLite across a restart.
    let restarted = spawn(config_with_updates(&db)).await;
    let again = udp_query(
        restarted.udp_addr.unwrap(),
        "dyn.persist.test.",
        RecordType::A,
    )
    .await;
    assert_eq!(first_answer(&again).as_deref(), Some("192.0.2.77"));

    shutdown(restarted).await;
}

#[tokio::test]
async fn update_refused_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // `base_config` leaves allow_dynamic_updates off.
    let server = spawn(base_config(&db)).await;
    setup_zone(&server, "locked.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    let msg = update_message(
        "locked.test.",
        vec![],
        vec![add_a_record("x.locked.test.", [192, 0, 2, 5], 60)],
    );
    let resp = udp_send(udp, &msg).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    // Nothing was written.
    let query = udp_query(udp, "x.locked.test.", RecordType::A).await;
    assert_eq!(query.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn update_unknown_zone_is_not_auth() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    let udp = server.udp_addr.expect("UDP is enabled");

    let msg = update_message(
        "nowhere.invalid.",
        vec![],
        vec![add_a_record("x.nowhere.invalid.", [192, 0, 2, 5], 60)],
    );
    let resp = udp_send(udp, &msg).await;
    assert_eq!(resp.response_code, ResponseCode::NotAuth);

    shutdown(server).await;
}

#[tokio::test]
async fn update_with_explicit_soa_writes_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    let zone_id = setup_zone(&server, "soa.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // Update the apex SOA record with new metadata, including a serial.
    let soa = RData::try_from_str(
        RecordType::SOA,
        "ns1.soa.test. admin.soa.test. 9001 3600 600 86400 300",
    )
    .unwrap();
    let mut record = Record::from_rdata(Name::from_utf8("soa.test.").unwrap(), 300, soa);
    record.dns_class = DNSClass::IN;
    let msg = update_message("soa.test.", vec![], vec![record]);
    assert_eq!(udp_send(udp, &msg).await.response_code, ResponseCode::NoError);

    let zone = server.catalog.store().get_zone(&zone_id).unwrap().unwrap();
    assert_eq!(zone.serial, 9001);
    assert_eq!(zone.primary_ns, "ns1.soa.test.");
    assert_eq!(zone.minimum, 300);

    // The SOA answer reflects the new metadata.
    let q = udp_query(udp, "soa.test.", RecordType::SOA).await;
    assert_eq!(q.response_code, ResponseCode::NoError);
    assert!(first_answer(&q).unwrap().contains("9001"));

    shutdown(server).await;
}

#[tokio::test]
async fn update_refuses_deleting_last_apex_ns() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_updates(&db)).await;
    setup_zone(&server, "ns.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // The default zone has exactly one apex NS; deleting it must be refused.
    let msg = update_message(
        "ns.test.",
        vec![],
        vec![delete_rrset("ns.test.", RecordType::NS)],
    );
    assert_eq!(udp_send(udp, &msg).await.response_code, ResponseCode::Refused);

    shutdown(server).await;
}
