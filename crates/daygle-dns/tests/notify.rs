//! Integration tests: RFC 1996 NOTIFY - inbound replies/refusals,
//! NOTIFY-triggered immediate secondary-zone pulls, and the outbound chain
//! from RFC 2136 dynamic updates.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use daygle_authoritative::notify::NotifySender;
use daygle_core::config::SecondaryZoneConfig;
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// Build a NOTIFY message (OpCode 4, QTYPE SOA) with the new serial in the
/// authority section, as BIND and Technitium send them.
fn notify_message(zone: &str, serial: u32) -> Message {
    let name = Name::from_utf8(zone).expect("valid zone name");
    let mut msg = Message::new(0x4e07, MessageType::Query, OpCode::Notify);
    msg.add_query(Query::query(name.clone(), RecordType::SOA));
    let soa = SOA::new(name.clone(), name.clone(), serial, 3600, 600, 86400, 300);
    msg.add_authority(Record::from_rdata(name, 0, RData::SOA(soa)));
    msg
}

/// Send a message over plaintext UDP and return the response.
async fn udp_send(addr: std::net::SocketAddr, msg: &Message) -> Message {
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

/// Secondary-zone config pointing at `master` with a long refresh interval so
/// only a NOTIFY can trigger a pull inside the test window.
fn secondary_config(name: &str, master: &str) -> SecondaryZoneConfig {
    SecondaryZoneConfig {
        name: name.to_string(),
        masters: vec![master.to_string()],
        refresh_secs: 3600,
        enabled: true,
        tsig_key: String::new(),
    }
}

async fn seed_zone(server: &daygle_dns::BoundServer, name: &str) -> String {
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

/// Change the master's zone data and bump the serial.
fn touch_master(server: &daygle_dns::BoundServer, zone_id: &str) {
    let store = server.catalog.store();
    store
        .upsert_record(
            zone_id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "TXT".to_string(),
                content: "\"hello-from-notify\"".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    store.bump_serial(zone_id).unwrap();
    server.catalog.reload().unwrap();
}

/// Poll the secondary until it answers `qname` with the given value.
async fn poll_for_answer(
    addr: std::net::SocketAddr,
    qname: &str,
    rtype: RecordType,
    value: &str,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let msg = udp_query(addr, qname, rtype).await;
        if let Some(answer) = first_answer(&msg) {
            if answer == value {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// A NOTIFY for a configured secondary zone is answered with the current SOA.
#[tokio::test]
async fn notify_for_configured_zone_replies_with_soa() {
    let dir = tempfile::tempdir().unwrap();

    let master_db = dir.path().join("master.db");
    let mut master_cfg = base_config(&master_db);
    master_cfg.authoritative.axfr_enabled = true;
    let master = spawn(master_cfg).await;
    seed_zone(&master, "notify.test").await;

    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.secondary_zones = vec![secondary_config(
        "notify.test",
        &master.tcp_addr.expect("master TCP").to_string(),
    )];
    config.authoritative.notify_listen_enabled = true;
    let secondary = spawn(config).await;

    let udp = secondary.udp_addr.expect("secondary UDP enabled");
    let reply = udp_send(udp, &notify_message("notify.test.", 99)).await;

    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert_eq!(reply.metadata.op_code, OpCode::Notify);
    assert!(reply.authoritative);
    let soa = reply
        .answers
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .expect("SOA in answer");
    match &soa.data {
        RData::SOA(soa) => assert_eq!(soa.serial, 1), // default zone serial
        _ => panic!("expected SOA rdata"),
    }

    shutdown(secondary).await;
    shutdown(master).await;
}

/// NOTIFYs for unconfigured zones or from non-masters are NOTIMP'd without
/// triggering a refresh.
#[tokio::test]
async fn notify_unknown_zone_or_non_master_is_notimp() {
    let dir = tempfile::tempdir().unwrap();

    let master_db = dir.path().join("master.db");
    let mut master_cfg = base_config(&master_db);
    master_cfg.authoritative.axfr_enabled = true;
    let master = spawn(master_cfg).await;
    seed_zone(&master, "known.test").await;

    let mut config = base_config(&dir.path().join("secondary.db"));
    // Masters live on 192.0.2.1 in this test, so 127.0.0.1 senders are not
    // one of the zone's masters.
    config.authoritative.secondary_zones =
        vec![secondary_config("known.test", "192.0.2.1")];
    config.authoritative.notify_listen_enabled = true;
    let secondary = spawn(config).await;

    let udp = secondary.udp_addr.expect("secondary UDP enabled");

    // Unknown zone.
    let reply = udp_send(udp, &notify_message("unknown.test.", 5)).await;
    assert_eq!(reply.response_code, ResponseCode::NotImp);
    assert_eq!(reply.metadata.op_code, OpCode::Notify);
    assert!(reply.answers.is_empty());

    // Known zone, but the sender is not one of its masters.
    let reply = udp_send(udp, &notify_message("known.test.", 5)).await;
    assert_eq!(reply.response_code, ResponseCode::NotImp);

    shutdown(secondary).await;
    shutdown(master).await;
}

/// A NOTIFY from the master triggers an immediate IXFR pull; with a 3600 s
/// refresh interval only the NOTIFY can cause the transfer in this window.
#[tokio::test]
async fn notify_triggers_immediate_pull() {
    let dir = tempfile::tempdir().unwrap();

    let master_db = dir.path().join("master.db");
    let mut master_cfg = base_config(&master_db);
    master_cfg.authoritative.axfr_enabled = true;
    let master = spawn(master_cfg).await;
    let zone_id = seed_zone(&master, "pull.test").await;

    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.secondary_zones = vec![secondary_config(
        "pull.test",
        &master.tcp_addr.expect("master TCP").to_string(),
    )];
    config.authoritative.notify_listen_enabled = true;
    let secondary = spawn(config).await;
    let udp = secondary.udp_addr.expect("secondary UDP enabled");

    // Change the master, then send the NOTIFY as the master would.
    touch_master(&master, &zone_id);
    let reply = udp_send(udp, &notify_message("pull.test.", 2)).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);

    assert!(
        poll_for_answer(udp, "www.pull.test.", RecordType::TXT, "hello-from-notify").await,
        "secondary did not pull the zone after the NOTIFY"
    );

    shutdown(secondary).await;
    shutdown(master).await;
}

/// The outbound wire path: a master's NotifySender reaches a running
/// secondary, which pulls immediately (refresh interval too long to matter).
#[tokio::test]
async fn sender_notify_reaches_secondary_and_pulls() {
    let dir = tempfile::tempdir().unwrap();

    let master_db = dir.path().join("master.db");
    let mut master_cfg = base_config(&master_db);
    master_cfg.authoritative.axfr_enabled = true;
    let master = spawn(master_cfg).await;
    let zone_id = seed_zone(&master, "push.test").await;

    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.secondary_zones = vec![secondary_config(
        "push.test",
        &master.tcp_addr.expect("master TCP").to_string(),
    )];
    config.authoritative.notify_listen_enabled = true;
    let secondary = spawn(config).await;
    let udp = secondary.udp_addr.expect("secondary UDP enabled");

    // Change the master, then NOTIFY the secondary exactly as the update
    // handler would (fire-and-forget, like handle_update_with_notify does).
    touch_master(&master, &zone_id);
    let sender = NotifySender::new(&[udp.to_string()]).expect("valid target");
    tokio::spawn(async move {
        sender.notify_zone("push.test").await;
    });

    assert!(
        poll_for_answer(udp, "www.push.test.", RecordType::TXT, "hello-from-notify").await,
        "secondary did not pull the zone after the sender's NOTIFY"
    );

    shutdown(secondary).await;
    shutdown(master).await;
}

/// A successful RFC 2136 update fires a NOTIFY (OpCode 4, QTYPE SOA) to every
/// configured target; the target is a capture socket so the exact wire message
/// can be asserted.
#[tokio::test]
async fn successful_update_sends_notify_to_targets() {
    let dir = tempfile::tempdir().unwrap();

    // Capture socket: receives the NOTIFY and acks it so the sender does not
    // wait out its timeout.
    let capture = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let capture_addr = capture.local_addr().unwrap();
    tokio::spawn({
        let capture = capture.clone();
        async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = capture.recv_from(&mut buf).await.expect("recv notify");
                let _ = Message::from_vec(&buf[..n]);
                let mut ack = Message::new(0, MessageType::Response, OpCode::Notify);
                ack.metadata.response_code = ResponseCode::NoError;
                if let Ok(bytes) = ack.to_vec() {
                    let _ = capture.send_to(&bytes, peer).await;
                }
            }
        }
    });

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.authoritative.allow_dynamic_updates = true;
    config.authoritative.notify_enabled = true;
    config.authoritative.notify_targets = vec![capture_addr.to_string()];
    let server = spawn(config).await;
    let zone_id = seed_zone(&server, "fired.test").await;
    let _ = zone_id;

    // RFC 2136 UPDATE: add www.fired.test A 192.0.2.77.
    let mut msg = Message::new(0x2a02, MessageType::Query, OpCode::Update);
    msg.add_zone(Query::query(
        Name::from_utf8("fired.test.").expect("zone name"),
        RecordType::SOA,
    ));
    let mut prereq = Record::from_rdata(
        Name::from_utf8("www.fired.test.").expect("name"),
        0,
        RData::Update0(RecordType::ANY),
    );
    prereq.dns_class = DNSClass::NONE;
    msg.add_pre_requisite(prereq);
    msg.add_update(Record::from_rdata(
        Name::from_utf8("www.fired.test.").expect("name"),
        300,
        RData::A(A([192, 0, 2, 77].into())),
    ));

    let udp = server.udp_addr.expect("server UDP enabled");
    let reply = udp_send(udp, &msg).await;
    assert_eq!(reply.response_code, ResponseCode::NoError, "update failed");

    // The NOTIFY should arrive on the capture socket.
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), capture.recv_from(&mut buf))
        .await
        .expect("timeout waiting for NOTIFY")
        .expect("recv NOTIFY");
    let notify = Message::from_vec(&buf[..n]).expect("decode NOTIFY");
    assert_eq!(notify.metadata.op_code, OpCode::Notify);
    assert_eq!(notify.queries.len(), 1);
    assert_eq!(notify.queries[0].query_type(), RecordType::SOA);
    assert_eq!(
        notify.queries[0].name().to_string().trim_end_matches('.'),
        "fired.test"
    );

    shutdown(server).await;
}
