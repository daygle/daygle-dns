//! Integration test: DNS over TLS with a self-signed certificate.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::{RecursionAccess, ResolutionMode};
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

#[tokio::test]
async fn serves_queries_over_dot() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    // Exercise the configured handshake timeout (not the default 20 s) so the
    // listener provably reads the setting.
    config.dot.handshake_timeout_secs = 1;

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "secure".to_string(),
                rtype: "A".to_string(),
                content: "203.0.113.7".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let dot = server.dot_addr.expect("DoT is enabled");
    let msg = dot_query(dot, "daygle.test", &cert, "secure.tls.test.", RecordType::A).await;

    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_refuse_dns_update_before_authoritative_update_handling() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    config.dot.allowed_networks = vec!["10.9.9.0/24".to_string()];
    config.authoritative.allow_dynamic_updates = true;
    config.authoritative.update_networks = vec!["127.0.0.1".to_string()];

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let mut update = Message::new(0x4321, MessageType::Query, OpCode::Update);
    update.add_zone(Query::query(
        Name::from_utf8("tls.test.").unwrap(),
        RecordType::SOA,
    ));
    let mut new_record = hickory_proto::rr::Record::from_rdata(
        Name::from_utf8("new.tls.test.").unwrap(),
        60,
        hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A([192, 0, 2, 99].into())),
    );
    new_record.dns_class = hickory_proto::rr::DNSClass::IN;
    update.add_update(new_record);

    let response = dot_send(server.dot_addr.unwrap(), "daygle.test", &cert, &update).await;
    assert_eq!(response.response_code, ResponseCode::Refused);
    assert!(server
        .catalog
        .store()
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .all(|record| record.name != "new.tls.test"));

    // NOTIFY also has an early dispatcher path; it must be rejected by the
    // listener ACL before the inbound-NOTIFY handler sees it.
    let mut notify = Message::new(0x4322, MessageType::Query, OpCode::Notify);
    notify.add_query(Query::query(
        Name::from_utf8("tls.test.").unwrap(),
        RecordType::SOA,
    ));
    let response = dot_send(server.dot_addr.unwrap(), "daygle.test", &cert, &notify).await;
    assert_eq!(response.response_code, ResponseCode::Refused);

    // The same UPDATE remains allowed over ordinary DNS, where the DoT ACL
    // does not apply.
    let udp = server.udp_addr.unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = update.to_vec().unwrap();
    socket.send_to(&bytes, udp).await.unwrap();
    let mut response_bytes = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut response_bytes),
    )
    .await
    .unwrap()
    .unwrap();
    let response = Message::from_vec(&response_bytes[..len]).unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(server
        .catalog
        .store()
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .any(|record| record.name == "new.tls.test"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_refuse_clients_outside_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    // The test client is 127.0.0.1, outside this list.
    config.dot.allowed_networks = vec!["10.9.9.0/24".to_string()];

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "secure".to_string(),
                rtype: "A".to_string(),
                content: "203.0.113.7".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    // On DoT the client is refused before any other processing...
    let dot = server.dot_addr.expect("DoT is enabled");
    let msg = dot_query(dot, "daygle.test", &cert, "secure.tls.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    // ...while plain UDP carries no listener list and still answers.
    let udp = server.udp_addr.expect("UDP is enabled");
    let msg = udp_query(udp, "secure.tls.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_grant_recursion_on_that_listener_only() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream(
        &dir.path().join("upstream.db"),
        "example.test.",
        "198.51.100.7",
    )
    .await;
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    // Recursion Access excludes the test client (127.0.0.1)...
    config.recursive.recursion_access = RecursionAccess::Custom;
    config.recursive.recursion_networks = vec!["10.0.0.0/8".to_string()];
    // ...but the DoT listener lists it.
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    config.dot.allowed_networks = vec!["127.0.0.1".to_string()];

    let server = spawn(config).await;
    let dot = server.dot_addr.expect("DoT is enabled");
    let udp = server.udp_addr.expect("UDP is enabled");

    // Listed on the DoT listener: the client may recurse there...
    let msg = dot_query(
        dot,
        "daygle.test",
        &cert,
        "host.example.test.",
        RecordType::A,
    )
    .await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));

    // ...plain DNS is governed by Recursion Access alone and stays refused.
    let msg = udp_query(udp, "host.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}
