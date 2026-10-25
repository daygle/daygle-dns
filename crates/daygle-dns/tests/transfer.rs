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
    msg.add_query(Query::query(
        Name::from_utf8(name).expect("valid name"),
        rtype,
    ));
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

/// A named network gates zone transfers: the list names `LAN`, and the
/// network it stands for decides who may transfer.
#[tokio::test]
async fn axfr_acl_accepts_named_networks() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let mut config = config_with_axfr(&db, true, vec!["LAN".to_string()]);
    config.networks = vec![daygle_dns_core::config::NamedNetwork {
        name: "LAN".to_string(),
        cidrs: vec!["10.0.0.0/8".to_string()],
        description: String::new(),
    }];
    let server = spawn(config).await;
    seed_zone(&server, "named.test").await;
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // 127.0.0.1 is not in LAN, so it is refused.
    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_transfer_query(tcp, "named.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    // Widening LAN to cover the test client lets the transfer through,
    // without touching the transfer setting itself.
    let resp = client
        .post(format!("{api}/networks"))
        .json(&serde_json::json!({
            "original_name": "LAN",
            "name": "LAN",
            "cidrs": ["127.0.0.0/8"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = tcp_transfer_query(tcp, "named.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::NoError);

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
    assert!(
        records.len() >= 3,
        "full zone expected, got {}",
        records.len()
    );
    assert_eq!(records.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(records.last().unwrap().record_type(), RecordType::SOA);
    assert!(
        records.iter().any(|r| r.data.to_string() == "192.0.2.10"),
        "A record missing from transfer"
    );

    shutdown(server).await;
}

/// A DNS query with the DO bit (asks for signatures) over UDP.
async fn udp_query_do(addr: std::net::SocketAddr, name: &str, rtype: RecordType) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = query_message(name, rtype);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(4096);
    msg.set_edns(edns);
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("timeout waiting for response")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

/// The signatures in an answer, as wire bytes (to compare two servers).
fn rrsigs(msg: &Message) -> Vec<Vec<u8>> {
    use hickory_proto::serialize::binary::BinEncodable;
    msg.answers
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
        .map(|r| r.data.to_bytes().unwrap())
        .collect()
}

fn soa_serial(record: &hickory_proto::rr::Record) -> u32 {
    match &record.data {
        hickory_proto::rr::RData::SOA(soa) => soa.serial,
        other => panic!("not an SOA: {other:?}"),
    }
}

/// A signed zone too big for one DNS message, behind TSIG: the master sends
/// it in several signed messages, signatures and all, with the serial the
/// console shows; a secondary holding the key pulls it and serves the
/// master's signatures unchanged.
#[tokio::test]
async fn signed_zone_larger_than_a_message_replicates_over_tsig() {
    const SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    let key = daygle_dns_core::config::TsigKeyConfig {
        name: "xfr-key.".to_string(),
        algorithm: "hmac-sha256".to_string(),
        secret: SECRET.to_string(),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_axfr(&dir.path().join("master.db"), true, vec![]);
    config.authoritative.dnssec_enabled = true;
    config.authoritative.tsig_keys = vec![key.clone()];
    config.authoritative.tsig_transfer_zones = vec!["big.test=xfr-key".to_string()];
    let master = spawn(config).await;
    let store = master.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "big.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    let records: Vec<RecordInput> = (0..1500)
        .map(|i| RecordInput {
            name: format!("host{i}"),
            rtype: "A".to_string(),
            content: format!("192.0.{}.{}", i / 250, i % 250),
            ttl: 300,
            priority: 0,
            disabled: false,
        })
        .collect();
    store.replace_records(&zone.id, &records).unwrap();
    master.catalog.sign_zone(&zone.id).unwrap();
    let serial = store.get_zone(&zone.id).unwrap().unwrap().serial;
    let master_tcp = master.tcp_addr.unwrap();
    let master_udp = master.udp_addr.unwrap();

    // Served with the stored serial (signing does not bump it).
    let reply = udp_query(master_udp, "big.test.", RecordType::SOA).await;
    assert_eq!(soa_serial(&reply.answers[0]), serial);

    // Without the key: refused. With it: the whole signed zone.
    let name: Name = "big.test.".parse().unwrap();
    let client = XfrClient::new(Duration::from_secs(5));
    assert!(client.axfr(master_tcp, &name).await.is_err());
    let tsig = daygle_dns_authoritative::tsig::TsigKey::from_config(&key).unwrap();
    let transfer = client
        .axfr_signed(master_tcp, &name, Some(&tsig))
        .await
        .expect("signed transfer of a multi-message zone");
    assert!(
        transfer.len() > 3000,
        "records and signatures: {}",
        transfer.len()
    );
    assert_eq!(soa_serial(transfer.first().unwrap()), serial);
    assert_eq!(soa_serial(transfer.last().unwrap()), serial);
    for rtype in [RecordType::RRSIG, RecordType::DNSKEY, RecordType::NSEC] {
        assert!(
            transfer.iter().any(|r| r.record_type() == rtype),
            "{rtype} missing"
        );
    }

    // A secondary with the key serves the zone exactly as signed.
    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.tsig_keys = vec![key];
    config.authoritative.secondary_zones = vec![SecondaryZoneConfig {
        name: "big.test".to_string(),
        masters: vec![master_tcp.to_string()],
        refresh_secs: 1,
        enabled: true,
        tsig_key: "xfr-key".to_string(),
    }];
    let secondary = spawn(config).await;
    let secondary_udp = secondary.udp_addr.unwrap();
    let expected = udp_query_do(master_udp, "host1499.big.test.", RecordType::A).await;
    assert!(!rrsigs(&expected).is_empty());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut served = None;
    while std::time::Instant::now() < deadline {
        let reply = udp_query_do(secondary_udp, "host1499.big.test.", RecordType::A).await;
        if first_answer(&reply).is_some() {
            served = Some(reply);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let served = served.expect("the secondary never served the zone");
    assert_eq!(first_answer(&served), first_answer(&expected));
    assert_eq!(
        rrsigs(&served),
        rrsigs(&expected),
        "the master's signatures"
    );
    let nx = udp_query_do(secondary_udp, "missing.big.test.", RecordType::A).await;
    assert_eq!(nx.response_code, ResponseCode::NXDomain);
    assert!(
        nx.authorities
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC),
        "denial proof from the master's NSEC chain"
    );

    shutdown(secondary).await;
    shutdown(master).await;
}

/// A scripted master: answers SOA queries with serial `serial`, IXFR with a
/// lone SOA, and AXFR with the opening SOA in a message of its own.
async fn scripted_master(serial: u32) -> std::net::SocketAddr {
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{RData, Record};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.unwrap();
                let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                stream.read_exact(&mut body).await.unwrap();
                let query = Message::from_vec(&body).unwrap();
                let zone: Name = "script.test.".parse().unwrap();
                let soa = Record::from_rdata(
                    zone.clone(),
                    300,
                    RData::SOA(SOA::new(
                        zone.clone(),
                        zone.clone(),
                        serial,
                        3600,
                        600,
                        86400,
                        300,
                    )),
                );
                let a = Record::from_rdata(
                    "www.script.test.".parse().unwrap(),
                    300,
                    RData::A(A::new(192, 0, 2, 7)),
                );
                let messages: Vec<Vec<Record>> = match query.queries[0].query_type() {
                    RecordType::AXFR => vec![vec![soa.clone()], vec![a, soa]],
                    _ => vec![vec![soa]],
                };
                for answers in messages {
                    let mut reply =
                        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    reply.add_query(query.queries[0].clone());
                    for record in answers {
                        reply.add_answer(record);
                    }
                    let bytes = reply.to_vec().unwrap();
                    stream
                        .write_all(&(bytes.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
        }
    });
    addr
}

/// IXFR answered with a lone SOA: when it is newer, the client must fetch
/// the zone by AXFR (not take the lone SOA as "no change", which left a new
/// secondary empty); when it is not, nothing is fetched. The AXFR reply opens
/// with an SOA in a message of its own, which must not end the transfer.
#[tokio::test]
async fn lone_soa_ixfr_replies_are_followed_correctly() {
    let master = scripted_master(5).await;
    let zone: Name = "script.test.".parse().unwrap();
    let client = XfrClient::new(Duration::from_secs(5));

    let records = client
        .ixfr_or_axfr(master, &zone, 1, None)
        .await
        .unwrap()
        .expect("a newer serial means a transfer");
    assert_eq!(records.len(), 3, "{records:?}");
    assert!(records.iter().any(|r| r.data.to_string() == "192.0.2.7"));

    assert!(client
        .ixfr_or_axfr(master, &zone, 5, None)
        .await
        .unwrap()
        .is_none());

    // A secondary of this master fills the zone on its first refresh.
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("secondary.db"));
    config.authoritative.secondary_zones = vec![SecondaryZoneConfig {
        name: "script.test".to_string(),
        masters: vec![master.to_string()],
        refresh_secs: 1,
        enabled: true,
        tsig_key: String::new(),
    }];
    let secondary = spawn(config).await;
    let udp = secondary.udp_addr.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut answer = None;
    while answer.is_none() && std::time::Instant::now() < deadline {
        answer = first_answer(&udp_query(udp, "www.script.test.", RecordType::A).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(answer.as_deref(), Some("192.0.2.7"));
    shutdown(secondary).await;
}
