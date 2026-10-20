//! Integration test: the local root zone (RFC 8806). A fake transfer server
//! serves a small signed root zone (with ZONEMD) over AXFR; Daygle must
//! verify it, serve it to its recursor on loopback (the configured root hint
//! has no server behind it, so resolution only works through the local
//! copy), keep it across a restart, reject a tampered copy, and in
//! forwarding mode answer NXDOMAIN for top-level domains the zone lacks.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use daygle_dns_authoritative::zonemd::sign_test_zone;
use daygle_dns_core::config::{DaygleConfig, LocalRootSettings, ResolutionMode};
use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Root hint with nothing listening: only the local root can answer.
const DEAD_ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
/// The `test.` TLD server.
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn soa(zone: &str, serial: u32) -> Record {
    Record::from_rdata(
        name(zone),
        86400,
        RData::SOA(SOA::new(
            name("a.root-servers.test."),
            name("nstld.test."),
            serial,
            1800,
            900,
            604800,
            86400,
        )),
    )
}

/// A signed root zone delegating only `test.`; returns the records and the
/// trust anchor (the signing key).
fn signed_root() -> (Vec<Record>, Vec<u8>) {
    let records = vec![
        soa(".", 2026102001),
        Record::from_rdata(
            Name::root(),
            518400,
            RData::NS(NS(name("a.root-servers.test."))),
        ),
        Record::from_rdata(name("test."), 172800, RData::NS(NS(name("ns.test.")))),
        Record::from_rdata(name("ns.test."), 172800, RData::A(TLD.into())),
        Record::from_rdata(
            Name::root(),
            86400,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                name("test."),
                vec![RecordType::NS, RecordType::SOA],
            ))),
        ),
        Record::from_rdata(
            name("test."),
            86400,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::root(),
                vec![RecordType::NS],
            ))),
        ),
    ];
    sign_test_zone(&Name::root(), records, now())
}

/// Serve `zone` to AXFR and SOA queries over TCP, one query per connection.
async fn spawn_transfer_server(zone: Vec<Record>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let zone = Arc::new(zone);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let zone = zone.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let query = Message::from_vec(&buf).unwrap();
                let mut response = Message::new(
                    query.metadata.id,
                    MessageType::Response,
                    query.metadata.op_code,
                );
                response.metadata.authoritative = true;
                response.queries = query.queries.clone();
                let soa = zone
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .unwrap()
                    .clone();
                match query.queries[0].query_type() {
                    RecordType::AXFR => {
                        response.answers.push(soa.clone());
                        response.answers.extend(
                            zone.iter()
                                .filter(|r| r.record_type() != RecordType::SOA)
                                .cloned(),
                        );
                        response.answers.push(soa);
                    }
                    _ => response.answers.push(soa),
                }
                let bytes = response.to_vec().unwrap();
                let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&bytes);
                let _ = stream.write_all(&framed).await;
            });
        }
    });
    addr
}

/// The `test.` TLD: answers `www.test.` itself.
async fn spawn_tld() -> u16 {
    let socket = tokio::net::UdpSocket::bind((TLD, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.authoritative = true;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                let qname = q.name().to_ascii().to_ascii_lowercase();
                match (qname.as_str(), q.query_type()) {
                    ("test.", RecordType::NS) => response.answers.push(Record::from_rdata(
                        name("test."),
                        300,
                        RData::NS(NS(name("ns.test."))),
                    )),
                    ("ns.test.", RecordType::A) => response.answers.push(Record::from_rdata(
                        name("ns.test."),
                        300,
                        RData::A(TLD.into()),
                    )),
                    ("www.test.", RecordType::A) => response.answers.push(Record::from_rdata(
                        name("www.test."),
                        300,
                        RData::A(Ipv4Addr::new(198, 51, 100, 7).into()),
                    )),
                    ("test." | "ns.test." | "www.test.", _) => {
                        response.authorities.push(soa("test.", 1))
                    }
                    _ => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                        response.authorities.push(soa("test.", 1));
                    }
                }
            }
            if socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });
    port
}

fn local_root_config(
    dir: &tempfile::TempDir,
    tld_port: u16,
    source: SocketAddr,
    anchor: &[u8],
) -> DaygleConfig {
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Recursive);
    config.recursive.root_hints = vec![DEAD_ROOT.to_string()];
    config.recursive.test_outbound_port = Some(tld_port);
    // The fake TLD is unsigned; the local root itself is still verified
    // against the test trust anchor.
    config.recursive.dnssec_validate = false;
    config.recursive.timeout_secs = 1;
    config.recursive.local_root = LocalRootSettings {
        enabled: true,
        sources: vec![source.to_string()],
        test_trust_anchor: Some(anchor.to_vec()),
    };
    config
}

async fn local_root_status(api: SocketAddr) -> serde_json::Value {
    reqwest::get(format!("http://{api}/api/local-root"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Poll the status until `done` holds (or fail after a few seconds).
async fn wait_for(api: SocketAddr, done: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    for _ in 0..100 {
        let status = local_root_status(api).await;
        if done(&status) {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "local root never reached the expected state: {}",
        local_root_status(api).await
    );
}

#[tokio::test]
async fn recursive_mode_resolves_through_the_local_root_zone() {
    let (zone, anchor) = signed_root();
    let source = spawn_transfer_server(zone).await;
    let tld_port = spawn_tld().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(local_root_config(&dir, tld_port, source, &anchor)).await;

    let status = wait_for(server.api_addr, |s| s["serving"] == true).await;
    assert_eq!(status["serial"], 2026102001);
    assert_eq!(status["tlds"], 1);
    assert_eq!(status["source"], source.to_string());
    assert!(status["last_error"].is_null(), "{status}");

    let udp = server.udp_addr.unwrap();
    // The root hint is dead: this only resolves via the local root.
    let msg = udp_query(udp, "www.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    // A TLD the root zone lacks is NXDOMAIN, answered locally.
    let msg = udp_query(udp, "host.no-such-tld.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    // The verified copy survives a restart, even with no reachable source.
    shutdown(server).await;
    assert!(dir.path().join("local-root.zone").exists());
    let mut config = local_root_config(&dir, tld_port, source, &anchor);
    config.recursive.local_root.sources = vec!["127.0.0.1:1".to_string()];
    let server = spawn(config).await;
    let status = wait_for(server.api_addr, |s| s["serving"] == true).await;
    assert_eq!(status["source"], "cache");
    let msg = udp_query(server.udp_addr.unwrap(), "www.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    shutdown(server).await;
}

#[tokio::test]
async fn tampered_root_zone_is_rejected() {
    let (mut zone, anchor) = signed_root();
    for record in &mut zone {
        if record.record_type() == RecordType::A {
            record.data = RData::A(Ipv4Addr::new(192, 0, 2, 66).into());
        }
    }
    let source = spawn_transfer_server(zone).await;
    let tld_port = spawn_tld().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(local_root_config(&dir, tld_port, source, &anchor)).await;

    let status = wait_for(server.api_addr, |s| s["last_error"].is_string()).await;
    assert_eq!(status["serving"], false);
    let error = status["last_error"].as_str().unwrap();
    assert!(error.contains("digest"), "{error}");
    assert!(!dir.path().join("local-root.zone").exists());
    shutdown(server).await;
}

#[tokio::test]
async fn forwarding_mode_answers_missing_tlds_from_the_local_root_zone() {
    let (zone, anchor) = signed_root();
    let source = spawn_transfer_server(zone).await;
    let tld_port = spawn_tld().await;
    // An upstream that answers every name.
    let upstream = common_upstream_answering_everything().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = local_root_config(&dir, tld_port, source, &anchor);
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![upstream.to_string()];
    let server = spawn(config).await;
    wait_for(server.api_addr, |s| s["serving"] == true).await;
    let udp = server.udp_addr.unwrap();

    // `test.` exists: forwarded as usual.
    let msg = udp_query(udp, "anything.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.80"));
    // `no-such-tld.` does not: NXDOMAIN without asking the upstream (which
    // would have answered).
    let msg = udp_query(udp, "host.no-such-tld.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    shutdown(server).await;
}

/// A forwarding upstream answering A 192.0.2.80 for every name.
async fn common_upstream_answering_everything() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_available = true;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                if q.query_type() == RecordType::A {
                    response.answers.push(Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(Ipv4Addr::new(192, 0, 2, 80).into()),
                    ));
                }
            }
            if socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });
    addr
}
