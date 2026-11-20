//! Integration test: a zone whose first name server is silent (it takes the
//! query and never answers) and whose second one works.
//!
//! The recursor's name server pool asks a zone's servers one at a time and
//! gives the whole walk a fixed budget (Hickory's 5s pool timeout). Waiting
//! the full configured timeout on the silent server used to spend that whole
//! budget, so the zone's second server was never asked and a perfectly
//! resolvable name failed with SERVFAIL. The Lookup page's trace showed only
//! one of `tracker.openbittorrent.com`'s two delegated servers ever asked for
//! exactly this reason.

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::*;
use daygle_dns_core::config::ResolutionMode;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 6, 1);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 6, 2);
/// `ns1.silent.test.`, delegated first, which never answers.
const SILENT: Ipv4Addr = Ipv4Addr::new(127, 0, 6, 3);
/// `ns2.silent.test.`, delegated second, which serves the zone.
const ALIVE: Ipv4Addr = Ipv4Addr::new(127, 0, 6, 4);

const ZONE: &str = "silent.test.";

/// What a fake server does with one question.
enum Reply {
    /// Authoritative answer records.
    Answer(Vec<Record>),
    /// Referral: NS records in the authority section plus glue.
    Referral(Vec<Record>, Vec<Record>),
    /// Authoritative NODATA (NOERROR, no answers) with the zone SOA.
    NoData(Record),
    /// Authoritative NXDOMAIN with the zone SOA.
    NxDomain(Record),
    /// Take the query and never answer.
    Silent,
}

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

fn ns(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 300, RData::NS(NS(name(target))))
}

fn a(owner: &str, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name(owner), 300, RData::A(ip.into()))
}

fn soa(zone: &str) -> Record {
    Record::from_rdata(
        name(zone),
        300,
        RData::SOA(SOA::new(
            name(&format!("ns.{zone}")),
            name("hostmaster.example."),
            1,
            3600,
            600,
            86400,
            60,
        )),
    )
}

fn is_under(qname: &str, zone: &str) -> bool {
    qname == zone || qname.ends_with(&format!(".{zone}"))
}

fn handle(server: Ipv4Addr, qname: &str, qtype: RecordType) -> Reply {
    match server {
        s if s == ROOT => {
            if qname == "." {
                return match qtype {
                    RecordType::NS => Reply::Answer(vec![ns(".", "ns.root.test.")]),
                    _ => Reply::NoData(soa(".")),
                };
            }
            if is_under(qname, "test.") {
                return Reply::Referral(vec![ns("test.", "ns.test.")], vec![a("ns.test.", TLD)]);
            }
            Reply::NxDomain(soa("."))
        }
        s if s == TLD => {
            if qname == "test." {
                return match qtype {
                    RecordType::NS => Reply::Answer(vec![ns("test.", "ns.test.")]),
                    _ => Reply::NoData(soa("test.")),
                };
            }
            if qname == "ns.test." && qtype == RecordType::A {
                return Reply::Answer(vec![a("ns.test.", TLD)]);
            }
            if is_under(qname, ZONE) {
                // The dead server is listed (and given glue) first.
                return Reply::Referral(
                    vec![ns(ZONE, "ns1.silent.test."), ns(ZONE, "ns2.silent.test.")],
                    vec![a("ns1.silent.test.", SILENT), a("ns2.silent.test.", ALIVE)],
                );
            }
            Reply::NxDomain(soa("test."))
        }
        s if s == SILENT => Reply::Silent,
        s if s == ALIVE => {
            if !is_under(qname, ZONE) {
                return Reply::NxDomain(soa("test."));
            }
            match (qname, qtype) {
                (ZONE, RecordType::NS) => Reply::Answer(vec![
                    ns(ZONE, "ns1.silent.test."),
                    ns(ZONE, "ns2.silent.test."),
                ]),
                ("ns2.silent.test.", RecordType::A) => {
                    Reply::Answer(vec![a("ns2.silent.test.", ALIVE)])
                }
                ("www.silent.test.", RecordType::A) => {
                    Reply::Answer(vec![a("www.silent.test.", Ipv4Addr::new(198, 51, 100, 9))])
                }
                _ => Reply::NoData(soa(ZONE)),
            }
        }
        _ => unreachable!(),
    }
}

fn spawn_fake(socket: tokio::net::UdpSocket, server: Ipv4Addr) {
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
            let mut silent = false;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                let qname = q.name().to_ascii().to_ascii_lowercase();
                match handle(server, &qname, q.query_type()) {
                    Reply::Answer(records) => {
                        response.metadata.authoritative = true;
                        response.answers.extend(records);
                    }
                    Reply::Referral(authority, glue) => {
                        response.authorities.extend(authority);
                        response.additionals.extend(glue);
                    }
                    Reply::NoData(soa) => {
                        response.metadata.authoritative = true;
                        response.authorities.push(soa);
                    }
                    Reply::NxDomain(soa) => {
                        response.metadata.authoritative = true;
                        response.metadata.response_code = ResponseCode::NXDomain;
                        response.authorities.push(soa);
                    }
                    Reply::Silent => silent = true,
                }
            }
            if silent {
                continue;
            }
            let bytes = response.to_vec().unwrap();
            if socket.send_to(&bytes, peer).await.is_err() {
                return;
            }
        }
    });
}

/// Hold every TCP connection open without answering, as a silent server
/// does: a recursor that falls back to TCP must not get an answer there
/// either.
fn spawn_silent_tcp(listener: tokio::net::TcpListener) {
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => held.push(stream),
                Err(_) => return,
            }
        }
    });
}

async fn spawn_hierarchy() -> u16 {
    'retry: loop {
        let root = tokio::net::UdpSocket::bind((ROOT, 0)).await.unwrap();
        let port = root.local_addr().unwrap().port();
        let mut sockets = vec![(root, ROOT)];
        for server in [TLD, SILENT, ALIVE] {
            match tokio::net::UdpSocket::bind((server, port)).await {
                Ok(socket) => sockets.push((socket, server)),
                Err(_) => continue 'retry,
            }
        }
        // The silent server also accepts TCP and never replies on it.
        if let Ok(listener) = tokio::net::TcpListener::bind((SILENT, port)).await {
            spawn_silent_tcp(listener);
        }
        for (socket, server) in sockets {
            spawn_fake(socket, server);
        }
        return port;
    }
}

async fn spawn_recursive() -> (daygle_dns::BoundServer, tempfile::TempDir) {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Recursive);
    config.recursive.root_hints = vec![ROOT.to_string()];
    config.recursive.test_outbound_port = Some(port);
    config.recursive.dnssec_validate = false;
    // The default wait for one name server, and enough client timeout for a
    // fallback to fit: the recursor's per-send budget is 5s.
    config.recursive.timeout_secs = 5;
    config.server.client_timeout_ms = 8_000;
    (spawn(config).await, dir)
}

/// Send a UDP query and answer with the reply and how long it took, waiting
/// longer than the client timeout so a slow failure is asserted on rather
/// than panicking in the helper.
async fn timed_query(
    addr: std::net::SocketAddr,
    qname: &str,
    rtype: RecordType,
) -> (Message, Duration) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = query_message(qname, rtype).to_vec().unwrap();
    let started = Instant::now();
    socket.send_to(&bytes, addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .expect("no reply at all")
        .unwrap();
    (Message::from_vec(&buf[..n]).unwrap(), started.elapsed())
}

#[tokio::test]
async fn a_zone_whose_first_name_server_is_silent_resolves_from_its_second() {
    let (server, _dir) = spawn_recursive().await;
    let udp = server.udp_addr.unwrap();
    let (msg, took) = timed_query(udp, "www.silent.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError, "{msg:?}");
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.9"));
    // The silent server is abandoned early enough for the working one to be
    // asked inside the recursor's 5s budget for the query.
    assert!(
        took < Duration::from_secs(5),
        "the answer took {took:?}: the silent server was waited out"
    );
    shutdown(server).await;
}
