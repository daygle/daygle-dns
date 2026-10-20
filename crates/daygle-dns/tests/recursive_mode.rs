//! Integration test: recursive mode. A fake DNS hierarchy runs on three
//! loopback addresses sharing one unprivileged port - a root server
//! (127.0.0.2), a `test.` TLD server (127.0.0.3) and an `example.test.`
//! authoritative server (127.0.0.4) - and Daygle must walk root -> TLD ->
//! authoritative to answer. Also covers recursion access control and NODATA
//! in forwarding mode.

mod common;

use std::net::{Ipv4Addr, SocketAddr};

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::{
    ConditionalZoneConfig, DaygleConfig, RecursionAccess, ResolutionMode,
};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const AUTH: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

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
            name(&format!("ns.{}", zone.trim_start_matches('.'))),
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

/// The root zone: delegates `test.` and knows nothing else.
fn root_server(qname: &str, qtype: RecordType) -> Reply {
    if qname == "." {
        return match qtype {
            RecordType::NS => Reply::Answer(vec![ns(".", "a.root.test.")]),
            _ => Reply::NoData(soa(".")),
        };
    }
    if is_under(qname, "test.") {
        return Reply::Referral(vec![ns("test.", "ns.test.")], vec![a("ns.test.", TLD)]);
    }
    Reply::NxDomain(soa("."))
}

/// The `test.` TLD: delegates `example.test.`.
fn tld_server(qname: &str, qtype: RecordType) -> Reply {
    if qname == "test." {
        return match qtype {
            RecordType::NS => Reply::Answer(vec![ns("test.", "ns.test.")]),
            _ => Reply::NoData(soa("test.")),
        };
    }
    if qname == "ns.test." && qtype == RecordType::A {
        return Reply::Answer(vec![a("ns.test.", TLD)]);
    }
    if is_under(qname, "example.test.") {
        return Reply::Referral(
            vec![ns("example.test.", "ns.example.test.")],
            vec![a("ns.example.test.", AUTH)],
        );
    }
    Reply::NxDomain(soa("test."))
}

/// The `example.test.` zone itself.
fn auth_server(qname: &str, qtype: RecordType) -> Reply {
    match (qname, qtype) {
        ("example.test.", RecordType::NS) => {
            Reply::Answer(vec![ns("example.test.", "ns.example.test.")])
        }
        ("example.test.", RecordType::SOA) => Reply::Answer(vec![soa("example.test.")]),
        ("ns.example.test.", RecordType::A) => Reply::Answer(vec![a("ns.example.test.", AUTH)]),
        ("www.example.test.", RecordType::A) => {
            Reply::Answer(vec![a("www.example.test.", Ipv4Addr::new(198, 51, 100, 7))])
        }
        ("www.example.test." | "example.test." | "ns.example.test.", _) => {
            Reply::NoData(soa("example.test."))
        }
        _ => Reply::NxDomain(soa("example.test.")),
    }
}

/// Serve `handler` over UDP on `ip:port` until the test ends.
fn spawn_fake(socket: tokio::net::UdpSocket, handler: fn(&str, RecordType) -> Reply) {
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
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                let qname = q.name().to_ascii().to_ascii_lowercase();
                match handler(&qname, q.query_type()) {
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
}

/// Bind the three fake servers on one port free on all three addresses.
async fn spawn_hierarchy() -> u16 {
    loop {
        let root = tokio::net::UdpSocket::bind((ROOT, 0)).await.unwrap();
        let port = root.local_addr().unwrap().port();
        let (Ok(tld), Ok(auth)) = (
            tokio::net::UdpSocket::bind((TLD, port)).await,
            tokio::net::UdpSocket::bind((AUTH, port)).await,
        ) else {
            continue;
        };
        spawn_fake(root, root_server);
        spawn_fake(tld, tld_server);
        spawn_fake(auth, auth_server);
        return port;
    }
}

fn recursive_config(dir: &tempfile::TempDir, port: u16) -> DaygleConfig {
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Recursive);
    config.recursive.root_hints = vec![ROOT.to_string()];
    config.recursive.test_outbound_port = Some(port);
    // The fake hierarchy is unsigned; the built-in root trust anchor would
    // (correctly) reject it.
    config.recursive.dnssec_validate = false;
    config.recursive.timeout_secs = 2;
    config
}

#[tokio::test]
async fn recursive_mode_walks_root_tld_authoritative() {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(recursive_config(&dir, port)).await;
    let udp = server.udp_addr.unwrap();

    // A real answer, three delegation levels down.
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));
    assert!(msg.recursion_available);

    // NODATA: the name exists, the type does not. Must not be NXDOMAIN.
    let msg = udp_query(udp, "www.example.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());

    // NXDOMAIN from the authoritative server and from the root.
    let msg = udp_query(udp, "missing.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    let msg = udp_query(udp, "host.no-such-tld.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn conditional_forwarder_overrides_recursive_mode() {
    let port = spawn_hierarchy().await;
    let forwarder = spawn_upstream_answering("corp.internal.", Ipv4Addr::new(10, 1, 2, 3)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    config.recursive.conditional_zones = vec![ConditionalZoneConfig {
        name: "corp.internal".to_string(),
        upstreams: vec![forwarder.to_string()],
    }];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "host.corp.internal.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("10.1.2.3"));
    // Everything else still recurses.
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn recursion_access_refuses_clients_outside_allowed_networks() {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = recursive_config(&dir, port);
    // The test client is 127.0.0.1, outside this list.
    config.recursive.recursion_access = RecursionAccess::Custom;
    config.recursive.recursion_networks = vec!["10.0.0.0/8".to_string()];
    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "local.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.9".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.unwrap();

    // Recursion is refused...
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);
    // ...but this server's own zones are answered for everyone.
    let msg = udp_query(udp, "host.local.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.9"));

    shutdown(server).await;
}

#[tokio::test]
async fn forwarding_mode_passes_nodata_through_as_noerror() {
    // The upstream knows v4only.test (A only): AAAA is NODATA, not NXDOMAIN.
    let upstream = spawn_upstream_answering("v4only.test.", Ipv4Addr::new(192, 0, 2, 44)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());
    let msg = udp_query(udp, "v4only.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.44"));

    shutdown(server).await;
}

/// A recursive upstream stub: answers A for `owner` (and names below it),
/// NODATA for other types there, NXDOMAIN elsewhere.
async fn spawn_upstream_answering(owner: &'static str, ip: Ipv4Addr) -> SocketAddr {
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
                let qname = q.name().to_ascii().to_ascii_lowercase();
                if is_under(&qname, owner) {
                    if q.query_type() == RecordType::A {
                        response.answers.push(a(&qname, ip));
                    } else {
                        response.authorities.push(soa(owner));
                    }
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
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
