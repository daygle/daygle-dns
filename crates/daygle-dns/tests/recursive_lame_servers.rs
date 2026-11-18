//! Integration tests: recursive mode against two kinds of real-world
//! name server setups that used to fail with SERVFAIL.
//!
//! - A zone with lame servers in its NS set (servers that answer REFUSED or
//!   SERVFAIL for it): the recursor gave up on the first such answer instead
//!   of asking the zone's other servers ("Query Refused" for
//!   `tapi.telstra.com`).
//! - IPv6 reverse names under a short delegation (`8.1.0.0.2.ip6.arpa`):
//!   finding the zone cut above a 34-label name ran past the recursor's
//!   name server recursion limit of 24.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::*;
use daygle_dns_core::config::ResolutionMode;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, PTR, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 4, 1);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 4, 2);
/// The servers of `lame.test.`: all but the last refuse or fail.
const LAME: [Ipv4Addr; 4] = [
    Ipv4Addr::new(127, 0, 4, 10),
    Ipv4Addr::new(127, 0, 4, 11),
    Ipv4Addr::new(127, 0, 4, 12),
    Ipv4Addr::new(127, 0, 4, 13),
];
/// Serves `ip6.arpa.` and refers `8.1.0.0.2.ip6.arpa.` onward.
const IP6: Ipv4Addr = Ipv4Addr::new(127, 0, 4, 20);
/// Serves `8.1.0.0.2.ip6.arpa.`.
const REVERSE: Ipv4Addr = Ipv4Addr::new(127, 0, 4, 21);

const SERVERS: [Ipv4Addr; 8] = [ROOT, TLD, LAME[0], LAME[1], LAME[2], LAME[3], IP6, REVERSE];

/// The address with a PTR record in the reverse zone.
const HOST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x8004, 0x2c42, 0x4300, 0, 0, 0, 1);

enum Reply {
    Answer(Vec<Record>),
    Referral(Vec<Record>, Vec<Record>),
    NoData(Record),
    NxDomain(Record),
    Code(ResponseCode),
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
            name("ns.invalid."),
            name("hostmaster.invalid."),
            1,
            3600,
            600,
            86400,
            60,
        )),
    )
}

fn under(qname: &str, zone: &str) -> bool {
    qname == zone || qname.ends_with(&format!(".{zone}"))
}

/// `addr` as its `ip6.arpa.` name.
fn reverse_name(addr: Ipv6Addr) -> String {
    let hex: String = addr.octets().iter().map(|b| format!("{b:02x}")).collect();
    let mut labels: Vec<String> = hex.chars().rev().map(String::from).collect();
    labels.push("ip6.arpa.".into());
    labels.join(".")
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
            if under(qname, "test.") {
                return Reply::Referral(vec![ns("test.", "ns.test.")], vec![a("ns.test.", TLD)]);
            }
            if under(qname, "ip6.arpa.") {
                return Reply::Referral(
                    vec![ns("ip6.arpa.", "ns.ip6.test.")],
                    vec![a("ns.ip6.test.", IP6)],
                );
            }
            Reply::NxDomain(soa("."))
        }
        s if s == TLD => {
            match qname {
                "ns.test." | "ns.ip6.test." if qtype == RecordType::A => {
                    return Reply::Answer(vec![a(
                        qname,
                        if qname == "ns.test." { TLD } else { IP6 },
                    )]);
                }
                "ns.reverse.test." if qtype == RecordType::A => {
                    return Reply::Answer(vec![a(qname, REVERSE)]);
                }
                _ => {}
            }
            if under(qname, "lame.test.") {
                let hosts: Vec<String> = (0..LAME.len())
                    .map(|i| format!("ns{i}.lame.test."))
                    .collect();
                return Reply::Referral(
                    hosts.iter().map(|h| ns("lame.test.", h)).collect(),
                    hosts.iter().zip(LAME).map(|(h, ip)| a(h, ip)).collect(),
                );
            }
            Reply::NxDomain(soa("test."))
        }
        s if LAME[..LAME.len() - 1].contains(&s) => {
            // Lame: alternate the two codes between servers.
            if s.octets()[3] % 2 == 0 {
                Reply::Code(ResponseCode::Refused)
            } else {
                Reply::Code(ResponseCode::ServFail)
            }
        }
        s if s == LAME[LAME.len() - 1] => match (qname, qtype) {
            ("lame.test.", RecordType::NS) => Reply::Answer(
                (0..LAME.len())
                    .map(|i| ns("lame.test.", &format!("ns{i}.lame.test.")))
                    .collect(),
            ),
            ("www.lame.test.", RecordType::A) => {
                Reply::Answer(vec![a("www.lame.test.", Ipv4Addr::new(198, 51, 100, 9))])
            }
            (q, RecordType::A) if q.starts_with("ns") && under(q, "lame.test.") => {
                let i: usize = q[2..3].parse().unwrap();
                Reply::Answer(vec![a(q, LAME[i])])
            }
            _ => Reply::NoData(soa("lame.test.")),
        },
        s if s == IP6 => {
            if under(qname, "8.1.0.0.2.ip6.arpa.") {
                return Reply::Referral(
                    vec![ns("8.1.0.0.2.ip6.arpa.", "ns.reverse.test.")],
                    vec![],
                );
            }
            if qname == "ip6.arpa." && qtype == RecordType::NS {
                return Reply::Answer(vec![ns("ip6.arpa.", "ns.ip6.test.")]);
            }
            Reply::NxDomain(soa("ip6.arpa."))
        }
        s if s == REVERSE => {
            let zone = "8.1.0.0.2.ip6.arpa.";
            if qname == zone {
                return match qtype {
                    RecordType::NS => Reply::Answer(vec![ns(zone, "ns.reverse.test.")]),
                    _ => Reply::NoData(soa(zone)),
                };
            }
            let host = reverse_name(HOST);
            if qname == host {
                return match qtype {
                    RecordType::PTR => Reply::Answer(vec![Record::from_rdata(
                        name(&host),
                        300,
                        RData::PTR(PTR(name("host.example."))),
                    )]),
                    _ => Reply::NoData(soa(zone)),
                };
            }
            if host.ends_with(&format!(".{qname}")) {
                return Reply::NoData(soa(zone));
            }
            Reply::NxDomain(soa(zone))
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
                    Reply::Code(code) => response.metadata.response_code = code,
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

async fn spawn_hierarchy() -> u16 {
    'retry: loop {
        let root = tokio::net::UdpSocket::bind((ROOT, 0)).await.unwrap();
        let port = root.local_addr().unwrap().port();
        let mut sockets = vec![(root, ROOT)];
        for server in &SERVERS[1..] {
            match tokio::net::UdpSocket::bind((*server, port)).await {
                Ok(socket) => sockets.push((socket, *server)),
                Err(_) => continue 'retry,
            }
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
    config.recursive.timeout_secs = 2;
    (spawn(config).await, dir)
}

#[tokio::test]
async fn a_zone_with_lame_servers_resolves_from_its_working_one() {
    let (server, _dir) = spawn_recursive().await;
    let udp = server.udp_addr.unwrap();
    // Asked repeatedly, so the lame servers come first at least once
    // whatever order the pool tries them in.
    for _ in 0..5 {
        let msg = udp_query(udp, "www.lame.test.", RecordType::A).await;
        assert_eq!(msg.response_code, ResponseCode::NoError, "{msg:?}");
        assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.9"));
    }
    shutdown(server).await;
}

#[tokio::test]
async fn ipv6_reverse_names_under_a_short_delegation_resolve() {
    let (server, _dir) = spawn_recursive().await;
    let udp = server.udp_addr.unwrap();
    let msg = udp_query(udp, &reverse_name(HOST), RecordType::PTR).await;
    assert_eq!(msg.response_code, ResponseCode::NoError, "{msg:?}");
    assert_eq!(first_answer(&msg).as_deref(), Some("host.example."));
    // An address with no PTR record is NXDOMAIN, not SERVFAIL.
    let other = Ipv6Addr::new(0x2001, 0x8004, 0x2c42, 0x4300, 0, 0, 0, 0);
    let msg = udp_query(udp, &reverse_name(other), RecordType::PTR).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain, "{msg:?}");
    shutdown(server).await;
}
