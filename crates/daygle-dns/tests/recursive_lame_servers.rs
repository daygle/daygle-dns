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
//! - A chain of CNAMEs between deeply nested names (`global.cainiao.com`,
//!   through Alibaba's GDS): the recursor counts each label of each name in
//!   the chain against one depth limit, and the chain ran past 24.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::*;
use daygle_dns_core::config::ResolutionMode;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, NS, PTR, SOA};
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

/// How many names the CNAME chain under `lame.test.` has.
const CHAIN_HOPS: usize = 6;

/// The `hop`th name of the CNAME chain: six labels below `lame.test.`,
/// none shared with another hop, as in the Alibaba GDS chain.
fn chain_name(hop: usize) -> String {
    format!("host.ovs.sg{hop}.tengine{hop}.ingress{hop}.chain{hop}.lame.test.")
}

/// Which hop of the CNAME chain `qname` is, if it is one.
fn chain_hop(qname: &str) -> Option<usize> {
    (0..CHAIN_HOPS).find(|&hop| chain_name(hop) == qname)
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
            // A CNAME is the answer for every type, NS included.
            ("alias.lame.test.", _) => Reply::Answer(vec![Record::from_rdata(
                name("alias.lame.test."),
                300,
                RData::CNAME(CNAME(name("www.lame.test."))),
            )]),
            // A chain of CNAMEs between deep names, the last with an address.
            (q, qtype) if chain_hop(q).is_some() => {
                let hop = chain_hop(q).unwrap();
                if hop + 1 < CHAIN_HOPS {
                    Reply::Answer(vec![Record::from_rdata(
                        name(q),
                        300,
                        RData::CNAME(CNAME(name(&chain_name(hop + 1)))),
                    )])
                } else if qtype == RecordType::A {
                    Reply::Answer(vec![a(q, Ipv4Addr::new(198, 51, 100, 7))])
                } else {
                    Reply::NoData(soa("lame.test."))
                }
            }
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
async fn a_long_cname_chain_between_deep_names_resolves() {
    let (server, _dir) = spawn_recursive().await;
    let udp = server.udp_addr.unwrap();
    let msg = udp_query(udp, &chain_name(0), RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError, "{msg:?}");
    assert_eq!(msg.answers.len(), CHAIN_HOPS, "{msg:?}");
    assert_eq!(
        msg.answers.last().map(|r| r.data.to_string()).as_deref(),
        Some("198.51.100.7"),
        "{msg:?}"
    );
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

#[tokio::test]
async fn the_lookup_page_reports_the_answer_and_every_query_sent() {
    let (server, _dir) = spawn_recursive().await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let lookup = |name: String, rtype: &str| {
        client
            .post(format!("{base}/resolver/lookup"))
            .json(&serde_json::json!({ "name": name, "type": rtype }))
            .send()
    };

    let body: serde_json::Value = lookup("www.lame.test".into(), "A")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["rcode"], "NOERROR", "{body}");
    assert_eq!(body["route"], "recursive");
    assert_eq!(body["answers"][0]["data"], "198.51.100.9");
    let trace = body["trace"].as_array().unwrap();
    // The walk starts at the root, and the lame servers' refusals are
    // listed alongside the working server's answer.
    assert_eq!(trace[0]["server"], ROOT.to_string(), "{body}");
    assert!(
        trace
            .iter()
            .any(|s| s["rcode"] == "REFUSED" || s["rcode"] == "SERVFAIL"),
        "{body}"
    );
    assert!(
        trace
            .iter()
            .any(|s| s["name"] == "www.lame.test." && s["rcode"] == "NOERROR"),
        "{body}"
    );

    // A name that does not exist is NXDOMAIN with its zone, not a failure.
    let missing = Ipv6Addr::new(0x2001, 0x8004, 0x2c42, 0x4300, 0, 0, 0, 0);
    let body: serde_json::Value = lookup(reverse_name(missing), "PTR")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["rcode"], "NXDOMAIN", "{body}");
    assert_eq!(body["negative_zone"], "8.1.0.0.2.ip6.arpa.");
    assert!(body["error"].is_null());

    // Bad input is refused.
    let resp = lookup("www.lame.test".into(), "NOPE").await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    shutdown(server).await;
}

#[tokio::test]
async fn an_ns_question_answered_with_a_cname_is_cached() {
    let (server, _dir) = spawn_recursive().await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let lookup = |rtype: &str| {
        client
            .post(format!("{base}/resolver/lookup"))
            .json(&serde_json::json!({ "name": "alias.lame.test", "type": rtype, "fresh": false }))
            .send()
    };
    let asked_ns = |body: &serde_json::Value| {
        body["trace"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["name"] == "alias.lame.test." && s["type"] == "NS")
            .count()
    };

    let body: serde_json::Value = lookup("A").await.unwrap().json().await.unwrap();
    assert_eq!(body["rcode"], "NOERROR", "{body}");
    assert!(asked_ns(&body) > 0, "{body}");
    // The recursor asks for the NS records of the name again on the next
    // lookup through it unless the CNAME it got back is cached.
    let body: serde_json::Value = lookup("TXT").await.unwrap().json().await.unwrap();
    assert_eq!(asked_ns(&body), 0, "{body}");
    shutdown(server).await;
}
