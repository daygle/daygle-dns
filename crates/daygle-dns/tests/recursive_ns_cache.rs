//! Integration test: recursive mode keeps resolving a zone after its name
//! servers have left the recursor's name server cache.
//!
//! The recursor then rebuilds them from the zone's NS records in its
//! response cache. Once the zone's own NS answer (sent without addresses)
//! has replaced the parent's referral there, the only addresses to be had
//! are the glue in the parent's referral - which the recursor used to
//! overlook, failing the zone with "no glue found for any nameservers".

mod common;

use std::net::Ipv4Addr;

use common::*;
use daygle_dns_core::config::ResolutionMode;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

const ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 2, 2);
const TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 2, 3);
const AUTH: Ipv4Addr = Ipv4Addr::new(127, 0, 2, 4);

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

/// The zone (`zN.test.`) a name is in.
fn zone_of(qname: &str) -> Option<String> {
    let labels: Vec<&str> = qname.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    (n >= 2 && labels[n - 1] == "test" && labels[n - 2].starts_with('z'))
        .then(|| format!("{}.test.", labels[n - 2]))
}

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
    if let Some(zone) = zone_of(qname) {
        let server = format!("ns.{zone}");
        return Reply::Referral(vec![ns(&zone, &server)], vec![a(&server, AUTH)]);
    }
    Reply::NxDomain(soa("test."))
}

/// Every `zN.test.` zone, answering with no additional records.
fn auth_server(qname: &str, qtype: RecordType) -> Reply {
    let Some(zone) = zone_of(qname) else {
        return Reply::NxDomain(soa("test."));
    };
    let server = format!("ns.{zone}");
    match qtype {
        RecordType::NS if qname == zone => Reply::Answer(vec![ns(&zone, &server)]),
        RecordType::A if qname == server => Reply::Answer(vec![a(&server, AUTH)]),
        RecordType::A if qname == format!("www.{zone}") => {
            Reply::Answer(vec![a(qname, Ipv4Addr::new(198, 51, 100, 7))])
        }
        _ => Reply::NoData(soa(&zone)),
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

#[tokio::test]
async fn a_zone_still_resolves_after_its_name_servers_leave_the_cache() {
    let port = spawn_hierarchy().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Recursive);
    config.recursive.root_hints = vec![ROOT.to_string()];
    config.recursive.test_outbound_port = Some(port);
    config.recursive.dnssec_validate = false;
    config.recursive.timeout_secs = 2;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "www.z0.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    // The zone's own NS answer (no glue) replaces the referral in the cache.
    let msg = udp_query(udp, "z0.test.", RecordType::NS).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    // Enough other zones to push z0's name servers out of the cache.
    for n in 1..1100 {
        let msg = udp_query(udp, &format!("www.z{n}.test."), RecordType::A).await;
        assert_eq!(msg.response_code, ResponseCode::NoError, "z{n}");
    }
    let msg = udp_query(udp, "other.z0.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError, "{msg:?}");
    shutdown(server).await;
}
