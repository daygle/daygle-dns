//! Integration test: EDNS Client Subnet (RFC 7871). Forwarded queries carry
//! the configured subnet, or the client's own public network; private
//! clients' addresses are not sent.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use serde_json::json;

/// What the fake upstream saw: per query name, the ECS option's address
/// and source prefix (`None`: no ECS option).
type Seen = Arc<Mutex<Vec<(String, Option<(String, u8)>)>>>;

/// A forwarding target that answers A queries like a CDN picking a server
/// by location: 198.51.100.<c> for an ECS subnet a.b.c.0, 192.0.2.1 without
/// one. Records any ECS option it was sent.
async fn fake_upstream() -> (std::net::SocketAddr, Seen) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let name = query.queries[0].name().to_string();
            let ecs = query
                .edns
                .as_ref()
                .and_then(|e| e.option(EdnsCode::Subnet))
                .and_then(|o| match o {
                    EdnsOption::Subnet(s) => Some((s.addr().to_string(), s.source_prefix())),
                    _ => None,
                });
            log.lock().unwrap().push((name.clone(), ecs.clone()));
            let mut reply = Message::new(query.id, MessageType::Response, query.op_code);
            reply.metadata.recursion_desired = true;
            reply.metadata.recursion_available = true;
            reply.add_query(query.queries[0].clone());
            if query.queries[0].query_type() == RecordType::A {
                let address = match &ecs {
                    Some((addr, _)) => {
                        let c = addr.parse::<std::net::Ipv4Addr>().unwrap().octets()[2];
                        A::new(198, 51, 100, c)
                    }
                    None => A::new(192, 0, 2, 1),
                };
                reply.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    60,
                    RData::A(address),
                ));
            }
            if let Some(edns) = &query.edns {
                let mut out = hickory_proto::op::Edns::new();
                out.set_max_payload(edns.max_payload());
                reply.set_edns(out);
            }
            let _ = socket.send_to(&reply.to_vec().unwrap(), from).await;
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn forwarded_queries_carry_the_client_subnet() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, seen) = fake_upstream().await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 1;
    config.recursive.timeout_secs = 2;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let ecs_of = |name: &str| {
        seen.lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, ecs)| ecs.clone())
            .expect("query reached the upstream")
    };

    // Off: no option.
    let msg = udp_query(udp, "one.example.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.1"));
    assert_eq!(ecs_of("one.example."), None);

    // A fixed subnet goes with every query, host bits cleared.
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({ "ecs": { "enabled": true, "subnet": "203.0.113.77/24" } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    udp_query(udp, "two.example.", RecordType::A).await;
    assert_eq!(
        ecs_of("two.example."),
        Some(("203.0.113.0".to_string(), 24))
    );

    // Per client: a loopback (private) client's address is not sent.
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({ "ecs": { "enabled": true, "subnet": "" } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    udp_query(udp, "three.example.", RecordType::A).await;
    assert_eq!(ecs_of("three.example."), None);

    // Bad settings are refused.
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({ "ecs": { "enabled": true, "ipv4_prefix": 40 } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    shutdown(server).await;
}

/// One TCP DNS query for `name` A, sent through a PROXY v1 header naming
/// `client` (the server trusts loopback as a proxy), so it comes from a
/// public address.
async fn ask_as(addr: std::net::SocketAddr, client: &str, name: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let query = query_message(name, RecordType::A).to_vec().unwrap();
    let mut bytes = format!("PROXY TCP4 {client} 127.0.0.1 40000 53\r\n").into_bytes();
    bytes.extend_from_slice(&(query.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&query);
    stream.write_all(&bytes).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut body).await.unwrap();
    first_answer(&Message::from_vec(&body).unwrap())
}

/// With each client's own network sent, an answer is for that network
/// alone (RFC 7871 section 7.3): whichever client asks first, every client
/// gets the answer for its own network, and a private client (no subnet
/// sent) gets the plain one, never another client's.
#[tokio::test]
async fn per_client_answers_are_not_shared_between_clients() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, seen) = fake_upstream().await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 1;
    config.recursive.timeout_secs = 2;
    config.ecs.enabled = true;
    config.server.proxy_protocol = vec!["127.0.0.0/8".to_string()];
    // The public clients below may use recursion too.
    config.recursive.recursion_access = daygle_dns_core::config::RecursionAccess::Allow;
    let server = spawn(config).await;
    let tcp = server.tcp_addr.unwrap();
    let udp = server.udp_addr.unwrap();

    // A phone on mobile data, then another network, then the LAN, then the
    // phone again: each gets its own answer.
    let mobile = Some("198.51.100.163".to_string());
    assert_eq!(ask_as(tcp, "1.145.163.193", "cdn.example.").await, mobile);
    assert_eq!(
        ask_as(tcp, "1.2.3.4", "cdn.example.").await.as_deref(),
        Some("198.51.100.3")
    );
    let lan = udp_query(udp, "cdn.example.", RecordType::A).await;
    assert_eq!(first_answer(&lan).as_deref(), Some("192.0.2.1"));
    assert_eq!(ask_as(tcp, "1.145.163.193", "cdn.example.").await, mobile);

    // The LAN answer is cached as before: asking again sends nothing.
    let asked = |name: &str| {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .count()
    };
    let before = asked("cdn.example.");
    let lan = udp_query(udp, "cdn.example.", RecordType::A).await;
    assert_eq!(first_answer(&lan).as_deref(), Some("192.0.2.1"));
    assert_eq!(
        asked("cdn.example."),
        before,
        "the LAN answer was not cached"
    );

    shutdown(server).await;
}
