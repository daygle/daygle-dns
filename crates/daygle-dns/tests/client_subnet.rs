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

/// A forwarding target that answers every A query with 192.0.2.1 and
/// records any ECS option it was sent.
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
            log.lock().unwrap().push((name.clone(), ecs));
            let mut reply = Message::new(query.id, MessageType::Response, query.op_code);
            reply.metadata.recursion_desired = true;
            reply.metadata.recursion_available = true;
            reply.add_query(query.queries[0].clone());
            if query.queries[0].query_type() == RecordType::A {
                reply.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, 1)),
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
