//! Integration test: DNS64 (RFC 6147). An IPv4-only name gets AAAA records
//! inside the NAT64 prefix, for the clients DNS64 serves, unless the client
//! validates for itself.

mod common;

use common::*;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde_json::json;

fn aaaa_answers(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
}

async fn send(addr: std::net::SocketAddr, msg: &Message) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

#[tokio::test]
async fn aaaa_is_synthesized_from_a() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream(
        &dir.path().join("upstream.db"),
        "v4only.test",
        "198.51.100.9",
    )
    .await;

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let set = |body: serde_json::Value| {
        let client = client.clone();
        let api = api.clone();
        async move {
            client
                .put(format!("{api}/config"))
                .json(&json!({ "dns64": body }))
                .send()
                .await
                .unwrap()
        }
    };

    // Off: no AAAA.
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(aaaa_answers(&msg).is_empty());

    // On, with a network-specific prefix (which may carry any address).
    let resp = set(json!({ "enabled": true, "prefix": "2001:db8:64::/96" })).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(aaaa_answers(&msg), ["2001:db8:64::c633:6409"]);
    assert!(!msg.authentic_data);
    // A queries are untouched; a missing name stays missing.
    let msg = udp_query(udp, "host.v4only.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.9"));
    let msg = udp_query(udp, "nothing.v4only.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    // A client that validates for itself (DO + CD) gets the real answer.
    let mut query = Message::new(0x6464, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.metadata.checking_disabled = true;
    query.add_query(Query::query(
        Name::from_ascii("host.v4only.test.").unwrap(),
        RecordType::AAAA,
    ));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    query.set_edns(edns);
    assert!(aaaa_answers(&send(udp, &query).await).is_empty());

    // The well-known prefix does not carry non-global addresses (the
    // upstream's is a documentation address).
    let resp = set(json!({ "enabled": true, "prefix": "64:ff9b::/96" })).await;
    assert!(resp.status().is_success());
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert!(aaaa_answers(&msg).is_empty());

    // Only the listed clients are served.
    let resp =
        set(json!({ "enabled": true, "prefix": "2001:db8:64::/96", "clients": ["10.0.0.0/8"] }))
            .await;
    assert!(resp.status().is_success());
    let msg = udp_query(udp, "host.v4only.test.", RecordType::AAAA).await;
    assert!(aaaa_answers(&msg).is_empty());

    // Bad settings are refused.
    let resp = set(json!({ "enabled": true, "prefix": "64:ff9b::/80" })).await;
    assert_eq!(resp.status(), 400);

    shutdown(server).await;
}
