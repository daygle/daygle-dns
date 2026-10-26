//! Integration test: conditional forwarding. Queries for a configured zone
//! are resolved by that zone's dedicated upstreams; everything else falls
//! through to the default upstreams.

mod common;

use common::*;
use daygle_dns_core::config::ConditionalZoneConfig;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};

/// A UDP DNS stub that answers every name under `<zone>.` with `ip` and
/// NXDOMAIN for everything else.
async fn spawn_stub(zone: &str, ip: &str) -> std::net::SocketAddr {
    let suffix = format!(".{zone}.");
    let ip: std::net::Ipv4Addr = ip.parse().unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mut buf = vec![0u8; 4096];

    tokio::spawn(async move {
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let query = match Message::from_vec(&buf[..len]) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_available = true;
            for q in query.queries.iter() {
                let qname = q.name().to_string();
                response.queries.push(q.clone());
                if qname.ends_with(&suffix) {
                    response.metadata.response_code = ResponseCode::NoError;
                    let record = Record::from_rdata(q.name().clone(), 60, RData::A(ip.into()));
                    response.answers.push(record);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            let bytes = response.to_vec().unwrap();
            if socket.send_to(&bytes, peer).await.is_err() {
                return;
            }
        }
    });

    addr
}

#[tokio::test]
async fn conditional_zone_resolves_via_dedicated_upstream() {
    // Two independent upstream stubs.
    //   stub_a: everything under zonea.test  -> 198.51.100.10
    //   stub_b: everything under zoneb.test  -> 198.51.100.20
    let stub_a = spawn_stub("zonea.test", "198.51.100.10").await;
    let stub_b = spawn_stub("zoneb.test", "198.51.100.20").await;

    // The main server forwards everything to stub_a by default, except
    // zoneb.test, which must go to stub_b.
    let mut config = base_config(&tempfile::tempdir().unwrap().path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![stub_a.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    config.recursive.conditional_zones = vec![ConditionalZoneConfig {
        name: "zoneb.test".to_string(),
        upstreams: vec![stub_b.to_string()],
    }];

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // Default upstream answers its own zone.
    let msg = udp_query(udp, "host.zonea.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.10"));

    // The conditional zone (apex and subdomains) is answered by its
    // dedicated upstream.
    let msg = udp_query(udp, "host.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.20"));

    let msg = udp_query(udp, "deep.host.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.20"));

    // A name outside both conditional and default zones is NXDOMAIN (stub_a
    // does not host it) and the code passes through.
    let msg = udp_query(udp, "host.zonec.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn console_conditional_zone_applies_live() {
    // Default upstream hosts zonea.test only; zoneb.test is unknown to it
    // until the console adds a conditional forwarder pointing at stub_b.
    let stub_a = spawn_stub("zonea.test", "198.51.100.10").await;
    let stub_b = spawn_stub("zoneb.test", "198.51.100.20").await;

    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![stub_a.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    // Real ports: validation rejects port 0, and that pre-existing error
    // would otherwise mask the error this test expects from a bad update.
    config.server.port = free_port();
    config.api.port = free_port();

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api/config", server.api_addr);
    let client = reqwest::Client::new();

    let msg = udp_query(udp, "host.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    // A forwarder without upstreams is rejected and changes nothing.
    let bad = client
        .put(&api)
        .json(&serde_json::json!({
            "recursive": { "conditional_zones": [{ "name": "zoneb.test", "upstreams": [] }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    // Names are normalized and blank upstreams dropped; the resolver is
    // rebuilt so the forwarder serves immediately, without a restart.
    let ok = client
        .put(&api)
        .json(&serde_json::json!({
            "recursive": { "conditional_zones": [
                { "name": " ZoneB.Test. ", "upstreams": [format!(" {stub_b} "), ""] }
            ] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let cfg: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(
        cfg["recursive"]["conditional_zones"],
        serde_json::json!([{ "name": "zoneb.test", "upstreams": [stub_b.to_string()] }])
    );

    let msg = udp_query(udp, "host.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.20"));

    // Removing it falls back to the default upstream again.
    let cleared = client
        .put(&api)
        .json(&serde_json::json!({ "recursive": { "conditional_zones": [] } }))
        .send()
        .await
        .unwrap();
    assert_eq!(cleared.status(), 200);
    let msg = udp_query(udp, "fresh.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}
