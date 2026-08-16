//! Integration test: conditional forwarding. Queries for a configured zone
//! are resolved by that zone's dedicated upstreams; everything else falls
//! through to the default upstreams.

mod common;

use common::*;
use daygle_core::config::ConditionalZoneConfig;
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
    let mut config = base_config(&tempfile::tempdir().unwrap().path().join("daygle.db"));
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
