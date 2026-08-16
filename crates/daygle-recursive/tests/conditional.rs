//! Focused tests for the conditional-forwarding resolver against a real UDP
//! DNS stub, isolating the resolver from the full server/dispatcher stack.
//!
//! The stub answers `host.<zone>` with a fixed A record and NXDOMAIN for
//! everything else, which is enough to exercise routing.

use std::net::SocketAddr;
use std::sync::Arc;

use daygle_core::config::{ConditionalZoneConfig, RecursiveSettings};
use daygle_core::Metrics;
use daygle_recursive::RecursiveResolver;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::lookup::Lookup;

/// A UDP DNS stub that answers every name under `<zone>.` with `ip` and
/// NXDOMAIN for everything else.
async fn spawn_stub(zone: &str, ip: &str) -> SocketAddr {
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

fn settings(upstream: SocketAddr, conditional: Vec<ConditionalZoneConfig>) -> RecursiveSettings {
    let mut s = RecursiveSettings::default();
    s.enabled = true;
    s.use_system_config = false;
    s.upstreams = vec![upstream.to_string()];
    s.dnssec_validate = false;
    s.attempts = 2;
    s.timeout_secs = 3;
    s.conditional_zones = conditional;
    s
}

fn first_ip(lookup: &Lookup) -> String {
    lookup
        .answers()
        .first()
        .expect("at least one record")
        .data
        .to_string()
}

#[tokio::test]
async fn conditional_subdomain_routes_to_dedicated_upstream() {
    // Default upstream answers zonea; the conditional zone answers zoneb.
    let stub_a = spawn_stub("zonea.test", "198.51.100.10").await;
    let stub_b = spawn_stub("zoneb.test", "198.51.100.20").await;

    let resolver = RecursiveResolver::build(
        &settings(
            stub_a,
            vec![ConditionalZoneConfig {
                name: "zoneb.test".to_string(),
                upstreams: vec![stub_b.to_string()],
            }],
        ),
        Arc::new(Metrics::default()),
    )
    .unwrap();

    // Default path: zonea via stub_a.
    let apex = resolver.lookup("host.zonea.test.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&apex), "198.51.100.10");

    // Conditional path: apex and subdomains of zoneb via stub_b.
    let apex = resolver.lookup("host.zoneb.test.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&apex), "198.51.100.20");

    // Deep subdomains of the conditional zone route there too.
    let deep = resolver.lookup("deep.host.zoneb.test.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&deep), "198.51.100.20");

    // Nothing outside the conditional zone leaks into it.
    let outside = resolver.lookup("deep.host.zonea.test.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&outside), "198.51.100.10");
}
