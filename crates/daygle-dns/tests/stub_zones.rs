//! Integration test: stub zones. Queries for names inside a configured
//! `[[authoritative.stub_zones]]` go straight to that zone's own
//! nameservers; disabled stubs fall back to the normal resolution path, and
//! a stub zone beats a conditional-zone match only when it is deeper.

mod common;

use common::*;
use daygle_dns_core::config::{ConditionalZoneConfig, StubZoneConfig};
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
async fn stub_zone_resolves_via_nameserver() {
    // The stub-zone nameserver serves everything under stub.test with
    // 198.51.100.40; the default upstream serves zonea.test with
    // 198.51.100.10 and knows nothing about stub.test.
    let stub_ns = spawn_stub("stub.test", "198.51.100.40").await;
    let default_upstream = spawn_stub("zonea.test", "198.51.100.10").await;

    let mut config = base_config(&tempfile::tempdir().unwrap().path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![default_upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    config.authoritative.stub_zones = vec![StubZoneConfig {
        name: "stub.test".to_string(),
        nss: vec![stub_ns.to_string()],
        ..Default::default()
    }];

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // Apex-level and deep names inside the stub zone are answered by the
    // zone's own nameserver - not by the default upstream (which only knows
    // zonea.test and would otherwise NXDOMAIN).
    for name in ["host.stub.test.", "deep.host.stub.test."] {
        let msg = udp_query(udp, name, RecordType::A).await;
        assert_eq!(msg.response_code, ResponseCode::NoError, "{name}");
        assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.40"));
    }

    // Names outside the stub zone still resolve through the default
    // upstream.
    let msg = udp_query(udp, "host.zonea.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.10"));

    shutdown(server).await;
}

#[tokio::test]
async fn deeper_stub_wins_and_disabled_stub_ignored() {
    // default upstream: zonea.test -> .10
    // conditional zone "zone.test"   -> stub_cond (serves *.zone.test) .20
    // stub zone      "sub.zone.test" -> stub_ns   (serves *.sub.zone.test) .40
    let stub_cond = spawn_stub("zone.test", "198.51.100.20").await;
    let stub_ns = spawn_stub("sub.zone.test", "198.51.100.40").await;
    let default_upstream = spawn_stub("zonea.test", "198.51.100.10").await;

    let mut config = base_config(&tempfile::tempdir().unwrap().path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![default_upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    config.recursive.conditional_zones = vec![ConditionalZoneConfig {
        name: "zone.test".to_string(),
        upstreams: vec![stub_cond.to_string()],
    }];
    config.authoritative.stub_zones = vec![
        StubZoneConfig {
            name: "sub.zone.test".to_string(),
            nss: vec![stub_ns.to_string()],
            ..Default::default()
        },
        StubZoneConfig {
            name: "disabled.zone.test".to_string(),
            nss: vec![stub_ns.to_string()],
            enabled: false,
            ..Default::default()
        },
    ];

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // The stub zone is deeper than the conditional zone, so its nameserver
    // answers.
    let msg = udp_query(udp, "host.sub.zone.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.40"));

    // Sibling names inside the conditional zone (but outside the stub) go to
    // the conditional upstream.
    let msg = udp_query(udp, "host.other.zone.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.20"));

    // The disabled stub zone is ignored: `disabled.zone.test` falls through
    // to the conditional zone's upstream, not the stub's nameserver.
    let msg = udp_query(udp, "host.disabled.zone.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.20"));

    // Outside every layer: the default upstream's passthrough NXDOMAIN.
    let msg = udp_query(udp, "host.zoneb.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

#[tokio::test]
async fn console_stub_zone_applies_live() {
    let stub_ns = spawn_stub("stub.test", "198.51.100.40").await;
    let default_upstream = spawn_stub("zonea.test", "198.51.100.10").await;

    let mut config = base_config(&tempfile::tempdir().unwrap().path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![default_upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.attempts = 2;
    config.recursive.timeout_secs = 3;
    // Real ports: validation rejects port 0, which would mask the error
    // this test expects from a bad update.
    config.server.port = free_port();
    config.api.port = free_port();

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api/config", server.api_addr);
    let client = reqwest::Client::new();

    let msg = udp_query(udp, "host.stub.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    // An enabled stub without nameservers is rejected.
    let bad = client
        .put(&api)
        .json(&serde_json::json!({
            "authoritative": { "stub_zones": [{ "name": "stub.test", "nss": [] }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    // refresh_secs and enabled default when omitted; the resolver is rebuilt
    // so the stub serves immediately.
    let ok = client
        .put(&api)
        .json(&serde_json::json!({
            "authoritative": { "stub_zones": [{ "name": "Stub.Test.", "nss": [stub_ns.to_string()] }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let cfg: serde_json::Value = ok.json().await.unwrap();
    let stub = &cfg["authoritative"]["stub_zones"][0];
    assert_eq!(stub["name"], serde_json::json!("stub.test"));
    assert_eq!(stub["enabled"], serde_json::json!(true));
    assert_eq!(stub["refresh_secs"], serde_json::json!(3600));

    let msg = udp_query(udp, "host.stub.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.40"));

    shutdown(server).await;
}
