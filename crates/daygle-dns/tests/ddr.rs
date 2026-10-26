//! Integration test: Discovery of Designated Resolvers (DDR, RFC 9462).

mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn svcb(reply: &hickory_proto::op::Message) -> Vec<String> {
    reply
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::SVCB)
        .map(|r| r.data.to_string())
        .collect()
}

/// The encrypted listeners are advertised at `_dns.resolver.arpa` and
/// `_dns.<name>`, only to clients allowed on them; the rest of
/// `resolver.arpa` stays local.
#[tokio::test]
async fn encrypted_listeners_are_advertised() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    for (enabled, cert, key, name) in [
        (
            &mut config.dot.enabled,
            &mut config.dot.cert_path,
            &mut config.dot.key_path,
            &mut config.dot.server_name,
        ),
        (
            &mut config.doh.enabled,
            &mut config.doh.cert_path,
            &mut config.doh.key_path,
            &mut config.doh.server_name,
        ),
    ] {
        *enabled = true;
        *cert = dir.path().join("server.crt").to_string_lossy().to_string();
        *key = dir.path().join("server.key").to_string_lossy().to_string();
        *name = "dns.daygle.test".to_string();
    }
    config.dot.self_signed = true;
    config.doh.self_signed = true;
    config.doh.http3 = true;
    config.dot.port = 0;
    config.doh.port = 0;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let reply = udp_query(udp, "_dns.resolver.arpa.", RecordType::SVCB).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    let records = svcb(&reply);
    assert_eq!(records.len(), 2, "{records:?}");
    let doh = records
        .iter()
        .find(|r| r.contains("h2"))
        .expect("DoH record");
    assert!(doh.contains("dns.daygle.test."), "{doh}");
    assert!(doh.contains("h3"), "{doh}");
    assert!(doh.contains("dns-query{?dns}"), "{doh}");
    assert!(records.iter().any(|r| r.contains("dot")), "{records:?}");
    // By name too.
    let reply = udp_query(udp, "_dns.dns.daygle.test.", RecordType::SVCB).await;
    assert_eq!(svcb(&reply).len(), 2);
    // Other types and names under resolver.arpa are answered here.
    let reply = udp_query(udp, "_dns.resolver.arpa.", RecordType::A).await;
    assert!(reply.answers.is_empty() && reply.response_code == ResponseCode::NoError);
    let reply = udp_query(udp, "other.resolver.arpa.", RecordType::SVCB).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain);

    // A listener this client may not use is not advertised.
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({ "dot": { "allowed_networks": ["10.0.0.0/8"] } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let records = svcb(&udp_query(udp, "_dns.resolver.arpa.", RecordType::SVCB).await);
    assert_eq!(records.len(), 1, "{records:?}");

    // Off: nothing is advertised.
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({ "ddr": { "enabled": false } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let reply = udp_query(udp, "_dns.resolver.arpa.", RecordType::SVCB).await;
    assert!(reply.answers.is_empty() && reply.response_code == ResponseCode::NoError);

    shutdown(server).await;
}
