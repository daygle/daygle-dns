//! Integration tests: DNS rebinding protection and DNS payload limits on
//! forwarded answers.

mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A forwarding server whose upstream hosts `filters.test`: a public
/// address, a private one, a little TXT data and a lot.
async fn forwarding_server(
    dir: &tempfile::TempDir,
    rebinding_protection: bool,
    allowlist: &[&str],
) -> daygle_dns::BoundServer {
    // Just over the 1024-byte TXT limit, yet small enough to cross from the
    // UDP-only upstream in one EDNS datagram (1232 bytes).
    let long = "a".repeat(220);
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "filters.test",
        &[
            ("public", "A", "198.51.100.10"),
            ("rebind", "A", "192.168.1.10"),
            ("trusted", "A", "192.168.1.11"),
            ("small", "TXT", "v=spf1 -all"),
            ("big", "TXT", &format!("{long}1")),
            ("big", "TXT", &format!("{long}2")),
            ("big", "TXT", &format!("{long}3")),
            ("big", "TXT", &format!("{long}4")),
            ("big", "TXT", &format!("{long}5")),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.recursive.rebinding_protection = rebinding_protection;
    config.policy.allowlist = allowlist.iter().map(|d| d.to_string()).collect();
    spawn(config).await
}

/// Whether `reply` is the empty `NOERROR` answer a response filter sends.
fn filtered(reply: &hickory_proto::op::Message) -> bool {
    reply.response_code == ResponseCode::NoError && reply.answers.is_empty()
}

#[tokio::test]
async fn groups_filter_local_addresses_and_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let server = forwarding_server(&dir, false, &[]).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // Off by default: everything comes through.
    let reply = udp_query(udp, "rebind.filters.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.168.1.10"));
    let reply = tcp_query(
        server.tcp_addr.unwrap(),
        "big.filters.test.",
        RecordType::TXT,
    )
    .await;
    assert_eq!(reply.answers.len(), 5, "{reply:?}");

    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "everyone",
            "block_local_addresses": true,
            "limit_payloads": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let group: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(group["block_local_addresses"], true);
    assert_eq!(group["limit_payloads"], true);

    let reply = udp_query(udp, "rebind.filters.test.", RecordType::A).await;
    assert!(filtered(&reply), "{reply:?}");
    let reply = tcp_query(
        server.tcp_addr.unwrap(),
        "big.filters.test.",
        RecordType::TXT,
    )
    .await;
    assert!(filtered(&reply), "{reply:?}");
    // Everyday answers are untouched.
    let reply = udp_query(udp, "public.filters.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.10"));
    let reply = udp_query(udp, "small.filters.test.", RecordType::TXT).await;
    assert_eq!(reply.answers.len(), 1);

    // The query log says why.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let log: serde_json::Value = client
            .get(format!("{base}/querylogs?outcome=blocked&per_page=100"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let text = log.to_string();
        if text.contains("local_address") && text.contains("payload") {
            assert!(text.contains("192.168.1.10"), "{text}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{text}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    shutdown(server).await;
}

#[tokio::test]
async fn global_rebinding_protection_applies_when_forwarding() {
    let dir = tempfile::tempdir().unwrap();
    let server = forwarding_server(&dir, true, &["trusted.filters.test"]).await;
    let udp = server.udp_addr.unwrap();

    let reply = udp_query(udp, "rebind.filters.test.", RecordType::A).await;
    assert!(filtered(&reply), "{reply:?}");
    let reply = udp_query(udp, "public.filters.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.10"));

    // An allowlisted name is trusted.
    let reply = udp_query(udp, "trusted.filters.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.168.1.11"));

    shutdown(server).await;
}
