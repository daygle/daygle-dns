//! Integration tests: response rate limiting (RRL).

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::ZoneInput;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

/// Send one UDP query; `None` when no reply arrives in time (dropped).
async fn try_udp(addr: std::net::SocketAddr, name: &str) -> Option<Message> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = query_message(name, RecordType::SOA).to_vec().unwrap();
    socket.send_to(&bytes, addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(Message::from_vec(&buf[..n]).unwrap())
}

/// Past the rate, identical UDP answers are dropped with every second one
/// sent truncated; TCP is never limited, and log-only mode only counts.
#[tokio::test]
async fn identical_responses_are_limited_over_udp() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.rrl.enabled = true;
    config.rrl.responses_per_second = 2;
    config.rrl.slip = 2;
    config.rrl.exempt = vec![];
    let server = spawn(config).await;
    server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "rrl.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.unwrap();

    let mut answered = 0;
    let mut truncated = 0;
    let mut dropped = 0;
    for _ in 0..8 {
        match try_udp(udp, "rrl.test.").await {
            Some(m) if m.metadata.truncation => {
                assert!(m.answers.is_empty());
                truncated += 1;
            }
            Some(m) => {
                assert!(!m.answers.is_empty(), "{m:?}");
                answered += 1;
            }
            None => dropped += 1,
        }
    }
    // The burst allowance, then alternately dropped and truncated (a little
    // credit trickles back while the dropped queries time out).
    assert!((2..=4).contains(&answered), "answered {answered}");
    assert!(truncated >= 2, "truncated {truncated}");
    assert!(dropped >= 2, "dropped {dropped}");
    // TCP is not limited.
    let reply = tcp_query(server.tcp_addr.unwrap(), "rrl.test.", RecordType::SOA).await;
    assert!(!reply.answers.is_empty());
    let metrics = server.metrics.snapshot();
    assert_eq!(metrics.rrl_dropped, dropped);
    assert_eq!(metrics.rrl_slipped, truncated);

    // Log-only: everything is answered, the excess is only counted.
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({ "rrl": {
            "enabled": true, "responses_per_second": 2, "slip": 2, "exempt": [], "log_only": true
        } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    for _ in 0..6 {
        let reply = try_udp(udp, "rrl.test.").await.expect("answered");
        assert!(!reply.metadata.truncation);
    }
    assert!(server.metrics.snapshot().rrl_would_limit >= 3);

    shutdown(server).await;
}
