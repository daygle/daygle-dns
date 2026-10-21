//! Integration test: with `[syslog]` turned on in Settings, server-log
//! entries and (when asked) query lines reach a syslog server over UDP and
//! over TCP, as RFC 5424 lines.

mod common;

use std::time::Duration;

use common::*;
use hickory_proto::rr::RecordType;
use serde_json::json;
use tokio::io::AsyncReadExt;

async fn put_syslog(api: &str, settings: serde_json::Value) -> reqwest::StatusCode {
    reqwest::Client::new()
        .put(format!("{api}/config"))
        .json(&json!({ "syslog": settings }))
        .send()
        .await
        .unwrap()
        .status()
}

/// Make the server log a warning (a failed sign-in).
async fn log_something(api: &str) {
    reqwest::Client::new()
        .post(format!("{api}/auth/login"))
        .json(&json!({ "username": "nobody", "password": "wrong-password" }))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn logs_reach_a_syslog_server() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let api = format!("http://{}/api", server.api_addr);
    let udp = server.udp_addr.unwrap();

    // Bad settings are refused.
    assert_eq!(
        put_syslog(&api, json!({ "enabled": true, "server": "" })).await,
        400
    );
    assert_eq!(
        put_syslog(
            &api,
            json!({ "enabled": true, "server": "127.0.0.1", "facility": "local9" })
        )
        .await,
        400
    );

    // UDP, with queries.
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = receiver.local_addr().unwrap();
    assert_eq!(
        put_syslog(
            &api,
            json!({ "enabled": true, "server": format!("udp://{target}"), "facility": "local3", "queries": true })
        )
        .await,
        200
    );
    udp_query(udp, "syslog.example.", RecordType::A).await;
    log_something(&api).await;
    let mut lines = Vec::new();
    let mut buf = vec![0u8; 4096];
    while lines.len() < 10 {
        match tokio::time::timeout(Duration::from_secs(3), receiver.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => lines.push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            _ => break,
        }
    }
    let query = lines
        .iter()
        .find(|l| l.contains(" query - ") && l.contains("qname=syslog.example"))
        .unwrap_or_else(|| panic!("query line in {lines:?}"));
    // local3 (19) * 8 + info (6) = 158.
    assert!(query.starts_with("<158>1 "), "{query}");
    assert!(query.contains(" daygle-dns "), "{query}");
    let warning = lines
        .iter()
        .find(|l| l.contains(" server - ") && l.contains("nobody"))
        .unwrap_or_else(|| panic!("server line in {lines:?}"));
    // local3 * 8 + warning (4) = 156.
    assert!(warning.starts_with("<156>1 "), "{warning}");

    // TCP, warnings and up only, no queries: octet-counted frames.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    assert_eq!(
        put_syslog(
            &api,
            json!({ "enabled": true, "server": format!("tcp://{target}"), "level": "warn" })
        )
        .await,
        200
    );
    udp_query(udp, "quiet.example.", RecordType::A).await;
    log_something(&api).await;
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the server connects")
        .unwrap();
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let text = String::from_utf8_lossy(&received).into_owned();
    // Split the octet-counted frames.
    let mut frames = Vec::new();
    let mut rest = text.as_str();
    while let Some((len, tail)) = rest.split_once(' ') {
        let len: usize = len.parse().expect("each frame starts with its length");
        frames.push(&tail[..len]);
        rest = &tail[len..];
    }
    assert!(!frames.is_empty());
    assert!(
        frames
            .iter()
            .all(|f| f.starts_with("<2") && f.contains(" server - ")),
        "{frames:?}"
    );
    let warning = frames
        .iter()
        .find(|f| f.contains("nobody"))
        .unwrap_or_else(|| panic!("sign-in warning in {frames:?}"));
    assert!(warning.starts_with("<28>1 "), "daemon/warning: {warning}");
    assert!(!text.contains("quiet.example"), "queries are off: {text}");
    assert!(
        !text.contains("Settings updated"),
        "info is below warn: {text}"
    );
    shutdown(server).await;
}
