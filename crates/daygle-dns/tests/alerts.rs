//! Integration tests: alerts by webhook. In their own test binary because
//! the alert sender is process-wide.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// A webhook receiver: each request's JSON body arrives on the channel.
async fn webhook() -> (String, mpsc::UnboundedReceiver<serde_json::Value>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        continue;
                    };
                    let length = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if body.len() < length {
                        continue;
                    }
                    let _ = tx.send(serde_json::from_str(&body[..length]).unwrap());
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
            });
        }
    });
    (url, rx)
}

async fn next(rx: &mut mpsc::UnboundedReceiver<serde_json::Value>) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("timed out waiting for the webhook")
        .expect("webhook receiver closed")
}

/// Alert settings are validated and the SMTP password is never echoed; the
/// test button and a real event (a blocklist that cannot be downloaded)
/// both reach the webhook.
#[tokio::test]
async fn alerts_reach_the_webhook() {
    let dir = tempfile::tempdir().unwrap();
    let (url, mut rx) = webhook().await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    let server = spawn(config).await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // On without anywhere to send to: refused.
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "alerts": { "enabled": true } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let alerts = serde_json::json!({
        "enabled": true,
        "webhook_url": url,
        "smtp_password": "hunter2",
    });
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "alerts": alerts }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let config: serde_json::Value = client
        .get(format!("{base}/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["alerts"]["smtp_password"], "[redacted]");
    assert_eq!(config["alerts"]["webhook_url"], url.as_str());

    // The test button.
    let resp = client
        .post(format!("{base}/alerts/test"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let alert = next(&mut rx).await;
    assert_eq!(alert["kind"], "test");
    assert_eq!(alert["source"], "daygle-dns");

    // A blocklist on a port nothing listens on.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}/list.txt", closed.local_addr().unwrap());
    drop(closed);
    let source = serde_json::json!({
        "name": "Dead List",
        "url": dead,
        "format": "domains",
        "refresh_secs": 3600,
        "enabled": true,
    });
    let resp = client
        .put(format!("{base}/policy/blocklist/sources"))
        .json(&serde_json::json!({ "sources": [source] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let alert = next(&mut rx).await;
    assert_eq!(alert["kind"], "blocklist_failure", "{alert}");
    assert!(
        alert["title"].as_str().unwrap().contains("Dead List"),
        "{alert}"
    );

    shutdown(server).await;
}
