//! Integration tests: reports (summaries of the query log, and sending
//! them to the alert destinations). In their own test binary because the
//! alert sender is process-wide.

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

/// The report summarizes the query log, per device too, and "send now"
/// delivers it to the alert destinations.
#[tokio::test]
async fn reports_summarize_and_send() {
    let dir = tempfile::tempdir().unwrap();
    let (url, mut rx) = webhook().await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.blocklist = vec!["ads.report.test".to_string()];
    config.logging.query_db_enabled = true;
    let server = spawn(config).await;
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let udp = server.udp_addr.unwrap();
    for _ in 0..3 {
        udp_query(udp, "ads.report.test.", hickory_proto::rr::RecordType::A).await;
    }

    // The query log is written in the background.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let report = loop {
        let body: serde_json::Value = client
            .get(format!("{base}/reports?hours=1"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if body["report"]["queries"].as_u64().unwrap_or(0) >= 3 {
            break body;
        }
        assert!(std::time::Instant::now() < deadline, "{body}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(report["report"]["blocked"], 3);
    assert_eq!(
        report["report"]["top_blocked"][0]["name"],
        "ads.report.test"
    );
    assert_eq!(report["report"]["clients"][0]["client"], "127.0.0.1");
    let one: serde_json::Value = client
        .get(format!("{base}/reports?hours=1&client=127.0.0.9"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one["report"]["queries"], 0);

    // Without a destination, sending is refused with the reason.
    let resp = client
        .post(format!("{base}/reports/send"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({
            "alerts": { "webhook_url": url },
            "reports": { "enabled": true, "frequency": "daily" },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = client
        .post(format!("{base}/reports/send"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let sent = next(&mut rx).await;
    assert_eq!(sent["kind"], "report");
    assert_eq!(sent["title"], "Daily DNS report");
    assert!(
        sent["message"]
            .as_str()
            .unwrap()
            .contains("ads.report.test"),
        "{sent}"
    );

    shutdown(server).await;
}
