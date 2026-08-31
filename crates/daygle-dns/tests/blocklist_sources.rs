//! Integration test: remote blocklist sources fetched over HTTP, scheduled
//! refresh, block enforcement, and the status/refresh API endpoints.

mod common;

use common::*;
use daygle_core::config::{BlocklistFormat, BlocklistSourceConfig};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A tiny in-process HTTP server that serves a hosts-style blocklist whose
/// content can be swapped out (to exercise refresh).
struct BlocklistServer {
    addr: std::net::SocketAddr,
    body: std::sync::Arc<std::sync::Mutex<String>>,
}

impl BlocklistServer {
    async fn spawn(body: &str) -> Self {
        let body = std::sync::Arc::new(std::sync::Mutex::new(body.to_string()));
        let body2 = body.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<std::net::SocketAddr>();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(addr).unwrap();
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let body = body2.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let body = body.lock().unwrap().clone();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            addr: rx.await.unwrap(),
            body,
        }
    }

    fn set(&self, body: &str) {
        *self.body.lock().unwrap() = body.to_string();
    }
}

#[tokio::test]
async fn blocklist_source_blocks_domains_and_refreshes() {
    let dir = tempfile::tempdir().unwrap();
    let source = BlocklistServer::spawn(
        "# ad blocking list\n127.0.0.1 ads-one.test\n0.0.0.0 ads-two.test\n",
    )
    .await;

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    config.policy.blocklist_sources = vec![BlocklistSourceConfig {
        name: "test-list".to_string(),
        url: format!("http://{}/blocklist", source.addr),
        format: BlocklistFormat::Hosts,
        refresh_secs: 1,
        enabled: true,
    }];
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    // An upstream that answers everything with a known IP.
    let stub = spawn_upstream(&dir.path().join("upstream.db"), "ok.test", "198.51.100.77").await;
    config.recursive.upstreams = vec![stub.to_string()];
    config.recursive.dnssec_validate = false;

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    // Wait for the initial fetch (the refresh loop fetches on its first tick).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut blocked = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "ads-one.test.", RecordType::A).await;
        if msg.response_code == ResponseCode::NXDomain {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(blocked, "domain from the remote source was not blocked");

    // A domain outside the list is unaffected (resolves via the upstream).
    let msg = udp_query(udp, "host.ok.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.77"));

    // The API reports the source and its domain count.
    let resp = reqwest::get(format!("http://{}/api/policy/blocklist/sources", server.api_addr))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["sources"][0]["name"], "test-list");
    let fetched_domains = json["sources"][0]["domains"].as_u64().unwrap();
    assert!(fetched_domains >= 2, "expected >= 2 domains, got {fetched_domains}");

    // Change the source content and trigger a manual refresh; the new domain
    // must start being blocked.
    source.set("127.0.0.1 ads-new.test\n");
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut refreshed = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "ads-new.test.", RecordType::A).await;
        if msg.response_code == ResponseCode::NXDomain {
            refreshed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(refreshed, "refreshed source content was not applied");

    shutdown(server).await;
}
