//! Integration test: remote blocklist sources fetched over HTTP, scheduled
//! refresh, block enforcement, and the status/refresh API endpoints.

mod common;

use common::*;
use daygle_dns_core::config::{BlocklistFormat, BlocklistSourceConfig};
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
        scope: Default::default(),
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
    let resp = reqwest::get(format!(
        "http://{}/api/policy/blocklist/sources",
        server.api_addr
    )) // lgtm
    .await
    .unwrap();
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["sources"][0]["name"], "test-list");
    let fetched_domains = json["sources"][0]["domains"].as_u64().unwrap();
    assert!(
        fetched_domains >= 2,
        "expected >= 2 domains, got {fetched_domains}"
    );

    // The status also carries the wall-clock time of the last successful
    // fetch as an RFC 3339 timestamp (the console's "Last Updated" column).
    let last_fetch_at = json["sources"][0]["last_fetch_at"]
        .as_str()
        .unwrap_or_else(|| panic!("last_fetch_at missing: {json}"));
    let fetched_at = chrono::DateTime::parse_from_rfc3339(last_fetch_at)
        .unwrap_or_else(|e| panic!("last_fetch_at not RFC 3339 ({e}): {last_fetch_at}"))
        .with_timezone(&chrono::Utc);
    let age = chrono::Utc::now() - fetched_at;
    assert!(
        age > -chrono::Duration::seconds(5) && age < chrono::Duration::minutes(5),
        "last_fetch_at {last_fetch_at} is not within the last 5 minutes"
    );

    // Change the source content and trigger a manual refresh; the new domain
    // must start being blocked.
    source.set("127.0.0.1 ads-new.test\n");
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        )) // lgtm
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

/// With no `[[policy.blocklist_sources]]` configured, the endpoints report 404
/// so the console can show "no sources" guidance instead of an empty list.
#[tokio::test]
async fn blocklist_sources_404_when_none_configured() {
    let dir = tempfile::tempdir().unwrap();
    let config = base_config(&dir.path().join("daygle-dns.db"));
    let server = spawn(config).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        )) // lgtm
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    let resp = client
        .post(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        )) // lgtm
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    shutdown(server).await;
}

/// Sources can be added, edited and removed through the console API (PUT with
/// the full desired list) without a restart: the change is persisted, applied
/// live, and fetched domains start - or stop - blocking immediately.
#[tokio::test]
async fn blocklist_sources_can_be_managed_through_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let one = BlocklistServer::spawn("# list one\n0.0.0.0 ads-crud-one.test\n").await;
    let two = BlocklistServer::spawn("# list two\n127.0.0.1 ads-crud-two.test\n").await;

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    let stub = spawn_upstream(&dir.path().join("upstream.db"), "ok.test", "198.51.100.77").await;
    config.recursive.upstreams = vec![stub.to_string()];
    config.recursive.dnssec_validate = false;

    let server = spawn(config).await;
    let client = reqwest::Client::new();
    let base = format!("http://{}/api/policy/blocklist/sources", server.api_addr);
    let udp = server.udp_addr.unwrap();

    // Nothing configured yet.
    let resp = client.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    let source = |name: &str, addr: std::net::SocketAddr| {
        serde_json::json!({
            "name": name,
            "url": format!("http://{addr}/list"),
            "format": "hosts",
            "refresh_secs": 3600,
            "enabled": true,
        })
    };

    // Add two sources in one PUT (the console always sends the full list).
    let resp = client
        .put(&base)
        .json(&serde_json::json!({ "sources": [source("one", one.addr), source("two", two.addr)] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "PUT failed: {}", resp.status());

    // Wait for the background fetch: both sources must report domain counts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut fetched = false;
    while std::time::Instant::now() < deadline {
        let json: serde_json::Value = client
            .get(&base)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let list = json["sources"].as_array().unwrap();
        if list.len() == 2 && list.iter().all(|s| s["domains"].as_u64().unwrap_or(0) >= 1) {
            fetched = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(fetched, "sources were not fetched after the PUT");

    // A domain from an added source is blocked...
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut blocked = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "ads-crud-one.test.", RecordType::A).await;
        if msg.response_code == ResponseCode::NXDomain {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(blocked, "domain from the PUT-added source was not blocked");

    // ...removing it (PUT with only the other source) unblocks it again.
    let resp = client
        .put(&base)
        .json(&serde_json::json!({ "sources": [source("two", two.addr)] }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "removal PUT failed: {}",
        resp.status()
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut unblocked = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "ads-crud-one.test.", RecordType::A).await;
        if msg.response_code != ResponseCode::NXDomain {
            unblocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(unblocked, "removed source kept blocking after the PUT");

    // Clearing the whole list returns the endpoint to 404 and stops the
    // remaining domain blocking right away.
    let resp = client
        .put(&base)
        .json(&serde_json::json!({ "sources": [] }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "clear PUT failed: {}",
        resp.status()
    );
    let resp = client.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut cleared = false;
    while std::time::Instant::now() < deadline {
        let msg = udp_query(udp, "ads-crud-two.test.", RecordType::A).await;
        if msg.response_code != ResponseCode::NXDomain {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        cleared,
        "domains kept blocking after all sources were removed"
    );

    // Invalid payloads are rejected (non-HTTP URL, duplicate names) and the
    // current (empty) state is untouched.
    for bad in [
        serde_json::json!({ "sources": [{ "name": "x", "url": "file:///etc/hosts", "format": "hosts" }] }),
        serde_json::json!({ "sources": [
            { "name": "dup", "url": "http://127.0.0.1:1/a", "format": "domains" },
            { "name": "DUP", "url": "http://127.0.0.1:1/b", "format": "domains" },
        ] }),
    ] {
        let resp = client.put(&base).json(&bad).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let resp = client.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    shutdown(server).await;
}

/// The validation endpoint probes a URL and checks the content really is the
/// declared format - catching a mislabeled source before it is saved - and
/// auto-detects the format when asked.
#[tokio::test]
async fn blocklist_source_validation_detects_format_mismatches() {
    let dir = tempfile::tempdir().unwrap();
    let hosts = BlocklistServer::spawn(
        "# StevenBlack-style\n127.0.0.1 localhost\n0.0.0.0 ads-validate-one.test\n0.0.0.0 ads-validate-two.test\n",
    )
    .await;
    let domains =
        BlocklistServer::spawn("# plain list\nads-validate-three.test\n*.tracker-validate.test\n")
            .await;

    let config = base_config(&dir.path().join("daygle-dns.db"));
    let server = spawn(config).await;
    let client = reqwest::Client::new();
    let base = format!(
        "http://{}/api/policy/blocklist/sources/validate",
        server.api_addr
    );
    let url_of = |addr: std::net::SocketAddr| format!("http://{addr}/list");

    // Hosts content validates as `hosts` and auto-detects as `hosts`.
    let resp = client
        .get(&base)
        .query(&[("url", url_of(hosts.addr)), ("format", "hosts".to_string())])
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["ok"], true, "hosts content did not validate: {json}");
    assert_eq!(json["format"], "hosts");
    assert!(json["domains"].as_u64().unwrap() >= 2);

    // ...but declaring it `adblock` is a mismatch, caught before saving.
    let resp = client
        .get(&base)
        .query(&[
            ("url", url_of(hosts.addr)),
            ("format", "adblock".to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        json["ok"], false,
        "hosts-as-adblock was not rejected: {json}"
    );
    assert!(
        json["reason"].as_str().unwrap().contains("hosts"),
        "reason should name the detected format: {json}"
    );

    // Auto-detect resolves the format from the content for both shapes.
    let resp = client
        .get(&base)
        .query(&[
            ("url", url_of(domains.addr)),
            ("format", "auto".to_string()),
        ])
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        json["ok"], true,
        "domains content failed auto-detect: {json}"
    );
    assert_eq!(json["format"], "domains");
    assert!(!json["sample"].as_array().unwrap().is_empty()); // Non-HTTP URLs and unknown formats are bad requests, not verdicts.
    let resp = client
        .get(&base)
        .query(&[("url", "ftp://example.com/list"), ("format", "auto")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = client
        .get(&base)
        .query(&[("url", url_of(hosts.addr)), ("format", "nope".to_string())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    shutdown(server).await;
}

/// A source scoped `dot` blocks only on the DoT listener: a public/remote
/// user over DNS-over-TLS gets NXDOMAIN for its domains, while the very same
/// query over plain UDP (the LAN path) is untouched.
#[tokio::test]
async fn dot_scoped_source_blocks_only_on_dot() {
    let dir = tempfile::tempdir().unwrap();
    // The stub upstream serves zone `ads.test` (with a host record); the
    // dot-scoped list blocks the zone apex itself, so a differential is
    // possible: the same name behaves differently on the two transports.
    let source = BlocklistServer::spawn("# public-user list\n0.0.0.0 ads.test\n").await;

    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    config.policy.blocklist_sources = vec![BlocklistSourceConfig {
        name: "dot-list".to_string(),
        url: format!("http://{}/blocklist", source.addr),
        format: BlocklistFormat::Hosts,
        refresh_secs: 1,
        enabled: true,
        scope: daygle_dns_core::config::BlocklistScope::Dot,
    }];
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    let stub = spawn_upstream(&dir.path().join("upstream.db"), "ads.test", "198.51.100.77").await;
    config.recursive.upstreams = vec![stub.to_string()];
    config.recursive.dnssec_validate = false;

    // Enable the DoT listener like tests/dot.rs does (self-signed cert).
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let dot = server.dot_addr.unwrap();

    // Wait for the initial fetch; the DoT client must see NXDOMAIN once the
    // list lands (the source refresh loop fetches on its first tick).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut blocked = false;
    while std::time::Instant::now() < deadline {
        let msg = dot_query(dot, "daygle.test", &cert, "ads.test.", RecordType::A).await;
        if msg.response_code == ResponseCode::NXDomain {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        blocked,
        "domain from the DoT-scoped source was not blocked on DoT"
    );

    // The same name over plain UDP is untouched: no NXDOMAIN, and recursion
    // through the stub yields NODATA for the zone apex (NOERROR).
    let msg = udp_query(udp, "ads.test.", RecordType::A).await;
    assert_ne!(msg.response_code, ResponseCode::NXDomain);
    assert_eq!(msg.response_code, ResponseCode::NoError);

    // An unlisted name on the DoT listener resolves via the upstream.
    let msg = dot_query(dot, "daygle.test", &cert, "host.ads.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.77"));

    // Replacing the DoT-scoped source with another (everyone-scoped) one
    // stops the DoT block. The refresher used to leave the last DoT-scoped
    // set in the engine, blocking until a restart.
    let other = BlocklistServer::spawn("0.0.0.0 other.test\n").await;
    let resp = reqwest::Client::new()
        .put(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        ))
        .json(&serde_json::json!({ "sources": [{
            "name": "other",
            "url": format!("http://{}/list", other.addr),
            "format": "hosts",
            "refresh_secs": 3600,
            "enabled": true,
        }] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "PUT failed: {}", resp.status());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut unblocked = false;
    while std::time::Instant::now() < deadline {
        let msg = dot_query(dot, "daygle.test", &cert, "ads.test.", RecordType::A).await;
        if msg.response_code != ResponseCode::NXDomain {
            unblocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(unblocked, "the removed DoT-scoped source kept blocking");

    shutdown(server).await;
}
