//! Integration tests: CNAME inspection, Safe Search, filtering-group
//! schedules, and the response filters (DNS rebinding protection and DNS
//! payload limits) on forwarded answers.

mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A server forwarding to an upstream that hosts `shop.test`, where
/// `metrics.shop.test` is a CNAME to `tracker.shop.test`.
async fn cname_server(dir: &tempfile::TempDir) -> daygle_dns::BoundServer {
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "shop.test",
        &[
            ("host", "A", "198.51.100.10"),
            ("metrics", "CNAME", "tracker.shop.test."),
            ("tracker", "A", "198.51.100.66"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.policy.blocklist = vec!["tracker.shop.test".to_string()];
    spawn(config).await
}

/// A tracker behind a CNAME on an allowed name is blocked; turning CNAME
/// inspection off lets it through, and the allowlist always wins.
#[tokio::test]
async fn cname_targets_are_inspected() {
    let dir = tempfile::tempdir().unwrap();
    let server = cname_server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api/config", server.api_addr);
    let client = reqwest::Client::new();

    let reply = udp_query(udp, "host.shop.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.10"));
    let reply = udp_query(udp, "metrics.shop.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain, "{reply:?}");

    // Off: the CNAME chain is answered as the upstream gave it.
    let resp = client
        .put(&api)
        .json(&serde_json::json!({ "policy": { "cname_inspection": false } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let reply = udp_query(udp, "metrics.shop.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply
        .answers
        .iter()
        .any(|r| r.data.to_string() == "198.51.100.66"));

    // On again, but the queried name is allowlisted: trusted as a whole.
    let resp = client
        .put(&api)
        .json(&serde_json::json!({
            "policy": { "cname_inspection": true, "allowlist": ["metrics.shop.test"] }
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let reply = udp_query(udp, "metrics.shop.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);

    shutdown(server).await;
}

/// A server forwarding to an upstream that hosts `google.com`, with
/// `www.google.com` and the forced Safe Search address in it.
async fn search_server(dir: &tempfile::TempDir) -> daygle_dns::BoundServer {
    search_server_with(dir, |_| {}).await
}

/// [`search_server`], with `adjust` applied to its configuration first.
async fn search_server_with(
    dir: &tempfile::TempDir,
    adjust: impl FnOnce(&mut daygle_dns_core::config::DaygleConfig),
) -> daygle_dns::BoundServer {
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "google.com",
        &[
            ("www", "A", "192.0.2.80"),
            ("forcesafesearch", "A", "216.239.38.120"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    adjust(&mut config);
    spawn(config).await
}

/// Whether `reply` is a Safe Search answer: a CNAME to Google's safe
/// address followed by that address.
fn is_safe_answer(reply: &hickory_proto::op::Message) -> bool {
    reply.response_code == ResponseCode::NoError
        && reply
            .answers
            .iter()
            .any(|r| r.data.to_string() == "forcesafesearch.google.com.")
        && reply
            .answers
            .iter()
            .any(|r| r.data.to_string() == "216.239.38.120")
}

/// The global switch rewrites the search engine for everyone; a filtering
/// group turns it on for its own clients only.
#[tokio::test]
async fn safe_search_rewrites_search_engines() {
    let dir = tempfile::tempdir().unwrap();
    let server = search_server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // Off by default.
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));

    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "policy": { "safe_search": true } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert!(is_safe_answer(&reply), "{reply:?}");
    // HTTPS records are answered empty, so browsers cannot learn other
    // endpoints from them.
    let reply = udp_query(udp, "www.google.com.", RecordType::HTTPS).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty(), "{reply:?}");
    // Other Google names are untouched.
    let reply = udp_query(udp, "forcesafesearch.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("216.239.38.120"));

    // Global off, a group for 127.0.0.2 on: only that client is rewritten.
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "policy": { "safe_search": false } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "kids",
            "clients": ["127.0.0.2"],
            "safe_search": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));
    let reply = udp_query_from([127, 0, 0, 2].into(), udp, "www.google.com.", RecordType::A).await;
    assert!(is_safe_answer(&reply), "{reply:?}");

    shutdown(server).await;
}

/// A group's schedule is validated, stored and returned; an always-matching
/// window keeps the group in force.
#[tokio::test]
async fn group_schedules_are_validated_and_applied() {
    let dir = tempfile::tempdir().unwrap();
    let server = search_server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let save = |schedule: serde_json::Value| {
        client
            .post(format!("{base}/policy/blocking"))
            .json(&serde_json::json!({
                "name": "bedtime",
                "block": ["www.google.com"],
                "schedule": schedule,
            }))
            .send()
    };

    let resp = save(serde_json::json!([{ "days": ["mon"], "start": "25:00", "end": "07:00" }]))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = save(serde_json::json!([{ "days": ["someday"], "start": "21:00", "end": "07:00" }]))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // Every day, all day: always in force.
    let resp = save(serde_json::json!([{ "days": [], "start": "00:00", "end": "00:00" }]))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let group: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(group["schedule"][0]["start"], "00:00");
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain);

    // A window on every day but today: the group is skipped.
    let today = chrono::Local::now()
        .format("%a")
        .to_string()
        .to_ascii_lowercase();
    let days: Vec<&str> = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        .into_iter()
        .filter(|d| !today.starts_with(d))
        .collect();
    let resp = save(serde_json::json!([{ "days": days, "start": "12:00", "end": "12:01" }]))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));

    shutdown(server).await;
}

/// A group blocks a whole service (its domains and their subdomains) with
/// one tick; an unknown service is refused.
#[tokio::test]
async fn groups_block_services() {
    let dir = tempfile::tempdir().unwrap();
    let server = search_server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let services: serde_json::Value = client
        .get(format!("{base}/policy/services"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(services["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == "roblox"));

    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({ "name": "kids", "blocked_services": ["nope"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({ "name": "kids", "blocked_services": ["Roblox"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let group: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(group["blocked_services"], serde_json::json!(["roblox"]));

    for name in ["roblox.com.", "setup.rbxcdn.com."] {
        let reply = udp_query(udp, name, RecordType::A).await;
        assert_eq!(reply.response_code, ResponseCode::NXDomain, "{name}");
    }
    // Other names are untouched.
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));

    shutdown(server).await;
}

/// A group blocks security categories and TLDs; unknown categories and
/// anything that is not a TLD are refused, and TLDs are stored normalized.
#[tokio::test]
async fn groups_block_security_categories_and_tlds() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = spawn_feed_mirror().await;
    let server = search_server_with(&dir, |config| {
        config.policy.feed_mirror = format!("http://{mirror}");
    })
    .await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let catalog: serde_json::Value = client
        .get(format!("{base}/policy/security"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(catalog["categories"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "dynamic_dns"));

    for bad in [
        serde_json::json!({ "name": "secure", "blocked_security": ["nope"] }),
        serde_json::json!({ "name": "secure", "blocked_tlds": ["co.uk"] }),
    ] {
        let resp = client
            .post(format!("{base}/policy/blocking"))
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST, "{bad}");
    }
    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "secure",
            // `tunneling` was retired: it is dropped, not refused.
            "blocked_security": ["Dynamic_DNS", "dynamic_dns", "tunneling", "high_risk_tlds"],
            "blocked_tlds": [".ZIP", "*.mov", "zip"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let group: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        group["blocked_security"],
        serde_json::json!(["dynamic_dns", "high_risk_tlds"])
    );
    assert_eq!(group["blocked_tlds"], serde_json::json!(["zip", "mov"]));

    // The lists are downloaded once a group uses them.
    for name in ["phish.duckdns.org.", "bad.top.", "update.zip.", "a.b.mov."] {
        wait_for(udp, name, |r| r.response_code == ResponseCode::NXDomain).await;
    }
    // The maintainer's allowlist is honoured.
    let explain: serde_json::Value = client
        .get(format!(
            "{base}/policy/explain?domain=good.top&client=127.0.0.1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(explain["verdict"]["blocked"], true, "{explain}");
    // The console sees the download.
    let catalog: serde_json::Value = client
        .get(format!("{base}/policy/security"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ddns = catalog["categories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "dynamic_dns")
        .unwrap();
    assert!(
        ddns["feed_status"]["entries"].as_u64().unwrap() > 0,
        "{ddns}"
    );
    // Other names are untouched.
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));

    // Domain Check names the category.
    let explain: serde_json::Value = client
        .get(format!(
            "{base}/policy/explain?domain=phish.duckdns.org&client=127.0.0.1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        explain.to_string().contains("Dynamic DNS Hostnames"),
        "{explain}"
    );

    shutdown(server).await;
}

/// With the block page on, a blocked name points at the page, and the page
/// says what was blocked and why; turned off, it is NXDOMAIN again.
#[tokio::test]
async fn block_page_explains_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.blocklist = vec!["ads.test".to_string()];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let free_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };

    let reply = udp_query(udp, "ads.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain);

    let page = serde_json::json!({
        "enabled": true, "ipv4": "127.0.0.1", "listen": "127.0.0.1",
        "port": free_port, "message": "Ask <Sam>",
    });
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "block_page": page }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let reply = udp_query(udp, "ads.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&reply).as_deref(), Some("127.0.0.1"));
    // No IPv6 address set: AAAA is empty, not NXDOMAIN.
    let reply = udp_query(udp, "ads.test.", RecordType::AAAA).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());

    let resp = client
        .get(format!("http://127.0.0.1:{free_port}/some/path"))
        .header("Host", "ads.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let html = resp.text().await.unwrap();
    assert!(html.contains("<strong>ads.test</strong>"), "{html}");
    assert!(html.contains("Reason:"), "{html}");
    assert!(html.contains("Ask &lt;Sam&gt;"), "{html}");

    // Off again.
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "block_page": { "enabled": false } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let reply = udp_query(udp, "ads.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

/// Internationalized names are matched in the punycode form they arrive in:
/// a list entry written in punycode (as published blocklists are) and one
/// typed in Unicode both block the query, and an unlisted IDN is not caught.
#[tokio::test]
async fn internationalized_names_are_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.blocklist = vec![
        "*.xn--e1afmkfd.test".to_string(),
        "bücher2.test".to_string(),
    ];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let reply = udp_query(udp, "ads.xn--e1afmkfd.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain, "{reply:?}");
    let reply = udp_query(udp, "xn--bcher2-3ya.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain, "{reply:?}");
    let reply = udp_query(udp, "xn--bcher-kva.test.", RecordType::A).await;
    assert_ne!(reply.response_code, ResponseCode::NXDomain, "{reply:?}");

    shutdown(server).await;
}

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

/// A minimal HTTP/1.1 server answering every request with the JSON
/// `respond` returns for its path (query string included).
async fn spawn_json_server(
    respond: impl Fn(std::net::SocketAddr, &str) -> serde_json::Value + Send + Sync + 'static,
) -> std::net::SocketAddr {
    spawn_http_server(move |addr, path| respond(addr, path).to_string()).await
}

/// A minimal HTTP/1.1 server answering every request with the body
/// `respond` returns for its path (query string included).
async fn spawn_http_server(
    respond: impl Fn(std::net::SocketAddr, &str) -> String + Send + Sync + 'static,
) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let respond = std::sync::Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let respond = std::sync::Arc::clone(&respond);
            tokio::spawn(async move {
                // Read the headers and any body, so closing the connection
                // never resets it under the client.
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = respond(addr, &path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

/// A server standing in for IANA's RDAP bootstrap file and a registry's
/// RDAP service: `new.co.zz` was registered three days ago, `old.co.zz` in
/// 2001.
async fn spawn_rdap() -> std::net::SocketAddr {
    spawn_json_server(|addr, path| {
        if path == "/dns.json" {
            serde_json::json!({
                "version": "1.0",
                "services": [[["zz"], [format!("http://{addr}/rdap/")]]]
            })
        } else if path.ends_with("/domain/new.co.zz") {
            let date = chrono::Utc::now() - chrono::Duration::days(3);
            serde_json::json!({"events": [
                {"eventAction": "registration", "eventDate": date.to_rfc3339()}
            ]})
        } else {
            serde_json::json!({"events": [
                {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}
            ]})
        }
    })
    .await
}

/// A newly registered domain is blocked once its registration date has
/// been looked up over RDAP, while an old one stays.
#[tokio::test]
async fn groups_block_newly_registered_domains() {
    let dir = tempfile::tempdir().unwrap();
    let rdap = spawn_rdap().await;
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "co.zz",
        &[
            ("www.new", "A", "198.51.100.30"),
            ("www.old", "A", "198.51.100.31"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.policy.rdap_bootstrap = format!("http://{rdap}/dns.json");
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);

    let resp = reqwest::Client::new()
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "secure",
            "blocked_security": ["newly_registered"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // The very first query waits for the RDAP lookup and is blocked.
    let reply = udp_query(udp, "www.new.co.zz.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty(), "{reply:?}");
    // An old domain resolves, on its first query too.
    let reply = udp_query(udp, "www.old.co.zz.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.31"));

    shutdown(server).await;
}

/// A server standing in for the Safe Browsing API: `evil.co.zz` is on the
/// SOCIAL_ENGINEERING list, the MALWARE list is empty.
async fn spawn_safe_browsing() -> std::net::SocketAddr {
    use base64::Engine as _;
    use sha2::Digest as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let full = sha2::Sha256::digest(b"evil.co.zz/");
    let prefix = full[..4].to_vec();
    spawn_json_server(move |_, path| {
        assert!(path.contains("key=test-key"), "{path}");
        if path.starts_with("/v4/threatLists") {
            serde_json::json!({"threatLists": [
                {"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"},
                {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"}
            ]})
        } else if path.starts_with("/v4/threatListUpdates:fetch") {
            let list = |threat: &str, prefixes: &[u8]| {
                serde_json::json!({
                    "threatType": threat,
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "responseType": "FULL_UPDATE",
                    "additions": [{"compressionType": "RAW", "rawHashes": {
                        "prefixSize": 4, "rawHashes": b64.encode(prefixes)
                    }}],
                    "newClientState": "c3RhdGU=",
                    "checksum": {"sha256": b64.encode(sha2::Sha256::digest(prefixes))}
                })
            };
            serde_json::json!({
                "listUpdateResponses": [list("MALWARE", &[]), list("SOCIAL_ENGINEERING", &prefix)],
                "minimumWaitDuration": "1800s"
            })
        } else {
            serde_json::json!({
                "matches": [{
                    "threatType": "SOCIAL_ENGINEERING",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "threat": {"hash": b64.encode(full)},
                    "cacheDuration": "300s"
                }],
                "negativeCacheDuration": "300s"
            })
        }
    })
    .await
}

/// A name on Google Safe Browsing's lists is blocked once the lists have
/// been downloaded; other names are not, and the key is never echoed back.
#[tokio::test]
async fn groups_block_google_safe_browsing_listings() {
    let dir = tempfile::tempdir().unwrap();
    let safe_browsing = spawn_safe_browsing().await;
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "co.zz",
        &[
            ("evil", "A", "198.51.100.40"),
            ("www.fine", "A", "198.51.100.41"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.policy.safe_browsing_key = "test-key".to_string();
    config.policy.safe_browsing_url = format!("http://{safe_browsing}");
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let config: serde_json::Value = client
        .get(format!("{base}/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["policy"]["safe_browsing_key"], "[redacted]");
    // Saving the placeholder back keeps the stored key.
    let resp = client
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "policy": { "safe_browsing_key": "[redacted]" } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "secure",
            "blocked_security": ["google_safe_browsing"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let reply = udp_query(udp, "evil.co.zz.", RecordType::A).await;
        if reply.response_code == ResponseCode::NoError && reply.answers.is_empty() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{reply:?}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let reply = udp_query(udp, "www.fine.co.zz.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.41"));

    shutdown(server).await;
}

/// A name whose address is on a consumer ISP's network is blocked once
/// the address's network (from an IP-to-ASN zone) and that network's type
/// (from PeeringDB) are known; a data-centre name is not.
#[tokio::test]
async fn groups_block_residential_hosting() {
    let dir = tempfile::tempdir().unwrap();
    let peeringdb = spawn_json_server(|_, path| {
        let kind = if path.ends_with("asn=64500") {
            "Cable/DSL/ISP"
        } else {
            "Content"
        };
        serde_json::json!({"data": [{"info_type": kind, "info_types": [kind]}]})
    })
    .await;
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "co.zz",
        &[
            ("home", "A", "198.51.100.50"),
            ("dc", "A", "198.51.100.60"),
            (
                "50.100.51.198.origin",
                "TXT",
                "64500 | 198.51.100.0/24 | ZZ",
            ),
            (
                "60.100.51.198.origin",
                "TXT",
                "64501 | 198.51.100.0/24 | ZZ",
            ),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.policy.peeringdb_url = format!("http://{peeringdb}");
    config.policy.ip_asn_zone_v4 = "origin.co.zz".to_string();
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);

    let resp = reqwest::Client::new()
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "secure",
            "blocked_security": ["residential_hosting"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // The very first query waits for the address and network lookups and
    // is blocked.
    let reply = udp_query(udp, "home.co.zz.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty(), "{reply:?}");
    // A data-centre address stays reachable, from its first query on.
    for _ in 0..20 {
        let reply = udp_query(udp, "dc.co.zz.", RecordType::A).await;
        assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.60"));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    shutdown(server).await;
}

/// A site subdomain that CNAMEs to a tracking company is blocked as a
/// disguised third-party tracker; a CNAME within the site is not.
#[tokio::test]
async fn groups_block_disguised_third_party_trackers() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = spawn_feed_mirror().await;
    let upstream = spawn_upstream_zones(
        &dir.path().join("upstream.db"),
        &[
            (
                "co.zz",
                &[
                    ("metrics", "CNAME", "shop.eulerian.net."),
                    ("www", "CNAME", "web.co.zz."),
                    ("web", "A", "198.51.100.70"),
                ],
            ),
            ("eulerian.net", &[("shop", "A", "198.51.100.71")]),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    config.policy.feed_mirror = format!("http://{mirror}");
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);

    // Without the category the CNAME comes through.
    let reply = udp_query(udp, "metrics.co.zz.", RecordType::A).await;
    assert_eq!(
        first_answer(&reply).as_deref(),
        Some("shop.eulerian.net."),
        "{reply:?}"
    );

    let resp = reqwest::Client::new()
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "private",
            "blocked_security": ["disguised_trackers"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    wait_for(udp, "metrics.co.zz.", |r| {
        r.response_code == ResponseCode::NoError && r.answers.is_empty()
    })
    .await;
    let reply = udp_query(udp, "www.co.zz.", RecordType::A).await;
    assert!(
        reply
            .answers
            .iter()
            .any(|r| r.data.to_string() == "198.51.100.70"),
        "{reply:?}"
    );

    shutdown(server).await;
}

/// A native tracking vendor blocks that vendor's telemetry names with the
/// privacy source, and only for the group that ticks it.
#[tokio::test]
async fn groups_block_native_tracking() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = spawn_feed_mirror().await;
    let server = search_server_with(&dir, |config| {
        config.policy.feed_mirror = format!("http://{mirror}");
    })
    .await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "private",
            "blocked_security": ["native_windows", "native_apple"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    for name in ["v10.events.data.microsoft.com.", "metrics.icloud.com."] {
        wait_for(udp, name, |r| r.response_code == ResponseCode::NXDomain).await;
    }
    let reply = udp_query(udp, "www.google.com.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("192.0.2.80"));

    let explain: serde_json::Value = client
        .get(format!(
            "{base}/policy/explain?domain=v10.events.data.microsoft.com&client=127.0.0.1"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(explain["verdict"]["source"], "privacy", "{explain}");
    assert!(
        explain
            .to_string()
            .contains("Native Tracking: Windows & Office"),
        "{explain}"
    );

    shutdown(server).await;
}

/// A server standing in for the categories' list hosts, through
/// `policy.feed_mirror`: HaGeZi's DynDNS, abused TLDs (with its allowlist)
/// and Apple and Windows native tracker lists, and AdGuard's cname-trackers
/// catalogue. Use `format!("http://{addr}")` as the mirror.
async fn spawn_feed_mirror() -> std::net::SocketAddr {
    spawn_http_server(|_, path| {
        let hagezi = "/raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
        match path.strip_prefix(hagezi) {
            Some("dyndns-onlydomains.txt") => "# HaGeZi\nduckdns.org\n".to_string(),
            Some("spam-tlds-onlydomains.txt") => "top\n".to_string(),
            Some("spam-tlds-allow-onlydomains.txt") => "good.top\n".to_string(),
            Some("native.apple-onlydomains.txt") => "metrics.icloud.com\n".to_string(),
            Some("native.winoffice-onlydomains.txt") => "events.data.microsoft.com\n".to_string(),
            _ if path.ends_with("/cname-trackers/master/script/src/cloaked-trackers.json") => {
                serde_json::json!([
                    {"company_name": "Eulerian", "type": "tracker", "domains": ["eulerian.net"]},
                    {"company_name": "Pardot", "type": "clickthrough", "domains": ["go.pardot.com"]}
                ])
                .to_string()
            }
            _ => String::new(),
        }
    })
    .await
}

/// Wait (up to 20 s, long enough for the feed loop to notice a new
/// category and download it) until `name` gets the response `blocked`
/// accepts.
async fn wait_for(
    udp: std::net::SocketAddr,
    name: &str,
    blocked: impl Fn(&hickory_proto::op::Message) -> bool,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let reply = udp_query(udp, name, RecordType::A).await;
        if blocked(&reply) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{name}: {reply:?}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
