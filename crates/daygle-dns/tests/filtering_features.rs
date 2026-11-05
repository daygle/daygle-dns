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
    let server = search_server(&dir).await;
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
            "blocked_security": ["Dynamic_DNS", "dynamic_dns", "tunneling"],
            "blocked_tlds": [".ZIP", "*.mov", "zip"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let group: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        group["blocked_security"],
        serde_json::json!(["dynamic_dns", "tunneling"])
    );
    assert_eq!(group["blocked_tlds"], serde_json::json!(["zip", "mov"]));

    for name in [
        "phish.duckdns.org.",
        "abc123.trycloudflare.com.",
        "update.zip.",
        "a.b.mov.",
    ] {
        let reply = udp_query(udp, name, RecordType::A).await;
        assert_eq!(reply.response_code, ResponseCode::NXDomain, "{name}");
    }
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

/// The detector categories: IDN homographs and DGA names are blocked by
/// name, and a parked domain once its name servers have been looked up.
#[tokio::test]
async fn groups_block_homographs_dga_and_parked_domains() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "parked.test",
        &[
            ("@", "NS", "ns1.sedoparking.com."),
            ("www", "A", "198.51.100.20"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/policy/blocking"))
        .json(&serde_json::json!({
            "name": "secure",
            "blocked_security": ["idn_homographs", "dga_domains", "parked_domains"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // `pаypal.com` with a Cyrillic 'а'.
    for name in ["xn--pypal-4ve.com.", "lqomwlpfnvbibkf.com."] {
        let reply = udp_query(udp, name, RecordType::A).await;
        assert_eq!(reply.response_code, ResponseCode::NXDomain, "{name}");
    }

    // The first query of a parked domain gets through and starts the name
    // server lookup; once that has finished, the domain is blocked.
    let reply = udp_query(udp, "www.parked.test.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.20"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let reply = udp_query(udp, "www.parked.test.", RecordType::A).await;
        if reply.response_code == ResponseCode::NoError && reply.answers.is_empty() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{reply:?}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    shutdown(server).await;
}

/// A minimal HTTP server standing in for IANA's RDAP bootstrap file and a
/// registry's RDAP service: `new.co.zz` was registered three days ago,
/// `old.co.zz` in 2001.
async fn spawn_rdap() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = if path == "/dns.json" {
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
                };
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/rdap+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

/// Typosquats are blocked by name; a newly registered domain once its
/// registration date has been looked up over RDAP, while an old one stays.
#[tokio::test]
async fn groups_block_typosquats_and_newly_registered_domains() {
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
            "blocked_security": ["typosquatting", "newly_registered"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    for name in ["paypa1.com.", "paypal-login.net."] {
        let reply = udp_query(udp, name, RecordType::A).await;
        assert_eq!(reply.response_code, ResponseCode::NXDomain, "{name}");
    }

    // First queries get through and start the RDAP lookups.
    for name in ["www.new.co.zz.", "www.old.co.zz."] {
        let reply = udp_query(udp, name, RecordType::A).await;
        assert!(first_answer(&reply).is_some(), "{name}: {reply:?}");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let reply = udp_query(udp, "www.new.co.zz.", RecordType::A).await;
        if reply.response_code == ResponseCode::NoError && reply.answers.is_empty() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{reply:?}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let reply = udp_query(udp, "www.old.co.zz.", RecordType::A).await;
    assert_eq!(first_answer(&reply).as_deref(), Some("198.51.100.31"));

    shutdown(server).await;
}
