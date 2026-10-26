//! Integration tests: CNAME inspection, Safe Search and filtering-group
//! schedules.

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
