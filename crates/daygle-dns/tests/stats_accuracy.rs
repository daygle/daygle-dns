//! Integration test: dashboard statistics count each served query exactly
//! once, even when the recursive lookup fails.
//!
//! Regression guard: a failed recursive lookup used to be recorded twice
//! (once as `Recursive` before the lookup, once as `Error` after), which made
//! one query appear as 2 in the time-series `queries` total and bumped the
//! top-domains table twice.

mod common;

use common::*;
use hickory_proto::rr::RecordType;
use serde_json::Value;

/// A recursive query that fails (unreachable upstream) must be counted once
/// in the time-series `queries` total with `errors = 1` - not double-counted
/// (once as `recursive` + once as `error`, which used to push `queries` to 2).
#[tokio::test]
async fn failed_recursive_query_is_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");

    let mut cfg = base_config(&db);
    // Recursion pointed at a TEST-NET address that will never answer; short
    // timeout so the failed lookup completes quickly.
    cfg.recursive.enabled = true;
    cfg.recursive.use_system_config = false;
    cfg.recursive.upstreams = vec!["192.0.2.1".to_string()];
    cfg.recursive.timeout_secs = 1;
    cfg.recursive.attempts = 1;
    cfg.recursive.dnssec_validate = false;

    let server = spawn(cfg).await;
    let udp = server.udp_addr.expect("UDP enabled");

    // The lookup fails; the dispatcher turns a code-less failure into SERVFAIL.
    let msg = udp_query(udp, "unreachable.example.", RecordType::A).await;
    assert_eq!(msg.response_code, hickory_proto::op::ResponseCode::ServFail);

    let client = reqwest::Client::new();
    let stats: Value = client
        .get(format!("http://{}/api/stats?window=1h", server.api_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sum_of = |field: &str| -> u64 {
        stats["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p[field].as_u64().unwrap_or(0))
            .sum()
    };

    let total = sum_of("queries");
    let errors = sum_of("errors");
    let recursive = sum_of("recursive");
    assert_eq!(total, 1, "one query must count once (got {total}): {stats}");
    assert_eq!(errors, 1, "the failure must be classified as error");
    assert_eq!(recursive, 0, "a failed lookup must not also count as recursive");

    // The top-domains table must list the queried name once, not twice.
    let top_domains = stats["top_domains"].as_array().unwrap();
    let entry = top_domains
        .iter()
        .find(|e| e["key"] == "unreachable.example")
        .expect("queried name appears in top domains");
    assert_eq!(
        entry["count"].as_u64().unwrap_or(0),
        1,
        "top-domains must count the query once: {top_domains:?}"
    );

    shutdown(server).await;
}
