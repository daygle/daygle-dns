//! Integration test: how recursive answers are classified, and lookups that
//! outlast the client timeout.
//!
//! NXDOMAIN and NODATA are normal answers, so they count as recursive, not
//! as errors. A lookup slower than `server.client_timeout_ms` gets SERVFAIL
//! but keeps running, so the client's retry is answered from the cache -
//! unless an expired answer is on hand, which is served instead (RFC 8767).

mod common;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use serde_json::Value;

/// A forwarding target that waits `delay` before each reply. `missing.`
/// names are NXDOMAIN, AAAA queries are NODATA, and A queries get
/// 192.0.2.1. Returns the address and a count of queries received.
async fn fake_upstream(delay: Duration) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let delay_ms = Arc::new(AtomicU64::new(delay.as_millis() as u64));
    fake_upstream_with(delay_ms, 300).await
}

/// [`fake_upstream`] with a delay that can change while it runs and answers
/// that live `ttl` seconds.
async fn fake_upstream_with(
    delay_ms: Arc<AtomicU64>,
    ttl: u32,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let socket = socket.clone();
            let delay = Duration::from_millis(delay_ms.load(Ordering::SeqCst));
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let q = query.queries[0].clone();
                let mut reply = Message::new(query.id, MessageType::Response, query.op_code);
                reply.metadata.recursion_desired = true;
                reply.metadata.recursion_available = true;
                reply.add_query(q.clone());
                if q.name().to_string().starts_with("missing.") {
                    reply.metadata.response_code = ResponseCode::NXDomain;
                } else if q.query_type() == RecordType::A {
                    reply.add_answer(Record::from_rdata(
                        q.name().clone(),
                        ttl,
                        RData::A(A::new(192, 0, 2, 1)),
                    ));
                }
                let _ = socket.send_to(&reply.to_vec().unwrap(), from).await;
            });
        }
    });
    (addr, count)
}

fn forwarding_config(
    db: &std::path::Path,
    upstream: std::net::SocketAddr,
) -> daygle_dns_core::config::DaygleConfig {
    let mut cfg = base_config(db);
    cfg.recursive.enabled = true;
    cfg.recursive.use_system_config = false;
    cfg.recursive.upstreams = vec![upstream.to_string()];
    cfg.recursive.dnssec_validate = false;
    cfg
}

async fn stats_sum(server: &daygle_dns::BoundServer, field: &str) -> u64 {
    let stats: Value = reqwest::Client::new()
        .get(format!("http://{}/api/stats?window=1h", server.api_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    stats["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p[field].as_u64().unwrap_or(0))
        .sum()
}

#[tokio::test]
async fn negative_answers_are_not_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, _) = fake_upstream(Duration::ZERO).await;
    let server = spawn(forwarding_config(&dir.path().join("d.db"), upstream)).await;
    let udp = server.udp_addr.expect("UDP enabled");

    let nx = udp_query(udp, "missing.example.", RecordType::A).await;
    assert_eq!(nx.response_code, ResponseCode::NXDomain);
    let nodata = udp_query(udp, "host.example.", RecordType::AAAA).await;
    assert_eq!(nodata.response_code, ResponseCode::NoError);
    assert!(nodata.answers.is_empty());

    assert_eq!(stats_sum(&server, "errors").await, 0);
    assert_eq!(stats_sum(&server, "recursive").await, 2);

    shutdown(server).await;
}

#[tokio::test]
async fn slow_lookup_still_fills_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, count) = fake_upstream(Duration::from_millis(1500)).await;
    let mut cfg = forwarding_config(&dir.path().join("d.db"), upstream);
    cfg.server.client_timeout_ms = 1000;
    cfg.recursive.timeout_secs = 3;
    cfg.recursive.attempts = 1;
    let server = spawn(cfg).await;
    let udp = server.udp_addr.expect("UDP enabled");

    let first = udp_query(udp, "slow.example.", RecordType::A).await;
    assert_eq!(first.response_code, ResponseCode::ServFail);
    assert_eq!(stats_sum(&server, "errors").await, 1);

    // The abandoned lookup completes in the background...
    tokio::time::sleep(Duration::from_millis(1000)).await;
    // ...so the retry is answered at once from the cache.
    let sent = count.load(Ordering::SeqCst);
    let started = Instant::now();
    let retry = udp_query(udp, "slow.example.", RecordType::A).await;
    assert_eq!(retry.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&retry).as_deref(), Some("192.0.2.1"));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "retry must hit the cache"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        sent,
        "the retry must not query upstream"
    );

    shutdown(server).await;
}

#[tokio::test]
async fn slow_lookup_serves_a_stale_answer_when_one_is_on_hand() {
    let dir = tempfile::tempdir().unwrap();
    let delay_ms = Arc::new(AtomicU64::new(0));
    let (upstream, _) = fake_upstream_with(delay_ms.clone(), 1).await;
    let mut cfg = forwarding_config(&dir.path().join("d.db"), upstream);
    cfg.server.client_timeout_ms = 1000;
    cfg.recursive.timeout_secs = 3;
    cfg.recursive.attempts = 1;
    cfg.recursive.min_cache_ttl = 0;
    cfg.recursive.prefetch_enabled = false;
    let server = spawn(cfg).await;
    let udp = server.udp_addr.expect("UDP enabled");

    // A good answer, cached for one second...
    let fresh = udp_query(udp, "bank.example.", RecordType::A).await;
    assert_eq!(fresh.response_code, ResponseCode::NoError);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // ...has expired when the upstream turns slow: rather than SERVFAIL at
    // the client timeout, the client gets the expired answer.
    delay_ms.store(1500, Ordering::SeqCst);
    let started = Instant::now();
    let slow = udp_query(udp, "bank.example.", RecordType::A).await;
    assert_eq!(slow.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&slow).as_deref(), Some("192.0.2.1"));
    assert!(
        started.elapsed() < Duration::from_millis(1400),
        "the stale answer must not wait for the upstream"
    );
    assert_eq!(stats_sum(&server, "errors").await, 0);

    shutdown(server).await;
}

#[tokio::test]
async fn client_timeout_changes_from_the_console_apply_live() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, _) = fake_upstream(Duration::from_millis(1500)).await;
    let mut cfg = forwarding_config(&dir.path().join("d.db"), upstream);
    cfg.server.client_timeout_ms = 1000;
    cfg.recursive.timeout_secs = 3;
    cfg.recursive.attempts = 1;
    let server = spawn(cfg).await;
    let udp = server.udp_addr.expect("UDP enabled");
    let put = |body: Value| {
        reqwest::Client::new()
            .put(format!("http://{}/api/config", server.api_addr))
            .json(&body)
            .send()
    };

    let first = udp_query(udp, "first.example.", RecordType::A).await;
    assert_eq!(first.response_code, ResponseCode::ServFail);

    // A longer timeout applies to the next query, no restart needed.
    let saved = put(serde_json::json!({ "server": { "client_timeout_ms": 3000 } }))
        .await
        .unwrap();
    assert_eq!(saved.status(), 200);
    let config: Value = reqwest::Client::new()
        .get(format!("http://{}/api/config", server.api_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["server"]["client_timeout_ms"], 3000);
    let second = udp_query(udp, "second.example.", RecordType::A).await;
    assert_eq!(second.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&second).as_deref(), Some("192.0.2.1"));

    shutdown(server).await;
}
