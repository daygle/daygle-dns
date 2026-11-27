//! The Lookup page's diagnostic lookup must not outlive the client answer
//! budget: a client query is stopped by the dispatcher at
//! `server.client_timeout_ms`, and a diagnostic that kept running every retry
//! (several times that budget when an upstream is silent) left the page
//! waiting long after the failure a client would already have seen.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::config::{RecursiveSettings, ResolutionMode};
use daygle_dns_core::Metrics;
use daygle_dns_recursive::RecursiveResolver;
use hickory_proto::op::{Message, MessageType, ResponseCode};

/// An upstream that takes every query and never answers.
async fn spawn_silent(ip: &str) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if socket.recv_from(&mut buf).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// An upstream that answers every query with `code`.
async fn spawn_answering(ip: &str, code: ResponseCode) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.queries = query.queries.clone();
            response.metadata.response_code = code;
            if let Ok(bytes) = response.to_vec() {
                if socket.send_to(&bytes, peer).await.is_err() {
                    return;
                }
            }
        }
    });
    addr
}

fn forwarding(upstream: SocketAddr, attempts: usize, client_timeout_ms: u64) -> RecursiveSettings {
    RecursiveSettings {
        enabled: true,
        mode: Some(ResolutionMode::Forwarding),
        use_system_config: false,
        upstreams: vec![upstream.to_string()],
        dnssec_validate: false,
        attempts,
        timeout_secs: 5,
        client_timeout_ms,
        ..RecursiveSettings::default()
    }
}

fn resolver(settings: &RecursiveSettings) -> RecursiveResolver {
    RecursiveResolver::build(settings, Arc::new(Metrics::default()), &[], None).unwrap()
}

/// Without the bound this retried the silent upstream until every attempt was
/// spent: 15 s with `attempts = 2`, 20 s at the default 3. The page now stops
/// at the client's own answer budget and shows the queries that were still
/// out, as SERVFAIL.
#[tokio::test]
async fn a_silent_upstream_stops_at_the_client_answer_budget() {
    let upstream = spawn_silent("127.0.0.10").await;
    let resolver = resolver(&forwarding(upstream, 2, 1_200));

    let started = Instant::now();
    let diagnosis = resolver
        .diagnose("www.failing.test.", "A", true)
        .await
        .expect("a diagnosis, not an API error");
    let took = started.elapsed();

    assert_eq!(diagnosis.rcode, "SERVFAIL");
    assert!(diagnosis.answers.is_empty());
    let error = diagnosis.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("client timeout of 1200 ms"),
        "the reason must name the budget the page stopped at: {error}"
    );
    assert!(
        took < Duration::from_secs(3),
        "the diagnostic outlived its budget: {took:?}"
    );
    assert!(
        !diagnosis.trace.is_empty(),
        "the queries already sent are still listed"
    );
    let stopped = diagnosis
        .trace
        .iter()
        .find(|step| step.rcode.is_none())
        .expect("the unanswered query is in the trace");
    assert!(
        stopped.outcome.contains("stopped at the client timeout"),
        "the trace must say why the row has no reply: {}",
        stopped.outcome
    );
}

/// A quick failure still finishes inside the budget and reports normally.
#[tokio::test]
async fn an_answering_upstream_is_not_cut_short() {
    let upstream = spawn_answering("127.0.0.11", ResponseCode::NXDomain).await;
    let resolver = resolver(&forwarding(upstream, 2, 8_000));

    let diagnosis = resolver
        .diagnose("missing.example.", "A", true)
        .await
        .expect("a diagnosis, not an API error");

    assert_eq!(diagnosis.rcode, "NXDOMAIN");
    assert!(diagnosis.error.is_none(), "{:?}", diagnosis.error);
    assert!(
        diagnosis.trace.iter().any(|step| step.rcode.is_some()),
        "the upstream's answer is traced"
    );
}
