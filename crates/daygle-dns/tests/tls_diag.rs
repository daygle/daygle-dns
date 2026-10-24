//! Integration test: encrypted-DNS diagnostics - certificate lifecycle
//! reports, coalesced handshake/connection failure warnings and actionable
//! DoH misuse logging, all reaching the console's Server Log tagged `tls`,
//! `https` and `quic` (the same values the query log records).
//!
//! One test function: the hickory bridge points at one session log per
//! process, so the servers are bound one at a time and the first server is
//! stopped before the next is spawned.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use daygle_dns::BoundServer;
use daygle_dns_core::LogLevel;
use rustls_pki_types::pem::PemObject as _;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Install the server binary's tracing setup once: fmt (warnings to stderr)
/// plus the hickory bridge that feeds Hickory's DoT/DoH failure events into
/// the console's Server Log. One global subscriber per process - this file
/// runs a single test, so the bridge always points at the server under test.
fn install_bridge() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ =
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_filter(tracing_subscriber::EnvFilter::new("warn")),
                )
                .with(daygle_dns::tls_diag::hickory_bridge().with_filter(
                    Targets::new().with_target("hickory_server", tracing::Level::DEBUG),
                ))
                .try_init();
    });
}

/// Poll `condition` until it holds (or panic after five seconds).
async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..100 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not met within five seconds");
}

/// The Server Log warnings tagged with one protocol value.
fn warns(server: &BoundServer, protocol: &str) -> Vec<String> {
    server
        .logs
        .entries()
        .into_iter()
        .filter(|e| e.level == LogLevel::Warn && e.component == protocol)
        .map(|e| e.message)
        .collect()
}

/// Connect a QUIC client offering the wrong ALPN (`h2` instead of `doq`):
/// the server rejects the handshake, which is exactly what should be logged.
async fn doq_alpn_mismatch(addr: SocketAddr, cert_path: &Path) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        rustls::pki_types::CertificateDer::<'_>::pem_file_iter(cert_path).expect("read cert file")
    {
        roots.add(cert.expect("parse cert")).expect("add root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = tls;
    tls.alpn_protocols = vec![b"h2".to_vec()];

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client config"),
    )));
    let connecting = endpoint.connect(addr, "daygle.test").expect("connect");
    // Err on both sides: the server logs the rejected handshake.
    let _ = connecting.await;
    endpoint.wait_idle().await;
}

/// Write a certificate pair that expired years ago (rcgen's own defaults are
/// valid for centuries, so the expiry path must be built explicitly).
fn write_expired_pair(cert_path: &Path, key_path: &Path) {
    use rcgen::{date_time_ymd, CertificateParams, KeyPair};
    let key_pair = KeyPair::generate().expect("key pair");
    let mut params = CertificateParams::new(vec!["expired.test".to_string()]).expect("params");
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2020, 12, 31);
    let cert_pem = params.self_signed(&key_pair).expect("self-sign");
    std::fs::write(cert_path, cert_pem.pem()).expect("write cert");
    std::fs::write(key_path, key_pair.serialize_pem()).expect("write key");
}

#[tokio::test]
async fn encrypted_dns_failures_and_certificates_reach_the_server_log() {
    install_bridge();

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let cert_str = cert.to_string_lossy().to_string();
    let key_str = key.to_string_lossy().to_string();

    let mut config = base_config(&db);
    // One self-signed certificate shared by the three encrypted listeners.
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert_str.clone();
    config.dot.key_path = key_str.clone();
    config.dot.server_name = "daygle.test".to_string();
    config.doh.enabled = true;
    config.doh.self_signed = true;
    config.doh.cert_path = cert_str.clone();
    config.doh.key_path = key_str.clone();
    config.doh.server_name = "daygle.test".to_string();
    config.doq.enabled = true;
    config.doq.self_signed = true;
    config.doq.listen = "127.0.0.1".to_string();
    config.doq.port = 0;
    config.doq.cert_path = cert_str.clone();
    config.doq.key_path = key_str.clone();
    config.doq.server_name = "daygle.test".to_string();

    let server = spawn(config).await;

    // 1. Certificate lifecycle: one info line per encrypted listener with the
    //    subject and the expiry date (reported on every start/reload).
    let entries = server.logs.entries();
    for protocol in ["tls", "https", "quic"] {
        assert!(
            entries.iter().any(|e| {
                e.level == LogLevel::Info
                    && e.component == protocol
                    && e.message.contains("valid until")
                    && e.message.contains("daygle.test")
            }),
            "no {protocol} certificate report in {:?}",
            entries
                .iter()
                .map(|e| (&e.component, &e.level, &e.message))
                .collect::<Vec<_>>()
        );
    }

    // 2. DoT handshake failures: warn, tagged tls, with the client address -
    //    and coalesced: three failing connections from one client, one line.
    use tokio::io::AsyncWriteExt as _;
    let dot = server.dot_addr.expect("DoT is enabled");
    for _ in 0..3 {
        let mut stream = tokio::net::TcpStream::connect(dot)
            .await
            .expect("connect DoT");
        let _ = stream.write_all(b"definitely not TLS\n").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    wait_until(|| warns(&server, "tls").len() == 1).await;
    let tls_warns = warns(&server, "tls");
    assert_eq!(tls_warns.len(), 1, "{tls_warns:?}");
    assert!(tls_warns[0].contains("127.0.0.1"), "{tls_warns:?}");
    assert!(tls_warns[0].contains("session failure"), "{tls_warns:?}");

    // 3. DoH misuse: a request to the wrong endpoint path is rejected with a
    //    reason (Hickory drops the stream; the log carries the reason), and
    //    repeats from the same client are counted rather than logged again.
    let doh = server.doh_addr.expect("DoH is enabled");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // lgtm
        .build()
        .unwrap();
    let _ = client
        .post(format!("https://{doh}/not-the-endpoint")) // lgtm
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(vec![0u8; 12])
        .send()
        .await;
    wait_until(|| warns(&server, "https").len() == 1).await;
    let https_warns = warns(&server, "https");
    assert_eq!(https_warns.len(), 1, "{https_warns:?}");
    assert!(https_warns[0].contains("bad path"), "{https_warns:?}");
    assert!(https_warns[0].contains("127.0.0.1"), "{https_warns:?}");
    // Second misuse (wrong content type on the right path): same key, so it
    // is counted silently.
    let _ = client
        .post(format!("https://{doh}/dns-query")) // lgtm
        .header("Content-Type", "text/plain")
        .body("nope")
        .send()
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        warns(&server, "https").len(),
        1,
        "repeated DoH misuse was not coalesced"
    );

    // 4. DoQ: a server-rejected handshake (wrong ALPN), three times from the
    //    same IP (each attempt uses a fresh source port) - one warn line,
    //    tagged quic, naming the client and the reason.
    let doq = server.doq_addr.expect("DoQ is enabled");
    for _ in 0..3 {
        doq_alpn_mismatch(doq, &cert).await;
    }
    wait_until(|| warns(&server, "quic").len() == 1).await;
    let quic_warns = warns(&server, "quic");
    assert_eq!(quic_warns.len(), 1, "{quic_warns:?}");
    assert!(quic_warns[0].contains("handshake failed"), "{quic_warns:?}");
    assert!(quic_warns[0].contains("127.0.0.1"), "{quic_warns:?}");

    shutdown(server).await;

    // 5. An expired certificate warns at bind time - before any client fails.
    let dir2 = tempfile::tempdir().unwrap();
    let db2 = dir2.path().join("daygle-dns.db");
    let expired = dir2.path().join("expired.crt");
    let expired_key = dir2.path().join("expired.key");
    write_expired_pair(&expired, &expired_key);

    let mut config2 = base_config(&db2);
    config2.dot.enabled = true;
    config2.dot.self_signed = false;
    config2.dot.cert_path = expired.to_string_lossy().to_string();
    config2.dot.key_path = expired_key.to_string_lossy().to_string();
    config2.dot.server_name = "expired.test".to_string();
    let server2 = spawn(config2).await;
    let expired_warns = warns(&server2, "tls");
    assert!(
        expired_warns.iter().any(|m| m.contains("expired")
            && m.contains("expired.test")
            && m.contains("encrypted clients cannot connect")),
        "{expired_warns:?}"
    );
    shutdown(server2).await;
}
