//! Integration test: per-client and per-domain query rate limiting.

mod common;

use common::*;
use daygle_dns_authoritative::model::ZoneInput;
use daygle_dns_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A config with rate limiting enabled, loopback NOT exempt (tests run from
/// 127.0.0.1). Each test gives the counter it exercises a small budget and
/// the other a large one so the two limits never interfere.
fn rate_limited_config(
    db: &std::path::Path,
    client_max: u32,
    domain_max: u32,
) -> DaygleConfig {
    let mut cfg = base_config(db);
    cfg.rate_limit.enabled = true;
    cfg.rate_limit.client_max_queries = client_max;
    cfg.rate_limit.client_window_secs = 60;
    cfg.rate_limit.domain_max_queries = domain_max;
    cfg.rate_limit.domain_window_secs = 60;
    cfg.rate_limit.exempt_loopback = false;
    cfg
}

async fn setup_zone(server: &daygle_dns::BoundServer, name: &str) {
    let store = server.catalog.store();
    store
        .create_zone(&ZoneInput {
            name: name.to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();
}

#[tokio::test]
async fn limits_queries_per_client() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // Domain budget is large so only the per-client counter matters.
    let server = spawn(rate_limited_config(&db, 3, 1000)).await;
    setup_zone(&server, "client.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // 3 distinct domains allowed, then the 4th from the same source IP is
    // SERVFAIL - the client counter is per-IP, not per-name.
    for i in 0..3 {
        let msg = udp_query(udp, &format!("a{i}.client.test."), RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }
    let limited = udp_query(udp, "b.client.test.", RecordType::A).await;
    assert_eq!(limited.response_code, ResponseCode::ServFail);

    // Every query counts against the client window, even different domains.
    let again = udp_query(udp, "c.client.test.", RecordType::A).await;
    assert_eq!(again.response_code, ResponseCode::ServFail);

    let snap = server.metrics.snapshot();
    assert_eq!(snap.rate_limited, 2);

    shutdown(server).await;
}

#[tokio::test]
async fn limits_queries_per_domain() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // Client budget is large so only the per-domain counter matters.
    let server = spawn(rate_limited_config(&db, 1000, 2)).await;
    setup_zone(&server, "domain.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // 2 allowed for the hot domain, then the 3rd is SERVFAIL.
    let first = udp_query(udp, "hot.domain.test.", RecordType::A).await;
    assert_ne!(first.response_code, ResponseCode::ServFail);
    let second = udp_query(udp, "hot.domain.test.", RecordType::A).await;
    assert_ne!(second.response_code, ResponseCode::ServFail);
    let limited = udp_query(udp, "hot.domain.test.", RecordType::A).await;
    assert_eq!(limited.response_code, ResponseCode::ServFail);

    // Other domains are unaffected, even from the same client.
    let other = udp_query(udp, "other.domain.test.", RecordType::A).await;
    assert_ne!(other.response_code, ResponseCode::ServFail);

    assert_eq!(server.metrics.snapshot().rate_limited, 1);

    shutdown(server).await;
}

#[tokio::test]
async fn loopback_is_exempt_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let mut cfg = rate_limited_config(&db, 1, 1000);
    // Re-enable the default exemption: 127.0.0.1 is never limited.
    cfg.rate_limit.exempt_loopback = true;
    let server = spawn(cfg).await;
    setup_zone(&server, "local.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    for _ in 0..10 {
        let msg = udp_query(udp, "x.local.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }
    assert_eq!(server.metrics.snapshot().rate_limited, 0);

    shutdown(server).await;
}

#[tokio::test]
async fn disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // `base_config` leaves rate limiting off.
    let server = spawn(base_config(&db)).await;
    setup_zone(&server, "open.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    for _ in 0..20 {
        let msg = udp_query(udp, "y.open.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }
    assert_eq!(server.metrics.snapshot().rate_limited, 0);

    shutdown(server).await;
}

#[tokio::test]
async fn rate_limit_settings_reload_live() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

    // Start with a strict limit, then relax it via reload. The config file
    // must pass validation, so give every listener a real (non-zero) port;
    // dot/doh stay disabled so only the numbers matter.
    let mut cfg = rate_limited_config(&db, 3, 1000);
    cfg.server.port = 15353;
    cfg.api.port = 15380;
    cfg.dot.port = 1853;
    cfg.doh.port = 1443;
    let toml = toml::to_string(&cfg).unwrap();
    std::fs::write(&cfg_path, &toml).unwrap();

    let server = daygle_dns::bind_with(std::sync::Arc::new(cfg.clone()), Some(cfg_path.clone()))
        .await
        .expect("bind");
    setup_zone(&server, "rl.test").await;
    let udp = server.udp_addr.expect("UDP is enabled");

    for _ in 0..3 {
        let msg = udp_query(udp, "z.rl.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }
    let limited = udp_query(udp, "z.rl.test.", RecordType::A).await;
    assert_eq!(limited.response_code, ResponseCode::ServFail);

    // Relax the limits in the file and reload - the change applies live.
    cfg.rate_limit.client_max_queries = 100;
    cfg.rate_limit.domain_max_queries = 100;
    let toml = toml::to_string(&cfg).unwrap();
    std::fs::write(&cfg_path, &toml).unwrap();
    server.reload().await.expect("reload");

    for _ in 0..50 {
        let msg = udp_query(udp, "z.rl.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }

    shutdown(server).await;
}
