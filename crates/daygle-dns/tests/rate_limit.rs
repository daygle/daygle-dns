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
fn rate_limited_config(db: &std::path::Path, client_max: u32, domain_max: u32) -> DaygleConfig {
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

/// Rate limiting is a console setting: changing it on the Settings page
/// (`PUT /api/config`) applies to the next query, and it is stored in the
/// database, so editing `[rate_limit]` in the config file afterwards no
/// longer overrides it (the file only seeds it on first boot).
#[tokio::test]
async fn rate_limit_settings_apply_live_from_the_console() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

    // Start with a strict limit, then relax it from the console. Settings
    // saves validate the whole config, so give every listener a real port.
    let mut cfg = rate_limited_config(&db, 3, 1000);
    cfg.server.port = free_port();
    cfg.api.port = free_port();
    std::fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();

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

    let mut relaxed = cfg.rate_limit.clone();
    relaxed.client_max_queries = 100;
    relaxed.domain_max_queries = 100;
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({ "rate_limit": relaxed }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    for _ in 0..50 {
        let msg = udp_query(udp, "z.rl.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }

    // A later file edit does not override the console's value.
    cfg.rate_limit.client_max_queries = 3;
    std::fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();
    server.reload().await.expect("reload");
    for _ in 0..20 {
        let msg = udp_query(udp, "z.rl.test.", RecordType::A).await;
        assert_ne!(msg.response_code, ResponseCode::ServFail);
    }

    shutdown(server).await;
}
