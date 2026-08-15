//! Integration test: live configuration reload.
//!
//! Exercises the three reloadable subsystems — policy, upstreams and
//! listeners — both through the synchronous [`daygle::BoundServer::reload`]
//! API and through the background file watcher.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use daygle::bind_with;
use daygle_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// Grab an ephemeral free port by binding and dropping a socket.
async fn free_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap().port()
}

/// Write `cfg` to `path` as TOML.
fn write_config(path: &PathBuf, cfg: &DaygleConfig) {
    let text = toml::to_string(cfg).expect("serialize config");
    std::fs::write(path, text).expect("write config");
}

/// Send a UDP query and return whether no valid DNS response arrived within
/// `wait`. A closed port either times out or yields an ICMP error, neither of
/// which is a valid response.
async fn expect_no_udp_response(addr: SocketAddr, wait: Duration) -> bool {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = query_message("example.com.", RecordType::A)
        .to_vec()
        .unwrap();
    socket.send_to(&bytes, addr).await.unwrap();
    let mut buf = [0u8; 4096];
    !matches!(
        tokio::time::timeout(wait, socket.recv_from(&mut buf)).await,
        Ok(Ok(_))
    )
}

#[tokio::test]
async fn reloads_policy_and_listeners_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let cfg_path = dir.path().join("daygle.toml");

    let port_a = free_port().await;
    let port_b = free_port().await;

    let mut cfg = base_config(&db);
    cfg.server.port = port_a;
    cfg.server.reload_enabled = false;
    cfg.recursive.enabled = false;
    cfg.dot.port = free_port().await;
    cfg.api.port = free_port().await;
    write_config(&cfg_path, &cfg);

    let loaded = DaygleConfig::load(&cfg_path).unwrap();
    let server = bind_with(Arc::new(loaded), Some(cfg_path.clone()))
        .await
        .expect("bind");

    let old_udp = server.udp_addr.expect("UDP enabled");
    assert_eq!(old_udp.port(), port_a);

    // Nothing blocked yet: the name is not authoritative and recursion is off.
    let msg = udp_query(old_udp, "blocked.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    // Edit the file: new port plus a blocklist entry.
    cfg.server.port = port_b;
    cfg.policy.blocklist = vec!["blocked.example".to_string()];
    write_config(&cfg_path, &cfg);

    server.reload().await.expect("reload");

    // The new listener is live and the blocklist is in effect.
    let new_udp = server.addrs().udp.expect("UDP rebound");
    assert_eq!(new_udp.port(), port_b);
    let blocked = udp_query(new_udp, "blocked.example.", RecordType::A).await;
    assert_eq!(blocked.response_code, ResponseCode::NXDomain);

    // Unblocked names still fall through (REFUSED, recursion off).
    let other = udp_query(new_udp, "allowed.example.", RecordType::A).await;
    assert_eq!(other.response_code, ResponseCode::Refused);

    // The old listener is gone.
    assert!(expect_no_udp_response(old_udp, Duration::from_millis(400)).await);

    shutdown(server).await;
}

#[tokio::test]
async fn reloads_recursive_upstreams() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let cfg_path = dir.path().join("daygle.toml");

    let up_a = spawn_upstream(&dir.path().join("up-a.db"), "a.test", "198.51.100.1").await;
    let up_b = spawn_upstream(&dir.path().join("up-b.db"), "b.test", "198.51.100.2").await;

    let mut cfg = base_config(&db);
    cfg.server.port = free_port().await;
    cfg.server.reload_enabled = false;
    cfg.recursive.enabled = true;
    cfg.recursive.use_system_config = false;
    cfg.recursive.upstreams = vec![up_a.to_string()];
    cfg.recursive.dnssec_validate = false;
    cfg.dot.port = free_port().await;
    cfg.api.port = free_port().await;
    write_config(&cfg_path, &cfg);

    let server = bind_with(
        Arc::new(DaygleConfig::load(&cfg_path).unwrap()),
        Some(cfg_path.clone()),
    )
    .await
    .expect("bind");
    let udp = server.udp_addr.expect("UDP enabled");

    // Resolves through upstream A.
    let msg = udp_query(udp, "host.a.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.1"));

    // Switch to upstream B.
    cfg.recursive.upstreams = vec![up_b.to_string()];
    write_config(&cfg_path, &cfg);
    server.reload().await.expect("reload");

    let msg = udp_query(udp, "host.b.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.2"));

    shutdown(server).await;
}

#[tokio::test]
async fn watches_config_file_and_applies_edits() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle.db");
    let cfg_path = dir.path().join("daygle.toml");

    let mut cfg = base_config(&db);
    cfg.server.port = free_port().await;
    cfg.server.reload_enabled = true;
    cfg.server.reload_interval_ms = 50;
    cfg.recursive.enabled = false;
    cfg.dot.port = free_port().await;
    cfg.api.port = free_port().await;
    write_config(&cfg_path, &cfg);

    let server = bind_with(
        Arc::new(DaygleConfig::load(&cfg_path).unwrap()),
        Some(cfg_path.clone()),
    )
    .await
    .expect("bind");
    let udp = server.udp_addr.expect("UDP enabled");

    // Not blocked yet.
    let msg = udp_query(udp, "watched.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    // Edit the file: the watcher should pick this up on its own.
    cfg.policy.blocklist = vec!["watched.example".to_string()];
    write_config(&cfg_path, &cfg);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let msg = udp_query(udp, "watched.example.", RecordType::A).await;
        if msg.response_code == ResponseCode::NXDomain {
            break;
        }
        assert!(Instant::now() < deadline, "watcher did not apply the edit in time");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    shutdown(server).await;
}
