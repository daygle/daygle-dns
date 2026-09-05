//! Integration test: live configuration reload.
//!
//! Exercises the three reloadable subsystems - policy, upstreams and
//! listeners - both through the synchronous [`daygle_dns::BoundServer::reload`]
//! API and through the background file watcher.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use daygle_dns::bind_with;
use daygle_dns_core::config::DaygleConfig;
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
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

    let port_a = free_port().await;
    let port_b = free_port().await;

    let mut cfg = base_config(&db);
    cfg.server.port = port_a;
    cfg.server.reload_enabled = false;
    cfg.recursive.enabled = false;
    cfg.dot.port = free_port().await;
    cfg.doh.port = free_port().await;
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

    // Edit the file: a new listener port (file-owned) plus a blocklist
    // entry (DB-owned - the overlay must win over the file, so this entry
    // is expected to be ignored).
    cfg.server.port = port_b;
    cfg.policy.blocklist = vec!["blocked.example".to_string()];
    write_config(&cfg_path, &cfg);

    server.reload().await.expect("reload");

    // The new listener is live (listener ports stay file-owned).
    let new_udp = server.addrs().udp.expect("UDP rebound");
    assert_eq!(new_udp.port(), port_b);

    // The file's blocklist entry was overridden by the DB overlay (which
    // holds the blocklist from first boot: empty), so the name is not blocked.
    let not_blocked = udp_query(new_udp, "blocked.example.", RecordType::A).await;
    assert_eq!(not_blocked.response_code, ResponseCode::Refused);

    // The old listener is gone.
    assert!(expect_no_udp_response(old_udp, Duration::from_millis(400)).await);

    shutdown(server).await;
}

#[tokio::test]
async fn reloads_recursive_upstreams() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

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
    cfg.doh.port = free_port().await;
    cfg.api.port = free_port().await;
    write_config(&cfg_path, &cfg);
    // Upstreams are a DB-owned runtime setting: seed the DB with the values
    // the file would have supplied on first boot.
    let seed_db = dir.path().join("daygle-dns.db");
    let store = daygle_dns_authoritative::ZoneStore::open(seed_db.to_string_lossy().as_ref()).unwrap();
    let mut cfg_for_db = DaygleConfig::load(&cfg_path).unwrap();
    cfg_for_db.recursive.upstreams = vec![up_a.to_string()];
    store
        .put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(&cfg_for_db))
        .unwrap();
    drop(store);

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

    // Switch to upstream B by updating the DB-owned runtime settings
    // (as the console does). The file's copy is irrelevant now.
    cfg.recursive.upstreams = vec![up_b.to_string()];
    write_config(&cfg_path, &cfg);
    let store = daygle_dns_authoritative::ZoneStore::open(
        dir.path().join("daygle-dns.db").to_string_lossy().as_ref(),
    )
    .unwrap();
    store
        .put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(&cfg))
        .unwrap();
    drop(store);
    server.reload().await.expect("reload");

    let msg = udp_query(udp, "host.b.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.2"));

    shutdown(server).await;
}

#[tokio::test]
async fn watches_config_file_and_applies_edits() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

    let mut cfg = base_config(&db);
    cfg.server.port = free_port().await;
    cfg.server.reload_enabled = true;
    cfg.server.reload_interval_ms = 50;
    cfg.recursive.enabled = false;
    cfg.dot.port = free_port().await;
    cfg.doh.port = free_port().await;
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

    // Edit the file: change the listener port (file-owned) and add a
    // blocklist entry (DB-owned, so the watcher must NOT apply it).
    let port_b = free_port().await;
    cfg.server.port = port_b;
    cfg.policy.blocklist = vec!["watched.example".to_string()];
    write_config(&cfg_path, &cfg);

    // The watcher picks up the file edit on its own; the listener port
    // changes once it does.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let bound = server.addrs().udp.expect("UDP enabled");
        if bound.port() == port_b {
            break;
        }
        assert!(Instant::now() < deadline, "watcher did not apply the edit in time");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The DB overlay wins: the file's blocklist entry is not applied.
    let new_udp = server.addrs().udp.expect("UDP enabled");
    let msg = udp_query(new_udp, "watched.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}
