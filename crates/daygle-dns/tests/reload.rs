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

/// Grab an ephemeral port that is free for both UDP and TCP by binding and
/// dropping a socket of each. The callers use these ports for TCP listeners
/// too (DNS over TCP, DoT, DoH, the API), and a port free for UDP can still
/// be taken for TCP, e.g. as the local port of another test's connection.
async fn free_port() -> u16 {
    loop {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return port;
        }
    }
}

/// Send one raw DNS query over TCP (length-prefixed) and read the response.
async fn tcp_transfer_query(
    addr: SocketAddr,
    name: &str,
    rtype: RecordType,
) -> hickory_proto::op::Message {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::Name;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect TCP");
    let mut msg = Message::new(0x2223, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_utf8(name).expect("valid name"),
        rtype,
    ));
    let bytes = msg.to_vec().expect("encode query");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.expect("write query");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let mut resp = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream.read_exact(&mut resp).await.expect("read body");
    Message::from_vec(&resp).expect("decode response")
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
    let store =
        daygle_dns_authoritative::ZoneStore::open(seed_db.to_string_lossy().as_ref()).unwrap();
    let mut cfg_for_db = DaygleConfig::load(&cfg_path).unwrap();
    cfg_for_db.recursive.upstreams = vec![up_a.to_string()];
    store
        .put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(
            &cfg_for_db,
        ))
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

/// Named networks saved from the console are the live source: once a network
/// is in the database overlay, editing it in the file does not change the
/// transfer gate (the overlay owns console-managed settings), but the console
/// change does.
#[tokio::test]
async fn console_owned_network_ignores_file_edits() {
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
    cfg.authoritative.axfr_enabled = true;
    cfg.authoritative.axfr_networks = vec!["LAN".to_string()];
    cfg.networks = vec![daygle_dns_core::config::NamedNetwork {
        name: "LAN".to_string(),
        cidrs: vec!["10.0.0.0/8".to_string()],
        description: String::new(),
    }];
    write_config(&cfg_path, &cfg);

    let server = bind_with(
        Arc::new(DaygleConfig::load(&cfg_path).unwrap()),
        Some(cfg_path.clone()),
    )
    .await
    .expect("bind");
    let tcp = server.tcp_addr.expect("TCP enabled");
    server.catalog.reload().unwrap();
    server
        .catalog
        .store()
        .create_zone(&daygle_dns_authoritative::model::ZoneInput {
            name: "filed.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();

    // 127.0.0.1 is outside LAN: refused.
    let resp = tcp_transfer_query(tcp, "filed.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    // Widen LAN in the file so it covers the test client. The overlay (the
    // stored network) wins, so the transfer stays refused after the watcher
    // has had time to read the file.
    cfg.networks[0].cidrs = vec!["127.0.0.0/8".to_string()];
    write_config(&cfg_path, &cfg);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resp = tcp_transfer_query(tcp, "filed.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::Refused);

    // The console change does reach the gate.
    let api = format!("http://{}/api", server.api_addr);
    let resp = reqwest::Client::new()
        .post(format!("{api}/networks"))
        .json(&serde_json::json!({
            "original_name": "LAN",
            "name": "LAN",
            "cidrs": ["127.0.0.0/8"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = tcp_transfer_query(tcp, "filed.test.", RecordType::AXFR).await;
    assert_eq!(resp.response_code, ResponseCode::NoError);

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
        assert!(
            Instant::now() < deadline,
            "watcher did not apply the edit in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The DB overlay wins: the file's blocklist entry is not applied.
    let new_udp = server.addrs().udp.expect("UDP enabled");
    let msg = udp_query(new_udp, "watched.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

/// Settings saved in the console survive a restart (a service restart, or
/// an in-place update) everywhere they are used, not just in the config the
/// console shows: the resolver, the filtering policy and the rest are built
/// from the saved settings at startup. They used to start from the config
/// file's values, so "Recursion Access: Everyone" read back as Everyone but
/// the resolver refused public clients until the setting was saved again.
#[tokio::test]
async fn console_settings_apply_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut file = base_config(&dir.path().join("daygle-dns.db"));
    file.recursive.enabled = true;
    file.recursive.mode = Some(daygle_dns_core::config::ResolutionMode::Forwarding);
    file.recursive.upstreams = vec!["127.0.0.1:9".to_string()];

    let public: std::net::IpAddr = "203.0.113.5".parse().unwrap();
    let server = spawn(file.clone()).await;
    assert!(
        !server.resolver.as_ref().unwrap().allows_client(public),
        "the default is private networks only"
    );
    let resp = reqwest::Client::new()
        .put(format!("http://{}/api/config", server.api_addr))
        .json(&serde_json::json!({
            "recursive": { "recursion_access": "allow" },
            "policy": { "blocklist": ["blocked.test"] },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    shutdown(server).await;

    // Restart with the same, untouched config file.
    let server = spawn(file).await;
    assert!(
        server.resolver.as_ref().unwrap().allows_client(public),
        "the saved recursion access applies from startup"
    );
    let udp = server.udp_addr.unwrap();
    let reply = udp_query(udp, "blocked.test.", RecordType::A).await;
    assert_eq!(
        reply.response_code,
        ResponseCode::NXDomain,
        "the saved blocklist applies from startup"
    );
    shutdown(server).await;
}
