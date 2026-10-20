//! Integration test: a wildcard IPv6 listen address (`::`) serves DNS and
//! the web console to both IPv6 and IPv4 clients.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::rr::RecordType;

fn ipv6_available() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

#[tokio::test]
async fn wildcard_ipv6_listen_serves_both_families() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    if !ipv6_available() {
        // Without IPv6 on the host, `::` cannot be bound at all; check the
        // IPv4 listeners still accept the bracketed and plain IPv4 forms.
        cfg.server.listen = "0.0.0.0".into();
        cfg.api.listen = "[127.0.0.1]".into();
        let server = spawn(cfg).await;
        assert!(server.api_addr.ip().is_loopback());
        eprintln!("IPv6 is not available on this host: dual-stack checks skipped");
        shutdown(server).await;
        return;
    }
    cfg.server.listen = "::".into();
    cfg.api.listen = "[::]".into();
    let server = spawn(cfg).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "dual.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.80".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let udp_port = server.udp_addr.expect("UDP is enabled").port();
    for ip in [
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ] {
        // Send from loopback in the target's family: an IPv4 socket cannot
        // reach `::1`.
        let reply = udp_query_from(
            ip,
            SocketAddr::new(ip, udp_port),
            "www.dual.test.",
            RecordType::A,
        )
        .await;
        assert_eq!(reply.answers.len(), 1, "DNS over {ip}");
    }

    let api_port = server.api_addr.port();
    for host in ["[::1]", "127.0.0.1"] {
        let status = reqwest::get(format!("http://{host}:{api_port}/api/status"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200, "web console over {host}");
    }
    shutdown(server).await;
}

#[tokio::test]
async fn ipv6_only_keeps_ipv4_clients_off_a_wildcard_listener() {
    if !ipv6_available() {
        eprintln!("IPv6 is not available on this host: IPv6-only check skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.server.listen = "::".into();
    cfg.server.ipv6_only = true;
    cfg.api.listen = "::".into();
    let server = spawn(cfg).await;
    let tcp_port = server.tcp_addr.expect("TCP is enabled").port();
    let api_port = server.api_addr.port();
    for port in [tcp_port, api_port] {
        assert!(tokio::net::TcpStream::connect(("::1", port)).await.is_ok());
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err(),
            "IPv4 reached port {port}"
        );
    }
    shutdown(server).await;
}
