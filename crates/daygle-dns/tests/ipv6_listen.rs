//! Integration tests for listen addresses: a wildcard IPv6 address (`::`)
//! serves DNS and the web console to IPv6 and IPv4 clients, `ipv6_only`
//! keeps IPv4 off it, and a listener can take several addresses.

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

/// A port free for TCP and UDP on every address in `ips`.
fn free_port_on(ips: &[IpAddr]) -> u16 {
    loop {
        let port = std::net::TcpListener::bind((ips[0], 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let free = ips.iter().all(|ip| {
            std::net::TcpListener::bind((*ip, port)).is_ok()
                && std::net::UdpSocket::bind((*ip, port)).is_ok()
        });
        if free {
            return port;
        }
    }
}

async fn zone_with_www(server: &daygle_dns::BoundServer) {
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "multi.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.81".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
}

#[tokio::test]
async fn a_listener_takes_several_addresses() {
    let one = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let two = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    let dns_port = free_port_on(&[one, two]);
    let api_port = free_port_on(&[one, two]);
    cfg.server.listen = "127.0.0.1, 127.0.0.2".into();
    cfg.server.port = dns_port;
    cfg.api.listen = "127.0.0.1,127.0.0.2".into();
    cfg.api.port = api_port;
    let server = spawn(cfg).await;
    zone_with_www(&server).await;

    for ip in [one, two] {
        let reply = udp_query_from(
            one,
            SocketAddr::new(ip, dns_port),
            "www.multi.test.",
            RecordType::A,
        )
        .await;
        assert_eq!(reply.answers.len(), 1, "UDP on {ip}");
        let reply = tcp_query(
            SocketAddr::new(ip, dns_port),
            "www.multi.test.",
            RecordType::A,
        )
        .await;
        assert_eq!(reply.answers.len(), 1, "TCP on {ip}");
        let status = reqwest::get(format!("http://{ip}:{api_port}/api/status"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200, "web console on {ip}");
    }
    // An address that is not listed is not listened on.
    assert!(tokio::net::TcpStream::connect((other, dns_port))
        .await
        .is_err());
    assert!(tokio::net::TcpStream::connect((other, api_port))
        .await
        .is_err());
    shutdown(server).await;
}

#[tokio::test]
async fn wildcard_ipv6_with_an_ipv4_address() {
    if !ipv6_available() {
        eprintln!("IPv6 is not available on this host: :: plus IPv4 check skipped");
        return;
    }
    // `::` next to an IPv4 address takes IPv6 only, so the IPv4 address can
    // be bound on the same port.
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    let port = free_port_on(&[v6, v4, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
    cfg.server.listen = "::, 127.0.0.1".into();
    cfg.server.port = port;
    let server = spawn(cfg).await;
    zone_with_www(&server).await;
    for ip in [v6, v4] {
        let reply = tcp_query(SocketAddr::new(ip, port), "www.multi.test.", RecordType::A).await;
        assert_eq!(reply.answers.len(), 1, "TCP on {ip}");
    }
    assert!(tokio::net::TcpStream::connect(("127.0.0.2", port))
        .await
        .is_err());
    shutdown(server).await;
}
