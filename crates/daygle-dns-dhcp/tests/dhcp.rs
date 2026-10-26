//! The DHCP service end to end over loopback: DHCPv4 through the relay
//! path (a client on loopback cannot be broadcast to), DHCPv6 by unicast,
//! and the DNS names registered for the leases.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use daygle_dns_authoritative::catalog::AuthorityCatalog;
use daygle_dns_authoritative::model::ZoneInput;
use daygle_dns_authoritative::store::ZoneStore;
use daygle_dns_core::config::AuthoritativeSettings;
use daygle_dns_core::dhcp::{Dhcp6Scope, DhcpScope, DhcpSettings};
use daygle_dns_core::logs::LogStore;
use daygle_dns_dhcp::DhcpService;
use dhcproto::{v4, v6, Decodable, Encodable};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

fn free_port(addr: &str) -> u16 {
    std::net::UdpSocket::bind(addr)
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn service(dir: &tempfile::TempDir) -> (Arc<DhcpService>, Arc<AuthorityCatalog>) {
    let store = ZoneStore::open(dir.path().join("zones.db").to_str().unwrap()).unwrap();
    for name in ["home.arpa", "127.in-addr.arpa"] {
        store
            .create_zone(&ZoneInput {
                name: name.to_string(),
                ..Default::default()
            })
            .unwrap();
    }
    let settings = AuthoritativeSettings {
        dnssec_enabled: false,
        ..Default::default()
    };
    let catalog = Arc::new(AuthorityCatalog::new(store, settings).unwrap());
    let service = DhcpService::new(catalog.clone(), Arc::new(LogStore::new(100)));
    (service, catalog)
}

async fn exchange(sock: &UdpSocket, to: std::net::SocketAddr, msg: &[u8]) -> Vec<u8> {
    sock.send_to(msg, to).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("a reply")
        .unwrap();
    buf.truncate(n);
    buf
}

/// Wait until `check` holds (the worker writes leases out shortly after).
async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..50 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not met in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn dhcpv4_through_a_relay_registers_the_name() {
    let dir = tempfile::tempdir().unwrap();
    let (service, catalog) = service(&dir);
    let shutdown = CancellationToken::new();
    service.start(shutdown.clone());
    let port = free_port("127.0.0.1:0");
    service.apply(&DhcpSettings {
        enabled: true,
        dns_zone: "home.arpa".to_string(),
        port_v4: port,
        scopes: vec![DhcpScope {
            name: "lo".to_string(),
            subnet: "127.0.0.0/24".to_string(),
            range_start: "127.0.0.100".to_string(),
            range_end: "127.0.0.200".to_string(),
            ..DhcpScope::default()
        }],
        ..DhcpSettings::default()
    });
    assert!(
        service.status().v4.starts_with("Listening"),
        "{:?}",
        service.status()
    );

    // The "relay" is a socket on loopback; it forwards for the client.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = format!("127.0.0.1:{port}").parse().unwrap();
    let mac = [2, 0, 0, 0, 0, 7];
    let request = |kind: v4::MessageType, requested: Option<Ipv4Addr>| {
        let mut msg = v4::Message::new(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            &mac,
        );
        msg.opts_mut().insert(v4::DhcpOption::MessageType(kind));
        msg.opts_mut()
            .insert(v4::DhcpOption::Hostname("Laptop".to_string()));
        if let Some(ip) = requested {
            msg.opts_mut()
                .insert(v4::DhcpOption::RequestedIpAddress(ip));
            msg.opts_mut()
                .insert(v4::DhcpOption::ServerIdentifier(Ipv4Addr::LOCALHOST));
        }
        msg.to_vec().unwrap()
    };
    let offer = v4::Message::from_bytes(
        &exchange(&relay, server, &request(v4::MessageType::Discover, None)).await,
    )
    .unwrap();
    assert!(offer.opts().has_msg_type(v4::MessageType::Offer));
    let ip = offer.yiaddr();
    assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 100));

    let ack = v4::Message::from_bytes(
        &exchange(&relay, server, &request(v4::MessageType::Request, Some(ip))).await,
    )
    .unwrap();
    assert!(ack.opts().has_msg_type(v4::MessageType::Ack));
    assert_eq!(ack.yiaddr(), ip);

    // The lease is saved and its names are served.
    let store = catalog.store_handle();
    eventually(|| {
        store
            .list_dhcp_leases()
            .unwrap()
            .iter()
            .any(|l| l.dns_records.len() == 2)
    })
    .await;
    let a = catalog
        .local_records("laptop.home.arpa", hickory_proto::rr::RecordType::A)
        .unwrap();
    assert_eq!(a.len(), 1);
    let ptr = catalog
        .local_records(
            "100.0.0.127.in-addr.arpa",
            hickory_proto::rr::RecordType::PTR,
        )
        .unwrap();
    assert_eq!(ptr.len(), 1);

    // Deleting the lease removes the names.
    assert!(service.delete_lease(&IpAddr::V4(ip)).unwrap());
    assert!(catalog
        .local_records("laptop.home.arpa", hickory_proto::rr::RecordType::A)
        .unwrap()
        .is_empty());
    assert!(store.list_dhcp_leases().unwrap().is_empty());
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread")]
async fn dhcpv6_hands_out_an_address() {
    // Skipped where loopback has no IPv6.
    let Ok(client) = UdpSocket::bind("[::1]:0").await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (service, _catalog) = service(&dir);
    let shutdown = CancellationToken::new();
    service.start(shutdown.clone());
    let port = free_port("[::1]:0");
    service.apply(&DhcpSettings {
        enabled: true,
        port_v6: port,
        scopes_v6: vec![Dhcp6Scope {
            name: "lo6".to_string(),
            interface: "lo".to_string(),
            prefix: "fd00:99::/64".to_string(),
            range_start: "fd00:99::10".to_string(),
            range_end: "fd00:99::20".to_string(),
            ..Dhcp6Scope::default()
        }],
        ..DhcpSettings::default()
    });
    assert!(
        service.status().v6.starts_with("Listening"),
        "{:?}",
        service.status()
    );

    let server = format!("[::1]:{port}").parse().unwrap();
    let mut solicit = v6::Message::new(v6::MessageType::Solicit);
    solicit
        .opts_mut()
        .insert(v6::DhcpOption::ClientId(vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 8]));
    solicit.opts_mut().insert(v6::DhcpOption::RapidCommit);
    solicit.opts_mut().insert(v6::DhcpOption::IANA(v6::IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: v6::DhcpOptions::new(),
    }));
    let reply =
        v6::Message::from_bytes(&exchange(&client, server, &solicit.to_vec().unwrap()).await)
            .unwrap();
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    let Some(v6::DhcpOption::IANA(ia)) = reply.opts().get(v6::OptionCode::IANA) else {
        panic!("no address: {reply:?}");
    };
    let Some(v6::DhcpOption::IAAddr(addr)) = ia.opts.get(v6::OptionCode::IAAddr) else {
        panic!("no address: {reply:?}");
    };
    let range = 0xfd00_0099_u128 << 96;
    assert!((range + 0x10..=range + 0x20).contains(&u128::from(addr.addr)));
    assert!(service
        .leases()
        .iter()
        .any(|l| l.address == IpAddr::V6(addr.addr) && l.state == "bound"));
    shutdown.cancel();
}
