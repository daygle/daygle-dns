//! Integration test: listener rebuilds (live reload) keep the NOTIFY hooks
//! and TSIG key ring.
//!
//! Regression guard: `start_listeners` used to build its dispatcher with
//! `NotifyHooks::default()` and an empty `TsigKeyRing`, so after any listener
//! rebinding (port change, settings update, reload API) TSIG-protected zone
//! transfers were refused and inbound NOTIFYs were answered NOTIMP.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use daygle_dns::bind_with;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_authoritative::tsig::{sign_request, TsigKey};
use daygle_dns_core::config::{DaygleConfig, SecondaryZoneConfig, TsigKeyConfig};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tsig_config() -> TsigKeyConfig {
    TsigKeyConfig {
        name: "reload-key.".to_string(),
        algorithm: "hmac-sha256".to_string(),
        // base64("0123456789abcdef") - no extra dev-dependency needed.
        secret: "MDEyMzQ1Njc4OWFiY2RlZg==".to_string(),
    }
}

fn config_with_tsig_and_notify(db: &std::path::Path) -> DaygleConfig {
    let mut cfg = base_config(db);
    cfg.authoritative.axfr_enabled = true;
    cfg.authoritative.tsig_keys = vec![tsig_config()];
    cfg.authoritative.tsig_transfer_zones =
        vec!["reload-transfer.test=reload-key".to_string()];
    cfg.authoritative.notify_listen_enabled = true;
    cfg.authoritative.secondary_zones = vec![SecondaryZoneConfig {
        name: "notify-reload.test".to_string(),
        masters: vec!["127.0.0.1".to_string()],
        refresh_secs: 3600,
        enabled: true,
        tsig_key: String::new(),
    }];
    cfg
}

/// Build and TSIG-sign an AXFR request for `zone`.
fn signed_axfr(zone: &str, key: &TsigKey) -> Vec<u8> {
    let mut msg = Message::new(0x5150, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_utf8(zone).expect("valid zone"),
        RecordType::AXFR,
    ));
    sign_request(&msg, key).expect("sign request")
}

/// Send raw wire bytes with a TCP length prefix and read one response.
async fn tcp_send_raw(addr: std::net::SocketAddr, bytes: &[u8]) -> Message {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(bytes);
    stream.write_all(&framed).await.expect("write");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.expect("read body");
    Message::from_vec(&resp).expect("decode response")
}

/// Send a NOTIFY (OpCode 4, QTYPE SOA) over UDP and return the reply.
async fn udp_notify(addr: std::net::SocketAddr, zone: &str) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = Message::new(0x4e07, MessageType::Query, OpCode::Notify);
    msg.add_query(Query::query(
        Name::from_utf8(zone).expect("valid zone"),
        RecordType::SOA,
    ));
    socket
        .send_to(&msg.to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("notify reply timeout")
        .expect("recv");
    Message::from_vec(&buf[..n]).expect("decode")
}

/// Grab an ephemeral free TCP port by binding and dropping a socket.
async fn free_tcp_port() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn tsig_transfers_and_notify_survive_listener_reload() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cfg_path = dir.path().join("daygle-dns.toml");

    let mut cfg = config_with_tsig_and_notify(&db);
    // The config file is validated, so ports must be concrete (not 0).
    cfg.server.port = free_tcp_port().await;
    cfg.dot.port = free_tcp_port().await;
    cfg.doh.port = free_tcp_port().await;
    cfg.api.port = free_tcp_port().await;
    std::fs::write(
        &cfg_path,
        toml::to_string(&cfg).expect("serialize config"),
    )
    .unwrap();

    let loaded = DaygleConfig::load(&cfg_path).unwrap();
    let server = bind_with(Arc::new(loaded), Some(cfg_path.clone()))
        .await
        .expect("bind");

    // Seed a zone protected by the TSIG key binding.
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "reload-transfer.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.55".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let key = TsigKey::from_config(&tsig_config()).unwrap();
    let wire = signed_axfr("reload-transfer.test.", &key);

    // Sanity before the reload: the signed transfer is served and inbound
    // NOTIFY (from the configured master IP) is accepted.
    let tcp_before = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_send_raw(tcp_before, &wire).await;
    assert_eq!(
        resp.response_code,
        ResponseCode::NoError,
        "signed AXFR must be served before the reload"
    );
    assert!(resp.signature().is_some(), "response must be TSIG-signed");

    let udp_before = server.udp_addr.expect("UDP enabled");
    let reply = udp_notify(udp_before, "notify-reload.test.").await;
    assert_eq!(
        reply.response_code,
        ResponseCode::NoError,
        "NOTIFY from the master must be accepted before the reload"
    );

    // Force a listener rebuild via the synchronous reload API.
    let new_port = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    cfg.server.port = new_port;
    std::fs::write(
        &cfg_path,
        toml::to_string(&cfg).expect("serialize config"),
    )
    .unwrap();
    server.reload().await.expect("reload");

    // The listeners moved to the new port...
    let addrs = server.addrs();
    let tcp_after = addrs.tcp.expect("TCP enabled after reload");
    let udp_after = addrs.udp.expect("UDP enabled after reload");
    assert_eq!(tcp_after.port(), new_port);
    assert_eq!(udp_after.port(), new_port);

    // ...and the TSIG ring must have survived: the same signed request is
    // still served instead of refused with an empty key ring.
    let resp = tcp_send_raw(tcp_after, &wire).await;
    assert_eq!(
        resp.response_code,
        ResponseCode::NoError,
        "signed AXFR must still be served after a listener reload"
    );
    assert!(resp.signature().is_some());

    // ...and the NOTIFY hooks must have survived: inbound NOTIFY is still
    // accepted (not answered NOTIMP by a default NotifyHooks).
    let reply = udp_notify(udp_after, "notify-reload.test.").await;
    assert_eq!(
        reply.response_code,
        ResponseCode::NoError,
        "NOTIFY from the master must still be accepted after a listener reload"
    );

    shutdown(server).await;
}
