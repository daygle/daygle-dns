//! Shared helpers for the Daygle integration tests.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use daygle_dns::bind;
use daygle_dns::dispatcher::DnsDispatcher;
use daygle_dns::BoundServer;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_authoritative::{AuthorityCatalog, ZoneStore};
use daygle_dns_core::config::{AuthoritativeSettings, DaygleConfig};
use daygle_dns_core::{LogStore, Metrics};
use daygle_dns_policy::PolicyEngine;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_server::server::Server;
use rustls_pki_types::pem::PemObject;

/// A loopback port that is free for both TCP and UDP, for tests that need
/// a fixed port number (one that settings validation accepts, or that a
/// restart reuses).
///
/// Ports come from below the kernel's ephemeral range (32768 and up on
/// Linux), which port-0 binds never hand out: binding port 0 and releasing
/// it instead lets any socket in a parallel test take the same number
/// before the server binds it. A counter keeps the ports of one test
/// process apart, and the process id spreads concurrent processes.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    const FIRST: u16 = 20_000;
    const COUNT: u16 = 12_000;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = (std::process::id() % u32::from(COUNT)) as u16;
    for _ in 0..COUNT {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
        let port = FIRST + (start + offset) % COUNT;
        let tcp = std::net::TcpListener::bind(("127.0.0.1", port));
        let udp = std::net::UdpSocket::bind(("127.0.0.1", port));
        if tcp.is_ok() && udp.is_ok() {
            return port;
        }
    }
    panic!(
        "no free loopback port between {FIRST} and {}",
        FIRST + COUNT
    );
}

/// A configuration with ephemeral ports and no recursion, bound to loopback.
pub fn base_config(db: &Path) -> DaygleConfig {
    let mut cfg = DaygleConfig::default();
    cfg.server.listen = "127.0.0.1".to_string();
    cfg.server.port = 0;
    cfg.server.udp_enabled = true;
    cfg.server.tcp_enabled = true;
    cfg.dot.enabled = false;
    cfg.dot.listen = "127.0.0.1".to_string();
    cfg.dot.port = 0;
    cfg.doh.enabled = false;
    cfg.doh.listen = "127.0.0.1".to_string();
    cfg.doh.port = 0;
    cfg.api.listen = "127.0.0.1".to_string();
    cfg.api.port = 0;
    cfg.api.api_token = String::new();
    // Integration tests exercise the API unauthenticated; the console-auth
    // default (on) is covered by the login/setup tests in console.rs.
    cfg.api.auth_required = false;
    cfg.recursive.enabled = false;
    cfg.recursive.use_system_config = false;
    cfg.authoritative.database = db.to_string_lossy().to_string();
    cfg.authoritative.dnssec_enabled = false;
    cfg
}

/// Bind a server from a configuration.
pub async fn spawn(config: DaygleConfig) -> BoundServer {
    bind(Arc::new(config)).await.expect("server should bind")
}

/// Build a DNS query message.
pub fn query_message(name: &str, rtype: RecordType) -> Message {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_utf8(name).expect("valid name"),
        rtype,
    ));
    msg
}

/// Send a query over plaintext UDP and return the response.
pub async fn udp_query(addr: SocketAddr, name: &str, rtype: RecordType) -> Message {
    udp_query_from([127, 0, 0, 1].into(), addr, name, rtype).await
}

/// Send a query over plaintext UDP from the loopback address `source` (so a
/// test can act as different clients) and return the response.
pub async fn udp_query_from(
    source: std::net::IpAddr,
    addr: SocketAddr,
    name: &str,
    rtype: RecordType,
) -> Message {
    let socket = tokio::net::UdpSocket::bind((source, 0))
        .await
        .expect("bind client socket");
    let bytes = query_message(name, rtype).to_vec().expect("encode query");
    socket.send_to(&bytes, addr).await.expect("send query");
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("timeout waiting for response")
        .expect("receive response");
    Message::from_vec(&buf[..n]).expect("decode response")
}

/// Send a query over TCP and return the response.
pub async fn tcp_query(addr: SocketAddr, name: &str, rtype: RecordType) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect TCP");
    let bytes = query_message(name, rtype).to_vec().expect("encode query");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.expect("write query");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.expect("read body");
    Message::from_vec(&resp).expect("decode response")
}

/// Send a DNS message over DNS-over-TLS (self-signed cert trusted via `cert_path`).
pub async fn dot_send(
    addr: SocketAddr,
    server_name: &str,
    cert_path: &Path,
    message: &Message,
) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect DoT");

    let mut roots = rustls::RootCertStore::empty();
    for cert in
        rustls::pki_types::CertificateDer::<'_>::pem_file_iter(cert_path).expect("open cert file")
    {
        roots.add(cert.expect("parse cert")).expect("add root");
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"dot".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .expect("server name")
        .to_owned();
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    let bytes = message.to_vec().expect("encode DNS message");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream.write_all(&framed).await.expect("write DNS message");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.expect("read body");
    Message::from_vec(&resp).expect("decode response")
}

/// Send a query over DNS-over-TLS (self-signed cert trusted via `cert_path`).
pub async fn dot_query(
    addr: SocketAddr,
    server_name: &str,
    cert_path: &Path,
    name: &str,
    rtype: RecordType,
) -> Message {
    dot_send(addr, server_name, cert_path, &query_message(name, rtype)).await
}

/// The presentation text of the first answer record, if any.
pub fn first_answer(msg: &Message) -> Option<String> {
    msg.answers.first().map(|r| r.data.to_string())
}

/// Stop a bound server and wait until its tasks (and so the database) are released.
pub async fn shutdown(server: BoundServer) {
    server.stop().await.expect("server stops cleanly");
}

/// Spawn a minimal authoritative-only upstream server serving `zone_name`.
pub async fn spawn_upstream(db: &Path, zone_name: &str, ip: &str) -> SocketAddr {
    spawn_upstream_with(db, zone_name, &[("host", "A", ip)]).await
}

/// An upstream authoritative for `zone_name`, holding `records` as
/// `(name, type, content)`.
pub async fn spawn_upstream_with(
    db: &Path,
    zone_name: &str,
    records: &[(&str, &str, &str)],
) -> SocketAddr {
    let store = ZoneStore::open(&db.to_string_lossy()).unwrap();
    let catalog = Arc::new(AuthorityCatalog::new(store, AuthoritativeSettings::default()).unwrap());
    let zone = catalog
        .store()
        .create_zone(&ZoneInput {
            name: zone_name.to_string(),
            ..Default::default()
        })
        .unwrap();
    for (name, rtype, content) in records {
        catalog
            .store()
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: name.to_string(),
                    rtype: rtype.to_string(),
                    content: content.to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    catalog.reload().unwrap();

    let dispatcher = DnsDispatcher::from_components(
        catalog,
        None,
        PolicyEngine::new(false),
        Arc::new(Metrics::default()),
        Arc::new(LogStore::new(100)),
    );
    let mut server = Server::new(dispatcher);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = socket.local_addr().unwrap();
    server.register_socket(socket);

    // Keep the upstream alive for the duration of the test.
    tokio::spawn(async move {
        let mut server = server;
        let _ = server.block_until_done().await;
    });

    addr
}
