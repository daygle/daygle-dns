//! Shared helpers for the Daygle integration tests.

#![allow(dead_code)]

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use daygle::bind;
use daygle::dispatcher::DnsDispatcher;
use daygle::BoundServer;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use daygle_authoritative::{AuthorityCatalog, ZoneStore};
use daygle_core::config::{AuthoritativeSettings, DaygleConfig};
use daygle_core::{LogStore, Metrics};
use daygle_policy::PolicyEngine;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_server::server::Server;

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
    cfg.api.listen = "127.0.0.1".to_string();
    cfg.api.port = 0;
    cfg.api.api_token = String::new();
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
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
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

/// Send a query over DNS-over-TLS (self-signed cert trusted via `cert_path`).
pub async fn dot_query(
    addr: SocketAddr,
    server_name: &str,
    cert_path: &Path,
    name: &str,
    rtype: RecordType,
) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect DoT");

    let mut roots = rustls::RootCertStore::empty();
    let cert_pem = std::fs::read(cert_path).expect("read cert");
    let mut reader = BufReader::new(cert_pem.as_slice());
    for cert in rustls_pemfile::certs(&mut reader) {
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

/// The presentation text of the first answer record, if any.
pub fn first_answer(msg: &Message) -> Option<String> {
    msg.answers.first().map(|r| r.data.to_string())
}

/// Stop a bound server by cancelling its shutdown token.
pub async fn shutdown(server: BoundServer) {
    server.shutdown_token().cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Spawn a minimal authoritative-only upstream server serving `zone_name`.
pub async fn spawn_upstream(db: &Path, zone_name: &str, ip: &str) -> SocketAddr {
    let store = ZoneStore::open(&db.to_string_lossy()).unwrap();
    let catalog = Arc::new(AuthorityCatalog::new(store, AuthoritativeSettings::default()).unwrap());
    let zone = catalog
        .store()
        .create_zone(&ZoneInput {
            name: zone_name.to_string(),
            ..Default::default()
        })
        .unwrap();
    catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "A".to_string(),
                content: ip.to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
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
