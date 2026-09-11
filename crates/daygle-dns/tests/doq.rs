//! Integration test: DNS over QUIC (RFC 9250) with a self-signed certificate
//! and the configurable connection idle timeout.

mod common;

use std::path::Path;
use std::sync::Arc;

use common::*;
use daygle_dns::BoundServer;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use quinn::crypto::rustls::QuicClientConfig;

/// DoQ reserved error codes (RFC 9250 §4.3).
const DOQ_PROTOCOL_ERROR: u64 = 0x2;

/// Open a new QUIC stream on `connection` and run one DNS query over it
/// (RFC 9250 §4.2: one message per stream, 2-octet length prefix, Message ID
/// 0), returning the decoded response.
async fn doq_query(name: &str, rtype: RecordType, connection: &quinn::Connection) -> Message {
    let mut query = query_message(name, rtype);
    // RFC 9250 §4.2.1: the DNS Message ID MUST be 0 over DoQ.
    query.metadata.id = 0;
    let bytes = query.to_vec().expect("encode query");

    let (mut send, mut recv) = connection.open_bi().await.expect("open bidi stream");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    send.write_all(&framed).await.expect("write query");
    send.finish().expect("finish send");

    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.expect("read length");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    recv.read_exact(&mut resp).await.expect("read message");
    Message::from_vec(&resp).expect("decode response")
}

/// Build a DoQ client endpoint trusting `cert_path` (`doq` ALPN).
fn doq_endpoint(cert_path: &Path) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::pem::PemObject::pem_file_iter(cert_path).expect("cert file") {
        roots.add(cert.expect("parse cert")).expect("add root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).expect("quic config"),
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Spawn a server with DoQ enabled on an ephemeral loopback port serving the
/// `quic.test` zone (`secure.quic.test` -> 203.0.113.7).
async fn doq_server(dir: &Path) -> (BoundServer, std::path::PathBuf) {
    let db = dir.join("daygle-dns.db");
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");

    let mut config = base_config(&db);
    config.doq.enabled = true;
    config.doq.listen = "127.0.0.1".to_string();
    config.doq.port = 0;
    config.doq.self_signed = true;
    config.doq.cert_path = cert.to_string_lossy().to_string();
    config.doq.key_path = key.to_string_lossy().to_string();
    config.doq.server_name = "daygle.test".to_string();
    config.doq.idle_timeout_secs = 600;

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "quic.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "secure".to_string(),
                rtype: "A".to_string(),
                content: "203.0.113.7".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    (server, cert)
}

#[tokio::test]
async fn serves_queries_over_doq() {
    let dir = tempfile::tempdir().unwrap();
    let (server, cert) = doq_server(dir.path()).await;

    let doq = server.doq_addr.expect("DoQ is enabled");
    let endpoint = doq_endpoint(&cert);
    let connection = endpoint
        .connect(doq, "daygle.test")
        .expect("connect")
        .await
        .expect("handshake");

    let msg = doq_query("secure.quic.test.", RecordType::A, &connection).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("203.0.113.7"));

    // A second transaction reuses the connection but opens a new stream.
    let second = doq_query("secure.quic.test.", RecordType::A, &connection).await;
    assert_eq!(second.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&second).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn rejects_nonzero_message_id() {
    let dir = tempfile::tempdir().unwrap();
    let (server, cert) = doq_server(dir.path()).await;

    let doq = server.doq_addr.expect("DoQ is enabled");
    let endpoint = doq_endpoint(&cert);
    let connection = endpoint
        .connect(doq, "daygle.test")
        .expect("connect")
        .await
        .expect("handshake");

    // The wire Message ID is deliberately left at 0x1234 (from
    // `query_message`), which RFC 9250 §4.2.1 makes a protocol violation.
    let bytes = query_message("secure.quic.test.", RecordType::A)
        .to_vec()
        .expect("encode query");

    let (mut send, mut recv) = connection.open_bi().await.expect("open bidi stream");
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    send.write_all(&framed).await.expect("write query");
    send.finish().expect("finish send");

    // The server must abort the stream with DOQ_PROTOCOL_ERROR rather than
    // answer.
    let mut buf = [0u8; 2];
    let read = recv.read(&mut buf).await;
    match read {
        Err(quinn::ReadError::Reset(code)) => {
            assert_eq!(u64::from(code), DOQ_PROTOCOL_ERROR);
        }
        other => panic!("expected protocol-error reset, got {other:?}"),
    }

    shutdown(server).await;
}
