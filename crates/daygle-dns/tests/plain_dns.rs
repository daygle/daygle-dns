//! Integration tests: plain DNS on the UDP and TCP listeners.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use daygle_dns_authoritative::{RecordInput, ZoneInput};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send `query` from `socket` to `to`; the reply and where it came from.
async fn exchange(
    socket: &tokio::net::UdpSocket,
    to: SocketAddr,
    query: &Message,
) -> (Message, SocketAddr) {
    socket.send_to(&query.to_vec().unwrap(), to).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let (len, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("an answer")
        .unwrap();
    (Message::from_vec(&buf[..len]).unwrap(), from)
}

/// A wildcard listener must answer from the address the query was sent to:
/// a resolver drops a reply from an address it did not ask. (All of
/// 127.0.0.0/8 is local on Linux, so the host has many such addresses.)
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_wildcard_listener_replies_from_the_address_asked() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.server.listen = "0.0.0.0".to_string();
    let server = spawn(config).await;
    let port = server.udp_addr.unwrap().port();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = query_message("example.test.", RecordType::A);
    for target in ["127.0.0.1", "127.0.0.2", "127.0.0.3"] {
        let to: SocketAddr = format!("{target}:{port}").parse().unwrap();
        let (_, from) = exchange(&socket, to, &query).await;
        assert_eq!(
            from, to,
            "the reply to a query sent to {to} came from {from}"
        );
    }
    shutdown(server).await;
}

/// The same on a dual-stack `::` listener: IPv4 clients (seen as
/// IPv4-mapped addresses) and IPv6 clients alike.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_dual_stack_listener_replies_from_the_address_asked() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("no IPv6 loopback here: skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.server.listen = "::".to_string();
    let server = spawn(config).await;
    let port = server.udp_addr.unwrap().port();
    let query = query_message("example.test.", RecordType::A);

    let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
    let (_, from) = exchange(&v4, to, &query).await;
    assert_eq!(from, to);

    let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let to: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    let (_, from) = exchange(&v6, to, &query).await;
    assert_eq!(from, to);
    shutdown(server).await;
}

/// An answer too big for the 512 octets a client without EDNS can take is
/// truncated, so the client retries over TCP, where it is answered whole.
#[tokio::test]
async fn oversized_udp_answers_are_truncated_and_whole_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "big.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    for i in 0..40 {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "many".to_string(),
                    rtype: "A".to_string(),
                    content: format!("192.0.2.{}", i + 1),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    server.catalog.reload().unwrap();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = query_message("many.big.test.", RecordType::A);
    socket
        .send_to(&query.to_vec().unwrap(), server.udp_addr.unwrap())
        .await
        .unwrap();
    let mut buf = vec![0u8; 65_535];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(len <= 512, "{len} octets to a client without EDNS");
    assert!(Message::from_vec(&buf[..len]).unwrap().metadata.truncation);

    let whole = tcp_query(server.tcp_addr.unwrap(), "many.big.test.", RecordType::A).await;
    assert!(!whole.metadata.truncation);
    assert_eq!(whole.answers.len(), 40);
    shutdown(server).await;
}

fn framed(message: &Message) -> Vec<u8> {
    let bytes = message.to_vec().unwrap();
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&bytes);
    out
}

async fn read_answer(stream: &mut TcpStream, within: Duration) -> Option<Message> {
    let mut len = [0u8; 2];
    tokio::time::timeout(within, stream.read_exact(&mut len))
        .await
        .ok()?
        .ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut body).await.ok()?;
    Message::from_vec(&body).ok()
}

/// Queries pipelined on one TCP connection are answered concurrently, as
/// each completes (RFC 7766 §6.2.1.1): a cached or local answer does not
/// wait behind a slow recursive lookup sent before it.
#[tokio::test]
async fn pipelined_tcp_queries_do_not_wait_for_each_other() {
    // An upstream that never answers: the recursive lookup runs until the
    // client timeout.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.mode = Some(daygle_dns_core::config::ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![silent.local_addr().unwrap().to_string()];
    config.recursive.dnssec_validate = false;
    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "fast.test".to_string(),
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

    let mut slow = query_message("slow.example.", RecordType::A);
    slow.metadata.id = 1;
    let mut fast = query_message("www.fast.test.", RecordType::A);
    fast.metadata.id = 2;
    let mut stream = TcpStream::connect(server.tcp_addr.unwrap()).await.unwrap();
    let mut both = framed(&slow);
    both.extend_from_slice(&framed(&fast));
    stream.write_all(&both).await.unwrap();

    let first = read_answer(&mut stream, Duration::from_secs(1))
        .await
        .expect("the local answer, without waiting for the slow lookup");
    assert_eq!(first.metadata.id, 2);
    assert_eq!(first_answer(&first).as_deref(), Some("192.0.2.80"));
    let second = read_answer(&mut stream, Duration::from_secs(10))
        .await
        .expect("the slow lookup is still answered");
    assert_eq!(second.metadata.id, 1);
    drop(silent);
    shutdown(server).await;
}

/// `server.tcp_max_connections` caps the plain-TCP connections served at
/// once; a slot frees when a connection closes.
#[tokio::test]
async fn tcp_connections_are_capped() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.server.tcp_max_connections = 3;
    let server = spawn(config).await;
    let tcp = server.tcp_addr.unwrap();
    let query = framed(&query_message("example.test.", RecordType::A));

    async fn served(tcp: SocketAddr, query: &[u8]) -> Option<TcpStream> {
        let mut stream = TcpStream::connect(tcp).await.ok()?;
        stream.write_all(query).await.ok()?;
        read_answer(&mut stream, Duration::from_secs(3)).await?;
        Some(stream)
    }

    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(served(tcp, &query).await.expect("within the cap"));
    }
    assert!(served(tcp, &query).await.is_none(), "over the cap");
    // Closing one frees its slot.
    drop(held.pop());
    let mut freed = None;
    for _ in 0..50 {
        freed = served(tcp, &query).await;
        if freed.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed.is_some(), "a slot frees when a connection closes");
    drop(held);
    shutdown(server).await;
}

/// A malformed query gets FORMERR on both transports; a datagram too short
/// to be DNS gets nothing.
#[tokio::test]
async fn malformed_queries_get_formerr() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    // A header announcing a question that is not there.
    let garbage = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xff];

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&[1, 2, 3], server.udp_addr.unwrap())
        .await
        .unwrap();
    socket
        .send_to(&garbage, server.udp_addr.unwrap())
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let reply = Message::from_vec(&buf[..len]).unwrap();
    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);

    let mut stream = TcpStream::connect(server.tcp_addr.unwrap()).await.unwrap();
    let mut frame = (garbage.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&garbage);
    stream.write_all(&frame).await.unwrap();
    let reply = read_answer(&mut stream, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    shutdown(server).await;
}
