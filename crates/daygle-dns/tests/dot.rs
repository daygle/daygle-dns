//! Integration test: DNS over TLS with a self-signed certificate.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::{RecursionAccess, ResolutionMode};
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

#[tokio::test]
async fn serves_queries_over_dot() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    // Exercise the configured handshake timeout (not the default 20 s) so the
    // listener provably reads the setting.
    config.dot.handshake_timeout_secs = 1;

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
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

    let dot = server.dot_addr.expect("DoT is enabled");
    let msg = dot_query(dot, "daygle.test", &cert, "secure.tls.test.", RecordType::A).await;

    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_refuse_dns_update_before_authoritative_update_handling() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    config.dot.allowed_networks = vec!["10.9.9.0/24".to_string()];
    config.authoritative.allow_dynamic_updates = true;
    config.authoritative.update_networks = vec!["127.0.0.1".to_string()];

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let mut update = Message::new(0x4321, MessageType::Query, OpCode::Update);
    update.add_zone(Query::query(
        Name::from_utf8("tls.test.").unwrap(),
        RecordType::SOA,
    ));
    let mut new_record = hickory_proto::rr::Record::from_rdata(
        Name::from_utf8("new.tls.test.").unwrap(),
        60,
        hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A([192, 0, 2, 99].into())),
    );
    new_record.dns_class = hickory_proto::rr::DNSClass::IN;
    update.add_update(new_record);

    let response = dot_send(server.dot_addr.unwrap(), "daygle.test", &cert, &update).await;
    assert_eq!(response.response_code, ResponseCode::Refused);
    assert!(server
        .catalog
        .store()
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .all(|record| record.name != "new.tls.test"));

    // NOTIFY also has an early dispatcher path; it must be rejected by the
    // listener ACL before the inbound-NOTIFY handler sees it.
    let mut notify = Message::new(0x4322, MessageType::Query, OpCode::Notify);
    notify.add_query(Query::query(
        Name::from_utf8("tls.test.").unwrap(),
        RecordType::SOA,
    ));
    let response = dot_send(server.dot_addr.unwrap(), "daygle.test", &cert, &notify).await;
    assert_eq!(response.response_code, ResponseCode::Refused);

    // The same UPDATE remains allowed over ordinary DNS, where the DoT ACL
    // does not apply.
    let udp = server.udp_addr.unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = update.to_vec().unwrap();
    socket.send_to(&bytes, udp).await.unwrap();
    let mut response_bytes = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut response_bytes),
    )
    .await
    .unwrap()
    .unwrap();
    let response = Message::from_vec(&response_bytes[..len]).unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(server
        .catalog
        .store()
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .any(|record| record.name == "new.tls.test"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_refuse_clients_outside_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    // The test client is 127.0.0.1, outside this list.
    config.dot.allowed_networks = vec!["10.9.9.0/24".to_string()];

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tls.test".to_string(),
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

    // On DoT the client is refused before any other processing...
    let dot = server.dot_addr.expect("DoT is enabled");
    let msg = dot_query(dot, "daygle.test", &cert, "secure.tls.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    // ...while plain UDP carries no listener list and still answers.
    let udp = server.udp_addr.expect("UDP is enabled");
    let msg = udp_query(udp, "secure.tls.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_grant_recursion_on_that_listener_only() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_upstream(
        &dir.path().join("upstream.db"),
        "example.test.",
        "198.51.100.7",
    )
    .await;
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    // Recursion Access excludes the test client (127.0.0.1)...
    config.recursive.recursion_access = RecursionAccess::Custom;
    config.recursive.recursion_networks = vec!["10.0.0.0/8".to_string()];
    // ...but the DoT listener lists it.
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = cert.to_string_lossy().to_string();
    config.dot.key_path = key.to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    config.dot.allowed_networks = vec!["127.0.0.1".to_string()];

    let server = spawn(config).await;
    let dot = server.dot_addr.expect("DoT is enabled");
    let udp = server.udp_addr.expect("UDP is enabled");

    // Listed on the DoT listener: the client may recurse there...
    let msg = dot_query(
        dot,
        "daygle.test",
        &cert,
        "host.example.test.",
        RecordType::A,
    )
    .await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));

    // ...plain DNS is governed by Recursion Access alone and stays refused.
    let msg = udp_query(udp, "host.example.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

/// A DoT config for `dir` with a self-signed certificate for `daygle.test`.
fn dot_config(dir: &std::path::Path) -> daygle_dns_core::config::DaygleConfig {
    let mut config = base_config(&dir.join("daygle-dns.db"));
    config.dot.enabled = true;
    config.dot.self_signed = true;
    config.dot.cert_path = dir.join("server.crt").to_string_lossy().to_string();
    config.dot.key_path = dir.join("server.key").to_string_lossy().to_string();
    config.dot.server_name = "daygle.test".to_string();
    config
}

/// Host `www.fast.test A 192.0.2.10` on `server`.
async fn seed_fast_zone(server: &daygle_dns::BoundServer) {
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
                content: "192.0.2.10".to_string(),
                ttl: 60,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
}

type DotStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// Open one DoT session, trusting the server's self-signed certificate.
async fn dot_connect(addr: std::net::SocketAddr, cert: &std::path::Path) -> DotStream {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    dot_handshake(tcp, cert).await.expect("TLS handshake")
}

/// The client side of a DoT handshake on `tcp`.
async fn dot_handshake(
    tcp: tokio::net::TcpStream,
    cert: &std::path::Path,
) -> std::io::Result<DotStream> {
    use rustls_pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_file_iter(cert).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"dot".to_vec()];
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
        .connect(
            rustls::pki_types::ServerName::try_from("daygle.test").unwrap(),
            tcp,
        )
        .await
}

fn framed(message: &Message) -> Vec<u8> {
    let bytes = message.to_vec().unwrap();
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&bytes);
    out
}

/// Read one framed answer; also returns its encoded length.
async fn read_answer(stream: &mut DotStream) -> (Message, usize) {
    use tokio::io::AsyncReadExt as _;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.expect("answer length");
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.expect("answer body");
    (Message::from_vec(&body).unwrap(), body.len())
}

/// RFC 7766 pipelining: a slow recursive query must not hold up a fast
/// authoritative one sent after it on the same connection - each is
/// answered as soon as it is ready, matched by message ID.
#[tokio::test]
async fn pipelined_queries_are_answered_as_they_complete() {
    use tokio::io::AsyncWriteExt as _;
    let dir = tempfile::tempdir().unwrap();
    // An upstream that never answers: recursion for it waits out the
    // client timeout.
    let black_hole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = dot_config(dir.path());
    config.recursive.enabled = true;
    config.recursive.mode = Some(ResolutionMode::Forwarding);
    config.recursive.upstreams = vec![black_hole.local_addr().unwrap().to_string()];
    config.server.client_timeout_ms = 2000;
    let server = spawn(config).await;
    seed_fast_zone(&server).await;
    let cert = dir.path().join("server.crt");
    let mut stream = dot_connect(server.dot_addr.unwrap(), &cert).await;

    let mut slow = query_message("slow.example.", RecordType::A);
    slow.metadata.id = 1;
    let mut fast = query_message("www.fast.test.", RecordType::A);
    fast.metadata.id = 2;
    let mut both = framed(&slow);
    both.extend(framed(&fast));
    let started = std::time::Instant::now();
    stream.write_all(&both).await.unwrap();

    let (first, _) = read_answer(&mut stream).await;
    assert_eq!(first.metadata.id, 2, "the fast answer comes first");
    assert_eq!(first_answer(&first).as_deref(), Some("192.0.2.10"));
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1500),
        "the fast answer waited {:?} behind the slow query",
        started.elapsed()
    );
    let (second, _) = read_answer(&mut stream).await;
    assert_eq!(second.metadata.id, 1);
    assert_eq!(second.metadata.response_code, ResponseCode::ServFail);

    drop(black_hole);
    shutdown(server).await;
}

/// RFC 8467: a padded query gets an answer padded to 468-octet blocks; an
/// unpadded one is left alone.
#[tokio::test]
async fn padded_queries_get_padded_answers() {
    use hickory_proto::op::Edns;
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use tokio::io::AsyncWriteExt as _;
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(dot_config(dir.path())).await;
    seed_fast_zone(&server).await;
    let cert = dir.path().join("server.crt");
    let mut stream = dot_connect(server.dot_addr.unwrap(), &cert).await;

    let mut padded = query_message("www.fast.test.", RecordType::A);
    let mut edns = Edns::new();
    edns.options_mut().insert(EdnsOption::Unknown(
        u16::from(EdnsCode::Padding),
        vec![0; 100],
    ));
    padded.edns = Some(edns);
    stream.write_all(&framed(&padded)).await.unwrap();
    let (answer, len) = read_answer(&mut stream).await;
    assert_eq!(first_answer(&answer).as_deref(), Some("192.0.2.10"));
    assert_eq!(len % 468, 0, "answer of {len} octets is not padded");

    let mut plain = query_message("www.fast.test.", RecordType::A);
    plain.edns = Some(Edns::new());
    stream.write_all(&framed(&plain)).await.unwrap();
    let (answer, len) = read_answer(&mut stream).await;
    assert_eq!(first_answer(&answer).as_deref(), Some("192.0.2.10"));
    assert!(len < 468, "unpadded query got a {len}-octet answer");

    shutdown(server).await;
}

/// One public client cannot hold every DoT slot: past an eighth of
/// `max_connections` (at least 4) its connections are refused and the
/// refusal is logged. The client is named by a trusted PROXY header (a
/// test can only connect from loopback, which is not capped).
#[tokio::test]
async fn one_client_cannot_take_every_connection() {
    use tokio::io::AsyncWriteExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut config = dot_config(dir.path());
    config.dot.max_connections = 8;
    config.server.proxy_protocol = vec!["127.0.0.1".to_string()];
    let server = spawn(config).await;
    let cert = dir.path().join("server.crt");
    let addr = server.dot_addr.unwrap();

    let connect_as = |client: &'static str| {
        let cert = cert.clone();
        async move {
            let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            tcp.write_all(format!("PROXY TCP4 {client} 127.0.0.1 40000 853\r\n").as_bytes())
                .await
                .unwrap();
            dot_handshake(tcp, &cert).await
        }
    };
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(connect_as("203.0.113.5").await.expect("within the limit"));
    }
    // The fifth from the same client is closed without a handshake.
    assert!(connect_as("203.0.113.5").await.is_err());
    assert!(server.logs.entries().iter().any(|e| e.component == "tls"
        && e.message.contains("203.0.113.5")
        && e.message.contains("too many connections from this client")));
    // Another client is unaffected.
    let mut other = connect_as("198.51.100.7").await.expect("another client");
    let mut probe = query_message("www.fast.test.", RecordType::A);
    probe.metadata.id = 5;
    other.write_all(&framed(&probe)).await.unwrap();
    let (answer, _) = read_answer(&mut other).await;
    assert_eq!(answer.metadata.id, 5);

    // A slot frees up when one of the held sessions ends.
    drop(held.pop());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _again = connect_as("203.0.113.5").await.expect("slot released");

    drop(held);
    shutdown(server).await;
}

/// An idle session closes after the handshake timeout, which doubles as
/// the read-inactivity timeout.
#[tokio::test]
async fn idle_sessions_close_after_the_timeout() {
    use tokio::io::AsyncReadExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut config = dot_config(dir.path());
    config.dot.handshake_timeout_secs = 1;
    let server = spawn(config).await;
    let cert = dir.path().join("server.crt");
    let mut stream = dot_connect(server.dot_addr.unwrap(), &cert).await;
    let mut byte = [0u8; 1];
    let started = std::time::Instant::now();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the idle session is closed");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
    shutdown(server).await;
}

/// Public DoT readiness: a listener open to everyone with a self-signed
/// certificate warns (Android Private DNS refuses it), and a listener
/// whose clients would be refused recursion says how to open it.
#[tokio::test]
async fn warns_about_what_stops_public_private_dns() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = dot_config(dir.path());
    config.dot.allowed_networks = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    let server = spawn(config).await;
    assert!(
        server.logs.entries().iter().any(|e| e.component == "tls"
            && e.level == daygle_dns_core::LogLevel::Warn
            && e.message.contains("self-signed")),
        "no self-signed warning"
    );
    shutdown(server).await;

    let dir = tempfile::tempdir().unwrap();
    let mut config = dot_config(dir.path());
    config.recursive.enabled = true;
    config.recursive.recursion_access = RecursionAccess::PrivateNetworks;
    let server = spawn(config).await;
    let entries = server.logs.entries();
    assert!(
        entries
            .iter()
            .any(|e| e.component == "tls" && e.message.contains("dot.allowed_networks")),
        "no recursion note"
    );
    // A LAN-only listener is not a public one: no certificate warning.
    assert!(!entries
        .iter()
        .any(|e| e.component == "tls" && e.message.contains("self-signed")));
    shutdown(server).await;
}

/// A TCP connect-and-close (a load balancer's health check, a port scan) is
/// not a failed client: nothing is logged for it.
#[tokio::test]
async fn silent_connections_are_not_logged_as_failures() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(dot_config(dir.path())).await;
    for _ in 0..3 {
        drop(
            tokio::net::TcpStream::connect(server.dot_addr.unwrap())
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let failures: Vec<_> = server
        .logs
        .entries()
        .into_iter()
        .filter(|e| e.component == "tls" && e.message.contains("session failure"))
        .map(|e| e.message)
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
    shutdown(server).await;
}

/// A client that pipelines queries but never reads the answers stalls its
/// connection's writer. The write times out, the session ends and its slot
/// is released, instead of being held forever.
#[tokio::test]
async fn a_client_that_never_reads_does_not_hold_its_slot() {
    use tokio::io::AsyncWriteExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut config = dot_config(dir.path());
    config.dot.max_connections = 8; // 4 per public client
    config.dot.handshake_timeout_secs = 1;
    config.server.proxy_protocol = vec!["127.0.0.1".to_string()];
    let server = spawn(config).await;
    // Large answers fill the socket buffers quickly.
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "big.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    let chunk = format!("\"{}\"", "x".repeat(250));
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "txt".to_string(),
                rtype: "TXT".to_string(),
                content: vec![chunk; 16].join(" "),
                ttl: 60,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    let cert = dir.path().join("server.crt");
    let addr = server.dot_addr.unwrap();

    let connect = || {
        let cert = cert.clone();
        async move {
            // A small receive buffer: the client's side fills at once.
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(4096).unwrap();
            let mut tcp = socket.connect(addr).await.unwrap();
            tcp.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 40000 853\r\n")
                .await
                .unwrap();
            dot_handshake(tcp, &cert).await
        }
    };
    let mut stalled = Vec::new();
    for _ in 0..4 {
        let mut stream = connect().await.expect("within the limit");
        let query = framed(&query_message("txt.big.test.", RecordType::TXT));
        stalled.push(tokio::spawn(async move {
            // Keep asking, never read; stops when the server gives up.
            for _ in 0..20_000 {
                if stream.write_all(&query).await.is_err() {
                    break;
                }
            }
            stream
        }));
    }
    // Every slot of this client is taken while the sessions are stalled...
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // ...and freed once their writes time out (1 s here).
    let mut admitted = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if connect().await.is_ok() {
            admitted = true;
            break;
        }
    }
    assert!(admitted, "the stalled sessions kept their slots");
    for task in stalled {
        task.abort();
    }
    shutdown(server).await;
}
