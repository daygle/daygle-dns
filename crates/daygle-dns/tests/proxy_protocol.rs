//! Integration test: PROXY protocol on the TCP listener. A trusted proxy's
//! header decides who the client is (here, for a per-client policy rule).

mod common;

use common::*;
use daygle_dns_core::config::PolicyRule;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Send `header` then one TCP DNS query for `who.test` A; `None` when the
/// server closes the connection instead of answering.
async fn ask(addr: std::net::SocketAddr, header: &[u8]) -> Option<Message> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let query = query_message("who.test.", RecordType::A).to_vec().unwrap();
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&(query.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&query);
    stream.write_all(&bytes).await.ok()?;
    let mut len = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(8),
        stream.read_exact(&mut len),
    )
    .await
    .ok()?
    .ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut body).await.ok()?;
    Some(Message::from_vec(&body).unwrap())
}

fn v2(command: u8, src: [u8; 4]) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x20 | command, 0x11, 0, 12]);
    header.extend_from_slice(&src);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&40000u16.to_be_bytes());
    header.extend_from_slice(&53u16.to_be_bytes());
    header
}

#[tokio::test]
async fn trusted_proxies_name_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.server.proxy_protocol = vec!["127.0.0.0/8".to_string()];
    config.policy.rules = vec![PolicyRule {
        clients: vec!["203.0.113.7/32".to_string()],
        domains: vec!["who.test".to_string()],
        action: "redirect".to_string(),
        redirect: Some("192.0.2.77".parse().unwrap()),
    }];
    let server = spawn(config).await;
    let tcp = server.tcp_addr.unwrap();

    // v1 and v2 headers naming 203.0.113.7: the rule applies.
    let msg = ask(tcp, b"PROXY TCP4 203.0.113.7 127.0.0.1 40000 53\r\n")
        .await
        .expect("answer");
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.77"));
    let msg = ask(tcp, &v2(1, [203, 0, 113, 7])).await.expect("answer");
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.77"));

    // Another client, or a LOCAL header (the proxy itself): it does not.
    let msg = ask(tcp, &v2(1, [203, 0, 113, 8])).await.expect("answer");
    assert_eq!(first_answer(&msg), None);
    let msg = ask(tcp, &v2(0, [0, 0, 0, 0])).await.expect("answer");
    assert_eq!(first_answer(&msg), None);

    // A trusted address that sends no header is not served.
    assert!(ask(tcp, b"").await.is_none());

    shutdown(server).await;
}
