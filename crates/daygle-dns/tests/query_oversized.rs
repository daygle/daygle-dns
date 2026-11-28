//! Integration test: a record too large for one DNS message, left in the
//! database by a build that did not check, is skipped by a normal lookup and
//! reported, instead of the whole answer coming back broken.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Send one query over TCP with EDNS, so the answer is not held to the 512
/// byte UDP limit: the case where the oversized record has to be encoded.
async fn tcp_query_with_edns(addr: std::net::SocketAddr, name: &str, rtype: RecordType) -> Message {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_utf8(name).expect("valid name"),
        rtype,
    ));
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    message.edns = Some(edns);

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect TCP");
    let bytes = message.to_vec().expect("encode query");
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

#[tokio::test]
async fn a_lookup_skips_a_record_it_cannot_encode() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");

    // Bring the zone up normally, then add the oversized row the way an older
    // build could have: straight into the database, past the write-time check.
    let server = spawn(base_config(&db)).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "skip.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.7".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    shutdown(server).await;

    let quoted = format!("\"{}\"", "x".repeat(250));
    let oversized = vec![quoted; 300].join(" ");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO records (id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at)
         VALUES ('oversized-record', ?1, 'big.skip.test', 'TXT', ?2, 300, 0, 0, '2026-01-01T00:00:00Z')",
        rusqlite::params![&zone.id, oversized],
    )
    .unwrap();
    drop(conn);

    let server = spawn(base_config(&db)).await;
    let tcp = server.tcp_addr.expect("TCP enabled");

    // Before, this answer carried the oversized record and could not be
    // encoded: the client got an empty answer with TC set, even over TCP.
    // Now the record is not served, and its name has nothing else.
    let resp = tcp_query_with_edns(tcp, "big.skip.test.", RecordType::TXT).await;
    assert_eq!(resp.response_code, ResponseCode::NXDomain);
    assert!(!resp.truncation, "the answer must not be truncated");
    assert!(
        resp.answers.is_empty(),
        "the oversized record was served: {:?}",
        resp.answers
    );

    // The rest of the zone is unaffected.
    let resp = tcp_query(tcp, "www.skip.test.", RecordType::A).await;
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1, "{:?}", resp.answers);

    // Skipping it is reported, so the stale record can be found and removed.
    let reported = server
        .logs
        .entries()
        .iter()
        .any(|entry| entry.component == "query" && entry.message.contains("big.skip.test"));
    assert!(reported, "the skipped record was not logged");

    shutdown(server).await;
}
