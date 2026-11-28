//! Integration test: a secondary zone is served from the records its master
//! transferred, not the record table, so a record too large for one DNS
//! message can reach it that way too. A lookup that would hit one skips and
//! reports it, like every other large-record path.

mod common;

use common::*;
use daygle_dns_authoritative::model::ZoneInput;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A transfer's records in the form a secondary keeps them: each record in
/// wire format, after its length (4 bytes), closing SOA left out.
fn stored_transfer(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        let mut buf = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            record
                .emit(&mut encoder)
                .expect("encode a transferred record");
        }
        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&buf);
    }
    out
}

/// Send one query over TCP with EDNS, so the answer is not held to the 512
/// byte UDP limit and the oversized record has to be encoded.
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
async fn a_secondary_lookup_skips_a_record_it_cannot_encode() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "sec.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .set_secondary(&zone.id, &["192.0.2.1:53".to_string()], 3600)
        .unwrap();

    // A zone as a master sent it. The TXT's record comes to 65,500 bytes on
    // the wire: small enough for a transfer message, too large for the answer
    // this server builds (header, question and OPT record included).
    let origin = Name::from_utf8("sec.test.").unwrap();
    let soa = Record::from_rdata(
        origin.clone(),
        300,
        RData::SOA(SOA::new(
            Name::from_utf8("ns.sec.test.").unwrap(),
            Name::from_utf8("admin.sec.test.").unwrap(),
            1,
            3600,
            600,
            86_400,
            300,
        )),
    );
    let www = Record::from_rdata(
        Name::from_utf8("www.sec.test.").unwrap(),
        300,
        RData::A(A::new(192, 0, 2, 9)),
    );
    let mut strings: Vec<String> = (0..260).map(|_| "x".repeat(250)).collect();
    strings.push("y".repeat(215));
    let big = Record::from_rdata(
        Name::from_utf8("big.sec.test.").unwrap(),
        300,
        RData::TXT(TXT::new(strings)),
    );
    store
        .set_transfer_data(&zone.id, &stored_transfer(&[soa, www, big]))
        .unwrap();
    server.catalog.reload().unwrap();

    let tcp = server.tcp_addr.expect("TCP enabled");

    // Before, this answer carried the oversized record and could not be
    // encoded: the client got an empty answer with TC set, even over TCP.
    let resp = tcp_query_with_edns(tcp, "big.sec.test.", RecordType::TXT).await;
    assert_eq!(resp.response_code, ResponseCode::NXDomain);
    assert!(!resp.truncation, "the answer must not be truncated");
    assert!(
        resp.answers.is_empty(),
        "the oversized record was served: {:?}",
        resp.answers
    );

    // The rest of the transferred zone is served as it came.
    let resp = tcp_query(tcp, "www.sec.test.", RecordType::A).await;
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1, "{:?}", resp.answers);

    // Skipping it is reported, so the stale record can be found and removed.
    let reported = server
        .logs
        .entries()
        .iter()
        .any(|entry| entry.component == "query" && entry.message.contains("big.sec.test"));
    assert!(reported, "the skipped record was not logged");

    shutdown(server).await;
}
