//! Integration test: ALIAS records answer A/AAAA at their name (the zone
//! apex included) with the target's addresses, whether the target is hosted
//! here or found through an upstream, and are kept apart from records and
//! from DNSSEC signing they cannot work with.

mod common;

use std::net::{Ipv4Addr, SocketAddr};

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::ResolutionMode;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};

/// An upstream that answers A for `cdn.example.net.` with 198.51.100.9 (TTL
/// 30) and NODATA for everything else under it.
async fn fake_upstream() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.recursion_available = true;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            for q in query.queries.iter() {
                response.queries.push(q.clone());
                if q.query_type() == RecordType::A
                    && q.name().to_ascii().eq_ignore_ascii_case("cdn.example.net.")
                {
                    response.answers.push(Record::from_rdata(
                        q.name().clone(),
                        30,
                        RData::A(Ipv4Addr::new(198, 51, 100, 9).into()),
                    ));
                }
            }
            let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

fn record(name: &str, rtype: &str, content: &str, ttl: u32) -> RecordInput {
    RecordInput {
        name: name.into(),
        rtype: rtype.into(),
        content: content.into(),
        ttl,
        priority: 0,
        disabled: false,
    }
}

fn a_of(msg: &Message) -> Vec<(String, u32, String)> {
    msg.answers
        .iter()
        .map(|r| (r.name.to_ascii(), r.ttl, r.data.to_string()))
        .collect()
}

#[tokio::test]
async fn alias_records_answer_with_their_target() {
    let upstream = fake_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.recursive.enabled = true;
    cfg.recursive.mode = Some(ResolutionMode::Forwarding);
    cfg.recursive.use_system_config = false;
    cfg.recursive.upstreams = vec![upstream.to_string()];
    cfg.recursive.dnssec_validate = false;
    let server = spawn(cfg).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "alias.test".into(),
            ..Default::default()
        })
        .unwrap();
    // The apex points at a CDN elsewhere; www points at a host in this zone.
    store
        .upsert_record(&zone.id, &record("@", "ALIAS", "CDN.example.net", 300))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("origin", "A", "192.0.2.10", 120))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("www", "ALIAS", "origin.alias.test.", 600))
        .unwrap();
    store
        .upsert_record(&zone.id, &record("@", "MX", "10 mail.alias.test.", 300))
        .unwrap();
    server.catalog.reload().unwrap();
    let udp = server.udp_addr.unwrap();

    // Apex ALIAS to an external target: the upstream's address, under the
    // apex name, with the lower TTL.
    let msg = udp_query(udp, "alias.test.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.authoritative);
    assert_eq!(
        a_of(&msg),
        [("alias.test.".into(), 30, "198.51.100.9".into())]
    );
    // Other types at the apex still come from the zone.
    let msg = udp_query(udp, "alias.test.", RecordType::MX).await;
    assert_eq!(msg.answers.len(), 1);
    // The target has no AAAA: NODATA, not NXDOMAIN.
    let msg = udp_query(udp, "alias.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty());

    // ALIAS to a host in this zone: answered from the zone data.
    let msg = udp_query(udp, "www.alias.test.", RecordType::A).await;
    assert_eq!(
        a_of(&msg),
        [("www.alias.test.".into(), 120, "192.0.2.10".into())]
    );

    // Records an ALIAS cannot sit with are refused, both ways round.
    let err = store
        .upsert_record(&zone.id, &record("@", "A", "192.0.2.1", 300))
        .unwrap_err()
        .to_string();
    assert!(err.contains("ALIAS"), "{err}");
    let err = store
        .upsert_record(&zone.id, &record("origin", "ALIAS", "cdn.example.net", 300))
        .unwrap_err()
        .to_string();
    assert!(err.contains("has A records"), "{err}");
    assert!(store
        .upsert_record(&zone.id, &record("loop", "ALIAS", "loop.alias.test", 300))
        .is_err());
    assert!(store
        .upsert_record(&zone.id, &record("bad", "ALIAS", "not a name!", 300))
        .is_err());

    // DNSSEC: a zone with an ALIAS cannot be signed, and a signed zone
    // takes no ALIAS.
    assert!(server
        .catalog
        .sign_zone(&zone.id)
        .unwrap_err()
        .to_string()
        .contains("ALIAS"));
    let signed = store
        .create_zone(&ZoneInput {
            name: "signed.test".into(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.sign_zone(&signed.id).unwrap();
    assert!(store
        .upsert_record(&signed.id, &record("@", "ALIAS", "cdn.example.net", 300))
        .unwrap_err()
        .to_string()
        .contains("DNSSEC"));
    shutdown(server).await;
}
