//! Integration test: PTR records in IPv4 and IPv6 reverse zones, and the
//! RFC 6303 empty reverse zones that answer for space with no hosted zone.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn ptr(name: &str, target: &str) -> RecordInput {
    RecordInput {
        name: name.to_string(),
        rtype: "PTR".to_string(),
        content: target.to_string(),
        ttl: 300,
        priority: 0,
        disabled: false,
    }
}

#[tokio::test]
async fn serves_ptr_records_in_reverse_zones() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(base_config(&db)).await;
    let store = server.catalog.store();

    // 192.0.2.0/24 and 2001:db8::/64, as the console names them.
    let v4 = store
        .create_zone(&ZoneInput {
            name: "2.0.192.in-addr.arpa".to_string(),
            ..Default::default()
        })
        .unwrap();
    let v6 = store
        .create_zone(&ZoneInput {
            name: "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa".to_string(),
            ..Default::default()
        })
        .unwrap();
    // Relative and fully qualified owner names, and a target without the
    // trailing dot.
    store
        .upsert_record(&v4.id, &ptr("42", "host.example.com."))
        .unwrap();
    store
        .upsert_record(&v4.id, &ptr("7.2.0.192.in-addr.arpa", "mail.example.com"))
        .unwrap();
    store
        .upsert_record(
            &v6.id,
            &ptr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "host.example.com."),
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    let cases = [
        ("42.2.0.192.in-addr.arpa.", "host.example.com."),
        ("7.2.0.192.in-addr.arpa.", "mail.example.com."),
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            "host.example.com.",
        ),
    ];
    for (qname, target) in cases {
        let msg = udp_query(udp, qname, RecordType::PTR).await;
        assert_eq!(msg.response_code, ResponseCode::NoError, "{qname}");
        assert!(msg.authoritative, "{qname} must be authoritative");
        assert_eq!(first_answer(&msg).as_deref(), Some(target), "{qname}");
    }

    // An address with no PTR in a hosted reverse zone is NXDOMAIN. A hosted
    // zone always wins over the RFC 6303 empty zone of the same space.
    let msg = udp_query(udp, "99.2.0.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}

/// RFC 6303 (BCP 163): the default empty zones answer authoritatively even
/// when recursion is off, so reverse queries for private, loopback, ULA and
/// test address space never leak upstream and fail fast locally.
#[tokio::test]
async fn rfc6303_empty_zones_answer_locally() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // base_config leaves recursion disabled: without RFC 6303 these queries
    // would be REFUSED or sent upstream instead of answered authoritatively.
    let server = spawn(base_config(&db)).await;
    let udp = server.udp_addr.expect("UDP is enabled");

    // Interior queries in the RFC 5737 TEST-NET-1 reverse zone (and the
    // RFC 1918 and ULA zones) are authoritative NXDOMAIN carrying the
    // empty zone's SOA for negative caching (RFC 2308).
    for (qname, apex) in [
        ("99.2.0.192.in-addr.arpa.", "2.0.192.in-addr.arpa."),
        ("7.10.in-addr.arpa.", "10.in-addr.arpa."),
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
            "d.f.ip6.arpa.",
        ),
    ] {
        let msg = udp_query(udp, qname, RecordType::PTR).await;
        assert!(
            msg.authoritative,
            "{qname} must be answered authoritatively"
        );
        assert_eq!(msg.response_code, ResponseCode::NXDomain, "{qname}");
        let soa = msg
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .unwrap_or_else(|| panic!("{qname} must carry the empty zone's SOA"));
        // The SOA lives on the empty zone's apex, whose MNAME is the apex
        // itself (RFC 6303, section 3).
        assert_eq!({ soa.name.to_string() }, apex, "{qname}");
        let hickory_proto::rr::RData::SOA(soa_data) = &soa.data else {
            panic!("SOA rdata expected for {qname}");
        };
        assert_eq!(soa_data.mname.to_string(), apex, "{qname}");
    }

    // The zone apex serves its own SOA and NS records, and answers other
    // types with NODATA (RFC 6303, section 3).
    let msg = udp_query(udp, "10.in-addr.arpa.", RecordType::SOA).await;
    assert!(msg.authoritative);
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(
        msg.answers
            .iter()
            .filter(|r| r.record_type() == RecordType::SOA)
            .count(),
        1,
        "the empty zone serves its SOA"
    );
    let msg = udp_query(udp, "10.in-addr.arpa.", RecordType::NS).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg
        .answers
        .iter()
        .any(|r| r.record_type() == RecordType::NS));
    let msg = udp_query(udp, "10.in-addr.arpa.", RecordType::A).await;
    assert!(msg.authoritative);
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert!(msg.answers.is_empty(), "apex NODATA expected");

    // Outside the empty zones, a query is not answered authoritatively:
    // with recursion off it is REFUSED, so the local claim stays exact.
    let msg = udp_query(udp, "77.3.0.192.in-addr.arpa.", RecordType::PTR).await;
    assert!(!msg.authoritative);
    assert_eq!(msg.response_code, ResponseCode::Refused);

    shutdown(server).await;
}
