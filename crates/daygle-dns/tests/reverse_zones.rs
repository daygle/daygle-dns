//! Integration test: PTR records in IPv4 and IPv6 reverse zones.

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

    // An address with no PTR in a hosted reverse zone is NXDOMAIN.
    let msg = udp_query(udp, "99.2.0.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
}
