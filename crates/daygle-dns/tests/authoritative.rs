//! Integration test: authoritative responses over UDP and TCP, plus policy
//! blocking.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_core::config::DaygleConfig;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

fn config_with_zone(db: &std::path::Path, upstream: Option<String>) -> DaygleConfig {
    let mut cfg = base_config(db);
    if let Some(up) = upstream {
        cfg.recursive.enabled = true;
        cfg.recursive.use_system_config = false;
        cfg.recursive.upstreams = vec![up];
        cfg.recursive.dnssec_validate = false;
    }
    cfg
}

#[tokio::test]
async fn serves_authoritative_a_record_over_udp() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let config = config_with_zone(&db, None);

    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "example.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.42".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    let msg = udp_query(udp, "www.example.test.", RecordType::A).await;

    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.42"));
    assert_eq!(server.metrics.snapshot().authoritative, 1);

    shutdown(server).await;
}

#[tokio::test]
async fn serves_extended_record_types() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db, None)).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "ext.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    let cases = [
        ("@", RecordType::HTTPS, "1 . alpn=h2,h3"),
        ("_svc", RecordType::SVCB, "1 svc.ext.test. port=8443"),
        (
            "_25._tcp.mail",
            RecordType::TLSA,
            "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6",
        ),
        (
            "host",
            RecordType::SSHFP,
            "4 2 9F6B2C1D0E3A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        ),
        (
            "sip",
            RecordType::NAPTR,
            "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.ext.test.",
        ),
        (
            "child",
            RecordType::DS,
            "12345 13 2 3F2A6B1C9D8E7F60514233241506F7E8D9C0B1A2938475665748392A1B0C0D0E",
        ),
    ];
    for (name, rtype, content) in cases {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: name.to_string(),
                    rtype: rtype.to_string(),
                    content: content.to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    for (name, rtype, _) in cases {
        let qname = if name == "@" {
            "ext.test.".to_string()
        } else {
            format!("{name}.ext.test.")
        };
        let msg = udp_query(udp, &qname, rtype).await;
        assert_eq!(msg.response_code, ResponseCode::NoError, "{rtype} {qname}");
        assert!(
            msg.answers.iter().any(|a| a.record_type() == rtype),
            "{rtype} {qname} must be answered, got {:?}",
            msg.answers
        );
    }

    shutdown(server).await;
}

#[tokio::test]
async fn serves_authoritative_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db, None)).await;

    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "tcp.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "host".to_string(),
                rtype: "AAAA".to_string(),
                content: "2001:db8::1".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();

    let tcp = server.tcp_addr.expect("TCP is enabled");
    let msg = tcp_query(tcp, "host.tcp.test.", RecordType::AAAA).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("2001:db8::1"));

    shutdown(server).await;
}

#[tokio::test]
async fn policy_blocklist_returns_nxdomain() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let mut config = base_config(&db);
    config.policy.blocklist = vec!["*.ads.example".to_string()];

    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();

    let msg = udp_query(udp, "banner.ads.example.", RecordType::A).await;
    assert_eq!(msg.response_code, ResponseCode::NXDomain);
    assert_eq!(server.metrics.snapshot().blocked, 1);

    // Unmatched names still get a normal (REFUSED, no recursion) response.
    let ok = udp_query(udp, "example.com.", RecordType::A).await;
    assert_eq!(ok.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

#[tokio::test]
async fn serves_wildcard_records() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(config_with_zone(&db, None)).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "wild.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    for (name, rtype, content) in [
        ("@", "A", "192.0.2.1"),
        ("*", "CNAME", "wild.test."),
        ("www", "A", "192.0.2.80"),
    ] {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: name.to_string(),
                    rtype: rtype.to_string(),
                    content: content.to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    // A name with no records of its own is answered by the wildcard.
    let msg = udp_query(udp, "anything.wild.test.", RecordType::CNAME).await;
    assert_eq!(msg.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&msg).as_deref(), Some("wild.test."));
    // An existing name is not covered by the wildcard.
    let msg = udp_query(udp, "www.wild.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("192.0.2.80"));

    shutdown(server).await;
}

/// `POST /api/zones/import` takes the zone file's SOA as the zone's SOA
/// settings, as creating a zone from a file does, and does not keep it as a
/// record (served beside the zone's own, the higher serial would win).
#[tokio::test]
async fn importing_a_zone_file_takes_its_soa() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(config_with_zone(&dir.path().join("daygle-dns.db"), None)).await;
    let text = "$ORIGIN imported.test.\n\
                @ 3600 IN SOA ns1.imported.test. hostmaster.imported.test. 2024010101 7200 900 1209600 600\n\
                @ 3600 IN NS ns1.imported.test.\n\
                www 300 IN A 192.0.2.80\n";
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/zones/import", server.api_addr))
        .json(&serde_json::json!({ "name": "imported.test", "text": text }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    let zone = server
        .catalog
        .store()
        .find_zone_by_name("imported.test")
        .unwrap()
        .unwrap();
    assert_eq!(zone.serial, 2024010101);
    assert_eq!(zone.primary_ns.trim_end_matches('.'), "ns1.imported.test");
    assert_eq!(zone.minimum, 600);
    let records = server.catalog.store().list_records(&zone.id).unwrap();
    assert!(records.iter().all(|r| r.rtype != "SOA"), "{records:?}");

    let reply = udp_query(server.udp_addr.unwrap(), "imported.test.", RecordType::SOA).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    let soa: Vec<_> = reply
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::SOA)
        .collect();
    assert_eq!(soa.len(), 1);
    assert!(
        soa[0].data.to_string().contains("2024010101"),
        "{}",
        soa[0].data
    );
    shutdown(server).await;
}
