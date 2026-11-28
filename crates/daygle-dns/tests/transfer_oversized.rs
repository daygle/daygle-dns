//! Integration test: a record too large for one DNS message, left in the
//! database by a build that did not check, is skipped by a zone transfer and
//! reported, instead of failing the whole transfer.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

#[tokio::test]
async fn a_transfer_skips_a_record_it_cannot_encode() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");

    // Bring the zone up normally, then add the oversized row the way an older
    // build could have: straight into the database, past the write-time check.
    let mut config = base_config(&db);
    config.authoritative.axfr_enabled = true;
    let server = spawn(config).await;
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
    let oversized = std::iter::repeat(quoted)
        .take(300)
        .collect::<Vec<_>>()
        .join(" ");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO records (id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at)
         VALUES ('oversized-record', ?1, 'big.skip.test', 'TXT', ?2, 300, 0, 0, '2026-01-01T00:00:00Z')",
        rusqlite::params![&zone.id, oversized],
    )
    .unwrap();
    drop(conn);

    let mut config = base_config(&db);
    config.authoritative.axfr_enabled = true;
    let server = spawn(config).await;
    let tcp = server.tcp_addr.expect("TCP enabled");
    let resp = tcp_query(tcp, "skip.test.", RecordType::AXFR).await;

    // The transfer succeeds, with the SOA framing intact and the rest of the
    // zone present.
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(
        resp.answers.first().expect("first answer").record_type(),
        RecordType::SOA
    );
    assert_eq!(
        resp.answers.last().expect("last answer").record_type(),
        RecordType::SOA
    );
    let owners: Vec<String> = resp.answers.iter().map(|r| r.name.to_utf8()).collect();
    assert!(
        owners.iter().any(|name| name == "www.skip.test."),
        "missing the A record: {owners:?}"
    );
    assert!(
        !owners.iter().any(|name| name == "big.skip.test."),
        "the oversized record was transferred: {owners:?}"
    );

    // Skipping it is reported, so the stale record can be found and removed.
    let reported = server
        .logs
        .entries()
        .iter()
        .any(|entry| entry.component == "transfer" && entry.message.contains("big.skip.test"));
    assert!(reported, "the skipped record was not logged");

    shutdown(server).await;
}
