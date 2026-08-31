//! Integration test: DNS over HTTPS (RFC 8484) with a self-signed
//! certificate, exercising the POST /dns-query path.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

#[tokio::test]
async fn serves_queries_over_doh() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");

    let mut config = base_config(&db);
    config.doh.enabled = true;
    config.doh.self_signed = true;
    config.doh.cert_path = cert.to_string_lossy().to_string();
    config.doh.key_path = key.to_string_lossy().to_string();
    config.doh.server_name = "daygle.test".to_string();

    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "https.test".to_string(),
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

    let doh = server.doh_addr.expect("DoH is enabled");

    // Build a DNS query as a wire-format message.
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_utf8("secure.https.test.").unwrap(),
        RecordType::A,
    ));
    let body = query.to_vec().expect("encode query");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // lgtm
        .build()
        .unwrap();
    let resp = client
        .post(format!("https://{doh}/dns-query")) // lgtm
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(body)
        .send()
        .await
        .expect("DoH request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let bytes = resp.bytes().await.unwrap();
    let response = Message::from_vec(&bytes).expect("decode DoH response");
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&response).as_deref(), Some("203.0.113.7"));

    shutdown(server).await;
}
