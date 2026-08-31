//! Integration test: DNS over TLS with a self-signed certificate.

mod common;

use common::*;
use daygle_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

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
