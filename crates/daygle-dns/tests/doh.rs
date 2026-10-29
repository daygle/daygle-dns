//! Integration test: DNS over HTTPS (RFC 8484) with a self-signed
//! certificate, exercising the POST /dns-query path.

mod common;

use std::sync::Arc;

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

/// RFC 8484 §4.1 GET (`?dns=`, base64url): the same answer as POST. This is
/// what `dig +https` sends by default.
#[tokio::test]
async fn serves_queries_over_doh_get() {
    use base64::Engine;

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

    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_utf8("secure.https.test.").unwrap(),
        RecordType::A,
    ));
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(query.to_vec().expect("encode query"));

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // lgtm
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://{doh}/dns-query")) // lgtm
        .query(&[("dns", encoded.as_str())])
        .header("Accept", "application/dns-message")
        .send()
        .await
        .expect("DoH GET request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/dns-message")
    );

    let bytes = resp.bytes().await.unwrap();
    let response = Message::from_vec(&bytes).expect("decode DoH GET response");
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(first_answer(&response).as_deref(), Some("203.0.113.7"));

    // A GET without the `dns` parameter is an HTTP 400 (RFC 8484 clients
    // read only the status): there is no DNS id to match an error against.
    let bad = client
        .get(format!("https://{doh}/dns-query")) // lgtm
        .send()
        .await
        .expect("DoH GET request without dns");
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);

    shutdown(server).await;
}

#[tokio::test]
async fn allowed_networks_refuse_clients_outside_the_list() {
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
    // The test client is 127.0.0.1, outside this list.
    config.doh.allowed_networks = vec!["10.9.9.0/24".to_string()];

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
    assert_eq!(response.response_code, ResponseCode::Refused);

    shutdown(server).await;
}

/// With `http3` on, the same DoH service answers over HTTP/3 (QUIC, UDP)
/// on the same port number.
#[tokio::test]
async fn serves_queries_over_http3() {
    use hickory_server::net::h3::H3ClientStream;
    use hickory_server::net::xfer::{DnsRequestSender, FirstAnswer};

    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("server.crt");
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.doh.enabled = true;
    config.doh.http3 = true;
    config.doh.self_signed = true;
    config.doh.cert_path = cert.to_string_lossy().to_string();
    config.doh.key_path = dir.path().join("server.key").to_string_lossy().to_string();
    config.doh.server_name = "daygle.test".to_string();
    let server = spawn(config).await;
    let zone = server
        .catalog
        .store()
        .create_zone(&ZoneInput {
            name: "h3.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    server
        .catalog
        .store()
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: "203.0.113.33".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    let h3 = server.doh3_addr.expect("HTTP/3 is enabled");
    assert_eq!(h3.port(), server.doh_addr.unwrap().port());

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_file_iter(&cert).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut stream = H3ClientStream::builder()
        .crypto_config(tls)
        .build(h3, Arc::from("daygle.test"), Arc::from("/dns-query"))
        .await
        .expect("HTTP/3 connection");

    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_utf8("www.h3.test.").unwrap(),
        RecordType::A,
    ));
    let response = stream
        .send_message(hickory_proto::op::DnsRequest::new(
            query,
            Default::default(),
        ))
        .first_answer()
        .await
        .expect("HTTP/3 answer");
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(
        response
            .answers
            .first()
            .map(|r| r.data.to_string())
            .as_deref(),
        Some("203.0.113.33")
    );

    shutdown(server).await;
}
