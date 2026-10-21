//! Integration test: catalog zones (RFC 9432). One server publishes a
//! catalog of its primary zones; another consumes it, serving each member
//! as a secondary zone and dropping the ones the catalog drops.

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use daygle_dns_authoritative::XfrClient;
use daygle_dns_core::config::CatalogConsumerConfig;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

async fn add_zone(server: &daygle_dns::BoundServer, name: &str, ip: &str) -> String {
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: name.to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "www".to_string(),
                rtype: "A".to_string(),
                content: ip.to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    server.catalog.reload().unwrap();
    zone.id
}

async fn wait_for(what: &str, mut check: impl AsyncFnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn catalog_zones_are_published_and_consumed() {
    let dir = tempfile::tempdir().unwrap();

    // Producer: two primary zones and a published catalog.
    let mut config = base_config(&dir.path().join("producer.db"));
    config.authoritative.axfr_enabled = true;
    config.authoritative.catalog_zone = "catalog.test".to_string();
    let producer = spawn(config).await;
    add_zone(&producer, "one.test", "192.0.2.1").await;
    let two = add_zone(&producer, "two.test", "192.0.2.2").await;
    let master = producer.tcp_addr.unwrap();

    // The catalog is a version 2 catalog listing both zones.
    let catalog = Name::from_ascii("catalog.test.").unwrap();
    let records = XfrClient::default().axfr(master, &catalog).await.unwrap();
    let members =
        daygle_dns_authoritative::catalog_zone::catalog_members(&catalog, &records).unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&"one.test".to_string()));
    assert!(members.contains(&"two.test".to_string()));
    let serial = |records: &[hickory_proto::rr::Record]| {
        records
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) => Some(soa.serial),
                _ => None,
            })
            .unwrap()
    };
    let first_serial = serial(&records);
    // A reload with no membership change keeps the serial.
    producer.catalog.reload().unwrap();
    let again = XfrClient::default().axfr(master, &catalog).await.unwrap();
    assert_eq!(serial(&again), first_serial);

    // Consumer: follows the catalog (an hour's refresh; NOTIFY wakes it).
    let mut config = base_config(&dir.path().join("consumer.db"));
    config.authoritative.notify_listen_enabled = true;
    config.authoritative.catalog_consumers = vec![CatalogConsumerConfig {
        name: "catalog.test".to_string(),
        masters: vec![master.to_string()],
        refresh_secs: 3600,
        enabled: true,
    }];
    let consumer = spawn(config).await;
    let udp = consumer.udp_addr.unwrap();
    for (name, ip) in [
        ("www.one.test.", "192.0.2.1"),
        ("www.two.test.", "192.0.2.2"),
    ] {
        wait_for(name, async || {
            first_answer(&udp_query(udp, name, RecordType::A).await).as_deref() == Some(ip)
        })
        .await;
    }
    // The members are secondaries owned by the catalog, and cannot be
    // deleted by hand.
    let api = format!("http://{}/api", consumer.api_addr);
    let client = reqwest::Client::new();
    let zones: serde_json::Value = client
        .get(format!("{api}/zones"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let one = zones
        .as_array()
        .unwrap()
        .iter()
        .find(|z| z["name"] == "one.test")
        .unwrap();
    assert_eq!(one["zone_type"], "secondary");
    assert_eq!(one["catalog"], "catalog.test");
    let resp = client
        .delete(format!("{api}/zones/{}", one["id"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Deleting a zone on the producer bumps the catalog serial; a NOTIFY
    // for the catalog makes the consumer drop the zone at once.
    producer.catalog.store().delete_zone(&two).unwrap();
    producer.catalog.reload().unwrap();
    let records = XfrClient::default().axfr(master, &catalog).await.unwrap();
    assert!(serial(&records) != first_serial);
    let mut notify = Message::new(0x4242, MessageType::Query, OpCode::Notify);
    notify.add_query(Query::query(catalog.clone(), RecordType::SOA));
    let reply = udp_send(udp, &notify).await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    wait_for("two.test to be removed", async || {
        consumer
            .catalog
            .store()
            .find_zone_by_name("two.test")
            .unwrap()
            .is_none()
    })
    .await;
    assert!(consumer
        .catalog
        .store()
        .find_zone_by_name("one.test")
        .unwrap()
        .is_some());

    // No longer following the catalog (in Settings) drops its zones.
    let resp = client
        .put(format!("{api}/config"))
        .json(&serde_json::json!({ "authoritative": { "catalog_consumers": [] } }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    wait_for("one.test to be removed", async || {
        consumer
            .catalog
            .store()
            .find_zone_by_name("one.test")
            .unwrap()
            .is_none()
    })
    .await;

    shutdown(consumer).await;
    shutdown(producer).await;
}

async fn udp_send(addr: std::net::SocketAddr, msg: &Message) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("reply")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}
