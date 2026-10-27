//! Integration test: persistent query logging writes served queries to the
//! configured directory when `logging.query_log_enabled` is set.

mod common;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::rr::RecordType;

#[tokio::test]
async fn logs_served_queries_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let logdir = dir.path().join("qlog");

    let mut config = base_config(&db);
    config.logging.query_log_enabled = true;
    config.logging.query_log_dir = logdir.to_string_lossy().to_string();
    config.logging.query_log_retention_days = 30;

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
    let _ = udp_query(udp, "www.example.test.", RecordType::A).await;

    // Writes flush eagerly, but the handler runs on the server task, so poll
    // briefly for the line to appear.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = logdir.join(format!("queries-{today}.log"));
    let mut text = String::new();
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if contents.contains("www.example.test") {
                text = contents;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let line = text
        .lines()
        .find(|l| l.contains("www.example.test"))
        .expect("the served query should be logged");
    let entry: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(entry["qname"], "www.example.test");
    assert_eq!(entry["qtype"], "A");
    assert_eq!(entry["outcome"], "authoritative");
    assert!(entry["client"].as_str().unwrap().starts_with("127.0.0.1"));

    shutdown(server).await;
}

/// The SQLite-backed query log records served queries and the API can
/// search/filter/paginate/export/clear them.
#[tokio::test]
async fn db_query_log_records_filters_and_clears() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let mut config = base_config(&db);
    config.logging.query_db_enabled = true;
    config.logging.query_db_max_rows = 0; // unlimited for the test
    let server = spawn(config).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "example.test".to_string(),
            ..Default::default()
        })
        .unwrap();
    for name in ["www", "api"] {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: name.to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.10".to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    server.catalog.reload().unwrap();

    let udp = server.udp_addr.expect("UDP is enabled");
    let _ = udp_query(udp, "www.example.test.", RecordType::A).await;
    let _ = udp_query(udp, "api.example.test.", RecordType::A).await;
    let _ = udp_query(udp, "missing.example.test.", RecordType::A).await;

    let api = format!("http://{}/api", server.api_addr);
    // Writes are batched (500 ms tick) - poll for the rows to land.
    let mut total = 0u64;
    for _ in 0..50 {
        if let Some(body) = reqwest_get(&format!("{api}/querylogs")).await {
            total = body["total"].as_u64().unwrap_or(0);
            if total >= 3 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(total, 3, "all three served queries must be recorded");

    // Protocol was captured from the UDP transport.
    let body = reqwest_get(&format!("{api}/querylogs")).await.unwrap();
    assert_eq!(body["entries"][0]["protocol"], "udp");

    // qname filter (substring match).
    let body = reqwest_get(&format!("{api}/querylogs?qname=api.example.test"))
        .await
        .unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["entries"][0]["qname"], "api.example.test");

    // No match for a name that was never queried.
    let body = reqwest_get(&format!("{api}/querylogs?qname=nowhere.example.test"))
        .await
        .unwrap();
    assert_eq!(body["total"], 0);

    // Pagination: 1 per page across 3 rows.
    let body = reqwest_get(&format!("{api}/querylogs?per_page=1&page=2"))
        .await
        .unwrap();
    assert_eq!(body["total"], 3);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1);

    // CSV export streams all rows with a header.
    let csv = reqwest_text(&format!("{api}/querylogs?format=csv"))
        .await
        .unwrap();
    assert!(csv.starts_with(
        "timestamp,client,qname,qtype,protocol,outcome,rcode,elapsed_ms,block_source,block_group,block_matched,block_reason\n"
    ));
    assert_eq!(csv.lines().count(), 4);

    // Clear empties the log.
    let status = reqwest_delete(&format!("{api}/querylogs")).await;
    assert!(status.is_success());
    let body = reqwest_get(&format!("{api}/querylogs")).await.unwrap();
    assert_eq!(body["total"], 0);

    shutdown(server).await;
}

/// The From/To filter takes times with any UTC offset (the console sends the
/// viewer's chosen zone) and compares them with the stored UTC timestamps
/// correctly, including whole seconds at the edges.
#[tokio::test]
async fn query_log_time_filter_honours_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(base_config(&db)).await;
    let store = server.catalog.store();
    let row = |id: i64, ts: &str, qname: &str| daygle_dns_authoritative::QueryLogRow {
        id,
        ts: ts.to_string(),
        client: "192.0.2.1".to_string(),
        qname: qname.to_string(),
        qtype: "A".to_string(),
        protocol: "udp".to_string(),
        outcome: "recursive".to_string(),
        rcode: Some("NOERROR".to_string()),
        elapsed_ms: 1,
        block: None,
    };
    // Stored the way the dispatcher writes them (`Utc::now().to_rfc3339()`:
    // the fraction is left out when it is zero).
    store
        .insert_query_logs(&[
            row(0, "2026-10-19T21:59:59.900000000+00:00", "before.test"),
            row(0, "2026-10-19T22:00:00+00:00", "start.test"),
            row(0, "2026-10-19T22:30:00.250000000+00:00", "middle.test"),
            row(0, "2026-10-19T23:00:00.999999000+00:00", "end.test"),
            row(0, "2026-10-19T23:00:01+00:00", "after.test"),
        ])
        .unwrap();

    let api = format!("http://{}/api", server.api_addr);
    let names = |body: serde_json::Value| {
        let mut names: Vec<String> = body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["qname"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    };
    // 09:00-10:00 in Sydney (UTC+11) is 22:00-23:00 UTC the day before.
    // Before the fix the local text was compared with the UTC text, which
    // matched nothing here.
    let from = "2026-10-20T09:00:00%2B11:00";
    let to = "2026-10-20T10:00:00%2B11:00";
    let body = reqwest_get(&format!("{api}/querylogs?from={from}&to={to}"))
        .await
        .unwrap();
    assert_eq!(names(body), ["end.test", "middle.test", "start.test"]);

    // The same range in UTC with `Z`, and as a bare time (taken as UTC).
    for (from, to) in [
        ("2026-10-19T22:00:00Z", "2026-10-19T23:00:00Z"),
        ("2026-10-19T22:00", "2026-10-19T23:00"),
    ] {
        let body = reqwest_get(&format!("{api}/querylogs?from={from}&to={to}"))
            .await
            .unwrap();
        assert_eq!(names(body), ["end.test", "middle.test", "start.test"]);
    }

    // Nonsense is rejected instead of silently matching everything or nothing.
    let status = reqwest::get(format!("{api}/querylogs?from=yesterday"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, 400);

    shutdown(server).await;
}

// Minimal HTTP helpers (the API is unauthenticated in base_config).
async fn reqwest_get(url: &str) -> Option<serde_json::Value> {
    let body = reqwest::get(url).await.ok()?.text().await.ok()?;
    serde_json::from_str(&body).ok()
}

async fn reqwest_text(url: &str) -> Option<String> {
    reqwest::get(url).await.ok()?.text().await.ok()
}

async fn reqwest_delete(url: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .delete(url)
        .send()
        .await
        .unwrap()
        .status()
}
