//! Integration test: why a query was blocked. Every blocked query in the
//! query log says what blocked it (the server blocklist, a named blocklist
//! source, a filtering group, a blocked service, a response policy zone)
//! and what matched, and `POST /api/policy/explain` shows every check a
//! domain meets for a device, with the verdict.

mod common;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use serde_json::{json, Value};

/// Serve `body` over HTTP at any path.
async fn serve(body: &'static str) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

const KIDS: [u8; 4] = [127, 0, 0, 2];

async fn rcode_from(udp: std::net::SocketAddr, client: [u8; 4], name: &str) -> ResponseCode {
    udp_query_from(IpAddr::from(client), udp, name, RecordType::A)
        .await
        .response_code
}

async fn explain(api: &str, body: Value) -> (reqwest::StatusCode, Value) {
    let query: Vec<(String, String)> = body
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    let response = reqwest::Client::new()
        .get(format!("{api}/policy/explain"))
        .query(&query)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// The logged blocked queries, once there are at least `want` of them.
async fn blocked_rows(api: &str, want: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body: Value = reqwest::get(format!("{api}/querylogs?outcome=blocked&per_page=100"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let rows = body["entries"].as_array().cloned().unwrap_or_default();
        if rows.len() >= want {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "only {} blocked rows",
            rows.len()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn row<'a>(rows: &'a [Value], qname: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["qname"] == qname)
        .unwrap_or_else(|| panic!("{qname} not logged: {rows:?}"))
}

#[tokio::test]
async fn blocks_say_why() {
    let dir = tempfile::tempdir().unwrap();
    let list = serve("# Syntax: domains, wildcard\nlist.test\n").await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    config.policy.blocklist = vec!["static.test".to_string()];
    config.policy.allowlist = vec!["ok.list.test".to_string()];
    config.logging.query_db_enabled = true;
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{api}/policy/blocklist/sources"))
        .json(&json!({ "sources": [{
            "name": "Ads Source",
            "url": format!("http://{list}/list"),
            "format": "wildcard",
        }] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = client
        .post(format!("{api}/policy/blocking"))
        .json(&json!({
            "name": "kids",
            "clients": ["127.0.0.2/32"],
            "block": ["*.games.test"],
            "blocked_services": ["roblox"],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = client
        .put(format!("{api}/config"))
        .json(&json!({ "rpz": [{ "name": "rpz.local", "rules": "bad.rpz.test CNAME ." }] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // Wait for the source to be fetched.
    let deadline = Instant::now() + Duration::from_secs(10);
    while rcode_from(udp, [127, 0, 0, 1], "x.list.test.").await != ResponseCode::NXDomain {
        assert!(Instant::now() < deadline, "the source never blocked");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        rcode_from(udp, [127, 0, 0, 1], "static.test.").await,
        ResponseCode::NXDomain
    );
    assert_ne!(
        rcode_from(udp, [127, 0, 0, 1], "ok.list.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        rcode_from(udp, KIDS, "a.games.test.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        rcode_from(udp, KIDS, "www.roblox.com.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        rcode_from(udp, [127, 0, 0, 1], "bad.rpz.test.").await,
        ResponseCode::NXDomain
    );

    // The query log keeps what blocked each one.
    let rows = blocked_rows(&api, 5).await;
    let static_row = row(&rows, "static.test");
    assert_eq!(static_row["block"]["source"], "blocklist");
    assert_eq!(static_row["block"]["matched"], "static.test");
    let source_row = row(&rows, "x.list.test");
    assert_eq!(source_row["block"]["source"], "blocklist_source");
    assert_eq!(source_row["block"]["matched"], "Ads Source");
    let reason = source_row["block"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("'Ads Source'") && reason.contains("*.list.test"),
        "{reason}"
    );
    let group_row = row(&rows, "a.games.test");
    assert_eq!(group_row["block"]["source"], "group");
    assert_eq!(group_row["block"]["group"], "kids");
    assert_eq!(group_row["block"]["matched"], "*.games.test");
    let service_row = row(&rows, "www.roblox.com");
    assert_eq!(service_row["block"]["source"], "service");
    assert_eq!(service_row["block"]["matched"], "Roblox");
    let rpz_row = row(&rows, "bad.rpz.test");
    assert_eq!(rpz_row["block"]["source"], "rpz");
    assert_eq!(rpz_row["block"]["matched"], "rpz.local");
    // Not blocked: no reason.
    let all: Value = reqwest::get(format!("{api}/querylogs?qname=ok.list.test"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all["entries"][0]["block"], Value::Null, "{all}");

    // Filter by what blocked, and the CSV columns.
    let services: Value = reqwest::get(format!("{api}/querylogs?block_source=service"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(services["total"], 1, "{services}");
    let csv = reqwest::get(format!("{api}/querylogs?format=csv&outcome=blocked"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(csv
        .lines()
        .next()
        .unwrap()
        .ends_with("block_source,block_group,block_matched,block_reason"));
    assert!(csv.contains(",service,kids,Roblox,"), "{csv}");

    // Explain: a blocklist source, with the earlier block from the log.
    let (status, body) = explain(
        &api,
        json!({ "domain": "X.list.test.", "client": "127.0.0.1" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["verdict"]["blocked"], true);
    assert_eq!(body["verdict"]["source"], "blocklist_source");
    assert_eq!(body["verdict"]["matched"], "Ads Source");
    let checks = body["checks"].as_array().unwrap();
    let find = |source: &str| {
        checks
            .iter()
            .find(|c| c["source"] == source)
            .unwrap_or_else(|| panic!("no {source} check: {checks:?}"))
    };
    assert_eq!(find("allowlist")["result"], "none");
    assert_eq!(find("blocklist")["result"], "none");
    assert_eq!(find("blocklist_source")["result"], "block");
    assert_eq!(find("rpz")["result"], "none");
    assert_eq!(body["recent"][0]["block"]["matched"], "Ads Source");

    // The allowlist wins, but the check that would block still shows.
    let (_, body) = explain(
        &api,
        json!({ "domain": "ok.list.test", "client": "127.0.0.1" }),
    )
    .await;
    assert_eq!(body["verdict"]["blocked"], false);
    assert_eq!(body["verdict"]["source"], "allowlist");
    let checks = body["checks"].as_array().unwrap();
    assert!(checks
        .iter()
        .any(|c| c["source"] == "allowlist" && c["result"] == "allow"));
    assert!(checks
        .iter()
        .any(|c| c["source"] == "blocklist_source" && c["result"] == "block"));

    // A group's blocked service, for its device only.
    let (_, body) = explain(
        &api,
        json!({ "domain": "roblox.com", "client": "127.0.0.2" }),
    )
    .await;
    assert_eq!(body["verdict"]["source"], "service");
    assert_eq!(body["verdict"]["group"], "kids");
    let checks = body["checks"].as_array().unwrap();
    assert!(checks
        .iter()
        .any(|c| c["source"] == "service" && c["group"] == "kids" && c["matched"] == "Roblox"));
    let (_, body) = explain(
        &api,
        json!({ "domain": "roblox.com", "client": "127.0.0.1" }),
    )
    .await;
    assert_eq!(body["verdict"]["blocked"], false);
    assert!(body["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["group"] != "kids"));

    // A response policy zone.
    let (_, body) = explain(
        &api,
        json!({ "domain": "bad.rpz.test", "client": "127.0.0.1" }),
    )
    .await;
    assert_eq!(body["verdict"]["source"], "rpz");
    assert_eq!(body["verdict"]["matched"], "rpz.local");

    // Nothing blocks it.
    let (_, body) = explain(
        &api,
        json!({ "domain": "fine.example", "client": "127.0.0.1" }),
    )
    .await;
    assert_eq!(body["verdict"]["blocked"], false);
    assert_eq!(body["verdict"]["reason"], "nothing blocks it");

    // The device must be an address or a known device name.
    let (status, _) = explain(
        &api,
        json!({ "domain": "x.list.test", "client": "nobody's phone" }),
    )
    .await;
    assert_eq!(status, 400);
    shutdown(server).await;
}
