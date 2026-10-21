//! Integration test: blocklist sources scoped to client groups, and sources
//! added in the console surviving a restart.

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

const GROUP_CLIENT: [u8; 4] = [127, 0, 0, 2];

async fn rcode_from(udp: std::net::SocketAddr, client: [u8; 4], name: &str) -> ResponseCode {
    udp_query_from(IpAddr::from(client), udp, name, RecordType::A)
        .await
        .response_code
}

/// Poll until a query from `client` for `name` gets `want`.
async fn wait_for(udp: std::net::SocketAddr, client: [u8; 4], name: &str, want: ResponseCode) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if rcode_from(udp, client, name).await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{name} from {client:?} never got {want:?}");
}

#[tokio::test]
async fn group_scoped_source_blocks_only_its_groups() {
    let dir = tempfile::tempdir().unwrap();
    // oisd domainswild2 style: each name also covers its subdomains.
    let list = serve("# Syntax: domains, wildcard\nads.test\n").await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.policy.enabled = true;
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.dnssec_validate = false;
    let upstream = spawn_upstream(&dir.path().join("up.db"), "ads.test", "198.51.100.7").await;
    config.recursive.upstreams = vec![upstream.to_string()];
    let server = spawn(config).await;
    let udp = server.udp_addr.unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // Auto-detect reads the wildcard hint in the header.
    let probe: Value = client
        .get(format!("{api}/policy/blocklist/sources/validate"))
        .query(&[("url", format!("http://{list}/domainswild2"))])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(probe["format"], "wildcard", "{probe}");
    assert_eq!(probe["domains"], 1, "{probe}");

    let put = |sources: Value, renames: Value| {
        client
            .put(format!("{api}/policy/blocklist/sources"))
            .json(&json!({ "sources": sources, "renames": renames }))
            .send()
    };
    let source = |name: &str| {
        json!([{
            "name": name,
            "url": format!("http://{list}/domainswild2"),
            "format": "wildcard",
            "scope": "groups",
        }])
    };
    let resp = put(source("Big List"), json!({})).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // A group can only select a source that exists.
    let resp = client
        .post(format!("{api}/policy/blocking"))
        .json(&json!({ "name": "lan", "blocklists": ["nope"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let group: Value = client
        .post(format!("{api}/policy/blocking"))
        .json(&json!({
            "name": "lan",
            "clients": ["127.0.0.2/32"],
            "allow": ["host.ads.test"],
            "blocklists": ["big list"],
            "response": { "kind": "refused" },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        group["blocklists"],
        json!(["Big List"]),
        "stored under the source's spelling"
    );

    // The group's clients are blocked for the name and its subdomains...
    wait_for(udp, GROUP_CLIENT, "x.ads.test.", ResponseCode::Refused).await;
    assert_eq!(
        rcode_from(udp, GROUP_CLIENT, "ads.test.").await,
        ResponseCode::Refused
    );
    // ...except what the group allows...
    assert_eq!(
        rcode_from(udp, GROUP_CLIENT, "host.ads.test.").await,
        ResponseCode::NoError
    );
    // ...and other clients are not blocked at all.
    assert_eq!(
        rcode_from(udp, [127, 0, 0, 1], "x.ads.test.").await,
        ResponseCode::NXDomain
    );
    let msg = udp_query(udp, "host.ads.test.", RecordType::A).await;
    assert_eq!(first_answer(&msg).as_deref(), Some("198.51.100.7"));

    // A renamed source keeps its groups.
    let resp = put(source("oisd big"), json!({ "Big List": "oisd big" }))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let groups: Value = client
        .get(format!("{api}/policy/blocking"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(groups[0]["blocklists"], json!(["oisd big"]));
    wait_for(udp, GROUP_CLIENT, "y.ads.test.", ResponseCode::Refused).await;

    // A removed source is dropped from its groups and stops blocking.
    let resp = put(json!([]), json!({})).await.unwrap();
    assert!(resp.status().is_success());
    let groups: Value = client
        .get(format!("{api}/policy/blocking"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(groups[0]["blocklists"], json!([]));
    wait_for(udp, GROUP_CLIENT, "z.ads.test.", ResponseCode::NXDomain).await;

    shutdown(server).await;
}

#[tokio::test]
async fn console_sources_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let list = serve("blocked.test\n").await;
    let server = spawn(base_config(&db)).await;
    let resp = reqwest::Client::new()
        .put(format!(
            "http://{}/api/policy/blocklist/sources",
            server.api_addr
        ))
        .json(&json!({ "sources": [{
            "name": "kept",
            "url": format!("http://{list}/list"),
            "scope": "groups",
        }] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    shutdown(server).await;

    let server = spawn(base_config(&db)).await;
    let json: Value = reqwest::get(format!(
        "http://{}/api/policy/blocklist/sources",
        server.api_addr
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(json["sources"][0]["name"], "kept", "{json}");
    assert_eq!(json["sources"][0]["scope"], "groups", "{json}");
    shutdown(server).await;
}
