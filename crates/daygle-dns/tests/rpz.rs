//! Integration tests: response policy zones (RPZ).

mod common;

use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

const RULES: &str = "\
nx.site.test            CNAME .
empty.site.test         CNAME *.
evil.site.test          A 192.0.2.66
walled.site.test        CNAME garden.site.test.
tcp.site.test           CNAME rpz-tcp-only.
quiet.site.test         CNAME rpz-drop.
*.cdn.site.test         CNAME .
ok.cdn.site.test        CNAME rpz-passthru.
bad-cdn.site.test       CNAME .
32.2.0.0.127.rpz-client-ip CNAME rpz-drop.
32.40.100.51.198.rpz-ip CNAME *.
";

/// A forwarding server whose upstream hosts `site.test`.
async fn server(dir: &tempfile::TempDir) -> daygle_dns::BoundServer {
    let upstream = spawn_upstream_with(
        &dir.path().join("upstream.db"),
        "site.test",
        &[
            ("host", "A", "198.51.100.10"),
            ("evil", "A", "203.0.113.5"),
            ("garden", "A", "198.51.100.99"),
            ("tcp", "A", "198.51.100.30"),
            ("alias", "CNAME", "bad-cdn.site.test."),
            ("bad-cdn", "A", "198.51.100.20"),
            ("ipblocked", "A", "198.51.100.40"),
            ("a.cdn", "A", "198.51.100.50"),
            ("ok.cdn", "A", "198.51.100.51"),
            ("feedblock", "A", "198.51.100.60"),
        ],
    )
    .await;
    let mut config = base_config(&dir.path().join("daygle-dns.db"));
    config.recursive.enabled = true;
    config.recursive.use_system_config = false;
    config.recursive.upstreams = vec![upstream.to_string()];
    config.recursive.dnssec_validate = false;
    spawn(config).await
}

async fn try_udp_from(source: [u8; 4], addr: std::net::SocketAddr, name: &str) -> Option<Message> {
    let socket = tokio::net::UdpSocket::bind((std::net::IpAddr::from(source), 0))
        .await
        .unwrap();
    let bytes = query_message(name, RecordType::A).to_vec().unwrap();
    socket.send_to(&bytes, addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(Message::from_vec(&buf[..n]).unwrap())
}

fn data(reply: &Message) -> Vec<String> {
    reply.answers.iter().map(|r| r.data.to_string()).collect()
}

async fn put_zones(base: &str, zones: serde_json::Value) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/config"))
        .json(&serde_json::json!({ "rpz": zones }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
}

#[tokio::test]
async fn rpz_actions_and_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();

    // A rule that does not parse is refused with its reason.
    let resp = client
        .put(format!("{base}/config"))
        .json(
            &serde_json::json!({ "rpz": [{ "name": "rpz.local", "rules": "bad.example CNAME" }] }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    put_zones(
        &base,
        serde_json::json!([{ "name": "rpz.local", "rules": RULES }]),
    )
    .await;
    let a = |name: &'static str| async move { udp_query(udp, name, RecordType::A).await };

    assert_eq!(a("host.site.test.").await.answers.len(), 1);
    assert_eq!(
        a("nx.site.test.").await.response_code,
        ResponseCode::NXDomain
    );
    let reply = a("empty.site.test.").await;
    assert_eq!(reply.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    // Local data, and NODATA for a type it has no record of.
    assert_eq!(data(&a("evil.site.test.").await), vec!["192.0.2.66"]);
    let reply = udp_query(udp, "evil.site.test.", RecordType::TXT).await;
    assert!(reply.answers.is_empty() && reply.response_code == ResponseCode::NoError);
    // A walled garden: the CNAME, followed.
    assert_eq!(
        data(&a("walled.site.test.").await),
        vec!["garden.site.test.", "198.51.100.99"]
    );
    // TCP-only: truncated over UDP, answered over TCP.
    let reply = a("tcp.site.test.").await;
    assert!(reply.metadata.truncation && reply.answers.is_empty());
    let reply = tcp_query(server.tcp_addr.unwrap(), "tcp.site.test.", RecordType::A).await;
    assert_eq!(data(&reply), vec!["198.51.100.30"]);
    // Drop: no answer at all.
    assert!(try_udp_from([127, 0, 0, 1], udp, "quiet.site.test.")
        .await
        .is_none());
    // A wildcard, and a PASSTHRU exception under it.
    assert_eq!(
        a("a.cdn.site.test.").await.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(data(&a("ok.cdn.site.test.").await), vec!["198.51.100.51"]);
    // A CNAME target and an answer address are triggers too.
    assert_eq!(
        a("alias.site.test.").await.response_code,
        ResponseCode::NXDomain
    );
    let reply = a("ipblocked.site.test.").await;
    assert!(reply.answers.is_empty() && reply.response_code == ResponseCode::NoError);
    // A client-IP trigger.
    assert!(try_udp_from([127, 0, 0, 2], udp, "host.site.test.")
        .await
        .is_none());

    // The tester explains, and the status counts.
    let explained: serde_json::Value = client
        .post(format!("{base}/rpz/test"))
        .json(&serde_json::json!({ "client": "127.0.0.1", "domain": "x.cdn.site.test" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(explained["matches"][0]["trigger"], "QNAME *.cdn.site.test");
    assert_eq!(explained["matches"][0]["action"], "NXDOMAIN");
    let status: serde_json::Value = client
        .get(format!("{base}/rpz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let zone = &status["zones"][0];
    assert_eq!(zone["loaded"], true);
    assert_eq!(zone["rules"]["qname"], 8);
    assert_eq!(zone["rules"]["wildcard"], 1);
    assert!(zone["hits"].as_u64().unwrap() >= 10, "{zone}");

    // Policy "disabled": matches are counted, nothing is acted on.
    put_zones(
        &base,
        serde_json::json!([{ "name": "rpz.local", "rules": RULES, "policy": "disabled" }]),
    )
    .await;
    assert_eq!(data(&a("evil.site.test.").await), vec!["203.0.113.5"]);
    // Policy override: everything the zone matches becomes NODATA.
    put_zones(
        &base,
        serde_json::json!([{ "name": "rpz.local", "rules": RULES, "policy": "nodata" }]),
    )
    .await;
    let reply = a("nx.site.test.").await;
    assert!(reply.answers.is_empty() && reply.response_code == ResponseCode::NoError);

    shutdown(server).await;
}

/// A zone transferred from a feed's server is loaded and applied.
#[tokio::test]
async fn rpz_zones_load_by_zone_transfer() {
    let dir = tempfile::tempdir().unwrap();
    let mut feed_config = base_config(&dir.path().join("feed.db"));
    feed_config.authoritative.axfr_enabled = true;
    let feed = spawn(feed_config).await;
    let store = feed.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "feed.rpz".to_string(),
            ..Default::default()
        })
        .unwrap();
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: "feedblock.site.test".to_string(),
                rtype: "CNAME".to_string(),
                content: ".".to_string(),
                ttl: 300,
                priority: 0,
                disabled: false,
            },
        )
        .unwrap();
    feed.catalog.reload().unwrap();

    let server = server(&dir).await;
    let udp = server.udp_addr.unwrap();
    let base = format!("http://{}/api", server.api_addr);
    assert_eq!(
        data(&udp_query(udp, "feedblock.site.test.", RecordType::A).await),
        vec!["198.51.100.60"]
    );
    put_zones(
        &base,
        serde_json::json!([{
            "name": "feed.rpz",
            "source": "transfer",
            "primaries": [feed.tcp_addr.unwrap().to_string()],
        }]),
    )
    .await;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let status: serde_json::Value = reqwest::get(format!("{base}/rpz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if status["zones"][0]["loaded"] == true {
            assert_eq!(status["zones"][0]["rules"]["qname"], 1, "{status}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{status}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reply = udp_query(udp, "feedblock.site.test.", RecordType::A).await;
    assert_eq!(reply.response_code, ResponseCode::NXDomain);

    shutdown(server).await;
    shutdown(feed).await;
}
