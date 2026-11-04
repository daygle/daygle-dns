//! Integration test: certificates from an ACME CA, against Pebble (Let's
//! Encrypt's test CA). Pebble validates through this server: it resolves
//! the names here, fetches HTTP-01 answers from the web console, and reads
//! DNS-01 TXT records from a hosted zone.
//!
//! Runs when `PEBBLE` names the pebble binary and `PEBBLE_DIR` its source
//! checkout (for its test certificates), e.g.
//! `go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.7.0` and
//! `PEBBLE_DIR=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.7.0`.
//! Skipped otherwise.

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::*;
use daygle_dns_authoritative::model::{RecordInput, ZoneInput};
use serde_json::{json, Value};

struct Pebble(std::process::Child);

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

async fn wait_for(client: &reqwest::Client, api: &str, name: &str) -> Value {
    for _ in 0..240 {
        let certs: Value = client
            .get(format!("{api}/certificates"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let cert = certs
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == json!(name))
            .cloned()
            .expect("listed");
        if cert["acme"]["status"] != json!("pending") {
            return cert;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("certificate '{name}' was not issued in time");
}

/// A running Pebble and how to use it.
struct Ca {
    _process: Pebble,
    directory: String,
    root: String,
}

/// Start Pebble, validating HTTP-01 against `http_port` and resolving names
/// through `dns`.
async fn start_pebble(
    pebble: &str,
    pebble_dir: &str,
    dir: &std::path::Path,
    http_port: u16,
    dns: std::net::SocketAddr,
) -> Ca {
    let ca_port = free_port();
    let config = dir.join("pebble.json");
    std::fs::write(
        &config,
        json!({ "pebble": {
            "listenAddress": format!("127.0.0.1:{ca_port}"),
            "managementListenAddress": format!("127.0.0.1:{}", free_port()),
            "certificate": format!("{pebble_dir}/test/certs/localhost/cert.pem"),
            "privateKey": format!("{pebble_dir}/test/certs/localhost/key.pem"),
            "httpPort": http_port,
            "tlsPort": free_port(),
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
        }})
        .to_string(),
    )
    .unwrap();
    let process = Pebble(
        std::process::Command::new(pebble)
            .args(["-config", config.to_str().unwrap(), "-dnsserver"])
            .arg(dns.to_string())
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("start pebble"),
    );
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", ca_port)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ca {
        _process: process,
        directory: format!("https://localhost:{ca_port}/dir"),
        root: std::fs::read_to_string(format!("{pebble_dir}/test/certs/pebble.minica.pem"))
            .unwrap(),
    }
}

#[tokio::test]
async fn certificates_from_an_acme_ca() {
    let (Ok(pebble), Ok(pebble_dir)) = (std::env::var("PEBBLE"), std::env::var("PEBBLE_DIR"))
    else {
        eprintln!("PEBBLE / PEBBLE_DIR not set: ACME test skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    // Pebble fetches HTTP-01 answers from this port.
    cfg.api.port = free_port();
    let server = spawn(cfg).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "acme.test".into(),
            ..Default::default()
        })
        .unwrap();
    for name in ["@", "www"] {
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: name.into(),
                    rtype: "A".into(),
                    content: Ipv4Addr::LOCALHOST.to_string(),
                    ttl: 60,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
    }
    server.catalog.reload().unwrap();

    let ca = start_pebble(
        &pebble,
        &pebble_dir,
        dir.path(),
        server.api_addr.port(),
        server.udp_addr.unwrap(),
    )
    .await;
    let (directory, root) = (ca.directory.clone(), ca.root.clone());
    let client = reqwest::Client::new();
    let api = format!("http://{}/api", server.api_addr);
    // Requests need the terms accepted.
    let request = |name: &str, domains: Value, challenge: &str| {
        client
            .post(format!("{api}/certificates/acme"))
            .json(&json!({ "name": name, "domains": domains, "challenge": challenge }))
            .send()
    };
    let resp = request("web", json!(["www.acme.test"]), "http")
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = client
        .put(format!("{api}/acme"))
        .json(&json!({
            "email": "ops@acme.test",
            "directory": directory,
            "agree_terms": true,
            "ca_certificate": root,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    // HTTP-01, answered by the web console.
    let resp = request("web", json!(["www.acme.test"]), "http")
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let cert = wait_for(&client, &api, "web").await;
    assert_eq!(cert["acme"]["status"], json!("valid"), "{cert}");
    assert_eq!(cert["names"], json!(["www.acme.test"]));
    assert_eq!(cert["self_signed"], json!(false));

    // DNS-01 with a wildcard, via a TXT record in the hosted zone that is
    // removed afterwards.
    let resp = request("wild", json!(["*.acme.test", "acme.test"]), "http")
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = request("wild", json!(["*.acme.test", "acme.test"]), "dns")
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let cert = wait_for(&client, &api, "wild").await;
    assert_eq!(cert["acme"]["status"], json!("valid"), "{cert}");
    let txt_left = store
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .any(|r| r.rtype == "TXT");
    assert!(!txt_left, "challenge TXT records are removed");

    // A name this server cannot prove fails with the reason.
    let resp = request("elsewhere", json!(["www.not-hosted.test"]), "dns")
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let cert = wait_for(&client, &api, "elsewhere").await;
    assert_eq!(cert["acme"]["status"], json!("failed"));
    assert!(cert["acme"]["last_error"]
        .as_str()
        .unwrap()
        .contains("no zone on this server"));

    // Renewing replaces the certificate.
    let before = wait_for(&client, &api, "web").await["not_before"].clone();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let resp = client
        .post(format!("{api}/certificates/web/renew"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let cert = wait_for(&client, &api, "web").await;
    assert_eq!(cert["acme"]["status"], json!("valid"));
    assert_ne!(cert["not_before"], before);

    // Uploading over an ACME certificate is refused; deleting stops it.
    let resp = client
        .post(format!("{api}/certificates"))
        .json(&json!({ "name": "web" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let resp = client
        .delete(format!("{api}/certificates/elsewhere"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    shutdown(server).await;
}

/// One UDP exchange with `server`.
async fn exchange(
    server: std::net::SocketAddr,
    query: &[u8],
) -> Option<hickory_proto::op::Message> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    socket.send_to(query, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    hickory_proto::op::Message::from_vec(&buf[..n]).ok()
}

/// A resolver for Pebble that behaves like a public recursive one: it asks
/// `outside` (the domain's own DNS) and, when the answer is a CNAME into
/// this server's zone, asks `ours` for the target and returns the whole
/// chain. (Pebble does not chase CNAMEs itself; Let's Encrypt's resolvers
/// do.)
async fn chasing_resolver(
    outside: std::net::SocketAddr,
    ours: std::net::SocketAddr,
) -> std::net::SocketAddr {
    use hickory_proto::rr::RData;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = hickory_proto::op::Message::from_vec(&buf[..n]) else {
                continue;
            };
            let Some(mut reply) = exchange(outside, &buf[..n]).await else {
                continue;
            };
            let target = reply.answers.iter().find_map(|r| match &r.data {
                RData::CNAME(target) => Some(target.0.clone()),
                _ => None,
            });
            if let (Some(target), Some(question)) = (target, query.queries.first()) {
                let mut chase = query.clone();
                chase.queries[0] = hickory_proto::op::Query::query(target, question.query_type());
                if let Some(chased) = exchange(ours, &chase.to_vec().unwrap()).await {
                    reply.answers.extend(chased.answers);
                    reply.metadata.response_code = chased.metadata.response_code;
                }
            }
            let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

/// DNS-01 for a domain whose DNS is elsewhere: its provider CNAMEs
/// `_acme-challenge.<name>` to a name in a zone this server hosts; the TXT
/// record is put there (found through this server's resolver) and the
/// certificate is issued.
#[tokio::test]
async fn dns_challenges_follow_a_cname_into_a_hosted_zone() {
    let (Ok(pebble), Ok(pebble_dir)) = (std::env::var("PEBBLE"), std::env::var("PEBBLE_DIR"))
    else {
        eprintln!("PEBBLE / PEBBLE_DIR not set: ACME test skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // The domain's own DNS, with the one-time delegation CNAME.
    let outside = spawn_upstream_with(
        &dir.path().join("outside.db"),
        "outside.test",
        &[(
            "_acme-challenge.dns",
            "CNAME",
            "dns.outside.test.acme-delegate.test.",
        )],
    )
    .await;
    let mut cfg = base_config(&dir.path().join("daygle-dns.db"));
    cfg.api.port = free_port();
    cfg.recursive.enabled = true;
    cfg.recursive.mode = Some(daygle_dns_core::config::ResolutionMode::Forwarding);
    cfg.recursive.upstreams = vec![outside.to_string()];
    cfg.recursive.dnssec_validate = false;
    let server = spawn(cfg).await;
    let store = server.catalog.store();
    let zone = store
        .create_zone(&ZoneInput {
            name: "acme-delegate.test".into(),
            ..Default::default()
        })
        .unwrap();
    server.catalog.reload().unwrap();

    let resolver = chasing_resolver(outside, server.udp_addr.unwrap()).await;
    let ca = start_pebble(
        &pebble,
        &pebble_dir,
        dir.path(),
        server.api_addr.port(),
        resolver,
    )
    .await;
    let client = reqwest::Client::new();
    let api = format!("http://{}/api", server.api_addr);
    let resp = client
        .put(format!("{api}/acme"))
        .json(&json!({
            "email": "ops@outside.test",
            "directory": ca.directory,
            "agree_terms": true,
            "ca_certificate": ca.root,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    // The wildcard and its parent: two TXT values at the delegated name.
    let resp = client
        .post(format!("{api}/certificates/acme"))
        .json(&json!({
            "name": "accounts",
            "domains": ["dns.outside.test", "*.dns.outside.test"],
            "challenge": "dns",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let cert = wait_for(&client, &api, "accounts").await;
    assert_eq!(cert["acme"]["status"], json!("valid"), "{cert}");
    let txt_left = store
        .list_records(&zone.id)
        .unwrap()
        .iter()
        .any(|r| r.rtype == "TXT");
    assert!(!txt_left, "challenge TXT records are removed");

    shutdown(server).await;
}

/// The Cloudflare API token is write-only: `GET /api/acme` shows only that
/// one is stored, sending the placeholder back keeps it, and a Cloudflare
/// certificate cannot be requested until one is set. Needs no CA.
#[tokio::test]
async fn cloudflare_token_is_write_only_and_required() {
    let dir = tempfile::tempdir().unwrap();
    let server = spawn(base_config(&dir.path().join("daygle-dns.db"))).await;
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let put = |body: Value| {
        let (client, api) = (client.clone(), api.clone());
        async move {
            let response = client
                .put(format!("{api}/acme"))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success(), "{}", response.status());
            response.json::<Value>().await.unwrap()
        }
    };
    let request = || async {
        client
            .post(format!("{api}/certificates/acme"))
            .json(&json!({
                "name": "dot",
                "domains": ["dns.example.com", "*.dns.example.com"],
                "challenge": "cloudflare",
            }))
            .send()
            .await
            .unwrap()
    };

    let got = put(json!({ "agree_terms": true })).await;
    assert_eq!(got["settings"]["cloudflare_api_token"], "");
    let response = request().await;
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("Cloudflare API token"), "{body}");

    let got = put(json!({ "agree_terms": true, "cloudflare_api_token": " secret-token " })).await;
    assert_eq!(got["settings"]["cloudflare_api_token"], "[redacted]");
    let stored = |store: &daygle_dns_authoritative::ZoneStore| {
        store.get_named_setting::<Value>("acme").unwrap().unwrap()["cloudflare_api_token"].clone()
    };
    assert_eq!(stored(server.catalog.store()), "secret-token");

    // Saving other settings with the placeholder keeps the token.
    put(json!({
        "agree_terms": true,
        "renew_days": 20,
        "cloudflare_api_token": "[redacted]",
    }))
    .await;
    assert_eq!(stored(server.catalog.store()), "secret-token");

    shutdown(server).await;
}
