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

    let ca_port = free_port();
    let config = dir.path().join("pebble.json");
    std::fs::write(
        &config,
        json!({ "pebble": {
            "listenAddress": format!("127.0.0.1:{ca_port}"),
            "managementListenAddress": format!("127.0.0.1:{}", free_port()),
            "certificate": format!("{pebble_dir}/test/certs/localhost/cert.pem"),
            "privateKey": format!("{pebble_dir}/test/certs/localhost/key.pem"),
            "httpPort": server.api_addr.port(),
            "tlsPort": free_port(),
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
        }})
        .to_string(),
    )
    .unwrap();
    let _pebble = Pebble(
        std::process::Command::new(&pebble)
            .args(["-config", config.to_str().unwrap(), "-dnsserver"])
            .arg(server.udp_addr.unwrap().to_string())
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("start pebble"),
    );
    let directory = format!("https://localhost:{ca_port}/dir");
    let root =
        std::fs::read_to_string(format!("{pebble_dir}/test/certs/pebble.minica.pem")).unwrap();
    let client = reqwest::Client::new();
    let api = format!("http://{}/api", server.api_addr);
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", ca_port)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

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
