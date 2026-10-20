//! Integration test: the web console can be served over HTTP and/or HTTPS,
//! changed from Settings at runtime, and a change that cannot work leaves
//! the console where it was.

mod common;

use common::*;
use serde_json::json;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A client that accepts the generated self-signed certificate and does
/// not follow redirects (so they can be checked).
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn put_web(
    client: &reqwest::Client,
    base: &str,
    web: serde_json::Value,
) -> reqwest::Response {
    client
        .put(format!("{base}/api/config"))
        .json(&json!({ "web": web }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn console_moves_between_http_and_https() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(base_config(&db)).await;
    let client = client();
    let http = format!("http://{}", server.api_addr);

    // Turn HTTPS on without choosing a certificate: a self-signed one is
    // generated, kept on the Certificates page, and served.
    let https_port = free_port();
    let resp = put_web(
        &client,
        &http,
        json!({ "https_enabled": true, "https_port": https_port }),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let addrs = server.web_addrs().await;
    let https_addr = addrs.https.expect("HTTPS is listening");
    assert_eq!(https_addr.port(), https_port);
    let https = format!("https://{https_addr}");
    let status = client
        .get(format!("{https}/api/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let certs: serde_json::Value = client
        .get(format!("{https}/api/certificates"))
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
        .find(|c| c["name"] == json!("web-console"))
        .expect("the generated certificate is listed");
    assert_eq!(cert["in_use"], json!(["Web Console"]));
    // HTTP still answers.
    assert_eq!(
        client
            .get(format!("{http}/api/status"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // Redirect HTTP to HTTPS.
    let resp = put_web(&client, &https, json!({ "redirect_http": true })).await;
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{http}/api/status?x=1"))
        .header(
            "host",
            format!("dns.example.test:{}", server.api_addr.port()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 308);
    assert_eq!(
        resp.headers()["location"],
        format!("https://dns.example.test:{https_port}/api/status?x=1").as_str()
    );

    // Changes that would cut the console off, or cannot work, are refused
    // and change nothing.
    let resp = put_web(
        &client,
        &https,
        json!({ "http_enabled": false, "https_enabled": false, "redirect_http": false }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_port = taken.local_addr().unwrap().port();
    let resp = put_web(&client, &https, json!({ "https_port": taken_port })).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.unwrap().contains("cannot listen"));
    let resp = put_web(&client, &https, json!({ "https_certificate": "missing" })).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(server.web_addrs().await, addrs);
    assert_eq!(
        client
            .get(format!("{https}/api/status"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    drop(taken);

    // A certificate in use cannot be deleted.
    let resp = client
        .delete(format!("{https}/api/certificates/web-console"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // HTTPS only.
    let resp = put_web(
        &client,
        &https,
        json!({ "http_enabled": false, "redirect_http": false }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(server.web_addrs().await.http, None);
    assert!(client
        .get(format!("{http}/api/status"))
        .send()
        .await
        .is_err());
    assert_eq!(
        client
            .get(format!("{https}/api/status"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    shutdown(server).await;

    // The choice survives a restart.
    let server = spawn(base_config(&db)).await;
    let addrs = server.web_addrs().await;
    assert_eq!(addrs.http, None);
    assert_eq!(addrs.https.map(|a| a.port()), Some(https_port));
    shutdown(server).await;

    // If the saved settings cannot start (here the HTTPS port is taken),
    // the server falls back to plain HTTP so the console stays reachable.
    let blocker = std::net::TcpListener::bind(("127.0.0.1", https_port)).unwrap();
    let server = spawn(base_config(&db)).await;
    let addrs = server.web_addrs().await;
    assert!(addrs.http.is_some());
    assert_eq!(addrs.https, None);
    assert_eq!(
        client
            .get(format!("http://{}/api/status", server.api_addr))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    drop(blocker);
    shutdown(server).await;
}
