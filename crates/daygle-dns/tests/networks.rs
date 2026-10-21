//! Integration test: named networks (Settings -> Networks) - managing them
//! through the API, renames following every reference, delete protection,
//! and adopting the networks split horizon kept before they were shared.

mod common;

use common::*;
use daygle_dns_authoritative::model::{
    RecordInput, SplitHorizonEntryInput, SplitHorizonNetworkInput, ZoneInput,
};
use hickory_proto::rr::RecordType;
use serde_json::{json, Value};

/// A zone serving `www.example.test` -> 192.0.2.42 (the public view).
fn public_www(store: &daygle_dns_authoritative::ZoneStore) {
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
}

async fn www(server: &daygle_dns::BoundServer) -> Option<String> {
    first_answer(&udp_query(server.udp_addr.unwrap(), "www.example.test.", RecordType::A).await)
}

async fn get(client: &reqwest::Client, url: &str) -> Value {
    client.get(url).send().await.unwrap().json().await.unwrap()
}

fn network<'a>(list: &'a Value, name: &str) -> Option<&'a Value> {
    list["networks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == name)
}

#[tokio::test]
async fn networks_are_managed_renamed_and_protected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(base_config(&db)).await;
    public_www(server.catalog.store());
    server.catalog.reload().unwrap();
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let post = |body: Value| client.post(format!("{api}/networks")).json(&body).send();

    // Built-ins are listed and their names are taken.
    let list = get(&client, &format!("{api}/networks")).await;
    assert_eq!(network(&list, "Private").unwrap()["builtin"], true);
    let resp = post(json!({ "name": "private", "cidrs": ["10.0.0.0/8"] }))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    // A name must not look like an address, and addresses must parse.
    let resp = post(json!({ "name": "10.0.0.1", "cidrs": ["10.0.0.0/8"] }))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = post(json!({ "name": "LAN", "cidrs": ["10.0.0.0/33"] }))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // The test client is on loopback, so LAN covers it.
    let resp = post(json!({ "name": "LAN", "cidrs": ["127.0.0.1"], "description": "Home" }))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let resp = post(json!({ "name": "lan", "cidrs": ["10.0.0.0/8"] }))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "names are case-insensitive"
    );

    // A split horizon entry can only name a network that exists.
    let entry = |networks: Value| json!({ "domain": "www.example.test", "networks": networks, "ips": ["10.0.0.5"] });
    let resp = client
        .post(format!("{api}/split-horizon/entries"))
        .json(&entry(json!(["Nope"])))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let resp = client
        .post(format!("{api}/split-horizon/entries"))
        .json(&entry(json!(["lan"])))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(www(&server).await.as_deref(), Some("10.0.0.5"));

    let list = get(&client, &format!("{api}/networks")).await;
    assert_eq!(
        network(&list, "LAN").unwrap()["used_by"],
        json!(["Split horizon 'www.example.test'"])
    );

    // A network in use cannot be deleted.
    let resp = client
        .delete(format!("{api}/networks/LAN"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["used_by"], json!(["Split horizon 'www.example.test'"]));

    // Renaming follows the reference, and the view keeps working.
    let resp = post(json!({ "original_name": "LAN", "name": "Home", "cidrs": ["127.0.0.0/8"] }))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let sh = get(&client, &format!("{api}/split-horizon")).await;
    assert_eq!(sh["entries"][0]["networks"], json!(["Home"]));
    assert_eq!(www(&server).await.as_deref(), Some("10.0.0.5"));

    // Changing the addresses applies at once: the client is no longer in it.
    let resp = post(
        json!({ "original_name": "Home", "name": "Home", "cidrs": ["10.9.0.0/24"],
        "description": "Home" }),
    )
    .await
    .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(www(&server).await.as_deref(), Some("192.0.2.42"));

    // Networks are saved with the settings and survive a restart.
    shutdown(server).await;
    let server = spawn(base_config(&db)).await;
    let api = format!("http://{}/api", server.api_addr);
    let list = get(&client, &format!("{api}/networks")).await;
    assert_eq!(
        network(&list, "Home").unwrap()["cidrs"],
        json!(["10.9.0.0/24"])
    );
    assert_eq!(network(&list, "Home").unwrap()["description"], "Home");

    // Unused, it can be deleted.
    let sh = get(&client, &format!("{api}/split-horizon")).await;
    let id = sh["entries"][0]["id"].as_str().unwrap().to_string();
    client
        .delete(format!("{api}/split-horizon/entries/{id}"))
        .send()
        .await
        .unwrap();
    let resp = client
        .delete(format!("{api}/networks/home"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let list = get(&client, &format!("{api}/networks")).await;
    assert!(network(&list, "Home").is_none());

    shutdown(server).await;
}

#[tokio::test]
async fn split_horizon_networks_become_shared_networks() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    // A database from before networks were shared: split horizon kept its
    // own, and one of them has a name a built-in network now takes.
    {
        let store = daygle_dns_authoritative::ZoneStore::open(&db.to_string_lossy()).unwrap();
        public_www(&store);
        for (name, cidr) in [("LAN", "127.0.0.0/8"), ("Private", "10.0.0.0/8")] {
            store
                .upsert_split_horizon_network(&SplitHorizonNetworkInput {
                    name: name.to_string(),
                    cidrs: vec![cidr.to_string()],
                })
                .unwrap();
        }
        for (domain, net) in [("www.example.test", "LAN"), ("vpn.example.test", "Private")] {
            store
                .create_split_horizon_entry(&SplitHorizonEntryInput {
                    domain: domain.to_string(),
                    networks: vec![net.to_string()],
                    ips: vec!["10.0.0.5".to_string()],
                    records: vec![],
                    ttl: 30,
                    disabled: false,
                })
                .unwrap();
        }
    }

    let server = spawn(base_config(&db)).await;
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let list = get(&client, &format!("{api}/networks")).await;
    assert_eq!(
        network(&list, "LAN").unwrap()["cidrs"],
        json!(["127.0.0.0/8"])
    );
    assert_eq!(network(&list, "LAN").unwrap()["builtin"], false);
    // The clash with the built-in is renamed, with what refers to it.
    let renamed = network(&list, "Private (Split Horizon)").expect("renamed");
    assert_eq!(
        renamed["used_by"],
        json!(["Split horizon 'vpn.example.test'"])
    );
    // And the views still answer.
    assert_eq!(www(&server).await.as_deref(), Some("10.0.0.5"));
    shutdown(server).await;

    // Adopted once: a restart does not add them again.
    let server = spawn(base_config(&db)).await;
    let list = get(&client, &format!("http://{}/api/networks", server.api_addr)).await;
    assert_eq!(list["networks"].as_array().unwrap().len(), 4);
    shutdown(server).await;
}
