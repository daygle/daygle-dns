//! Integration test: a backup downloaded from the API restores the server
//! to that point after a restart, and a staged restore can be cancelled.

mod common;

use common::*;
use daygle_dns_authoritative::model::ZoneInput;

async fn zone_names(server: &daygle_dns::BoundServer) -> Vec<String> {
    let mut names: Vec<String> = server
        .catalog
        .store()
        .list_zones()
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn backup_and_restore_through_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daygle-dns.db");
    let server = spawn(base_config(&db)).await;
    let api = format!("http://{}/api", server.api_addr);
    let client = reqwest::Client::new();
    let create = |name: &str| ZoneInput {
        name: name.to_string(),
        ..Default::default()
    };
    server
        .catalog
        .store()
        .create_zone(&create("kept.test"))
        .unwrap();

    let resp = client.get(format!("{api}/backup")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let disposition = resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(disposition.contains("daygle-dns-backup-"), "{disposition}");
    let backup = resp.bytes().await.unwrap();

    // Not a backup: refused, nothing staged.
    let resp = client
        .post(format!("{api}/backup/restore"))
        .body("not a backup")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let pending: serde_json::Value = client
        .get(format!("{api}/backup/restore"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(pending["pending"].is_null());

    // Stage, cancel, stage again.
    server
        .catalog
        .store()
        .create_zone(&create("later.test"))
        .unwrap();
    let staged: serde_json::Value = client
        .post(format!("{api}/backup/restore"))
        .body(backup.clone())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(staged["pending"]["zones"], 1);
    let resp = client
        .delete(format!("{api}/backup/restore"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client
        .delete(format!("{api}/backup/restore"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = client
        .post(format!("{api}/backup/restore"))
        .body(backup)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Nothing changes until a restart.
    assert_eq!(zone_names(&server).await, ["kept.test", "later.test"]);
    shutdown(server).await;

    let server = spawn(base_config(&db)).await;
    assert_eq!(zone_names(&server).await, ["kept.test"]);
    let pending: serde_json::Value =
        reqwest::get(format!("http://{}/api/backup/restore", server.api_addr))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(pending["pending"].is_null());
    // The previous database is kept beside it.
    let kept_aside = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("daygle-dns.db.before-restore-")
        });
    assert!(kept_aside);
    shutdown(server).await;
}
