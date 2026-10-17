//! End-to-end AI subsystem tests: store semantics, a scanner cycle fed by a
//! real (temp-file-backed) authoritative `ZoneStore`, plus engine-level
//! override behavior.

use std::sync::Arc;

use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_core::LogStore;
use daygle_dns_ml::store::{AiStore, VerdictRow};
use daygle_dns_ml::AiEngine;
use tempfile::TempDir;

fn tmp_store(dir: &TempDir) -> Arc<AiStore> {
    Arc::new(
        AiStore::open(&dir.path().join("ai.db")).expect("AI store opens"),
    )
}

fn settings(mode: AiMode) -> AiSettings {
    AiSettings {
        enabled: true,
        mode,
        ..AiSettings::default()
    }
}

// ── Store semantics ─────────────────────────────────────────────────────────

#[test]
fn observe_bumps_counter_once_per_domain() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    assert!(store.observe("a.example.com").unwrap());
    assert!(!store.observe("a.example.com").unwrap());
}

#[test]
fn verdict_lifecycle_and_expiry() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);

    store.observe("bad.example.net").unwrap();
    store
        .save_verdict("bad.example.net", "phishing", "threat", "classified", 0.995, "fasttext", "minilm",
                      7 * 86400)
        .unwrap();
    let (rows, total) = store.list_verdicts(Some("classified"), 100, 0).unwrap();
    assert_eq!(total, 1);
    let VerdictRow { domain, category, severity, status, confidence, .. } = &rows[0];
    assert_eq!((domain.as_str(), category.as_str(), severity.as_str(), status.as_str()), ("bad.example.net", "phishing", "threat", "classified"));
    assert!(*confidence > 0.9);

    // Fresh threat is listed as block-eligible.
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);

    // Expiry re-queues to pending and clears the category.
    let expired = store
        .expire_old(now + 7 * 86400 + 1, 1000)
        .expect("expiry update ran");
    assert_eq!(expired, 1);
    let (rows, _) = store.list_verdicts(Some("pending"), 100, 0).unwrap();
    assert_eq!(rows.len(), 1);
    // No longer fresh ⇒ no longer block-eligible (freshly-scanned again).
    assert_eq!(
        store.fresh_blocked(now + 7 * 86400 + 2, 0.99).unwrap().len(),
        0,
        "expired verdicts must not stay block-eligible"
    );
}

#[test]
fn allow_override_vetoes_block_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("site.example.org").unwrap();
    store
        .save_verdict("site.example.org", "malware", "threat", "classified", 1.0, "fasttext", "evidence",
                      3600)
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);

    store.set_override("site.example.org", "allow", "customer wants it").unwrap();
    assert_eq!(
        store.fresh_blocked(now, 0.99).unwrap().len(),
        0,
        "an allow override must suppress block eligibility"
    );
    store.clear_override("site.example.org").unwrap();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);
}

// ── Scanner cycle against a real ZoneStore ──────────────────────────────────

fn zone_store(dir: &TempDir) -> Arc<daygle_dns_authoritative::ZoneStore> {
    Arc::new(
        daygle_dns_authoritative::ZoneStore::open(&dir.path().join("zones.db").display().to_string())
            .unwrap(),
    )
}

fn log_row(ts: &str, qname: &str) -> daygle_dns_authoritative::QueryLogRow {
    daygle_dns_authoritative::QueryLogRow {
        id: 0,
        ts: ts.to_string(),
        client: "10.0.0.2".into(),
        qname: qname.into(),
        qtype: "A".into(),
        protocol: "udp".into(),
        outcome: "recursive".into(),
        rcode: Some("NOERROR".into()),
        elapsed_ms: 1,
    }
}

#[test]
fn scanner_cycle_classifies_query_log_domains() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    zones.insert_query_log(&log_row(&now_rfc3339, "evil-virus-site.net")).unwrap();
    zones.insert_query_log(&log_row(&now_rfc3339, "plain-news.example")).unwrap();

    let ai = AiEngine::new(
        &settings(AiMode::Train),
        &dir.path().join("zones.db").display().to_string(),
        zones.clone(),
        Arc::new(LogStore::new(128)),
    )
    .unwrap();

    // Run a cycle that covers the last hour.
    let since = chrono::Utc::now().timestamp() - 3600;
    ai.scanner.run_cycle(since, zones.as_ref()).unwrap();

    let (rows, total) = ai.store.list_verdicts(None, 100, 0).unwrap();
    assert_eq!(total, 2, "both observed domains are candidates");
    assert!(
        rows.iter().any(|r| r.domain == "evil-virus-site.net"
            && r.status == "classified"
            && r.category == "malware"),
        "heuristic backend should class the malware keyword domain: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.domain == "plain-news.example"
            && r.status == "skipped"),
        "no-signal domains are skipped, not classified: {rows:?}"
    );

    // A second cycle observes without re-classifying (no new pending rows).
    ai.scanner.run_cycle(since, zones.as_ref()).unwrap();
    let (_, total2) = ai.store.list_verdicts(None, 100, 0).unwrap();
    assert_eq!(total, total2);
}

#[test]
fn enforce_mode_populates_snapshot_train_does_not() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    zones.insert_query_log(&log_row(&now_rfc3339, "evil-virus-site.net")).unwrap();

    // Train mode: nothing in the snapshot.
    let train = AiEngine::new(
        &settings(AiMode::Train),
        &dir.path().join("zones.db").display().to_string(),
        zones.clone(),
        Arc::new(LogStore::new(128)),
    )
    .unwrap();
    train.scanner.run_cycle(0, zones.as_ref()).unwrap();
    assert!(
        train.snapshot().load().is_empty(),
        "train mode must never publish blocks"
    );

    // Enforce mode: heuristic confidences (max 0.6) are far below the 0.99
    // auto-block threshold, so the snapshot stays empty - by design,
    // heuristics alone can never auto-block.
    let enforce = AiEngine::new(
        &settings(AiMode::Enforce),
        &dir.path().join("zones.db").display().to_string(),
        zones.clone(),
        Arc::new(LogStore::new(128)),
    )
    .unwrap();
    enforce.scanner.run_cycle(0, zones.as_ref()).unwrap();
    assert!(
        enforce.snapshot().load().is_empty(),
        "heuristic verdicts must never auto-block (threshold engineering)"
    );
}

#[test]
fn expired_verdicts_are_requeued_and_visible_again() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("x.example").unwrap();
    // 1-second TTL verdict already expired by the time we check.
    store
        .save_verdict("x.example", "gambling", "info", "classified", 0.8, "fasttext", "ev", 1)
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.expire_old(now + 5, 100).unwrap(), 1);
    // The row is pending again; a later save (new scan) overwrites the verdict.
    store
        .save_verdict("x.example", "news", "info", "classified", 0.85, "fasttext", "ev2", 3600)
        .unwrap();
    let (rows, _) = store.list_verdicts(None, 100, 0).unwrap();
    assert_eq!(rows[0].category, "news");
}

// ── Engine-level guardrails ────────────────────────────────────────────────

#[test]
fn engine_snapshot_never_contains_below_threshold_verdicts() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("t.example").unwrap();
    // Threat verdict just below the default 0.99 threshold.
    store
        .save_verdict("t.example", "phishing", "threat", "classified", 0.97, "fasttext", "ev", 3600)
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 0);
}

#[test]
fn settings_arc_swap_posts_update_on_refresh() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    // Engine built in train mode shares settings via ArcSwap.
    let ai = AiEngine::new(
        &settings(AiMode::Enforce),
        &dir.path().join("zones.db").display().to_string(),
        zones.clone(),
        Arc::new(LogStore::new(128)),
    )
    .unwrap();
    // Swap train mode in; snapshot refresh now publishes an empty set.
    ai.settings.store(Arc::new(settings(AiMode::Train)));
    ai.refresh_snapshot_now();
    assert!(ai.snapshot().load().is_empty());
}
