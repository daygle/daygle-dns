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
    Arc::new(AiStore::open(&dir.path().join("ai.db")).expect("AI store opens"))
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
        .save_verdict(
            "bad.example.net",
            "phishing",
            "threat",
            "classified",
            0.995,
            "fasttext",
            "minilm",
            7 * 86400,
        )
        .unwrap();
    let (rows, total) = store
        .list_verdicts(Some("classified"), None, 100, 0)
        .unwrap();
    assert_eq!(total, 1);
    let VerdictRow {
        domain,
        category,
        severity,
        status,
        confidence,
        ..
    } = &rows[0];
    assert_eq!(
        (
            domain.as_str(),
            category.as_str(),
            severity.as_str(),
            status.as_str()
        ),
        ("bad.example.net", "phishing", "threat", "classified")
    );
    assert!(*confidence > 0.9);

    // Fresh threat is listed as block-eligible.
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);

    // Expiry re-queues to pending and clears the category.
    let expired = store
        .expire_old(now + 7 * 86400 + 1, 1000)
        .expect("expiry update ran");
    assert_eq!(expired, 1);
    let (rows, _) = store.list_verdicts(Some("pending"), None, 100, 0).unwrap();
    assert_eq!(rows.len(), 1);
    // No longer fresh ⇒ no longer block-eligible (freshly-scanned again).
    assert_eq!(
        store
            .fresh_blocked(now + 7 * 86400 + 2, 0.99)
            .unwrap()
            .len(),
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
        .save_verdict(
            "site.example.org",
            "malware",
            "threat",
            "classified",
            1.0,
            "fasttext",
            "evidence",
            3600,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);

    store
        .set_override("site.example.org", "allow", "customer wants it")
        .unwrap();
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
        daygle_dns_authoritative::ZoneStore::open(
            &dir.path().join("zones.db").display().to_string(),
        )
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
    zones
        .insert_query_log(&log_row(&now_rfc3339, "evil-virus-site.net"))
        .unwrap();
    zones
        .insert_query_log(&log_row(&now_rfc3339, "plain-news.example"))
        .unwrap();

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

    let (rows, total) = ai.store.list_verdicts(None, None, 100, 0).unwrap();
    assert_eq!(total, 2, "both observed domains are candidates");
    assert!(
        rows.iter().any(|r| r.domain == "evil-virus-site.net"
            && r.status == "classified"
            && r.category == "malware"),
        "heuristic backend should class the malware keyword domain: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.domain == "plain-news.example" && r.status == "skipped"),
        "no-signal domains are skipped, not classified: {rows:?}"
    );

    // A second cycle observes without re-classifying (no new pending rows).
    ai.scanner.run_cycle(since, zones.as_ref()).unwrap();
    let (_, total2) = ai.store.list_verdicts(None, None, 100, 0).unwrap();
    assert_eq!(total, total2);
}

#[test]
fn enforce_mode_populates_snapshot_train_does_not() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    zones
        .insert_query_log(&log_row(&now_rfc3339, "evil-virus-site.net"))
        .unwrap();

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
        .save_verdict(
            "x.example",
            "gambling",
            "info",
            "classified",
            0.8,
            "fasttext",
            "ev",
            1,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.expire_old(now + 5, 100).unwrap(), 1);
    // The row is pending again; a later save (new scan) overwrites the verdict.
    store
        .save_verdict(
            "x.example",
            "news",
            "info",
            "classified",
            0.85,
            "fasttext",
            "ev2",
            3600,
        )
        .unwrap();
    let (rows, _) = store.list_verdicts(None, None, 100, 0).unwrap();
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
        .save_verdict(
            "t.example",
            "phishing",
            "threat",
            "classified",
            0.97,
            "fasttext",
            "ev",
            3600,
        )
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

// ── Scanner lifecycle fixes ────────────────────────────────────────────────

fn engine(dir: &TempDir, settings: AiSettings) -> Arc<AiEngine> {
    let zones = zone_store(dir);
    AiEngine::new(
        &settings,
        &dir.path().join("zones.db").display().to_string(),
        zones,
        Arc::new(LogStore::new(128)),
    )
    .unwrap()
}

#[test]
fn expired_verdicts_are_reclassified_by_the_next_cycle() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let ai = engine(&dir, settings(AiMode::Train));
    // A verdict that has already expired, for a domain no longer queried.
    ai.store.observe("evil-virus-site.net").unwrap();
    ai.store
        .save_verdict(
            "evil-virus-site.net",
            "malware",
            "threat",
            "classified",
            0.35,
            "heuristic",
            "old",
            1,
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // One cycle re-queues it and classifies it again - it must not be left
    // pending.
    ai.scanner
        .run_cycle(chrono::Utc::now().timestamp(), zones.as_ref())
        .unwrap();
    let (rows, _) = ai.store.list_verdicts(None, None, 10, 0).unwrap();
    assert_eq!(rows[0].status, "classified", "{rows:?}");
    assert!(rows[0].expires_at > chrono::Utc::now().timestamp());
}

#[test]
fn expiry_runs_on_its_own_interval() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let ai = engine(
        &dir,
        AiSettings {
            expire_check_secs: 3600,
            ..settings(AiMode::Train)
        },
    );
    // The first cycle runs the expiry check...
    ai.scanner.run_cycle(0, zones.as_ref()).unwrap();
    ai.store.observe("x.example").unwrap();
    ai.store
        .save_verdict(
            "x.example",
            "news",
            "info",
            "classified",
            0.8,
            "fasttext",
            "ev",
            1,
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // ...and the next one, within the hour, leaves the expired verdict alone.
    ai.scanner.run_cycle(0, zones.as_ref()).unwrap();
    let (rows, _) = ai
        .store
        .list_verdicts(Some("classified"), None, 10, 0)
        .unwrap();
    assert_eq!(rows.len(), 1, "expiry must wait for expire_check_secs");
}

#[test]
fn auto_block_categories_decide_what_blocks() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();
    for name in ["bet-slip.example", "www.casino-games.example"] {
        zones
            .insert_query_log(&log_row(&now_rfc3339, name))
            .unwrap();
    }
    // Gambling is an `info` category; once the operator lists it (and the
    // threshold admits the heuristic's 0.3), it blocks like any other.
    let ai = engine(
        &dir,
        AiSettings {
            auto_block_categories: vec!["gambling".to_string()],
            block_threshold: 0.25,
            workers: 4,
            ..settings(AiMode::Enforce)
        },
    );
    ai.scanner.run_cycle(0, zones.as_ref()).unwrap();
    let snapshot = ai.snapshot().load_full();
    assert!(snapshot.contains_key("bet-slip.example"), "{snapshot:?}");
    assert!(snapshot.contains_key("www.casino-games.example"));
    assert_eq!(ai.blockable_counts().unwrap().get("gambling"), Some(&2));

    // An exemption on a parent domain covers its subdomains.
    ai.set_allow_override("casino-games.example", "test")
        .unwrap();
    let snapshot = ai.snapshot().load_full();
    assert!(!snapshot.contains_key("www.casino-games.example"));
    assert!(snapshot.contains_key("bet-slip.example"));
}

#[test]
fn verdict_list_searches_and_flags_exemptions() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    for d in ["a.example", "b.example", "c.other"] {
        store.observe(d).unwrap();
    }
    store
        .save_verdict(
            "b.example",
            "news",
            "info",
            "classified",
            0.9,
            "fasttext",
            "ev",
            3600,
        )
        .unwrap();
    store.set_override("a.example", "allow", "").unwrap();

    let (rows, total) = store.list_verdicts(None, Some("EXAMPLE"), 10, 0).unwrap();
    assert_eq!(total, 2);
    // Most recently classified first, pending last.
    assert_eq!(rows[0].domain, "b.example");
    assert!(rows.iter().any(|r| r.domain == "a.example" && r.overridden));
    // LIKE wildcards are literal.
    assert_eq!(store.list_verdicts(None, Some("%"), 10, 0).unwrap().1, 0);
    assert_eq!(store.list_overrides().unwrap().len(), 1);
}

#[test]
fn harvest_reads_only_the_requested_window() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now = chrono::Utc::now();
    let old = (now - chrono::Duration::hours(2)).to_rfc3339();
    zones
        .insert_query_log(&log_row(&old, "old.example"))
        .unwrap();
    zones
        .insert_query_log(&log_row(&now.to_rfc3339(), "new.example"))
        .unwrap();
    // The window is a timestamp: only the last hour's domain is recorded.
    let names = zones
        .distinct_recent_query_names(now.timestamp() - 3600, 100)
        .unwrap();
    assert_eq!(names, vec!["new.example".to_string()]);
    let ai = engine(&dir, settings(AiMode::Train));
    ai.scanner
        .run_cycle(now.timestamp() - 3600, zones.as_ref())
        .unwrap();
    let (rows, total) = ai.store.list_verdicts(None, None, 10, 0).unwrap();
    assert_eq!(total, 1, "{rows:?}");
    assert_eq!(rows[0].domain, "new.example");
}
