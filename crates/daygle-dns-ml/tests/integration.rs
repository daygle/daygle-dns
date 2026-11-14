//! End-to-end AI subsystem tests: store semantics, a scanner cycle fed by a
//! real (temp-file-backed) authoritative `ZoneStore`, plus engine-level
//! override behavior.

use std::sync::Arc;

use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_core::LogStore;
use daygle_dns_ml::backend::Channel;
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

/// A database from before the channel split stored one verdict per domain.
/// Opening it must keep every threat verdict blocking, and queue the channel
/// that never ran so the next scan fills it in.
#[test]
fn store_upgrades_a_pre_channel_database() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ai.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ai_verdicts (
                domain        TEXT PRIMARY KEY,
                category      TEXT NOT NULL DEFAULT '',
                severity      TEXT NOT NULL DEFAULT '',
                status        TEXT NOT NULL DEFAULT 'pending',
                confidence    REAL NOT NULL DEFAULT 0,
                backend       TEXT NOT NULL DEFAULT '',
                evidence      TEXT NOT NULL DEFAULT '',
                observations  INTEGER NOT NULL DEFAULT 0,
                classified_at INTEGER NOT NULL DEFAULT 0,
                expires_at    INTEGER NOT NULL DEFAULT 0,
                last_seen     INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO ai_verdicts
                (domain, category, severity, status, confidence, backend,
                 evidence, observations, classified_at, expires_at, last_seen)
            VALUES
                ('bad.example', 'phishing', 'threat', 'classified', 0.999,
                 'fasttext', 'ev', 3, 1000, 9999999999, 2000),
                ('news.example', 'news', 'info', 'classified', 0.8,
                 'fasttext', 'ev', 1, 1000, 9999999999, 500);",
        )
        .unwrap();
    }

    let store = AiStore::open(&path).expect("old database upgrades");
    let now = chrono::Utc::now().timestamp();
    // The old threat verdict still blocks: an upgrade must not unblock
    // domains while the next scan runs.
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);

    let (rows, total) = store.list_verdicts(None, None, 10, 0).unwrap();
    assert_eq!(total, 4, "each domain gains its missing channel: {rows:?}");
    let row = |domain: &str, channel: &str| {
        rows.iter()
            .find(|r| r.domain == domain && r.channel == channel)
            .unwrap_or_else(|| panic!("no {channel} row for {domain}: {rows:?}"))
    };
    let bad_threat = row("bad.example", "threat");
    assert_eq!(bad_threat.category, "phishing");
    assert_eq!(bad_threat.status, "classified");
    assert_eq!(bad_threat.observations, 3, "observation counts survive");
    assert_eq!(row("bad.example", "content").status, "pending");
    let news_content = row("news.example", "content");
    assert_eq!(news_content.category, "news");
    assert_eq!(news_content.status, "classified");
    assert_eq!(row("news.example", "threat").status, "pending");
}

/// Categorization is information, not a decision: a content verdict never
/// reaches the block snapshot, whatever it is called and however confident.
#[test]
fn content_categorizations_never_auto_block() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("shop.example").unwrap();
    store
        .save_verdict(
            Channel::Content,
            "shop.example",
            "malware",
            "info",
            "classified",
            1.0,
            "fasttext",
            "categorizer said malware",
            3600,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!(
        store.fresh_blocked(now, 0.99).unwrap().is_empty(),
        "a content row must never be block-eligible"
    );

    // The same label on the threat channel is what blocks.
    store
        .save_verdict(
            Channel::Threat,
            "shop.example",
            "malware",
            "threat",
            "classified",
            1.0,
            "fasttext",
            "threat model said malware",
            3600,
        )
        .unwrap();
    assert_eq!(store.fresh_blocked(now, 0.99).unwrap().len(), 1);
}

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
            Channel::Threat,
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

    // Expiry re-queues a domain still being queried to pending and clears
    // the category.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    store.observe("bad.example.net").unwrap();
    let expired = store
        .expire_old(now + 7 * 86400 + 1, 1000)
        .expect("expiry update ran");
    assert_eq!(expired, 1);
    let (rows, _) = store.list_verdicts(Some("pending"), None, 100, 0).unwrap();
    assert_eq!(rows.len(), 2, "both channels re-queue together");
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

/// When one channel's row was dropped on expiry (the domain had not been
/// queried since) and the domain shows up again, the recreated row is new,
/// but the surviving channel's row must still count the sighting - otherwise
/// its `last_seen` stays old and its own expiry deletes it instead of
/// re-checking a domain that is plainly in use.
#[test]
fn a_recreated_channel_row_still_bumps_the_surviving_one() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    assert!(store.observe("mixed.example").unwrap());
    // The threat verdict expires quickly; the content one much later.
    store
        .save_verdict(
            Channel::Threat,
            "mixed.example",
            "",
            "",
            "skipped",
            0.0,
            "test",
            "no signal",
            1,
        )
        .unwrap();
    store
        .save_verdict(
            Channel::Content,
            "mixed.example",
            "news",
            "info",
            "classified",
            0.9,
            "test",
            "label",
            86400,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    // Not queried since: the threat row is dropped, not re-queued.
    assert_eq!(store.expire_old(now + 10, 100).unwrap(), 0);
    let row = |channel: &str| -> VerdictRow {
        let (rows, _) = store.list_verdicts(None, None, 100, 0).unwrap();
        rows.into_iter()
            .find(|r| r.channel == channel)
            .unwrap_or_else(|| panic!("{channel} row exists"))
    };
    assert_eq!(store.list_verdicts(None, None, 100, 0).unwrap().1, 1);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(
        store.observe("mixed.example").unwrap(),
        "the dropped threat row starts over as new"
    );
    assert_eq!(row("threat").status, "pending");
    assert_eq!(
        row("content").observations,
        2,
        "the surviving content row counts the sighting"
    );
    // Seen after it was classified: its own expiry re-checks it.
    assert_eq!(store.expire_old(now + 2 * 86400, 100).unwrap(), 1);
    assert_eq!(row("content").status, "pending");
}

/// An expiry backlog larger than one batch is visible, so the scanner
/// carries on with it next cycle instead of an `expire_check_secs` later.
#[test]
fn expiry_backlogs_are_reported() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    for domain in ["a.example", "b.example"] {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                Channel::Content,
                domain,
                "news",
                "info",
                "classified",
                0.9,
                "test",
                "label",
                1,
            )
            .unwrap();
    }
    let later = chrono::Utc::now().timestamp() + 10;
    assert!(store.has_expired(later).unwrap());
    store.expire_old(later, 1).unwrap();
    assert!(
        store.has_expired(later).unwrap(),
        "one left for the next batch"
    );
    store.expire_old(later, 1).unwrap();
    assert!(!store.has_expired(later).unwrap());
}

/// A relabel is a categorization: the threat channel's row keeps the
/// model's label and is not reported as relabelled.
#[test]
fn relabels_mark_only_the_content_row() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("shop.example").unwrap();
    store
        .set_category_override("shop.example", "shopping")
        .unwrap();
    let (rows, _) = store.list_verdicts(None, None, 100, 0).unwrap();
    for row in rows {
        assert_eq!(
            row.category_overridden,
            row.channel == "content",
            "{}",
            row.channel
        );
    }
    let only_set = |channel| {
        store
            .list_verdicts_filtered(
                &daygle_dns_ml::store::VerdictFilter {
                    label: Some("set"),
                    channel: Some(channel),
                    ..Default::default()
                },
                daygle_dns_ml::store::VerdictPage {
                    limit: 100,
                    offset: 0,
                },
            )
            .unwrap()
            .1
    };
    assert_eq!(only_set("content"), 1);
    assert_eq!(only_set("threat"), 0);
}

#[test]
fn allow_override_vetoes_block_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("site.example.org").unwrap();
    store
        .save_verdict(
            Channel::Threat,
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
        block: None,
        account: None,
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

    // Two observed domains, and both channels classify each of them.
    let (rows, total) = ai.store.list_verdicts(None, None, 100, 0).unwrap();
    assert_eq!(
        total, 4,
        "both observed domains are candidates in both channels"
    );
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
            Channel::Content,
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
    std::thread::sleep(std::time::Duration::from_millis(1100));
    store.observe("x.example").unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(store.expire_old(now + 5, 100).unwrap(), 1);
    // The row is pending again; a later save (new scan) overwrites the verdict.
    store
        .save_verdict(
            Channel::Content,
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
            Channel::Threat,
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
    // A verdict that has already expired, for a domain queried since.
    ai.store.observe("evil-virus-site.net").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
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
    ai.store.observe("evil-virus-site.net").unwrap();

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
            Channel::Content,
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

/// A dedicated threat model is a detector in its own right: what it reports
/// blocks without the operator listing the label, which is the whole point of
/// giving the threat channel its own model.
#[test]
fn dedicated_threat_model_blocks_its_own_labels() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            // No shared model on purpose: the missing file only degrades the
            // channel to the heuristic rules, and the *configured* dedicated
            // path is what moves the label list out of the block decision.
            model_path: String::new(),
            threat_model_path: "/nonexistent/threat.bin".to_string(),
            auto_block_categories: vec!["phishing".to_string()],
            block_threshold: 0.25,
            ..settings(AiMode::Enforce)
        },
    );
    ai.store.observe("casino-bonus.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "casino-bonus.example",
            "gambling",
            "threat",
            "classified",
            0.8,
            "heuristic",
            "ev",
            3600,
        )
        .unwrap();
    let blockable = ai.blockable_counts().unwrap();
    assert_eq!(
        blockable.get("gambling"),
        Some(&1),
        "a dedicated model's label blocks without being listed: {blockable:?}"
    );
}

/// Without a second model the label list is the only thing separating a threat
/// from an ordinary category, so an unlisted label still blocks nothing.
#[test]
fn shared_classifier_keeps_the_label_list_as_the_filter() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            model_path: String::new(),
            auto_block_categories: vec!["phishing".to_string()],
            block_threshold: 0.25,
            ..settings(AiMode::Enforce)
        },
    );
    ai.store.observe("casino-bonus.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "casino-bonus.example",
            "gambling",
            "threat",
            "classified",
            0.8,
            "heuristic",
            "ev",
            3600,
        )
        .unwrap();
    assert!(
        !ai.blockable_counts().unwrap().contains_key("gambling"),
        "an unlisted label must not block with the shared classifier"
    );
}

/// A correction is not an exemption: the detection is kept (so the mistake
/// stays visible and the model can be retrained from it) but it stops
/// blocking and leaves the exported list until the mark is cleared.
/// Corrections outrank verdicts when building a training set, and a domain
/// the operator vetoed is not evidence for the model.
#[test]
fn training_data_prefers_corrections_and_skips_vetoed_domains() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    for domain in ["a.example", "b.example"] {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                Channel::Content,
                domain,
                "news",
                "info",
                "classified",
                0.95,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
    }
    store
        .set_category_override("a.example", "shopping")
        .unwrap();
    store
        .set_override("b.example", "not_threat", "not news")
        .unwrap();

    let (pairs, stats) = daygle_dns_ml::learn::collect(&store, &settings(AiMode::Train)).unwrap();
    assert_eq!(
        pairs,
        vec![("shopping".to_string(), "a.example".to_string())],
        "the relabel wins and the vetoed domain is not training data"
    );
    assert_eq!(stats.corrections, 1);
    assert_eq!(stats.verdicts, 0);
}

/// A retrain with nothing to learn from is refused; once there is enough, it
/// installs a model beside `ai.db` and records what it was built from.
#[test]
fn retraining_installs_a_learned_model_once_there_is_data() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            block_threshold: 0.5,
            ..settings(AiMode::Train)
        },
    );
    let refused = ai.retrain_learned_model().unwrap_err().to_string();
    assert!(refused.contains("not enough training data"), "{refused}");
    assert!(!ai.learned_model_path().exists());

    let labels = ["news", "shopping", "gambling"];
    for i in 0..240 {
        let domain = format!("site{i}.example");
        ai.store.observe(&domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Content,
                &domain,
                labels[i % labels.len()],
                "info",
                "classified",
                0.95,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
    }

    let stats = ai.retrain_learned_model().unwrap();
    assert_eq!(stats.examples, 240);
    assert_eq!(stats.labels, 3);
    assert!(ai.learned_model_path().is_file());
    let record = ai.learned_model_record().expect("the retrain is recorded");
    assert_eq!(record["examples"], 240);
    assert_eq!(record["labels"], 3);
    // The new model is live: the content channel switched from the heuristic
    // fallback to the trained fastText file, without a restart.
    assert!(ai.learned_model_active());
    assert_eq!(ai.content_backend_name(), "fasttext");
}

/// Each accepted retrain keeps the model it replaced, and a rollback swaps the
/// two - live, and reversibly.
#[test]
fn a_retrain_keeps_one_model_to_roll_back_to() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            block_threshold: 0.5,
            ..settings(AiMode::Train)
        },
    );
    let labels = ["news", "shopping", "gambling"];
    for i in 0..240 {
        let domain = format!("site{i}.example");
        ai.store.observe(&domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Content,
                &domain,
                labels[i % labels.len()],
                "info",
                "classified",
                0.95,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
    }
    ai.retrain_learned_model().unwrap();
    assert!(
        !ai.learned_model_previous(),
        "nothing has been replaced yet"
    );
    assert_eq!(ai.learned_model_record().unwrap()["examples"], 240);

    // Three more domains: a second retrain replaces the first model.
    for i in 240..243 {
        let domain = format!("site{i}.example");
        ai.store.observe(&domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Content,
                &domain,
                labels[i % labels.len()],
                "info",
                "classified",
                0.95,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
    }
    ai.retrain_learned_model().unwrap();
    assert_eq!(ai.learned_model_record().unwrap()["examples"], 243);
    assert!(ai.learned_model_previous());

    ai.rollback_learned_model().unwrap();
    assert_eq!(
        ai.learned_model_record().unwrap()["examples"],
        240,
        "the record follows the restored model"
    );
    // Reversible: the model just replaced is now the previous one.
    ai.rollback_learned_model().unwrap();
    assert_eq!(ai.learned_model_record().unwrap()["examples"], 243);
}

/// A threat candidate is offered for a page read once, and what the page said
/// lands on its evidence without touching the verdict itself.
#[test]
fn a_threat_candidate_is_offered_for_a_page_read_once() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    ai.store.observe("phishy.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "phishy.example",
            "phishing",
            "threat",
            "classified",
            0.99,
            "fasttext",
            "ev",
            3600,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(
        ai.store.page_fetch_candidates(now, 0.2, 16).unwrap(),
        vec![("phishy.example".to_string(), 0.99)]
    );

    // An exempted domain is not fetched, whatever the model said.
    ai.store.observe("exempt.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "exempt.example",
            "phishing",
            "threat",
            "classified",
            0.99,
            "fasttext",
            "ev",
            3600,
        )
        .unwrap();
    ai.store
        .set_override("exempt.example", "not_threat", "")
        .unwrap();
    assert_eq!(
        ai.store.page_fetch_candidates(now, 0.2, 16).unwrap(),
        vec![("phishy.example".to_string(), 0.99)]
    );

    assert!(ai
        .store
        .record_page_reading(
            "phishy.example",
            "page \"Sign in\" reads phishing (60%)",
            Some(0.8),
        )
        .unwrap());
    assert!(
        ai.store
            .page_fetch_candidates(now, 0.2, 16)
            .unwrap()
            .is_empty(),
        "a classification is not read twice"
    );
    let rows = ai.store.verdicts_for("phishy.example").unwrap();
    let threat = rows.iter().find(|r| r.channel == "threat").unwrap();
    assert_eq!(threat.category, "phishing");
    assert_eq!(
        threat.confidence, 0.8,
        "the page rule's confidence is stored with the verdict"
    );
    assert!(threat.evidence.contains("ev"), "{}", threat.evidence);
    assert!(
        threat.evidence.contains("reads phishing"),
        "{}",
        threat.evidence
    );
}

/// "Not a threat" corrections train a `benign` label only when
/// `ai.learn_negatives` asks for it; the domain's machine label is dropped
/// either way, so the model is not taught the very label the operator denied.
#[test]
fn not_a_threat_corrections_are_learned_only_when_enabled() {
    let dir = TempDir::new().unwrap();
    // A low threshold keeps the test about the override, not about whether a
    // 1.0 verdict clears the block threshold.
    let mut cfg = settings(AiMode::Train);
    cfg.block_threshold = 0.5;
    let ai = engine(&dir, cfg.clone());
    for i in 0..12 {
        let domain = format!("innocent{i}.example");
        ai.store.observe(&domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Threat,
                &domain,
                "phishing",
                "threat",
                "classified",
                1.0,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
        ai.store
            .set_override(&domain, "not_threat", "looked fine")
            .unwrap();
    }
    // A domain nobody corrected: proves threat verdicts do become training
    // data, so the assertions below are not vacuous.
    ai.store.observe("control.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "control.example",
            "phishing",
            "threat",
            "classified",
            1.0,
            "fasttext",
            "ev",
            3600,
        )
        .unwrap();

    let dataset = daygle_dns_ml::learn::collect_dataset(&ai.store, &cfg).unwrap();
    assert!(
        !dataset.pairs.iter().any(|(label, _)| label == "benign"),
        "off by default: a single-label model is not given a negative class"
    );
    assert!(
        dataset
            .pairs
            .iter()
            .any(|(label, domain)| label == "phishing" && domain == "control.example"),
        "a threat verdict nobody corrected is training data: {dataset:?}",
        dataset = dataset.pairs
    );
    assert!(
        !dataset
            .pairs
            .iter()
            .any(|(_, domain)| domain.starts_with("innocent")),
        "a denied label is not training data under any label, with negatives off"
    );

    cfg.learn_negatives = true;
    let dataset = daygle_dns_ml::learn::collect_dataset(&ai.store, &cfg).unwrap();
    assert_eq!(dataset.stats.negatives, 10, "one in five is held back");
    assert!(dataset
        .pairs
        .iter()
        .any(|(label, _)| label == daygle_dns_ml::learn::BENIGN_LABEL));
    assert!(
        !dataset
            .pairs
            .iter()
            .any(|(label, domain)| label == "phishing" && domain.starts_with("innocent")),
        "the denied label never comes back alongside the benign pair"
    );
}

/// Corrections are held back from training in fifths, and the candidate is
/// accepted when it does as well on them as the model in use.
#[test]
fn retraining_judges_itself_on_held_out_corrections() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            block_threshold: 0.5,
            ..settings(AiMode::Train)
        },
    );
    let labels = ["news", "shopping", "gambling"];
    for i in 0..240 {
        let domain = format!("site{i}.example");
        ai.store.observe(&domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Content,
                &domain,
                labels[i % labels.len()],
                "info",
                "classified",
                0.95,
                "fasttext",
                "ev",
                3600,
            )
            .unwrap();
    }
    for i in 0..10 {
        ai.store
            .set_category_override(&format!("site{i}.example"), labels[i % labels.len()])
            .unwrap();
    }

    let stats = ai.retrain_learned_model().unwrap();
    assert_eq!(stats.corrections, 8, "two of ten corrections are held out");
    let record = ai.learned_model_record().unwrap();
    assert_eq!(record["validation_examples"], 2);
    assert!(
        record["validation_accuracy"].as_f64().is_some(),
        "the held-out score is recorded: {record}"
    );
}

#[test]
fn marking_a_threat_not_a_threat_stops_blocking_and_export() {
    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            auto_block_categories: vec!["gambling".to_string()],
            block_threshold: 0.25,
            ..settings(AiMode::Enforce)
        },
    );
    ai.store.observe("casino-bonus.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "casino-bonus.example",
            "gambling",
            "threat",
            "classified",
            0.9,
            "heuristic",
            "ev",
            3600,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert_eq!(ai.store.export_threats(now, 0.25).unwrap().len(), 1);
    assert!(ai.blockable_counts().unwrap().contains_key("gambling"));

    ai.set_not_threat_override("casino-bonus.example", "not gambling")
        .unwrap();
    assert!(ai.blockable_counts().unwrap().is_empty());
    assert!(
        ai.store.export_threats(now, 0.25).unwrap().is_empty(),
        "a corrected detection must leave the exported threat list"
    );
    // The verdict itself survives, for audit and for the console (the other
    // row is the categorizer's pending one).
    let rows = ai.store.verdicts_for("casino-bonus.example").unwrap();
    assert!(
        rows.iter()
            .any(|r| r.channel == "threat" && r.category == "gambling"),
        "the corrected detection is kept: {rows:?}"
    );
    // The correction is training data, alongside a relabel.
    ai.set_category_override("casino-bonus.example", "news")
        .unwrap();
    let corrections = ai.store.corrections().unwrap();
    let mark = corrections
        .iter()
        .find(|c| c.domain == "casino-bonus.example" && c.action == "not_threat")
        .expect("the correction is recorded");
    assert_eq!(mark.reason, "not gambling");
    assert!(corrections
        .iter()
        .any(|c| c.domain == "casino-bonus.example"
            && c.action == "category"
            && c.category == "news"));

    assert!(ai.clear_override("casino-bonus.example").unwrap());
    assert!(ai.blockable_counts().unwrap().contains_key("gambling"));
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
            Channel::Content,
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

    // Two matching domains, one row per channel each.
    let (rows, total) = store.list_verdicts(None, Some("EXAMPLE"), 10, 0).unwrap();
    assert_eq!(total, 4);
    // Most recently classified first, pending last.
    assert_eq!(rows[0].domain, "b.example");
    assert!(rows.iter().any(|r| r.domain == "a.example" && r.overridden));
    // LIKE wildcards are literal.
    assert_eq!(store.list_verdicts(None, Some("%"), 10, 0).unwrap().1, 0);
    assert_eq!(store.list_overrides().unwrap().len(), 1);
}

#[test]
fn filtered_verdict_and_threat_lists_apply_filters_before_pagination() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    for (domain, category, severity, channel) in [
        ("bad-phish.example", "phishing", "threat", Channel::Threat),
        ("bad-malware.example", "malware", "threat", Channel::Threat),
        ("disputed.example", "phishing", "disputed", Channel::Threat),
        ("news.example", "news", "info", Channel::Content),
    ] {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                channel,
                domain,
                category,
                severity,
                "classified",
                0.9,
                "test",
                "evidence",
                3600,
            )
            .unwrap();
    }
    store
        .set_override("bad-phish.example", "allow", "false positive")
        .unwrap();

    let (rows, total) = store
        .list_verdicts_filtered(
            &daygle_dns_ml::store::VerdictFilter {
                category: Some("PHISH"),
                severity: Some("threat"),
                exemption: Some("exempt"),
                channel: Some("threat"),
                ..Default::default()
            },
            daygle_dns_ml::store::VerdictPage {
                limit: 10,
                offset: 0,
            },
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].domain, "bad-phish.example");
    assert!(rows[0].overridden);

    let (rows, total) = store
        .list_threats_filtered(
            &daygle_dns_ml::store::VerdictFilter {
                category: Some("malware"),
                severity: Some("threat"),
                exemption: Some("not_exempt"),
                ..Default::default()
            },
            daygle_dns_ml::store::VerdictPage {
                limit: 10,
                offset: 0,
            },
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].domain, "bad-malware.example");
    assert!(!rows[0].overridden);

    let (_, total) = store
        .list_threats_filtered(
            &daygle_dns_ml::store::VerdictFilter {
                severity: Some("disputed"),
                ..Default::default()
            },
            daygle_dns_ml::store::VerdictPage {
                limit: 10,
                offset: 0,
            },
        )
        .unwrap();
    assert_eq!(total, 1);
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
    assert_eq!(total, 2, "one row per channel: {rows:?}");
    assert!(rows.iter().all(|r| r.domain == "new.example"), "{rows:?}");
}

/// A domain nobody has queried since its verdict was made is dropped when
/// the verdict expires, instead of being re-classified forever; it starts
/// over as new if it is queried again.
#[test]
fn expired_verdicts_of_unqueried_domains_are_dropped() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("gone.example.com").unwrap();
    for channel in Channel::all() {
        store
            .save_verdict(
                channel,
                "gone.example.com",
                "news",
                "info",
                "classified",
                0.8,
                "fasttext",
                "ev",
                1,
            )
            .unwrap();
    }
    let later = chrono::Utc::now().timestamp() + 5;
    assert_eq!(store.expire_old(later, 100).unwrap(), 0);
    let (_, total) = store.list_verdicts(None, None, 10, 0).unwrap();
    assert_eq!(total, 0, "the stale row is gone");
    assert!(store.observe("gone.example.com").unwrap(), "back as new");
}

/// A threat the verifier disputed keeps its category and confidence but is
/// never block-eligible.
#[test]
fn disputed_threats_never_auto_block() {
    let dir = TempDir::new().unwrap();
    let store = tmp_store(&dir);
    store.observe("disputed.example.com").unwrap();
    store
        .save_verdict(
            Channel::Threat,
            "disputed.example.com",
            "phishing",
            "disputed",
            "classified",
            0.999,
            "fasttext+minilm-onnx",
            "verifier disagrees",
            3600,
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!(store.fresh_blocked(now, 0.99).unwrap().is_empty());
}

/// Only internet names outside the server's own zones are classified:
/// single-label names, reverse lookups, local-only suffixes and hosted
/// zones are left alone.
#[test]
fn local_and_hosted_names_are_not_classified() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    zones
        .create_zone(&daygle_dns_authoritative::model::ZoneInput {
            name: "corp-virus.net".to_string(),
            ..Default::default()
        })
        .unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    for name in [
        "wpad",
        "1.0.168.192.in-addr.arpa",
        "virus-printer.local",
        "virus.home.arpa",
        "www.corp-virus.net",
        "evil-virus-site.net",
    ] {
        zones.insert_query_log(&log_row(&now, name)).unwrap();
    }
    let ai = AiEngine::new(
        &settings(AiMode::Train),
        &dir.path().join("zones.db").display().to_string(),
        zones.clone(),
        Arc::new(LogStore::new(128)),
    )
    .unwrap();
    ai.scanner.run_cycle(0, zones.as_ref()).unwrap();
    let (rows, _) = ai.store.list_verdicts(None, None, 100, 0).unwrap();
    assert!(!rows.is_empty());
    assert!(
        rows.iter().all(|r| r.domain == "evil-virus-site.net"),
        "only the internet name is classified: {rows:?}"
    );
}

/// A classifier that panics on one domain: in a multi-worker cycle the
/// verdicts of the other domains must stay with their own domains.
#[test]
fn a_panicking_worker_does_not_shift_verdicts() {
    use daygle_dns_ml::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};
    struct PanicsOnOne;
    impl DomainClassifier for PanicsOnOne {
        fn name(&self) -> String {
            "test".to_string()
        }
        fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
            if input.domain.starts_with("a-") {
                panic!("classifier failure");
            }
            Some(Verdict {
                category: input.domain.clone(),
                confidence: 0.9,
                severity: Severity::Info,
                evidence: String::new(),
            })
        }
    }

    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let now = chrono::Utc::now().to_rfc3339();
    let names = ["a-panics.com", "b-site.com", "c-site.com", "d-site.com"];
    for name in names {
        zones.insert_query_log(&log_row(&now, name)).unwrap();
    }
    let store = tmp_store(&dir);
    let scanner = daygle_dns_ml::scanner::Scanner::new(
        store.clone(),
        Box::new(PanicsOnOne),
        Box::new(PanicsOnOne),
        Arc::new(arc_swap::ArcSwap::from_pointee(AiSettings {
            workers: 4,
            ..settings(AiMode::Train)
        })),
        Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
        Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
        Arc::new(LogStore::new(128)),
    );
    scanner.run_cycle(0, zones.as_ref()).unwrap();
    let (rows, _) = store.list_verdicts(None, None, 100, 0).unwrap();
    for row in rows {
        if row.domain == "a-panics.com" {
            assert_eq!(row.status, "skipped");
        } else {
            assert_eq!(row.category, row.domain, "verdict stayed with its domain");
        }
    }
}

// ── Category blocking (operator policy over content labels) ─────────────────

/// The content label reaches the category snapshot - which is what a group's
/// `blocked_categories` matches - while the auto-block snapshot stays empty.
#[test]
fn content_labels_feed_the_category_snapshot_only() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    ai.store.observe("casino.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Content,
            "casino.example",
            "gambling",
            "info",
            "classified",
            1.0,
            "fasttext",
            "categorizer said gambling",
            3600,
        )
        .unwrap();
    ai.refresh_snapshot_now();

    let categories = ai.category_snapshot().load();
    assert_eq!(
        categories.get("casino.example").unwrap().category,
        "gambling"
    );
    assert!(
        ai.snapshot().load().is_empty(),
        "a content label must never become an auto-block"
    );
    drop(categories);

    // Expired verdicts leave the category snapshot with the block snapshot.
    let (rows, _) = ai.store.list_verdicts(None, None, 10, 0).unwrap();
    assert!(!rows.is_empty());
    ai.store
        .set_override("casino.example", "allow", "test")
        .unwrap();
    ai.refresh_snapshot_now();
    assert!(
        ai.category_snapshot().load().is_empty(),
        "an allow override exempts a domain from category blocking too"
    );
}

/// A threat label is a category a group can block only on the threat
/// channel's terms: a verdict at or above the block threshold, in either
/// mode. The categorizer's own guess at the label does not count - a group
/// blocking "malware" blocked Windows Update on a 77% guess.
#[test]
fn threat_labels_reach_the_category_snapshot_on_threat_terms_only() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    let save = |channel, domain: &str, severity: &str, confidence| {
        ai.store.observe(domain).unwrap();
        ai.store
            .save_verdict(
                channel,
                domain,
                "malware",
                severity,
                "classified",
                confidence,
                "fasttext",
                "said malware",
                3600,
            )
            .unwrap();
    };
    // Guessed malware by both passes, below the threshold.
    save(Channel::Content, "download.update.example", "info", 0.77);
    save(Channel::Threat, "download.update.example", "threat", 0.77);
    // A threat at the threshold, and one the verifier disputed.
    save(Channel::Threat, "dropper.example", "threat", 0.995);
    save(Channel::Threat, "disputed.example", "disputed", 0.995);
    ai.refresh_snapshot_now();

    let categories = ai.category_snapshot().load();
    assert!(
        !categories.contains_key("download.update.example"),
        "a low-confidence malware guess is not a blockable category"
    );
    assert_eq!(
        categories
            .get("dropper.example")
            .map(|c| c.category.as_str()),
        Some("malware"),
        "a threat at the threshold is, also in train mode"
    );
    assert!(!categories.contains_key("disputed.example"));
    assert!(
        ai.snapshot().load().is_empty(),
        "train mode still auto-blocks nothing"
    );
    drop(categories);

    // The operator's own label stands, whatever the confidence.
    ai.set_category_override("download.update.example", "malware")
        .unwrap();
    assert_eq!(
        ai.category_snapshot()
            .load()
            .get("download.update.example")
            .map(|c| c.category.clone())
            .as_deref(),
        Some("malware")
    );
}

/// An operator relabel wins over the model, survives re-classification and is
/// what the console and category blocking see.
#[test]
fn category_override_relabels_and_survives_rescans() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    ai.store.observe("thing.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Content,
            "thing.example",
            "news",
            "info",
            "classified",
            0.9,
            "fasttext",
            "model said news",
            3600,
        )
        .unwrap();
    ai.refresh_snapshot_now();

    let category_of = |domain: &str| -> Option<String> {
        ai.category_snapshot()
            .load()
            .get(domain)
            .map(|c| c.category.clone())
    };
    assert_eq!(category_of("thing.example").as_deref(), Some("news"));

    ai.set_category_override("thing.example", "gambling")
        .unwrap();
    assert_eq!(category_of("thing.example").as_deref(), Some("gambling"));

    // A later scan overwrites the model's verdict; the operator's label stays.
    ai.store
        .save_verdict(
            Channel::Content,
            "thing.example",
            "news",
            "info",
            "classified",
            0.95,
            "fasttext",
            "model said news again",
            3600,
        )
        .unwrap();
    ai.refresh_snapshot_now();
    assert_eq!(category_of("thing.example").as_deref(), Some("gambling"));

    let (rows, _) = ai.store.list_verdicts(None, None, 10, 0).unwrap();
    let row = rows.iter().find(|r| r.domain == "thing.example").unwrap();
    assert_eq!(row.category, "gambling", "the console shows the relabel");
    assert!(row.category_overridden);

    assert!(ai.clear_category_override("thing.example").unwrap());
    assert_eq!(category_of("thing.example").as_deref(), Some("news"));
    let (rows, _) = ai.store.list_verdicts(None, None, 10, 0).unwrap();
    assert!(
        !rows
            .iter()
            .find(|r| r.domain == "thing.example")
            .unwrap()
            .category_overridden
    );
}

/// The list can show only the domains the operator relabelled, or only the
/// ones still carrying the scanner's label.
#[test]
fn the_verdict_list_filters_on_who_set_the_category() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    for domain in ["mine.example", "scanners.example"] {
        ai.store.observe(domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Content,
                domain,
                "news",
                "info",
                "classified",
                0.9,
                "fasttext",
                "model said news",
                3600,
            )
            .unwrap();
    }
    ai.set_category_override("mine.example", "cloud").unwrap();

    let listed = |label| {
        let (rows, total) = ai
            .store
            .list_verdicts_filtered(
                &daygle_dns_ml::store::VerdictFilter {
                    label,
                    ..Default::default()
                },
                daygle_dns_ml::store::VerdictPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(total as usize, rows.len());
        let mut domains: Vec<String> = rows.into_iter().map(|r| r.domain).collect();
        domains.sort();
        domains
    };
    assert_eq!(listed(Some("set")), ["mine.example"]);
    assert_eq!(listed(Some("scanner")), ["scanners.example"]);
    assert_eq!(listed(None), ["mine.example", "scanners.example"]);

    // Reset: the domain goes back to the scanner's list.
    assert!(ai.clear_category_override("mine.example").unwrap());
    assert!(listed(Some("set")).is_empty());
}

/// A relabel stands on its own: an operator can categorize a domain the model
/// has not classified yet, and that label is blockable straight away.
#[test]
fn relabel_without_a_verdict_is_blockable() {
    let dir = TempDir::new().unwrap();
    let ai = engine(&dir, settings(AiMode::Train));
    ai.set_category_override("untouched.example", "gambling")
        .unwrap();
    ai.refresh_snapshot_now();
    let categories = ai.category_snapshot().load();
    let entry = categories
        .get("untouched.example")
        .expect("relabel published");
    assert_eq!(entry.category, "gambling");
    assert_eq!(entry.expires_at, i64::MAX, "an operator label has no TTL");
}

/// An exemption added through the engine on a *subdomain* of a blocked
/// domain reaches the policy plugin: queries for that subdomain resolve,
/// while the parent stays blocked. (The block snapshot is keyed on the
/// verdict's domain, so this needs the plugin's query-time check.)
#[tokio::test]
async fn subdomain_exemption_reaches_the_policy_plugin() {
    use daygle_dns_policy::{PolicyContext, PolicyPlugin};

    let dir = TempDir::new().unwrap();
    let ai = engine(
        &dir,
        AiSettings {
            auto_block_categories: vec!["malware".to_string()],
            ..settings(AiMode::Enforce)
        },
    );
    ai.store.observe("bad.example.com").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "bad.example.com",
            "malware",
            "threat",
            "classified",
            1.0,
            "test",
            "test",
            3600,
        )
        .unwrap();
    ai.refresh_snapshot_now();
    let plugin = ai.block_plugin();
    let query = |name: &str| PolicyContext {
        client: "192.0.2.1".parse().unwrap(),
        query_name: name.to_string(),
        record_type: "A".to_string(),
        listener: None,
    };
    assert!(plugin
        .evaluate(&query("www.bad.example.com"))
        .await
        .is_some());

    ai.set_allow_override("www.bad.example.com", "Testing")
        .unwrap();
    assert!(plugin
        .evaluate(&query("www.bad.example.com"))
        .await
        .is_none());
    assert!(plugin.evaluate(&query("bad.example.com")).await.is_some());

    ai.clear_override("www.bad.example.com").unwrap();
    assert!(plugin
        .evaluate(&query("www.bad.example.com"))
        .await
        .is_some());
}
