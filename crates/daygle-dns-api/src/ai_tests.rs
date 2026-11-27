//! HTTP-level tests for the AI endpoints: the handlers are exercised through
//! the real router (auth middleware included, explicitly disabled in the
//! test configuration), not called directly.
//!
//! The state is the smallest one the router accepts: an in-memory catalog, no
//! listeners, no web server, and an optional AI engine on a scratch database.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use daygle_dns_authoritative::ZoneStore;
use daygle_dns_core::config::{AiMode, AiSettings, PageRule};
use daygle_dns_core::logs::LogStore;
use daygle_dns_ml::backend::Channel;
use daygle_dns_ml::AiEngine;
use tower::ServiceExt;

use crate::{router, AppState};

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("daygle-ai-http-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn engine(dir: &std::path::Path) -> Arc<AiEngine> {
    let settings = AiSettings {
        enabled: true,
        mode: AiMode::Train,
        database: dir.join("ai.db").to_string_lossy().into_owned(),
        ..Default::default()
    };
    AiEngine::new(
        &settings,
        &dir.join("zones.db").to_string_lossy(),
        Arc::new(ZoneStore::open(":memory:").unwrap()),
        Arc::new(LogStore::new(200)),
    )
    .unwrap()
}

/// [`engine`] with a configured reference model, as a real install has: a
/// retrain only learns the scanner's own verdicts that a fixed reference
/// agrees with, and this one knows the names [`seed_content`] writes.
fn engine_with_reference(dir: &std::path::Path) -> Arc<AiEngine> {
    let mut pairs = Vec::new();
    for i in 0..60 {
        for label in ["news", "shopping", "gambling"] {
            pairs.push((label.to_string(), format!("{label}-ref{i}.example")));
        }
    }
    let reference = dir.join("reference.bin");
    daygle_dns_ml::learn::train(&pairs, &reference).unwrap();
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&reference)
        .unwrap()
        .set_modified(past)
        .unwrap();
    let settings = AiSettings {
        enabled: true,
        mode: AiMode::Train,
        database: dir.join("ai.db").to_string_lossy().into_owned(),
        model_path: reference.to_string_lossy().into_owned(),
        ..Default::default()
    };
    AiEngine::new(
        &settings,
        &dir.join("zones.db").to_string_lossy(),
        Arc::new(ZoneStore::open(":memory:").unwrap()),
        Arc::new(LogStore::new(200)),
    )
    .unwrap()
}

/// Seed one confident content verdict, enough of them to retrain on.
fn seed_content(ai: &AiEngine, i: usize) {
    let labels = ["news", "shopping", "gambling"];
    let label = labels[i % labels.len()];
    let domain = format!("{label}-site{i}.example");
    ai.store.observe(&domain).unwrap();
    ai.store
        .save_verdict(
            Channel::Content,
            &domain,
            labels[i % labels.len()],
            "info",
            "classified",
            0.95,
            "corpus",
            "synthetic",
            3_600,
        )
        .unwrap();
}

async fn call(
    state: AppState,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let response = router(state)
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn json(state: AppState, uri: &str) -> serde_json::Value {
    let (status, _, body) = call(state, "GET", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("{uri} did not return JSON: {e}: {body}"))
}

#[tokio::test]
async fn status_reports_the_page_content_defaults_over_http() {
    let dir = scratch_dir("status");
    let ai = engine(&dir);
    let status = json(AppState::for_tests(Some(ai)), "/api/ai/status").await;
    assert_eq!(status["fetch_pages"], true);
    assert_eq!(status["page_fetch_timeout_secs"], 5);
    assert_eq!(status["page_fetch_max_bytes"], 524_288);
    assert_eq!(status["page_candidates_per_scan"], 16);
    assert_eq!(status["page_rule"], "corroborate");
    assert!(
        (status["page_confidence_floor"].as_f64().unwrap() - 0.6).abs() < 1e-6,
        "{}",
        status["page_confidence_floor"]
    );
    assert_eq!(status["learn_negatives"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn page_content_settings_are_applied_and_clamped() {
    let dir = scratch_dir("settings");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    // Out-of-range values go through the same HTTP path the console uses.
    let (status, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({
            "ai": {
                "fetch_pages": true,
                "page_fetch_timeout_secs": 240,
                "page_fetch_max_bytes": 12,
                "page_candidates_per_scan": 5_000,
                "page_rule": "decide",
                "page_confidence_floor": 0.999
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let applied = ai.settings.load_full();
    assert!(applied.fetch_pages);
    assert_eq!(
        applied.page_fetch_timeout_secs, 30,
        "clamped to its maximum"
    );
    assert_eq!(
        applied.page_fetch_max_bytes,
        16 * 1024,
        "clamped to its floor"
    );
    assert_eq!(applied.page_candidates_per_scan, 64);
    assert_eq!(applied.page_rule, daygle_dns_core::config::PageRule::Decide);
    assert!(
        (applied.page_confidence_floor - 0.99).abs() < 1e-6,
        "clamped to its maximum: {}",
        applied.page_confidence_floor
    );
    drop(applied);

    // And the status endpoint reports what the engine now runs with.
    let reported = json(state, "/api/ai/status").await;
    assert_eq!(reported["fetch_pages"], true);
    assert_eq!(reported["page_fetch_timeout_secs"], 30);
    assert_eq!(reported["page_fetch_max_bytes"], 16_384);
    assert_eq!(reported["page_candidates_per_scan"], 64);
    assert_eq!(reported["page_rule"], "decide");
    assert!(
        (reported["page_confidence_floor"].as_f64().unwrap() - 0.99).abs() < 1e-6,
        "{}",
        reported["page_confidence_floor"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn threat_export_and_corrections_are_served_as_csv() {
    let dir = scratch_dir("export");
    let ai = engine(&dir);
    ai.store.observe("evil.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "evil.example",
            "phishing",
            "threat",
            "classified",
            1.0,
            "fasttext",
            "looks like a login page",
            3_600,
        )
        .unwrap();
    ai.set_category_override("shopping.example", "shopping")
        .unwrap();

    // A second verdict whose category starts with a formula character: the
    // CSV must guard it, not hand a spreadsheet a formula.
    ai.store.observe("formula.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "formula.example",
            "=cmd|' /C calc'!A0",
            "threat",
            "classified",
            1.0,
            "fasttext",
            "synthetic",
            3_600,
        )
        .unwrap();

    // The export is what blocks, so the hostile label has to be one the
    // scanner treats as a threat for the row to reach the CSV at all.
    let mut cfg = (*ai.settings.load_full()).clone();
    cfg.auto_block_categories
        .push("=cmd|' /C calc'!A0".to_string());
    ai.settings.store(std::sync::Arc::new(cfg));

    let state = AppState::for_tests(Some(ai.clone()));
    let (status, headers, body) = call(
        state.clone(),
        "GET",
        "/api/ai/threats/export?format=csv",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/csv; charset=utf-8"
    );
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], "domain,category,confidence,expires_at", "{body}");
    assert_eq!(lines.len(), 3, "header plus two rows: {body}");
    let row = lines
        .iter()
        .find(|line| line.starts_with("evil.example,"))
        .unwrap_or_else(|| panic!("evil.example missing: {body}"));
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(fields.len(), 4, "{row}");
    assert_eq!(fields[1], "phishing");
    assert_eq!(fields[2], "1.000", "confidence keeps three decimals");
    assert!(
        fields[3].contains('T') && (fields[3].ends_with("+00:00") || fields[3].ends_with('Z')),
        "expiry is an RFC 3339 timestamp: {}",
        fields[3]
    );
    assert!(
        !body
            .lines()
            .any(|line| line.starts_with("formula.example,=")),
        "a formula-shaped category must not sit unguarded at the start of a field: {body}"
    );
    assert!(body.contains("'=cmd"), "{body}");

    let (status, _, body) = call(
        state.clone(),
        "GET",
        "/api/ai/threats/export?format=list",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<&str> = body.lines().collect();
    assert_eq!(listed, vec!["evil.example", "formula.example"]);

    let (status, headers, body) =
        call(state.clone(), "GET", "/api/ai/corrections?format=csv", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/csv; charset=utf-8"
    );
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines[0], "domain,action,category,reason,created_at",
        "{body}"
    );
    let row = lines
        .iter()
        .find(|line| line.starts_with("shopping.example,"))
        .unwrap_or_else(|| panic!("shopping.example missing: {body}"));
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(fields.len(), 5, "{row}");
    assert_eq!(fields[1], "category");
    assert_eq!(fields[2], "shopping");
    assert_eq!(fields[3], "", "a relabel carries no reason");
    assert!(fields[4].contains('T'), "{}", fields[4]);

    // A verdict the page rule capped: the explain endpoint reports the
    // decision and the confidence it started from.
    ai.store.observe("capped.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "capped.example",
            "phishing",
            "threat",
            "classified",
            0.995,
            "fasttext",
            "ev",
            3_600,
        )
        .unwrap();
    ai.store
        .record_page_reading(
            "capped.example",
            "page reads shopping (80%)",
            Some(0.2),
            Some(&daygle_dns_ml::page::TextVerdict {
                category: "shopping",
                confidence: 0.8,
                cues: vec!["add to cart"],
                also: vec![],
            }),
        )
        .unwrap();
    ai.store
        .record_page_adjustment("capped.example", PageRule::Decide, 0.995, 0.2)
        .unwrap();

    let explained = json(state.clone(), "/api/ai/explain?domain=evil.example").await;
    assert_eq!(explained["domain"], "evil.example");
    assert_eq!(explained["threat"]["category"], "phishing");
    assert_eq!(explained["threat"]["over_threshold"], true);
    assert!(
        explained["page_adjustment"].is_null(),
        "an untouched verdict has no page decision to report: {explained}"
    );
    assert!(
        explained["page_reading"].is_null(),
        "an unread page has no reading to report: {explained}"
    );

    let capped = json(state, "/api/ai/explain?domain=capped.example").await;
    assert_eq!(capped["page_adjustment"]["rule"], "decide");
    assert!(
        (capped["page_adjustment"]["prior_confidence"]
            .as_f64()
            .unwrap()
            - 0.995)
            .abs()
            < 1e-3,
        "{}",
        capped["page_adjustment"]
    );
    assert!(
        (capped["page_adjustment"]["confidence"].as_f64().unwrap() - 0.2).abs() < 1e-3,
        "{}",
        capped["page_adjustment"]
    );
    assert_eq!(capped["threat"]["over_threshold"], false);
    assert!(
        capped["reasons"].as_array().unwrap().iter().any(|r| r
            .as_str()
            .unwrap_or_default()
            .contains("gate score, 20%, is below")),
        "the below-threshold reason compares the gate score, not the confidence: {capped}"
    );
    assert_eq!(capped["page_reading"]["category"], "shopping");
    assert!(
        (capped["page_reading"]["confidence"].as_f64().unwrap() - 0.8).abs() < 1e-3,
        "{}",
        capped["page_reading"]
    );
    assert_eq!(capped["page_reading"]["cues"][0], "add to cart");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn model_health_reports_whether_a_probe_was_possible() {
    let dir = scratch_dir("model-health");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai));

    let health = json(state.clone(), "/api/ai/model-health").await;
    assert!(health["available"].is_boolean(), "{health}");
    assert!(health["model"].is_string(), "{health}");
    if health["available"] == true {
        assert!(
            health["lost"].as_u64().unwrap() <= health["checked"].as_u64().unwrap(),
            "{health}"
        );
        assert!(
            !health["sample"].as_array().unwrap().is_empty(),
            "an available probe pins its names: {health}"
        );
    } else {
        assert!(health["reason"].is_string(), "{health}");
    }

    // A pinned probe round-trips: the same body can be posted back, and a
    // unavailable model still answers 200 so the update step can skip gating.
    let sample = health["sample"].clone();
    let pinned = if sample.is_array() {
        sample
    } else {
        serde_json::json!([{"label": "phishing", "domain": "pinned.example"}])
    };
    let (status, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/model-health",
        Some(serde_json::json!({ "sample": pinned })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let probed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(probed["available"].is_boolean(), "{probed}");

    let (status, _, _) = call(
        state,
        "POST",
        "/api/ai/model-health",
        Some(serde_json::json!({ "sample": [] })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an empty sample is refused"
    );

    // Disabled AI is a 200 with nothing to probe, not a 404.
    let (status, _, body) = call(
        AppState::for_tests(None),
        "GET",
        "/api/ai/model-health",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let disabled: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(disabled["available"], false, "{disabled}");
    assert!(disabled["reason"].is_string(), "{disabled}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn retrain_and_rollback_explain_what_they_cannot_do() {
    let dir = scratch_dir("limits");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));

    // Fewer than MIN_EXAMPLES: the retrain refuses rather than training on
    // nothing, and says so through the API.
    let (status, _, body) = call(state.clone(), "POST", "/api/ai/retrain", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("200"), "{body}");

    // No retrain has happened, so there is nothing to restore.
    let (status, _, body) = call(state, "POST", "/api/ai/rollback", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("no previous model"), "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn retrain_and_rollback_succeed_over_http() {
    let dir = scratch_dir("retrain");
    let ai = engine_with_reference(&dir);
    for i in 0..240 {
        seed_content(&ai, i);
    }
    let state = AppState::for_tests(Some(ai.clone()));
    let (status, _, body) = call(state.clone(), "POST", "/api/ai/retrain", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let retrained: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(retrained["verdicts"], 240, "{body}");
    assert!(
        retrained["starter"].as_u64().unwrap() > 0,
        "the starter corpus rides along: {body}"
    );
    assert_eq!(retrained["active"], true);
    // No corrections were held back, and the response says so.
    assert_eq!(retrained["validation_examples"], 0, "{body}");
    assert!(
        retrained["message"]
            .as_str()
            .unwrap()
            .contains("only checked"),
        "{body}"
    );

    // A second retrain replaces the first, which is what a rollback restores.
    for i in 240..243 {
        seed_content(state.ai.as_ref().unwrap(), i);
    }
    let (status, _, body) = call(state.clone(), "POST", "/api/ai/retrain", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let status_body = json(state.clone(), "/api/ai/status").await;
    assert_eq!(status_body["learned_model"]["previous"], true);
    assert_eq!(status_body["learned_model"]["last"]["verdicts"], 243);

    let (status, _, body) = call(state.clone(), "POST", "/api/ai/rollback", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("previous model is in use"), "{body}");
    let status_body = json(state, "/api/ai/status").await;
    assert_eq!(
        status_body["learned_model"]["last"]["verdicts"], 240,
        "the restored model's record comes back with it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ai_endpoints_say_so_when_the_engine_is_disabled() {
    let state = AppState::for_tests(None);
    for uri in [
        "/api/ai/status",
        "/api/ai/threats",
        "/api/ai/threats/export",
        "/api/ai/corrections",
        "/api/ai/explain?domain=example.com",
    ] {
        let (status, _, body) = call(state.clone(), "GET", uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
        assert!(body.contains("AI subsystem is disabled"), "{uri}: {body}");
    }
}

#[tokio::test]
async fn status_reports_trials_and_retrain_takes_a_model() {
    let dir = scratch_dir("trials");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let status = json(state.clone(), "/api/ai/status").await;
    assert_eq!(status["trial_new_models"], true, "{status}");
    assert!(
        status["learned_model"]["trial"]["history"].is_array(),
        "{status}"
    );
    assert_eq!(status["learned_model"]["candidate"], false, "{status}");
    assert_eq!(status["verifier_enabled"], false, "{status}");
    assert_eq!(
        status["verifier_supported"],
        daygle_dns_ml::VERIFIER_SUPPORTED,
        "{status}"
    );
    assert_eq!(status["verifier_running"], false, "switched off: {status}");
    if !daygle_dns_ml::VERIFIER_SUPPORTED {
        let (code, _, body) = call(
            state.clone(),
            "PUT",
            "/api/config",
            Some(serde_json::json!({ "ai": { "verifier_enabled": true } })),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("no ONNX support"), "{body}");
    } else if status["verifier_installed"] == false {
        // Nothing to switch on: refused, and nothing stored.
        let (code, _, body) = call(
            state.clone(),
            "PUT",
            "/api/config",
            Some(serde_json::json!({ "ai": { "verifier_enabled": true } })),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("not installed"), "{body}");
    }

    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The console's threat list follows the labels treated as threats: a label
/// the operator unticked leaves the list at once, without a rescan, and one
/// they tick brings back the verdict rows already stored for it.
#[tokio::test]
async fn threat_list_follows_the_labels_treated_as_threats() {
    let dir = scratch_dir("threat-labels");
    let ai = engine(&dir);
    let mut cfg = (*ai.settings.load_full()).clone();
    // The list narrows the built-in families: phishing is turned off for now,
    // so only malware counts as a threat.
    cfg.auto_block_categories = vec!["malware".to_string()];
    cfg.auto_block_removals = vec!["phishing".to_string(), "scam".to_string()];
    ai.settings.store(Arc::new(cfg));
    for (domain, label) in [
        ("bad.example", "malware"),
        ("ads.example", "ads"),
        ("phish.example", "phishing"),
    ] {
        ai.store.observe(domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Threat,
                domain,
                label,
                "threat",
                "classified",
                0.99,
                "fasttext",
                "synthetic",
                3_600,
            )
            .unwrap();
    }
    let state = AppState::for_tests(Some(ai.clone()));

    // Only the label still in effect is a detected threat.
    let listed = json(state.clone(), "/api/ai/threats").await;
    assert_eq!(listed["total"], 1, "{listed}");
    assert_eq!(listed["entries"][0]["domain"], "bad.example", "{listed}");
    // The three outputs are reported apart: the label's role, the
    // classification (no content verdict here, so none) and what DNS does
    // about the domain - train mode keeps it monitored, never blocked.
    assert_eq!(listed["entries"][0]["label_role"], "threat", "{listed}");
    assert_eq!(listed["entries"][0]["decision"], "monitor", "{listed}");
    assert_eq!(
        listed["entries"][0]["classification"],
        serde_json::Value::Null,
        "{listed}"
    );

    // Ticking the other two labels through the console's settings update
    // shows the rows already stored under them.
    let (status, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({
            "ai": { "auto_block_categories": ["malware", "ads", "phishing"] }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = json(state.clone(), "/api/ai/threats").await;
    assert_eq!(listed["total"], 3, "every ticked label is listed: {listed}");
    // A list that leaves a built-in family out records it as removed.
    let status = json(state.clone(), "/api/ai/status").await;
    assert_eq!(
        status["auto_block_removals"],
        serde_json::json!(["scam"]),
        "{status}"
    );
    assert_eq!(
        status["threat_labels"],
        serde_json::json!(["malware", "phishing", "ads"]),
        "{status}"
    );

    // Untick them again: their rows and their stored verdicts go at once.
    let (status, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({
            "ai": { "auto_block_categories": ["malware"] }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = json(state.clone(), "/api/ai/threats").await;
    assert_eq!(listed["total"], 1, "{listed}");
    assert_eq!(
        listed["entries"][0]["domain"], "bad.example",
        "the unticked labels' rows are gone: {listed}"
    );
    // Sending the list alone records the families it no longer names as
    // removals, so the saved config keeps them off.
    let status = json(state.clone(), "/api/ai/status").await;
    assert_eq!(
        status["auto_block_removals"],
        serde_json::json!(["phishing", "scam"]),
        "{status}"
    );
    assert_eq!(
        status["threat_labels"],
        serde_json::json!(["malware"]),
        "{status}"
    );

    // Unticking is a decision to forget: the verdicts are deleted, so a later
    // re-tick cannot resurrect them.
    let verdicts = json(state.clone(), "/api/ai/verdicts?channel=threat").await;
    let kept: Vec<&str> = verdicts["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["domain"].as_str())
        .collect();
    assert!(
        !kept.contains(&"ads.example") && !kept.contains(&"phish.example"),
        "the unticked labels' verdicts are deleted: {verdicts}"
    );
    assert!(kept.contains(&"bad.example"), "{verdicts}");

    // No label is a threat at all: nothing is listed, and the last stored
    // verdict goes with the label.
    let (status, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({ "ai": { "auto_block_categories": [] } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = json(state, "/api/ai/threats").await;
    assert_eq!(listed["total"], 0, "{listed}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Declaring a label a threat re-queues the domains that already carry it, so
/// the next scan reports them instead of leaving them out until their TTL.
#[tokio::test]
async fn declaring_a_threat_label_requeues_its_domains() {
    let dir = scratch_dir("threat-requeue");
    let ai = engine(&dir);
    ai.store.observe("ads.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Content,
            "ads.example",
            "ads",
            "info",
            "classified",
            0.9,
            "fasttext",
            "ad network",
            3_600,
        )
        .unwrap();
    // Classified while `ads` was an ordinary category: the threat channel had
    // nothing to report, so the row says so and carries no label.
    ai.store
        .save_verdict(
            Channel::Threat,
            "ads.example",
            "",
            "",
            "skipped",
            0.0,
            "fasttext",
            "no signal",
            3_600,
        )
        .unwrap();
    let state = AppState::for_tests(Some(ai.clone()));

    let (status, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({
            "ai": { "auto_block_categories": ["malware", "phishing", "scam", "ads"] }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let verdicts = json(state, "/api/ai/verdicts?channel=threat").await;
    let row = verdicts["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["domain"] == "ads.example")
        .unwrap_or_else(|| panic!("the threat row is still stored: {verdicts}"));
    assert_eq!(
        row["status"], "pending",
        "the domain is due a fresh threat verdict: {verdicts}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The console warns before saving a label list that drops one: the status it
/// already loads carries the stored threat verdicts per label.
#[tokio::test]
async fn status_reports_stored_threat_verdicts_by_label() {
    let dir = scratch_dir("threat-counts");
    let ai = engine(&dir);
    for (domain, label) in [
        ("ads-one.example", "ads"),
        ("ads-two.example", "ads"),
        ("phish.example", "phishing"),
    ] {
        ai.store.observe(domain).unwrap();
        ai.store
            .save_verdict(
                Channel::Threat,
                domain,
                label,
                "threat",
                "classified",
                0.99,
                "fasttext",
                "ev",
                3_600,
            )
            .unwrap();
        // Categorizations are not threat verdicts and are not counted.
        ai.store
            .save_verdict(
                Channel::Content,
                domain,
                "news",
                "info",
                "classified",
                0.9,
                "fasttext",
                "ev",
                3_600,
            )
            .unwrap();
    }
    let status = json(AppState::for_tests(Some(ai)), "/api/ai/status").await;
    assert_eq!(status["threat_counts"]["ads"], 2, "{status}");
    assert_eq!(status["threat_counts"]["phishing"], 1, "{status}");
    assert_eq!(
        status["threat_counts"]["news"],
        serde_json::Value::Null,
        "content labels are not threat verdicts: {status}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn outside_evidence_settings_round_trip_over_http() {
    let dir = scratch_dir("evidence");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let status = json(state.clone(), "/api/ai/status").await;
    assert_eq!(status["threat_feeds"], true, "on by default");
    assert_eq!(status["network_evidence"], true, "on by default");
    assert_eq!(status["domain_age"], true, "on by default");
    assert!(
        status["threat_feed_status"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["label"] == "popular"),
        "the popular-sites list is listed too"
    );
    assert!(status["learned_model"]["watch"].is_null());
    let feeds = status["threat_feed_status"].as_array().unwrap();
    assert!(
        feeds.iter().any(|f| f["label"] == "phishing"),
        "every feed is listed before its first download: {feeds:?}"
    );
    assert_eq!(status["page_model"]["active"], false);

    let (code, _, body) = call(state.clone(), "POST", "/api/ai/threat-feeds/update", None).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert!(body.contains("\"requested\":true"), "{body}");

    let (code, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({
            "ai": { "threat_feeds": false, "network_evidence": false, "domain_age": false }
        })),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let applied = ai.settings.load_full();
    assert!(!applied.threat_feeds && !applied.network_evidence && !applied.domain_age);
    let reported = json(state.clone(), "/api/ai/status").await;
    assert_eq!(reported["threat_feeds"], false);
    assert_eq!(reported["network_evidence"], false);
    let (code, _, body) = call(state, "POST", "/api/ai/threat-feeds/update", None).await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "nothing to update while off: {body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn explain_reports_outside_evidence() {
    let dir = scratch_dir("explain-evidence");
    let ai = engine(&dir);
    let start = chrono::Utc::now().timestamp() - 30 * 86_400;
    let clients: Vec<String> = (0..4).map(|i| format!("10.0.0.{i}")).collect();
    for day in 0..15 {
        ai.store
            .record_sightings_at(
                &[("update.vendor.example".to_string(), clients.clone())],
                start + day * 86_400,
            )
            .unwrap();
    }
    ai.store.observe("update.vendor.example").unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            "update.vendor.example",
            "malware",
            "disputed",
            "classified",
            0.995,
            "fasttext",
            "keyword, established on this network (looked up on 15 days by 4+ clients): disputed",
            3_600,
        )
        .unwrap();
    let state = AppState::for_tests(Some(ai));
    let explained = json(
        state.clone(),
        "/api/ai/explain?domain=update.vendor.example",
    )
    .await;
    assert_eq!(explained["sighting"]["days"], 15, "{explained}");
    assert_eq!(explained["sighting"]["clients"], 4);
    assert_eq!(explained["sighting"]["established"], true);
    assert!(explained["threat_feed"].is_null());
    let reasons = explained["reasons"].to_string();
    assert!(reasons.contains("used it for weeks"), "{reasons}");
    assert!(
        reasons.contains("at 99.5%"),
        "never rounded up to 100%: {reasons}"
    );

    let unseen = json(state, "/api/ai/explain?domain=never.example").await;
    assert!(unseen["sighting"].is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_language_model_status_reports_an_unreachable_server() {
    let dir = scratch_dir("llm-status");
    let ai = engine(&dir);
    let mut settings = (*ai.settings.load_full()).clone();
    // A port nothing listens on.
    settings.llm_url = "http://127.0.0.1:9".to_string();
    ai.apply_settings(&settings);
    let status = json(AppState::for_tests(Some(ai)), "/api/ai/llm").await;
    assert_eq!(status["reachable"], false);
    assert_eq!(status["enabled"], false);
    assert_eq!(status["model"], "qwen2.5:1.5b");
    assert!(status["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert_eq!(status["service"]["local"], true);
    assert!(status["suggested_models"]
        .as_array()
        .is_some_and(|s| !s.is_empty()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A test is given at least five minutes even when the per-answer limit is
/// shorter, because its first answer also loads the model. The status says
/// which limit it will use, so the raise is visible instead of silent.
#[tokio::test]
async fn the_test_limit_is_raised_and_reported() {
    let dir = scratch_dir("llm-test-timeout");
    let ai = engine(&dir);
    let mut settings = (*ai.settings.load_full()).clone();
    settings.llm_url = "http://127.0.0.1:9".to_string();
    settings.llm_timeout_secs = 60;
    ai.apply_settings(&settings);
    let state = AppState::for_tests(Some(ai.clone()));
    let status = json(state.clone(), "/api/ai/llm").await;
    assert_eq!(
        status["timeout_secs"], 60,
        "the per-answer limit is unchanged"
    );
    assert_eq!(status["test_timeout_secs"], 300, "raised for a test");

    // A limit already above the floor is used as it is.
    settings.llm_timeout_secs = 450;
    ai.apply_settings(&settings);
    let status = json(state, "/api/ai/llm").await;
    assert_eq!(status["test_timeout_secs"], 450);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn language_model_requests_are_validated() {
    let dir = scratch_dir("llm-validate");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    for bad in ["", "../../etc/passwd", "qwen; rm -rf /", "-flag"] {
        let (code, _, body) = call(
            state.clone(),
            "POST",
            "/api/ai/llm/pull",
            Some(serde_json::json!({ "model": bad })),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let (code, _, _) = call(
        state.clone(),
        "POST",
        "/api/ai/llm/service",
        Some(serde_json::json!({ "action": "reboot" })),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    // A server on another machine is managed where it runs.
    let mut settings = (*ai.settings.load_full()).clone();
    settings.llm_url = "http://10.0.0.5:11434".to_string();
    ai.apply_settings(&settings);
    let (code, _, body) = call(
        state,
        "POST",
        "/api/ai/llm/service",
        Some(serde_json::json!({ "action": "install" })),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn threshold_trials_are_recorded_and_never_apply_themselves() {
    let dir = scratch_dir("threshold-http");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let base = ai.settings.load_full().block_threshold;

    let before = json(state.clone(), "/api/ai/threshold").await;
    assert!((before["block_threshold"].as_f64().unwrap() - base as f64).abs() < 1e-6);
    assert!((before["fpr_target"].as_f64().unwrap() - 0.01).abs() < 1e-6);
    assert!(before["in_force"].is_null());
    assert!(before["trials"].as_array().unwrap().is_empty());

    // No scored threats on a fresh store: the trial is still recorded, and
    // says why it chose nothing.
    let (code, _, body) = call(state.clone(), "POST", "/api/ai/threshold/trial", None).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let trial: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(trial["trial"]["passed"], false);
    assert_eq!(trial["trial"]["in_force"], false);
    assert!(trial["message"].as_str().is_some_and(|m| !m.is_empty()));
    let id = trial["trial"]["id"].as_i64().unwrap();

    // Recording it changed nothing.
    let after = json(state.clone(), "/api/ai/threshold").await;
    assert!(after["in_force"].is_null());
    assert_eq!(after["trials"][0]["id"], id);
    assert!((after["block_threshold"].as_f64().unwrap() - base as f64).abs() < 1e-6);

    let apply = serde_json::json!({ "id": id });
    let (code, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/apply",
        Some(apply),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
    let (code, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/apply",
        Some(serde_json::json!({ "id": id + 99 })),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND, "{body}");
    let (code, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/rollback",
        Some(serde_json::json!({ "id": id })),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "{body}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn applying_a_trial_records_the_live_model_and_rollback_reports_it() {
    let dir = scratch_dir("threshold-model");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    // A store with no evidence cannot produce a passing trial itself, so the
    // candidate is recorded directly; the HTTP paths are what this checks.
    let trial = ai
        .store
        .save_threshold_trial(&daygle_dns_ml::store::NewThresholdTrial {
            model: "builtin".to_string(),
            base_threshold: 0.99,
            candidate: 0.96,
            fpr_target: 0.01,
            passed: true,
            report: "{}".to_string(),
        })
        .unwrap();
    let live = daygle_dns_ml::threshold::model_version(&ai.live_model_path());

    let (code, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/apply",
        Some(serde_json::json!({ "id": trial.id })),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let applied = ai.store.threshold_trial(trial.id).unwrap().unwrap();
    assert!(applied.in_force());
    assert_eq!(applied.applied_model, live);
    assert!((applied.base_threshold - 0.99).abs() < 1e-6);

    // The list names the model the candidate actually went live with, next to
    // the one the trial was measured against.
    let listed = json(state.clone(), "/api/ai/threshold").await;
    assert_eq!(
        listed["in_force"]["applied_model"].as_str(),
        Some(live.as_str())
    );

    let (code, _, body) = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/rollback",
        Some(serde_json::json!({ "id": trial.id })),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let rolled: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!((rolled["block_threshold"].as_f64().unwrap() - 0.99).abs() < 1e-6);
    assert_eq!(rolled["model"].as_str(), Some(live.as_str()));
    assert_eq!(rolled["live_model"].as_str(), Some(live.as_str()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn autonomy_and_the_false_positive_target_round_trip() {
    let dir = scratch_dir("threshold-settings");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let (code, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({ "ai": {
            "autonomy": false,
            "threshold_fpr_target": 9.0
        }})),
    )
    .await;
    assert!(code.is_success(), "{body}");
    let applied = ai.settings.load_full();
    assert!(!applied.autonomy);
    assert!((applied.threshold_fpr_target - 0.5).abs() < 1e-6);
    let status = json(state, "/api/ai/status").await;
    assert_eq!(status["autonomy"], false);
    assert!((status["threshold_fpr_target"].as_f64().unwrap() - 0.5).abs() < 1e-6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn language_model_settings_are_saved_and_bad_ones_refused() {
    let dir = scratch_dir("llm-settings");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let (code, _, body) = call(
        state.clone(),
        "PUT",
        "/api/config",
        Some(serde_json::json!({ "ai": {
            "llm_enabled": true,
            "llm_url": "http://127.0.0.1:11434/",
            "llm_model": "llama3.2:3b",
            "llm_candidates_per_scan": 500
        }})),
    )
    .await;
    assert!(code.is_success(), "{body}");
    let applied = ai.settings.load_full();
    assert!(applied.llm_enabled);
    assert_eq!(applied.llm_url, "http://127.0.0.1:11434");
    assert_eq!(applied.llm_model, "llama3.2:3b");
    assert_eq!(applied.llm_candidates_per_scan, 32);
    let (code, _, body) = call(
        state,
        "PUT",
        "/api/config",
        Some(serde_json::json!({ "ai": { "llm_url": "file:///etc/passwd" } })),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn signals_report_every_structured_observation_behind_a_verdict() {
    let dir = scratch_dir("signals");
    let ai = engine(&dir);
    ai.store.observe("bad-signal.example").unwrap();
    ai.store
        .save_verdicts(&[daygle_dns_ml::store::NewVerdict {
            domain: "bad-signal.example".to_string(),
            channel: Channel::Threat,
            category: "phishing".to_string(),
            severity: "threat".to_string(),
            status: "classified".to_string(),
            confidence: 0.97,
            backend: "fasttext".to_string(),
            evidence: "model, phishing at 0.97".to_string(),
            threat_score: 0.97,
            expires_after_secs: 3_600,
        }])
        .unwrap();
    let state = AppState::for_tests(Some(ai));

    let report = json(state.clone(), "/api/ai/signals?domain=bad-signal.example").await;
    let sources: Vec<&str> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .map(|row| row["source"].as_str().unwrap())
        .collect();
    assert_eq!(
        sources,
        vec![
            "model",
            "verifier",
            "feed",
            "popularity",
            "network_history",
            "domain_age",
            "hostname",
            "page",
            "llm"
        ]
    );
    assert_eq!(report["observations"][0]["direction"], "threat");
    assert_eq!(report["observations"][0]["scope"]["kind"], "hostname");
    assert_eq!(
        report["observations"][2]["scope"]["kind"],
        "registered_domain"
    );
    assert_eq!(report["observations"][0]["family"], "name_model");
    assert!(report["observations"][0]["observed_at"].as_i64().unwrap() > 0);
    // Fusion is reported; with no calibration map the calibrated score is null
    // and the gate keeps comparing the confidence.
    assert!(report["fusion"]["score"].is_f64());
    assert!(report["calibrated"].is_null());

    let missing = call(
        state,
        "GET",
        "/api/ai/signals?domain=never-seen.example",
        None,
    )
    .await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND, "{}", missing.2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn calibration_is_identity_until_a_map_is_fitted_and_promoted() {
    let dir = scratch_dir("calibration");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai));

    let status = json(state.clone(), "/api/ai/calibration").await;
    assert_eq!(status["calibration_active"], false);
    assert!(status["active"].is_null());
    assert!(status["note"]
        .as_str()
        .unwrap()
        .contains("not a calibrated probability"));

    // No labelled verdicts yet: fitting explains why nothing was fitted.
    let fitted = call(state.clone(), "POST", "/api/ai/calibration/fit", None).await;
    assert!(fitted.0.is_success(), "{}", fitted.2);
    let body: serde_json::Value = serde_json::from_str(&fitted.2).unwrap();
    assert_eq!(body["fitted"], false);
    assert_eq!(body["accepted"], false);
    assert!(body["reason"].as_str().unwrap().contains("not enough"));

    // Applying a version that does not exist is a 404.
    let applied = call(
        state,
        "POST",
        "/api/ai/calibration/apply",
        Some(serde_json::json!({"version": "cal-missing"})),
    )
    .await;
    assert_eq!(applied.0, StatusCode::NOT_FOUND, "{}", applied.2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_candidate_is_snapshotted_promoted_and_restored_as_one_version() {
    let dir = scratch_dir("candidates");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai));

    let status = json(state.clone(), "/api/ai/status").await;
    assert_eq!(status["fusion"], "monitor");
    assert_eq!(status["calibrated"], false);
    assert_eq!(status["authority"]["enabled"], false);

    let created = call(state.clone(), "POST", "/api/ai/candidates/snapshot", None).await;
    assert!(created.0.is_success(), "{}", created.2);
    let created: serde_json::Value = serde_json::from_str(&created.2).unwrap();
    let id = created["candidate"]["id"].as_i64().expect("a candidate id");
    let version = created["candidate"]["version"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(created["candidate"]["status"], "candidate");
    assert!(created["candidate"]["block_threshold"].as_f64().is_some());
    assert!(created["candidate"]["signal_weights"]["model"]
        .as_f64()
        .is_some());

    let listed = json(state.clone(), "/api/ai/candidates").await;
    assert!(listed["active"].is_null());
    assert_eq!(listed["candidates"][0]["version"], version);

    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({"id": id})),
    )
    .await;
    assert!(promoted.0.is_success(), "{}", promoted.2);
    let listed = json(state.clone(), "/api/ai/candidates").await;
    assert_eq!(listed["active"]["version"], version.as_str());

    // The first version replaced nothing, so there is nothing to restore.
    let rolled = call(state.clone(), "POST", "/api/ai/candidates/rollback", None).await;
    assert_eq!(rolled.0, StatusCode::CONFLICT, "{}", rolled.2);
    let _ = std::fs::remove_dir_all(&dir);
}
// ---- The configuration boundary of a candidate version -------------------
//
// A candidate version is only in force once its threshold is published through
// the config path, and that step happens after the engine has committed the
// promotion. These tests fail the publication (an invalid stored overlay or a
// re-score that cannot be written) and then check that the version, its
// artifact, the loaded model, the threshold, the persisted overlay and the
// threshold-trial bookkeeping all agree again.

/// A candidate version recorded straight in the store: `bytes` are kept as its
/// artifact at `path` (the engine's live model path), so a promotion moves the
/// version into force exactly as a snapshot would.
fn candidate_version(
    ai: &AiEngine,
    version: &str,
    path: &str,
    bytes: &[u8],
    threshold: f32,
    scoring_config: serde_json::Value,
) -> i64 {
    let sha = ai.store.store_model_artifact(path, bytes).unwrap();
    ai.store
        .save_candidate(&daygle_dns_ml::store::NewCandidate {
            version: version.to_string(),
            model_path: path.to_string(),
            model_sha256: sha,
            model_size: bytes.len() as i64,
            block_threshold: threshold,
            calibration: None,
            signal_weights: Default::default(),
            scoring_config,
            validation_report: serde_json::Value::Null,
            metrics: None,
        })
        .unwrap()
        .id
}

/// The block threshold a restart would configure: the AI overlay persisted in
/// the catalog, which is what the next boot applies.
fn overlay_threshold(state: &AppState) -> Option<f32> {
    state
        .catalog
        .store()
        .get_named_setting::<daygle_dns_core::config::RuntimeSettings>("runtime")
        .unwrap()
        .and_then(|settings| settings.ai)
        .and_then(|ai| ai.block_threshold)
}

/// Make every re-score that would write `mode` into a stored verdict fail at the
/// persistence boundary: the mode column is written by a re-score and by nothing
/// else, so a verdict already re-scored under another mode stays writable.
fn fail_rescore_for(dir: &std::path::Path, mode: &str) {
    let conn = rusqlite::Connection::open(dir.join("ai.db")).unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER injected_rescore_failure BEFORE UPDATE OF assessment_mode ON ai_verdicts
         WHEN NEW.assessment_mode = '{mode}'
         BEGIN SELECT RAISE(ABORT, 'injected re-score failure'); END;"
    ))
    .unwrap();
}

/// One confident threat verdict, so a re-score has a row to write.
fn seed_threat(ai: &AiEngine, domain: &str) {
    ai.store.observe(domain).unwrap();
    ai.store
        .save_verdict(
            Channel::Threat,
            domain,
            "phishing",
            "threat",
            "classified",
            0.97,
            "fasttext",
            "model, phishing at 0.97",
            3_600,
        )
        .unwrap();
}

#[tokio::test]
async fn a_first_promotion_whose_config_cannot_be_published_is_undone() {
    let dir = scratch_dir("first-promotion-publish");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let live = ai.live_model_path();
    assert_eq!(state.config.load_full().ai.block_threshold, 0.99);

    // The built-in model has no artifact to displace, so what this path has to
    // put back is the version itself, its calibration, weights and the
    // threshold configuration. The artifact bytes a first promotion displaces
    // are covered by the engine's own integration test, which can install a
    // deliberately broken model.
    let bytes = std::fs::read(&live).unwrap_or_default();
    let id = candidate_version(
        &ai,
        "broken-config",
        &live,
        &bytes,
        0.97,
        serde_json::json!({ "workers": 0 }),
    );

    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": id })),
    )
    .await;
    assert_eq!(promoted.0, StatusCode::BAD_REQUEST, "{}", promoted.2);

    // No version in force, the candidate is a candidate again, and the file the
    // next start reads and the model the channels run are the configured ones.
    assert!(ai.store.active_candidate().unwrap().is_none());
    assert_eq!(ai.store.candidate(id).unwrap().unwrap().status, "candidate");
    assert_eq!(ai.live_model_path(), live, "the configured model is loaded");
    // The threshold and the persisted overlay never moved.
    assert_eq!(state.config.load_full().ai.block_threshold, 0.99);
    assert_eq!(ai.settings.load_full().block_threshold, 0.99);
    assert_eq!(overlay_threshold(&state), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_promotion_whose_config_cannot_be_published_keeps_the_previous_version() {
    let dir = scratch_dir("promotion-publish");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let live = ai.live_model_path();
    let bytes = std::fs::read(&live).unwrap_or_default();
    let first = candidate_version(&ai, "first", &live, &bytes, 0.95, serde_json::json!({}));
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": first })),
    )
    .await;
    assert!(promoted.0.is_success(), "{}", promoted.2);
    assert_eq!(overlay_threshold(&state), Some(0.95));

    let second = candidate_version(
        &ai,
        "bad-config",
        &live,
        &bytes,
        0.90,
        serde_json::json!({ "category_ttl_secs": 1 }),
    );
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": second })),
    )
    .await;
    assert_eq!(promoted.0, StatusCode::BAD_REQUEST, "{}", promoted.2);

    let active = ai.store.active_candidate().unwrap().unwrap();
    assert_eq!(
        active.id, first,
        "the version that was in force stays in force"
    );
    assert_eq!(active.status, "active");
    assert_eq!(
        ai.store.candidate(second).unwrap().unwrap().status,
        "rolled_back"
    );
    // Its threshold is the one in force, in the config, in the engine and in the
    // overlay a restart would apply.
    assert_eq!(state.config.load_full().ai.block_threshold, 0.95);
    assert_eq!(ai.settings.load_full().block_threshold, 0.95);
    assert_eq!(overlay_threshold(&state), Some(0.95));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_rollback_whose_config_cannot_be_published_keeps_the_version_in_force() {
    let dir = scratch_dir("rollback-publish");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let live = ai.live_model_path();
    let bytes = std::fs::read(&live).unwrap_or_default();
    let first = candidate_version(&ai, "first", &live, &bytes, 0.95, serde_json::json!({}));
    let second = candidate_version(&ai, "second", &live, &bytes, 0.90, serde_json::json!({}));
    for id in [first, second] {
        let promoted = call(
            state.clone(),
            "POST",
            "/api/ai/candidates/promote",
            Some(serde_json::json!({ "id": id })),
        )
        .await;
        assert!(promoted.0.is_success(), "{}", promoted.2);
    }
    assert_eq!(overlay_threshold(&state), Some(0.90));

    // The version a rollback would restore can no longer be published.
    let conn = rusqlite::Connection::open(dir.join("ai.db")).unwrap();
    conn.execute(
        "UPDATE ai_candidates SET scoring_config = ?1 WHERE id = ?2",
        rusqlite::params![r#"{"workers":0}"#, first],
    )
    .unwrap();
    drop(conn);

    let rolled = call(state.clone(), "POST", "/api/ai/candidates/rollback", None).await;
    assert_eq!(rolled.0, StatusCode::BAD_REQUEST, "{}", rolled.2);

    // The rollback was taken back: the version that was in force is whole again,
    // and no other version's threshold was published over it.
    let active = ai.store.active_candidate().unwrap().unwrap();
    assert_eq!(active.id, second);
    assert_eq!(
        ai.store.candidate(first).unwrap().unwrap().status,
        "superseded"
    );
    assert_eq!(state.config.load_full().ai.block_threshold, 0.90);
    assert_eq!(ai.settings.load_full().block_threshold, 0.90);
    assert_eq!(overlay_threshold(&state), Some(0.90));
    let _ = std::fs::remove_dir_all(&dir);
}
#[tokio::test]
async fn a_promotion_whose_fusion_cannot_be_re_scored_is_undone() {
    let dir = scratch_dir("fusion-publish");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    seed_threat(&ai, "fusion-pending.example");
    fail_rescore_for(&dir, "decide");

    let live = ai.live_model_path();
    let bytes = std::fs::read(&live).unwrap_or_default();
    let id = candidate_version(
        &ai,
        "decide-mode",
        &live,
        &bytes,
        0.97,
        serde_json::json!({ "fusion": "decide" }),
    );
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": id })),
    )
    .await;
    assert!(!promoted.0.is_success(), "{}", promoted.2);

    // A mode whose scores cannot be written is refused before it is published:
    // nothing moved, and no version is in force.
    assert!(ai.store.active_candidate().unwrap().is_none());
    assert_eq!(ai.store.candidate(id).unwrap().unwrap().status, "candidate");
    assert_eq!(state.config.load_full().ai.fusion.as_str(), "monitor");
    assert_eq!(state.config.load_full().ai.block_threshold, 0.99);
    assert_eq!(overlay_threshold(&state), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_promotion_whose_undo_fails_reports_what_could_not_be_put_back() {
    let dir = scratch_dir("promotion-undo-publish");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let live = ai.live_model_path();
    let bytes = std::fs::read(&live).unwrap_or_default();
    let first = candidate_version(&ai, "first", &live, &bytes, 0.95, serde_json::json!({}));
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": first })),
    )
    .await;
    assert!(promoted.0.is_success(), "{}", promoted.2);

    // The version that would have to come back now points at a file that is not
    // a model, so its own restoration fails as well.
    let broken = dir.join("broken.bin");
    std::fs::write(&broken, b"not a model").unwrap();
    let conn = rusqlite::Connection::open(dir.join("ai.db")).unwrap();
    conn.execute(
        "UPDATE ai_candidates SET model_path = ?1 WHERE id = ?2",
        rusqlite::params![broken.to_string_lossy(), first],
    )
    .unwrap();
    drop(conn);

    let second = candidate_version(
        &ai,
        "bad-config",
        &live,
        &bytes,
        0.90,
        serde_json::json!({ "workers": 0 }),
    );
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": second })),
    )
    .await;

    // The failed configuration is reported together with the stage that could
    // not be put back, rather than discarding the undo's own failure.
    assert_eq!(
        promoted.0,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        promoted.2
    );
    assert!(
        promoted.2.contains("could not load candidate first"),
        "{}",
        promoted.2
    );
    // The store is back on the version that was in force, whose configuration
    // was never replaced.
    let active = ai.store.active_candidate().unwrap().unwrap();
    assert_eq!(active.id, first);
    assert_eq!(state.config.load_full().ai.block_threshold, 0.95);
    assert_eq!(overlay_threshold(&state), Some(0.95));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_version_change_retires_the_threshold_trial_in_force() {
    let dir = scratch_dir("trial-retired");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai.clone()));
    let trial = ai
        .store
        .save_threshold_trial(&daygle_dns_ml::store::NewThresholdTrial {
            model: "builtin".to_string(),
            base_threshold: 0.99,
            candidate: 0.96,
            fpr_target: 0.01,
            passed: true,
            report: "{}".to_string(),
        })
        .unwrap();
    assert!(ai
        .store
        .mark_threshold_applied(trial.id, 0.99, "builtin")
        .unwrap());
    assert!(ai.store.applied_threshold_trial().unwrap().is_some());

    let live = ai.live_model_path();
    let bytes = std::fs::read(&live).unwrap_or_default();
    let id = candidate_version(
        &ai,
        "trial-owner",
        &live,
        &bytes,
        0.95,
        serde_json::json!({}),
    );
    let promoted = call(
        state.clone(),
        "POST",
        "/api/ai/candidates/promote",
        Some(serde_json::json!({ "id": id })),
    )
    .await;
    assert!(promoted.0.is_success(), "{}", promoted.2);

    // The trial measured the scoring the version replaced, so it is no longer in
    // force and cannot put its own base threshold back over this version's.
    assert!(ai.store.applied_threshold_trial().unwrap().is_none());
    let status = json(state.clone(), "/api/ai/threshold").await;
    assert!(status["in_force"].is_null());
    let rolled = call(
        state.clone(),
        "POST",
        "/api/ai/threshold/rollback",
        Some(serde_json::json!({ "id": trial.id })),
    )
    .await;
    assert_eq!(rolled.0, StatusCode::CONFLICT, "{}", rolled.2);
    assert_eq!(state.config.load_full().ai.block_threshold, 0.95);
    // The trial is kept as history: retired, not deleted.
    let kept = ai.store.threshold_trial(trial.id).unwrap().unwrap();
    assert!(kept.applied_at > 0 && kept.rolled_back_at > 0);
    let _ = std::fs::remove_dir_all(&dir);
}
