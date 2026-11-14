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

/// Seed one confident content verdict, enough of them to retrain on.
fn seed_content(ai: &AiEngine, i: usize) {
    let labels = ["news", "shopping", "gambling"];
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
    assert_eq!(status["fetch_pages"], false);
    assert_eq!(status["page_fetch_timeout_secs"], 5);
    assert_eq!(status["page_fetch_max_bytes"], 524_288);
    assert_eq!(status["page_candidates_per_scan"], 16);
    assert_eq!(status["page_rule"], "evidence");
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
        .record_page_reading("capped.example", "page reads shopping (80%)", Some(0.2))
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
    let ai = engine(&dir);
    for i in 0..240 {
        seed_content(&ai, i);
    }
    let state = AppState::for_tests(Some(ai.clone()));
    let (status, _, body) = call(state.clone(), "POST", "/api/ai/retrain", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let retrained: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(retrained["examples"], 240, "{body}");
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
    assert_eq!(status_body["learned_model"]["last"]["examples"], 243);

    let (status, _, body) = call(state.clone(), "POST", "/api/ai/rollback", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("previous model is in use"), "{body}");
    let status_body = json(state, "/api/ai/status").await;
    assert_eq!(
        status_body["learned_model"]["last"]["examples"], 240,
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
