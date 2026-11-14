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
use daygle_dns_core::config::{AiMode, AiSettings};
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
                "page_candidates_per_scan": 5_000
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
    drop(applied);

    // And the status endpoint reports what the engine now runs with.
    let reported = json(state, "/api/ai/status").await;
    assert_eq!(reported["fetch_pages"], true);
    assert_eq!(reported["page_fetch_timeout_secs"], 30);
    assert_eq!(reported["page_fetch_max_bytes"], 16_384);
    assert_eq!(reported["page_candidates_per_scan"], 64);
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

    let state = AppState::for_tests(Some(ai));
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
    assert!(body.starts_with("domain,"), "{body}");
    assert!(body.contains("evil.example"), "{body}");

    let (status, _, body) = call(
        state.clone(),
        "GET",
        "/api/ai/threats/export?format=list",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.trim(), "evil.example");

    let (status, headers, body) =
        call(state.clone(), "GET", "/api/ai/corrections?format=csv", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/csv; charset=utf-8"
    );
    assert!(
        body.starts_with("domain,action,category,reason,created_at"),
        "{body}"
    );
    assert!(body.contains("shopping.example"), "{body}");

    let explained = json(state, "/api/ai/explain?domain=evil.example").await;
    assert_eq!(explained["domain"], "evil.example");
    assert_eq!(explained["threat"]["category"], "phishing");
    assert_eq!(explained["threat"]["over_threshold"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn retrain_and_rollback_explain_what_they_cannot_do() {
    let dir = scratch_dir("limits");
    let ai = engine(&dir);
    let state = AppState::for_tests(Some(ai));

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
