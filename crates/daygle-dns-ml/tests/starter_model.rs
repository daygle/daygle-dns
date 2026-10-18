//! The bundled starter fastText model: it must load, classify the categories
//! it was trained for, and degrade to the heuristic backend (not a startup
//! failure) when the file is missing from disk.

use std::sync::Arc;

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::LogStore;
use daygle_dns_ml::backend::{ClassificationInput, DomainClassifier, Severity};
use daygle_dns_ml::fasttext_backend::FastTextBackend;
use daygle_dns_ml::AiEngine;
use tempfile::TempDir;

const STARTER_MODEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/daygle-starter.bin"
);

fn base_settings() -> AiSettings {
    AiSettings {
        enabled: true,
        ..AiSettings::default()
    }
}

fn zone_store(dir: &TempDir) -> Arc<daygle_dns_authoritative::ZoneStore> {
    Arc::new(
        daygle_dns_authoritative::ZoneStore::open(
            &dir.path().join("zones.db").display().to_string(),
        )
        .unwrap(),
    )
}

#[test]
fn bundled_starter_model_loads_and_classifies() {
    let backend = FastTextBackend::load(STARTER_MODEL).expect("starter model loads");

    let phishing = backend
        .classify(&ClassificationInput::domain_only(
            "secure-account-login-verify.com",
        ))
        .expect("phishing-shaped verdict");
    assert_eq!(phishing.category, "phishing", "phishing probe shape");
    assert_eq!(phishing.severity, Severity::Threat);

    let adult = backend
        .classify(&ClassificationInput::domain_only("www.pornhub.com"))
        .expect("a known adult domain gets an adult verdict");
    assert_eq!(adult.category, "adult", "adult labels come from the model");

    // Everyday names land in content categories instead of threats.
    let news = backend
        .classify(&ClassificationInput::domain_only("www.reuters.com"))
        .expect("trained everyday domain");
    assert_eq!(news.category, "news");
    assert_eq!(news.severity, Severity::Info);
}

#[test]
fn engine_tolerates_missing_model_file_falls_back_to_heuristic() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let logs = Arc::new(LogStore::new(256));

    let settings = AiSettings {
        model_path: "/definitely/not/a/real/model.bin".into(),
        ..base_settings()
    };
    let engine = AiEngine::new(
        &settings,
        &dir.path().join("daygle.db").display().to_string(),
        zones,
        logs.clone(),
    )
    .expect("missing model file falls back instead of failing the engine");

    // The fallback surfaces as a Warn log naming the missing file.
    let hit = logs.entries().iter().any(|e| {
        e.component == "ai"
            && e.message.contains("not found on disk")
            && e.message.contains("/definitely/not/a/real/model.bin")
    });
    assert!(
        hit,
        "expected a Warn log about the missing model file, got {:?}",
        logs.tail(8)
    );

    // The fallback engine is still fully wired: overrides work.
    engine
        .set_allow_override("allowed.example.com", "test")
        .unwrap();
}

#[test]
fn engine_with_bundled_model_builds() {
    let dir = TempDir::new().unwrap();
    let zones = zone_store(&dir);
    let logs = Arc::new(LogStore::new(256));

    let settings = AiSettings {
        model_path: STARTER_MODEL.into(),
        ..base_settings()
    };
    AiEngine::new(
        &settings,
        &dir.path().join("daygle.db").display().to_string(),
        zones,
        logs,
    )
    .expect("bundled model builds without a misspelled log or a load error");
}
