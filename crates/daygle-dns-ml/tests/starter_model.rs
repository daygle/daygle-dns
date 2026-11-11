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

fn label(backend: &FastTextBackend, domain: &str) -> String {
    backend
        .classify(&ClassificationInput::domain_only(domain))
        .map(|v| v.category)
        .unwrap_or_default()
}

/// Update, telemetry, work, CDN and mail hosts have categories of their
/// own. Update hosts share "download" and "update" with the malware
/// examples: they were labelled malware, and a group blocking that category
/// then blocked Windows Update.
#[test]
fn infrastructure_hosts_have_their_own_categories() {
    let backend = FastTextBackend::load(STARTER_MODEL).expect("starter model loads");
    for (domain, want) in [
        ("download.windowsupdate.com", "system"),
        ("au.download.windowsupdate.com", "system"),
        ("2.au.download.windowsupdate.com", "system"),
        ("4.au.download.windowsupdate.com", "system"),
        ("c.pki.goog", "system"),
        ("mobile.events.data.microsoft.com", "telemetry"),
        ("incoming.telemetry.mozilla.org", "telemetry"),
        ("cityofmelbourne-my.sharepoint.com", "business"),
        ("dualstack.n.sni.us-eu.fastly.net", "cdn"),
        ("smtp.gmail.com", "email"),
        // Devices, tools and services with nowhere to go before: a camera
        // app and a patch management agent were guessed as phishing.
        ("security-app.eufylife.com", "iot"),
        ("api.eufylife.com", "iot"),
        ("server.au.action1.com", "remote-access"),
        ("labs.sophos.com", "security"),
        ("api.openai.com", "ai"),
        ("www.codebuff.com", "ai"),
        ("web.whatsapp.com", "messaging"),
        ("au.nordvpn.com", "vpn-proxy"),
    ] {
        assert_eq!(label(&backend, domain), want, "{domain}");
    }
}

/// The new categories do not swallow what the model already told apart.
#[test]
fn new_categories_leave_the_others_alone() {
    let backend = FastTextBackend::load(STARTER_MODEL).expect("starter model loads");
    for (domain, want) in [
        ("trojan-bin-update.click", "malware"),
        ("keylogger-download-pro.info", "malware"),
        ("www.reuters.com", "news"),
        ("github.com", "developer"),
        ("aws.amazon.com", "cloud"),
        ("www.netflix.com", "streaming"),
        ("paypal-secure-login-verify.xyz", "phishing"),
        ("secure-account-login-verify.com", "phishing"),
        ("free-bitcoin-doubler.win", "scam"),
        ("www.facebook.com", "social"),
        ("download.windowsupdate.com", "system"),
        ("security.ubuntu.com", "system"),
    ] {
        assert_eq!(label(&backend, domain), want, "{domain}");
    }
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
