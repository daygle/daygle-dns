//! # daygle-dns-ml
//!
//! The AI subsystem of Daygle DNS: a CPU-only background classifier that
//! scans domains *already observed in the query log*, records verdicts with
//! TTLs, and (in enforce mode) auto-blocks fresh, high-confidence threat
//! verdicts.
//!
//! The codebase:
//!
//! | Module                      | Role |
//! |-----------------------------|------|
//! | [`backend`]                 | the pluggable classifier trait and its two [`backend::Channel`]s |
//! | [`channel`]                 | scopes a classifier to one job (categorize, or detect threats) |
//! | [`heuristic`]               | zero-model keyword fallback |
//! | [`fasttext_backend`]        | supervised fastText `.bin` models |
//! | [`store`]                   | SQLite verdict + override store |
//! | [`scanner`]                 | background worker, block + category snapshots |
//! | [`plugin`]                  | the policy engine integration |
//!
//! Design guards:
//!
//! 1. **Two jobs, two channels.** Categorization and threat detection are
//!    separate passes (`Channel::Content` / `Channel::Threat`), each with its
//!    own model, confidence floor and verdict TTL. Only the threat channel
//!    feeds the auto-block snapshot; content labels feed the category
//!    snapshot instead, which is only read by per-group category policy. So
//!    a label never blocks by itself, and a blocked category is always an
//!    operator rule over a label.
//! 2. **Never on the DNS hot path.** The plugin consults a pre-built,
//!    atomically-swapped map; the classifier itself only runs on the
//!    background scan cycle.
//! 3. **Train-first.** The default `AiMode::Train` records verdicts only -
//!    flipping to enforce is a deliberate operator action.
//! 4. **Operator overrides always win.** The user's allowlist is checked
//!    by the policy engine *before* plugins, and `ai_overrides` rows veto
//!    individual verdicts at snapshot build time.
//! 5. **Expiry means re-check, not stale blocking.** Verdicts carry TTLs;
//!    expired verdicts re-enter the scan queue and drop out of the block
//!    snapshot until a fresh classification exists.

pub mod backend;
pub mod channel;
pub mod fasttext_backend;
pub mod heuristic;
pub mod plugin;
pub mod scanner;
pub mod learn;
pub mod store;
pub mod verify;

#[cfg(feature = "verifier-onnx")]
pub mod verifier_onnx;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::LogStore;
use tokio_util::sync::CancellationToken;

use crate::backend::{Channel, DomainClassifier};
use crate::scanner::{BlockSnapshot, CategorySnapshot, Scanner};
use crate::store::AiStore;
use std::path::Path;

/// Everything the scanner, plugin and API need, wired together once.
pub struct AiEngine {
    pub store: Arc<AiStore>,
    pub scanner: Arc<Scanner>,
    pub settings: Arc<ArcSwap<AiSettings>>,
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    categories: Arc<ArcSwap<CategorySnapshot>>,
    plugin: Arc<plugin::AiBlockPlugin>,
    query_store: Arc<daygle_dns_authoritative::ZoneStore>,
    /// The classifier the scanner retrained for itself, beside `ai.db`.
    learned: std::path::PathBuf,
    /// Whether a retrained model is the one currently loaded (at startup or
    /// after a live swap).
    learned_active: std::sync::atomic::AtomicBool,
    /// The model file the running classifier was loaded from: the baseline a
    /// candidate retrain must match.
    active_model: Arc<ArcSwap<String>>,
    content_swap: Arc<backend::Reloadable>,
    threat_swap: Arc<backend::Reloadable>,
    logs: Arc<LogStore>,
    retrainer: Arc<learn::Retrainer>,
}

impl AiEngine {
    /// Build the engine. `authoritative_database` locates the default
    /// verdict-store path (`ai.db` beside the zone DB) when
    /// `settings.database` is empty; `query_store` is the authoritative
    /// zone store supplying the query-log harvest.
    pub fn new(
        settings: &AiSettings,
        authoritative_database: &str,
        query_store: Arc<daygle_dns_authoritative::ZoneStore>,
        logs: Arc<LogStore>,
    ) -> Result<Arc<Self>> {
        let database_path = database_path(settings, authoritative_database);
        let store = Arc::new(AiStore::open(&database_path)?);
        // A model the scanner retrained for itself wins over the configured
        // shared model while it is the newer artifact. A channel that names
        // its own model still gets it, and deleting the file falls back to
        // `ai.model_path`.
        // ...but a model the operator configured more recently wins, so
        // pointing `ai.model_path` at a new file is never silently ignored.
        let learned_path = learn::learned_model_path(&database_path);
        let configured = Path::new(settings.model_path.trim());
        let learned_active = learned_path.is_file()
            && match configured.metadata().and_then(|m| m.modified()) {
                Ok(configured_at) => learned_path
                    .metadata()
                    .and_then(|m| m.modified())
                    .map(|learned_at| learned_at >= configured_at)
                    .unwrap_or(false),
                // No configured model file (heuristic backend): the trained
                // one is all there is.
                Err(_) => true,
            };
        let shared_model_path = if learned_active {
            learned_path.to_string_lossy().into_owned()
        } else {
            settings.model_path.clone()
        };
        if learned_active {
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!(
                    "using the classifier the AI retrained for itself: {}",
                    learned_path.display()
                ),
            );
        }
        // Live settings, shared by the scanner, the plugin and the threat
        // channel's category list, so editing `auto_block_categories` takes
        // effect without a restart.
        let settings_swap = Arc::new(ArcSwap::from_pointee(settings.clone()));

        // One model per channel: each channel uses its own path when
        // configured and falls back to the shared `ai.model_path`, so a
        // deployment can run a wide categorizer and a narrow, high-precision
        // threat detector side by side - or one model for both.
        let content_model_path =
            resolve_model_path(&settings.category_model_path, &shared_model_path);
        let threat_model_path =
            resolve_model_path(&settings.threat_model_path, &shared_model_path);

        let content: Box<dyn DomainClassifier + Send + Sync> =
            Box::new(channel::ChannelBackend::content(load_primary(
                content_model_path,
                Channel::Content,
                &logs,
            )?));
        let threat: Box<dyn DomainClassifier + Send + Sync> =
            Box::new(channel::ChannelBackend::threat(
                load_primary(threat_model_path, Channel::Threat, &logs)?,
                settings_swap.clone(),
            ));

        // The verifier second-checks the threat channel only: categorization
        // needs no second opinion, and a content label never blocks. A load
        // failure degrades to the primary classifier - it never disables the
        // AI subsystem.
        #[cfg(feature = "verifier-onnx")]
        let threat = wrap_verifier(threat, settings, &logs);

        // The channels sit behind reloadable handles, so a retrain can be
        // installed without a restart.
        let active_model = Arc::new(ArcSwap::from_pointee(if learned_active {
            learned_path.to_string_lossy().into_owned()
        } else {
            shared_model_path.clone()
        }));
        let content_swap = backend::Reloadable::new(content);
        let threat_swap = backend::Reloadable::new(threat);
        let engine_logs = logs.clone();

        let snapshot = Arc::new(ArcSwap::from_pointee(BlockSnapshot::new()));
        let categories = Arc::new(ArcSwap::from_pointee(CategorySnapshot::new()));
        let retrainer = Arc::new(learn::Retrainer::new(
            store.clone(),
            settings_swap.clone(),
            logs.clone(),
            learned_path.clone(),
            active_model.clone(),
        ));
        let scanner = Scanner::new(
            store.clone(),
            Box::new(content_swap.clone()),
            Box::new(threat_swap.clone()),
            settings_swap.clone(),
            snapshot.clone(),
            categories.clone(),
            logs,
        );
        scanner.set_retrainer(retrainer.clone());

        let plugin = plugin::AiBlockPlugin::new(
            snapshot.clone(),
            categories.clone(),
            scanner.exemptions(),
            settings_swap.clone(),
        );
        Ok(Arc::new(Self {
            store,
            scanner,
            settings: settings_swap,
            snapshot,
            categories,
            plugin,
            query_store,
            learned: learned_path,
            learned_active: std::sync::atomic::AtomicBool::new(learned_active),
            active_model,
            content_swap,
            threat_swap,
            logs: engine_logs,
            retrainer,
        }))
    }

    /// The plugin to install into the policy engine.
    pub fn block_plugin(&self) -> Arc<plugin::AiBlockPlugin> {
        self.plugin.clone()
    }

    /// Let the live client groups override the enforcement mode per client
    /// (their `ai_mode` setting: inherit, enforce, record only).
    pub fn set_client_groups(&self, groups: Arc<ArcSwap<daygle_dns_policy::AdvancedBlocking>>) {
        self.plugin.set_client_groups(groups);
    }

    /// The model the scanner maintains for itself, beside `ai.db`.
    pub fn learned_model_path(&self) -> &Path {
        &self.learned
    }

    /// Whether a retrained model is the one currently loaded.
    pub fn learned_model_active(&self) -> bool {
        self.learned_active
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What the last successful retrain achieved, as recorded beside the model.
    pub fn learned_model_record(&self) -> Option<serde_json::Value> {
        let raw = std::fs::read(learn::stats_path(&self.learned)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Retrain the classifier from the scanner's own confident verdicts and the
    /// operator's corrections, judge it on held-out corrections, then load it
    /// into the running channels.
    pub fn retrain_learned_model(&self) -> Result<learn::TrainingStats> {
        let stats = self.retrainer.retrain()?;
        self.activate_retrained_model()?;
        Ok(stats)
    }

    /// Load the model the retrainer just installed, without a restart. A
    /// channel with its own configured model keeps it.
    fn activate_retrained_model(&self) -> Result<()> {
        let settings = self.settings.load_full();
        let learned = self.learned.to_string_lossy().into_owned();
        if settings.category_model_path.trim().is_empty() {
            let content: Box<dyn DomainClassifier + Send + Sync> =
                Box::new(channel::ChannelBackend::content(load_primary(
                    &learned,
                    Channel::Content,
                    &self.logs,
                )?));
            self.content_swap.replace(content);
        }
        if settings.threat_model_path.trim().is_empty() {
            let threat: Box<dyn DomainClassifier + Send + Sync> =
                Box::new(channel::ChannelBackend::threat(
                    load_primary(&learned, Channel::Threat, &self.logs)?,
                    self.settings.clone(),
                ));
            #[cfg(feature = "verifier-onnx")]
            let threat = wrap_verifier(threat, &settings, &self.logs);
            self.threat_swap.replace(threat);
        }
        self.active_model.store(Arc::new(learned));
        self.learned_active
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.logs.push(
            daygle_dns_core::LogLevel::Info,
            "ai",
            "the retrained classifier is now in use",
        );
        Ok(())
    }

    /// Kick the scanner for one immediate cycle (used by the rescan API).
    pub fn trigger_rescan(&self) {
        self.scanner.rescan_notify.notify_one();
    }

    /// Add an `allow` override and refresh the snapshots immediately.
    pub fn set_allow_override(&self, domain: &str, reason: &str) -> Result<()> {
        self.store.set_override(domain, "allow", reason)?;
        self.refresh_snapshot_now();
        Ok(())
    }

    /// Operator correction: `domain` is not a threat, whatever the model said.
    /// The threat verdict is kept for audit and retraining, but it stops
    /// blocking and leaves the exported threat list until the mark is cleared.
    pub fn set_not_threat_override(&self, domain: &str, reason: &str) -> Result<()> {
        self.store.set_override(domain, "not_threat", reason)?;
        self.refresh_snapshot_now();
        Ok(())
    }

    /// Relabel `domain` as `category` for the console and category blocking.
    /// The scanner keeps classifying it; the operator's label wins.
    pub fn set_category_override(&self, domain: &str, category: &str) -> Result<()> {
        self.store.set_category_override(domain, category)?;
        self.refresh_snapshot_now();
        Ok(())
    }

    /// Drop a category relabel, so the model's label applies again.
    pub fn clear_category_override(&self, domain: &str) -> Result<bool> {
        let existed = self.store.clear_category_override(domain)?;
        if existed {
            self.refresh_snapshot_now();
        }
        Ok(existed)
    }

    /// Drop an override and refresh the block snapshot immediately.
    pub fn clear_override(&self, domain: &str) -> Result<bool> {
        let existed = self.store.clear_override(domain)?;
        if existed {
            self.refresh_snapshot_now();
        }
        Ok(existed)
    }

    /// Apply edited settings to the running engine: the scanner, the plugin
    /// and the threat channel read them live, the snapshots are rebuilt
    /// under the new rules and a scan is started. Returns whether the change
    /// also needs a restart: the models, the verifier and the database are
    /// loaded once, at startup.
    pub fn apply_settings(&self, new: &AiSettings) -> bool {
        let old = self.settings.load_full();
        let restart = needs_restart(&old, new);
        self.settings.store(Arc::new(new.clone()));
        self.refresh_snapshot_now();
        self.trigger_rescan();
        restart
    }

    /// Force a snapshot rebuild from the current store contents.
    pub fn refresh_snapshot_now(&self) {
        let cfg = self.settings.load().clone();
        let now = chrono::Utc::now().timestamp();
        // Snapshot rebuild logic lives in the scanner (which owns the
        // invariant "enforce mode ⇒ populated; train mode ⇒ empty"); the
        // direct clone keeps this path cheap.
        self.scanner.refresh_snapshot(&cfg, now);
    }

    /// Run scan + expiry cycles until `shutdown` fires.
    pub async fn run_forever(self: Arc<Self>, shutdown: CancellationToken) {
        self.scanner
            .clone()
            .run_forever(self.query_store.clone(), shutdown)
            .await;
    }

    /// Access the query-log source (the authoritative zone store).
    pub fn query_store(&self) -> &Arc<daygle_dns_authoritative::ZoneStore> {
        &self.query_store
    }

    /// Snapshot accessor for the block test harness.
    pub fn snapshot(&self) -> Arc<ArcSwap<BlockSnapshot>> {
        self.snapshot.clone()
    }

    /// Snapshot accessor for the category snapshot (tests and diagnostics).
    pub fn category_snapshot(&self) -> Arc<ArcSwap<CategorySnapshot>> {
        self.categories.clone()
    }

    /// The pipelines actually running, one per channel (e.g.
    /// `fasttext (categories) / fasttext+minilm-onnx (threats)`); both
    /// channels collapse to the bare name when they run the same pipeline. A
    /// missing model file falls back to `heuristic`, whatever the settings
    /// say.
    pub fn backend_name(&self) -> String {
        self.scanner.backend_name()
    }

    /// The content-categorization pipeline actually running.
    pub fn content_backend_name(&self) -> String {
        self.scanner.content_backend_name()
    }

    /// The threat-detection pipeline actually running (verifier included).
    pub fn threat_backend_name(&self) -> String {
        self.scanner.threat_backend_name()
    }

    /// Domains that qualify for auto-blocking now, counted by category:
    /// blocked in enforce mode, what would be blocked in train mode.
    pub fn blockable_counts(&self) -> Result<std::collections::BTreeMap<String, usize>> {
        let cfg = self.settings.load();
        let mut counts = std::collections::BTreeMap::new();
        for block in self
            .scanner
            .eligible_blocks(&cfg, chrono::Utc::now().timestamp())?
            .values()
        {
            *counts.entry(block.category.clone()).or_insert(0) += 1;
        }
        Ok(counts)
    }

    /// Categories the loaded backend can emit (model labels or heuristic
    /// rules), for the console's auto-block category picker.
    pub fn backend_categories(&self) -> Vec<String> {
        self.scanner.categories()
    }
}

/// Whether going from `old` to `new` changes what is loaded at startup:
/// a model, the verifier (its files and threshold) or the database.
fn needs_restart(old: &AiSettings, new: &AiSettings) -> bool {
    old.model_path != new.model_path
        || old.category_model_path != new.category_model_path
        || old.threat_model_path != new.threat_model_path
        || old.verifier_model_path != new.verifier_model_path
        || old.verifier_reference_path != new.verifier_reference_path
        || old.verifier_threshold != new.verifier_threshold
        || old.database != new.database
}

/// Resolve a channel's model path: its own when configured, else the shared
/// `ai.model_path`.
fn resolve_model_path<'a>(channel_path: &'a str, shared_path: &'a str) -> &'a str {
    if channel_path.trim().is_empty() {
        shared_path
    } else {
        channel_path
    }
}

/// Load a channel's primary classifier: the configured model, or the
/// zero-model heuristic rules.
///
/// A configured-but-corrupt model is a startup error (fail fast) rather than a
/// silent downgrade. A configured-but-*missing* file only degrades that channel
/// to the heuristic backend (with a log line naming the channel), so installs
/// stay alive if a bundled model was moved or deleted.
fn load_primary(
    model_path: &str,
    channel: Channel,
    logs: &Arc<LogStore>,
) -> Result<Box<dyn DomainClassifier + Send + Sync>> {
    let path = model_path.trim();
    if path.is_empty() {
        return Ok(Box::new(heuristic::HeuristicBackend));
    }
    if !Path::new(path).is_file() {
        logs.push(
            daygle_dns_core::LogLevel::Warn,
            "ai",
            format!(
                "AI {} model '{path}' not found on disk; using the built-in heuristic backend",
                channel.as_str()
            ),
        );
        return Ok(Box::new(heuristic::HeuristicBackend));
    }
    Ok(Box::new(fasttext_backend::FastTextBackend::load(path)?))
}

/// Wrap the threat channel in the MiniLM/ONNX verifier when one is configured.
#[cfg(feature = "verifier-onnx")]
fn wrap_verifier(
    inner: Box<dyn DomainClassifier + Send + Sync>,
    settings: &AiSettings,
    logs: &Arc<LogStore>,
) -> Box<dyn DomainClassifier + Send + Sync> {
    if settings.verifier_model_path.trim().is_empty() {
        return inner;
    }
    let reference = if settings.verifier_reference_path.trim().is_empty() {
        None
    } else {
        Some(settings.verifier_reference_path.as_str())
    };
    match verifier_onnx::MiniLmVerifier::load(&settings.verifier_model_path, reference) {
        Ok(verifier) => {
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!(
                    "AI verifier active: MiniLM model '{}' corroborates threat verdicts",
                    settings.verifier_model_path
                ),
            );
            Box::new(verify::VerifyingBackend::new(
                inner,
                verifier,
                settings.verifier_threshold,
            ))
        }
        Err(e) => {
            logs.push(
                daygle_dns_core::LogLevel::Warn,
                "ai",
                format!("MiniLM verifier not loaded ({e}); threat verdicts rely on the primary classifier only"),
            );
            inner
        }
    }
}

/// Resolve the database path: the config value, or `ai.db` beside the
/// authoritative zone database.
pub fn database_path(settings: &AiSettings, authoritative_database: &str) -> PathBuf {
    if !settings.database.trim().is_empty() {
        PathBuf::from(&settings.database)
    } else if let Some(parent) = Path::new(authoritative_database).parent() {
        parent.join("ai.db")
    } else {
        PathBuf::from("ai.db")
    }
}

/// Startup helper used by the binary: builds the engine (or `None` when the
/// AI subsystem is disabled), logging why it is missing so misconfiguration
/// never stalls startup.
pub fn build_ai_engine(
    settings: &AiSettings,
    authoritative_database: &str,
    query_store: Arc<daygle_dns_authoritative::ZoneStore>,
    logs: Arc<LogStore>,
) -> Option<Arc<AiEngine>> {
    if !settings.enabled {
        return None;
    }
    match AiEngine::new(settings, authoritative_database, query_store, logs.clone()) {
        Ok(engine) => Some(engine),
        Err(e) => {
            logs.push(
                daygle_dns_core::LogLevel::Error,
                "ai",
                format!("AI subsystem disabled at startup: {e}"),
            );
            tracing::warn!(error = %e, "AI subsystem disabled at startup");
            None
        }
    }
}

/// A convenience error for callers that expect the engine to exist.
pub fn ai_disabled_error() -> DaygleError {
    DaygleError::NotFound("AI subsystem is disabled for this server".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_load_time_settings_need_a_restart() {
        let old = AiSettings::default();
        let mut live = old.clone();
        live.mode = daygle_dns_core::config::AiMode::Enforce;
        live.block_threshold = 0.99;
        live.auto_block_categories = vec!["scam".to_string()];
        assert!(!needs_restart(&old, &live));
        for change in [
            |s: &mut AiSettings| s.threat_model_path = "/m/threat.bin".to_string(),
            |s: &mut AiSettings| s.category_model_path = "/m/cat.bin".to_string(),
            |s: &mut AiSettings| s.verifier_model_path = "/m/v.onnx".to_string(),
            |s: &mut AiSettings| s.verifier_threshold += 0.1,
            |s: &mut AiSettings| s.database = "/d/ai.db".to_string(),
        ] {
            let mut new = old.clone();
            change(&mut new);
            assert!(needs_restart(&old, &new));
        }
    }
}
