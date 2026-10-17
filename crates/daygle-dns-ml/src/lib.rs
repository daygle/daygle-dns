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
//! | [`backend`]                 | the pluggable classifier trait |
//! | [`heuristic`]               | zero-model keyword fallback |
//! | [`fasttext_backend`]        | supervised fastText `.bin` models |
//! | [`store`]                   | SQLite verdict + override store |
//! | [`scanner`]                 | background worker, block snapshot |
//! | [`plugin`]                  | the policy engine integration |
//!
//! Design guards:
//!
//! 1. **Never on the DNS hot path.** The plugin consults a pre-built,
//!    atomically-swapped map; the classifier itself only runs on the
//!    background scan cycle.
//! 2. **Train-first.** The default `AiMode::Train` records verdicts only -
//!    flipping to enforce is a deliberate operator action.
//! 3. **Operator overrides always win.** The user's allowlist is checked
//!    by the policy engine *before* plugins, and `ai_overrides` rows veto
//!    individual verdicts at snapshot build time.
//! 4. **Expiry means re-check, not stale blocking.** Verdicts carry TTLs;
//!    expired verdicts re-enter the scan queue and drop out of the block
//!    snapshot until a fresh classification exists.

pub mod backend;
pub mod fasttext_backend;
pub mod heuristic;
pub mod plugin;
pub mod scanner;
pub mod store;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::LogStore;
use tokio_util::sync::CancellationToken;

use crate::backend::DomainClassifier;
use crate::scanner::{BlockSnapshot, Scanner};
use crate::store::AiStore;
use std::path::Path;

/// Everything the scanner, plugin and API need, wired together once.
pub struct AiEngine {
    pub store: Arc<AiStore>,
    pub scanner: Arc<Scanner>,
    pub settings: Arc<ArcSwap<AiSettings>>,
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    plugin: Arc<plugin::AiBlockPlugin>,
    query_store: Arc<daygle_dns_authoritative::ZoneStore>,
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

        // Backend selection: trained model when configured, heuristics
        // otherwise. A configured-but-broken model is a startup error (fail
        // fast) rather than a silent downgrade.
        let classifier: Box<dyn DomainClassifier + Send + Sync> =
            if settings.model_path.trim().is_empty() {
                Box::new(heuristic::HeuristicBackend)
            } else {
            Box::new(fasttext_backend::FastTextBackend::load(&settings.model_path)?)
        };

        let settings = Arc::new(ArcSwap::from_pointee(settings.clone()));
        let snapshot = Arc::new(ArcSwap::from_pointee(BlockSnapshot::new()));
        let scanner = Scanner::new(
            store.clone(),
            classifier,
            settings.clone(),
            snapshot.clone(),
            logs.clone(),
        );
        let plugin = plugin::AiBlockPlugin::new(snapshot.clone(), settings.clone());
        Ok(Arc::new(Self {
            store,
            scanner,
            settings,
            snapshot,
            plugin,
            query_store,
        }))
    }

    /// The plugin to install into the policy engine.
    pub fn block_plugin(&self) -> Arc<plugin::AiBlockPlugin> {
        self.plugin.clone()
    }

    /// Kick the scanner for one immediate cycle (used by the rescan API).
    pub fn trigger_rescan(&self) {
        self.scanner.rescan_notify.notify_one();
    }

    /// Add an `allow` override and refresh the block snapshot immediately.
    pub fn set_allow_override(&self, domain: &str, reason: &str) -> Result<()> {
        self.store.set_override(domain, "allow", reason)?;
        self.refresh_snapshot_now();
        Ok(())
    }

    /// Drop an override and refresh the block snapshot immediately.
    pub fn clear_override(&self, domain: &str) -> Result<bool> {
        let existed = self.store.clear_override(domain)?;
        if existed {
            self.refresh_snapshot_now();
        }
        Ok(existed)
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
}

/// Resolve the database path: the config value, or `ai.db` beside the
/// authoritative zone database.
fn database_path(settings: &AiSettings, authoritative_database: &str) -> PathBuf {
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
