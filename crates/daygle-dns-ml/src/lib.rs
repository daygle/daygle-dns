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

pub mod age;
pub mod backend;
pub mod channel;
pub mod evidence;
pub mod fasttext_backend;
pub mod heuristic;
pub mod intel;
pub mod learn;
pub mod llm;
pub mod maintain;
pub mod page;
pub mod page_model;
pub mod plugin;
#[cfg(feature = "verifier-onnx")]
pub mod reference;
pub mod scanner;
pub mod store;
pub mod verify;

#[cfg(feature = "verifier-onnx")]
pub mod verifier_onnx;

/// Whether this build can run the MiniLM/ONNX verifier. Static and musl
/// builds leave ONNX Runtime out, and a configured verifier then never loads.
pub const VERIFIER_SUPPORTED: bool = cfg!(feature = "verifier-onnx");

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

/// Rebuilds the threat channel in place.
type ReloadThreat = dyn Fn() -> Result<()> + Send + Sync;

/// One model the scanner maintains: the file it writes, what is live, and
/// the retrainer that looks after it.
struct Maintained {
    learned: std::path::PathBuf,
    /// Whether the learned file is the one the live channel loaded.
    active: Arc<std::sync::atomic::AtomicBool>,
    /// The model file the live channel loaded: the baseline every candidate
    /// is judged against.
    model: Arc<ArcSwap<String>>,
    retrainer: Arc<maintain::Retrainer>,
}

impl Maintained {
    fn active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn record(&self) -> Option<serde_json::Value> {
        let raw = std::fs::read(learn::stats_path(&self.learned)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// The maintenance state of this model, as the status API reports it.
    fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.learned.display().to_string(),
            "present": self.learned.is_file(),
            "active": self.active(),
            "previous": self.retrainer.has_previous(),
            "candidate": self.retrainer.has_candidate(),
            "last": self.record(),
            "trial": self.retrainer.trial().to_json(),
            // The watch on a model that went live on its own: undone
            // automatically if it misbehaves before `until`.
            "watch": self.retrainer.watching().map(|(promoted_at, until)| {
                serde_json::json!({ "promoted_at": promoted_at, "until": until })
            }),
        })
    }
}

/// Everything the scanner, plugin and API need, wired together once.
pub struct AiEngine {
    pub store: Arc<AiStore>,
    pub scanner: Arc<Scanner>,
    pub settings: Arc<ArcSwap<AiSettings>>,
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    categories: Arc<ArcSwap<CategorySnapshot>>,
    plugin: Arc<plugin::AiBlockPlugin>,
    query_store: Arc<daygle_dns_authoritative::ZoneStore>,
    /// The classifier the scanner maintains for itself.
    shared: Maintained,
    maintenance: Arc<maintain::Maintenance>,
    /// Rebuilds the threat channel (live model, current verifier settings).
    reload_threat: Arc<ReloadThreat>,
    /// The maintained threat feeds.
    intel: Arc<intel::Intel>,
    /// The page-text model the maintenance step keeps trained.
    page_model: Arc<page_model::PageModel>,
    /// Registration-date lookups for new threats.
    domain_age: Arc<age::DomainAge>,
    /// The language-model server's management side (models, downloads).
    llm: Arc<llm::LlmManager>,
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
        // Live settings, shared by the scanner, the plugin and the threat
        // channel's threat label set, so editing `auto_block_categories` or
        // `auto_block_removals` takes effect without a restart.
        let settings_swap = Arc::new(ArcSwap::from_pointee(settings.clone()));
        // Outside evidence: the threat feeds (the last good download, until
        // the refresh loop fetches newer) and how this network uses each
        // domain.
        let intel = intel::Intel::new(store.clone(), settings_swap.clone(), logs.clone());
        let network =
            evidence::NetworkEvidence::new(store.clone(), intel.clone(), settings_swap.clone());
        let page_model = page_model::PageModel::new(
            database_path.with_file_name(page_model::PAGE_MODEL_FILE),
            store.clone(),
            network.clone(),
            logs.clone(),
        );

        // A model the scanner retrained for itself wins over the configured
        // one while it is the newer artifact and loads; a model the operator
        // configured more recently wins, so pointing a path at a new file is
        // never silently ignored, and a damaged learned file never stops the
        // AI from starting.
        let learned_shared = learn::learned_model_path(&database_path);
        let learned_reference = database_path.with_file_name(LEARNED_REFERENCE_FILE);
        let pick = |learned: &Path, configured: &str, what: &str| -> bool {
            if !prefer_learned(learned, configured) {
                return false;
            }
            if learn::model_labels(learned).is_none() {
                logs.push(
                    daygle_dns_core::LogLevel::Warn,
                    "ai",
                    format!(
                        "the retrained {what} {} could not be loaded; using the configured model instead",
                        learned.display()
                    ),
                );
                return false;
            }
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!(
                    "using the {what} the AI retrained for itself: {}",
                    learned.display()
                ),
            );
            true
        };
        let shared_learned = pick(&learned_shared, &settings.model_path, "classifier");
        let shared_path = if shared_learned {
            learned_shared.to_string_lossy().into_owned()
        } else {
            settings.model_path.clone()
        };
        // Both channels run the one model.
        let content = content_channel(&shared_path, &logs)?;
        let threat = threat_channel(
            &shared_path,
            settings,
            &settings_swap,
            &logs,
            &learned_reference,
            &network,
        )?;

        // A model file that changed while the server was down (a release
        // bundle, a new configured path) re-checks verdicts like a promotion.
        note_live_model(&store, &shared_path, &logs);

        // The channels sit behind reloadable handles, so a new model goes
        // live without a restart.
        let content_swap = backend::Reloadable::new(content);
        let threat_swap = backend::Reloadable::new(threat);
        let snapshot = Arc::new(ArcSwap::from_pointee(BlockSnapshot::new()));
        let categories = Arc::new(ArcSwap::from_pointee(CategorySnapshot::new()));

        let shared = {
            let model = Arc::new(ArcSwap::from_pointee(shared_path));
            Maintained {
                learned: learned_shared.clone(),
                active: Arc::new(std::sync::atomic::AtomicBool::new(shared_learned)),
                retrainer: Arc::new(maintain::Retrainer::new(
                    store.clone(),
                    settings_swap.clone(),
                    logs.clone(),
                    learned_shared.clone(),
                    model.clone(),
                )),
                model,
            }
        };
        shared.retrainer.set_evidence(network.clone());

        // Every model that goes live - a promotion, a manual retrain or a
        // rollback - goes through these.
        shared.retrainer.set_installer({
            let settings = settings_swap.clone();
            let logs = logs.clone();
            let content_swap = content_swap.clone();
            let threat_swap = threat_swap.clone();
            let model = shared.model.clone();
            let active = shared.active.clone();
            let learned = learned_shared.clone();
            let reference = learned_reference.clone();
            let network = network.clone();
            let store = store.clone();
            Box::new(move |path: &Path| {
                let current = settings.load_full();
                let file = path.to_string_lossy().into_owned();
                // Build both before installing either, so a load failure
                // never leaves the channels on different models.
                let content = content_channel(&file, &logs)?;
                let threat =
                    threat_channel(&file, &current, &settings, &logs, &reference, &network)?;
                content_swap.replace(content);
                threat_swap.replace(threat);
                announce(&logs, path == learned, "classifier", &file);
                note_live_model(&store, &file, &logs);
                model.store(Arc::new(file));
                active.store(path == learned, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            })
        });
        // Rebuild the threat channel from the live threat model and the
        // current settings: a new verifier reference, or the verifier
        // switched on or off, takes effect without a restart.
        let reload_threat: Arc<ReloadThreat> = {
            let settings = settings_swap.clone();
            let logs = logs.clone();
            let threat_swap = threat_swap.clone();
            let reference = learned_reference.clone();
            let network = network.clone();
            let live_model = shared.model.clone();
            Arc::new(move || {
                let current = settings.load_full();
                let channel = threat_channel(
                    &live_model.load_full(),
                    &current,
                    &settings,
                    &logs,
                    &reference,
                    &network,
                )?;
                threat_swap.replace(channel);
                Ok(())
            })
        };

        // The verifier's reference is refreshed from operator truth after
        // each maintenance step, and the threat channel reloaded with it.
        let refresh_reference: maintain::Step = {
            let store = store.clone();
            let settings = settings_swap.clone();
            let logs = logs.clone();
            let reference = learned_reference.clone();
            let reload = reload_threat.clone();
            let page_model = page_model.clone();
            Box::new(move || {
                let current = settings.load_full();
                page_model.maybe_retrain(&current);
                if !refresh_verifier_reference(&store, &current, &reference, &logs) {
                    return;
                }
                if let Err(e) = reload() {
                    logs.push(
                        daygle_dns_core::LogLevel::Warn,
                        "ai",
                        format!("could not reload the threat channel with the new verifier reference: {e}"),
                    );
                }
            })
        };
        let maintenance = Arc::new(maintain::Maintenance::new(
            shared.retrainer.clone(),
            refresh_reference,
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
        scanner.set_maintenance(maintenance.clone());
        scanner.set_page_model(page_model.clone());
        let domain_age =
            age::DomainAge::new(store.clone(), daygle_dns_policy::rdap::IANA_BOOTSTRAP);
        scanner.set_domain_age(domain_age.clone());

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
            shared,
            maintenance,
            reload_threat,
            intel,
            page_model,
            domain_age,
            llm: llm::LlmManager::new(),
        }))
    }

    /// Keep the threat feeds downloaded and fresh until `shutdown`. `mirror`
    /// gives `policy.feed_mirror` (a base URL, or empty).
    pub async fn run_threat_feeds(
        &self,
        mirror: impl Fn() -> String + Send + 'static,
        shutdown: CancellationToken,
    ) {
        self.intel.clone().run(mirror, shutdown).await;
    }

    /// Look registration dates up through `url` (`policy.rdap_bootstrap`).
    pub fn set_rdap_bootstrap(&self, url: &str) {
        self.domain_age.set_bootstrap(url);
    }

    /// The threat feed listing `domain` (as the AI uses the feeds now).
    pub fn threat_feed_for(&self, domain: &str) -> Option<&'static intel::IntelFeed> {
        self.intel.index().feed_for(domain)
    }

    /// Download every threat feed now (the update-feeds API).
    pub fn update_threat_feeds(&self) {
        self.intel.update_now();
    }

    /// Each threat feed with its download state, for the status API.
    /// The language-model server's management side, for the console.
    pub fn llm(&self) -> Arc<llm::LlmManager> {
        self.llm.clone()
    }

    pub fn intel_status(&self) -> Vec<serde_json::Value> {
        self.intel.status()
    }

    /// The page-text model's state, for the status API.
    pub fn page_model_status(&self) -> serde_json::Value {
        self.page_model.status()
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
        &self.shared.learned
    }

    /// The model's maintenance state, for the status API.
    pub fn maintained_status(&self) -> serde_json::Value {
        self.shared.status()
    }

    /// Run the scheduled maintenance step now - judge a candidate whose
    /// trial ended, or build one when due, then refresh the verifier
    /// reference. The scan loop calls the same step after each cycle.
    /// Returns the build, if one ran.
    pub fn run_due_maintenance(&self) -> Option<Result<learn::TrainingStats>> {
        self.maintenance.run()
    }

    /// Put the previous model back in front of the scanner, live. Reversible:
    /// the model it replaces becomes the previous one.
    pub fn rollback_learned_model(&self) -> Result<()> {
        self.shared.retrainer.rollback()
    }

    /// Retrain the classifier now and put it live at once (the
    /// operator's explicit choice, so no shadow trial).
    pub fn retrain_learned_model(&self) -> Result<learn::TrainingStats> {
        self.shared.retrainer.retrain()
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
        // A threat label the operator set earlier says the opposite: the
        // newer decision wins.
        if self
            .store
            .category_override(domain)?
            .is_some_and(|label| self.settings.load().is_auto_block_category(&label))
        {
            self.store.clear_category_override(domain)?;
        }
        self.store.set_override(domain, "not_threat", reason)?;
        self.refresh_snapshot_now();
        Ok(())
    }

    /// Relabel `domain` as `category`: the operator's word on the domain,
    /// on both tabs. A label ticked as a threat makes it a threat (it
    /// blocks in enforce mode, whatever the model said); any other label is
    /// an ordinary category and stops the model's threat verdict from
    /// blocking. The scanner keeps classifying the domain underneath.
    pub fn set_category_override(&self, domain: &str, category: &str) -> Result<()> {
        if self.settings.load().is_auto_block_category(category) {
            // "Not a threat" says the opposite; the newer decision wins.
            if self
                .store
                .list_overrides()?
                .iter()
                .any(|o| o.domain == domain && o.action == "not_threat")
            {
                self.store.clear_override(domain)?;
            }
        }
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
    /// under the new rules and a scan is started. A verifier change reloads
    /// the threat channel in place. Returns whether the change also needs a
    /// restart: the models and the database are loaded once, at startup.
    pub fn apply_settings(&self, new: &AiSettings) -> bool {
        let old = self.settings.load_full();
        let mut restart = needs_restart(&old, new);
        let verifier_changed = verifier_changed(&old, new);
        self.settings.store(Arc::new(new.clone()));
        // The outside evidence was switched: the threat verdicts it touches
        // are re-checked on the next scan rather than at their expiry.
        if old.threat_feeds != new.threat_feeds
            || old.network_evidence != new.network_evidence
            || old.domain_age != new.domain_age
        {
            self.intel.recheck_evidence();
        }
        if verifier_changed && !restart {
            if let Err(e) = (self.reload_threat)() {
                tracing::warn!(error = %e, "could not reload the threat channel for the verifier");
                restart = true;
            }
        }
        // The label list moving is a decision about what the stored threat
        // verdicts mean, so the store follows it now: a label the operator
        // stopped treating as a threat takes its detections with it (a later
        // re-tick starts over from a fresh classification), and a label newly
        // declared a threat re-queues the domains whose categorization
        // already carries it, since while it was an ordinary category the
        // threat channel stored a `skipped` row. Both are bounded to the
        // domains in question and start the moment the list changes rather
        // than at each verdict's TTL.
        // Both sides are the effective set, so unticking a built-in family
        // through `auto_block_removals` withdraws its verdicts exactly as
        // editing the list does.
        let old_labels = old.threat_labels();
        let new_labels = new.threat_labels();
        let removed: Vec<String> = old_labels
            .iter()
            .filter(|label| !new.is_auto_block_category(label))
            .cloned()
            .collect();
        if !removed.is_empty() {
            match self.store.delete_threats_for_labels(&removed) {
                Ok(deleted) if deleted > 0 => tracing::info!(
                    labels = ?removed,
                    deleted,
                    "deleted threat verdicts for labels no longer treated as threats"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "could not delete threat verdicts for removed labels"
                ),
            }
        }
        let added: Vec<String> = new_labels
            .iter()
            .filter(|label| !old.is_auto_block_category(label))
            .cloned()
            .collect();
        if !added.is_empty() {
            match self.store.requeue_threats_for_labels(&added) {
                Ok(queued) if queued > 0 => tracing::info!(
                    labels = ?added,
                    queued,
                    "re-queued threat verdicts for newly declared threat labels"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "could not re-queue threat verdicts for newly declared labels"
                ),
            }
        }
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

    /// Snapshot accessor for the block test harness.
    pub fn snapshot(&self) -> Arc<ArcSwap<BlockSnapshot>> {
        self.snapshot.clone()
    }

    /// The model file the threat channel classifies with: the learned model
    /// when one is active, otherwise the configured one.
    pub fn live_model_path(&self) -> String {
        self.shared.model.load_full().to_string()
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

    /// The threat list as blocking sees it, with the confidence that qualified
    /// each row: the stored threats narrowed by everything the block snapshot
    /// applies (the label list with the shared classifier, and exemptions on
    /// the domain or any parent), strongest first.
    pub fn export_threats(&self) -> Result<Vec<(String, String, f32, i64)>> {
        let cfg = self.settings.load_full();
        let now = chrono::Utc::now().timestamp();
        let eligible = self.scanner.eligible_blocks(&cfg, now)?;
        // The operator's own threat labels are exported at full confidence,
        // with their label and no expiry, in place of the model's row.
        let mut rows: Vec<(String, String, f32, i64)> = self
            .store
            .export_threats(now, cfg.block_threshold)?
            .into_iter()
            .filter(|(domain, ..)| {
                eligible
                    .get(domain)
                    .is_some_and(|block| block.expires_at != i64::MAX)
            })
            .collect();
        let mut labelled: Vec<(String, String, f32, i64)> = eligible
            .into_iter()
            .filter(|(_, block)| block.expires_at == i64::MAX)
            .map(|(domain, block)| (domain, block.category, 1.0, i64::MAX))
            .collect();
        labelled.sort_by(|a, b| a.0.cmp(&b.0));
        labelled.append(&mut rows);
        Ok(labelled)
    }

    /// Categories the loaded backend can emit (model labels or heuristic
    /// rules), for the console's auto-block category picker.
    pub fn backend_categories(&self) -> Vec<String> {
        self.scanner.categories()
    }
}

/// Whether going from `old` to `new` changes what is loaded at startup: a
/// model or the database.
fn needs_restart(old: &AiSettings, new: &AiSettings) -> bool {
    old.model_path != new.model_path || old.database != new.database
}

/// Whether the verifier (its files or threshold) changed: applied live by
/// rebuilding the threat channel.
fn verifier_changed(old: &AiSettings, new: &AiSettings) -> bool {
    old.verifier_model_path != new.verifier_model_path
        || old.verifier_reference_path != new.verifier_reference_path
        || old.verifier_threshold != new.verifier_threshold
}

fn content_channel(
    model: &str,
    logs: &Arc<LogStore>,
) -> Result<Box<dyn DomainClassifier + Send + Sync>> {
    Ok(Box::new(channel::ChannelBackend::content(load_primary(
        model,
        Channel::Content,
        logs,
    )?)))
}

#[cfg_attr(not(feature = "verifier-onnx"), allow(unused_variables))]
fn threat_channel(
    model: &str,
    settings: &AiSettings,
    settings_swap: &Arc<ArcSwap<AiSettings>>,
    logs: &Arc<LogStore>,
    learned_reference: &Path,
    network: &Arc<evidence::NetworkEvidence>,
) -> Result<Box<dyn DomainClassifier + Send + Sync>> {
    let threat: Box<dyn DomainClassifier + Send + Sync> =
        Box::new(channel::ChannelBackend::threat(
            load_primary(model, Channel::Threat, logs)?,
            settings_swap.clone(),
        ));
    // The verifier second-checks the threat channel only: categorization
    // needs no second opinion, and a content label never blocks. A load
    // failure degrades to the primary classifier - it never disables the
    // AI subsystem.
    #[cfg(feature = "verifier-onnx")]
    let threat = wrap_verifier(threat, settings, logs, learned_reference);
    // Network evidence sits outside the verifier: a feed listing outranks a
    // MiniLM dispute, and it is the second opinion an install without ONNX
    // has. It reads `ai.network_evidence` live, so it is always in place.
    Ok(Box::new(evidence::EvidenceBackend::new(
        threat,
        network.clone(),
    )))
}

/// How soon verdicts are re-checked once a different model is live: spread
/// over this window, so a better model corrects old verdicts in days.
pub const MODEL_CHANGE_RECHECK_SECS: i64 = 3 * 86_400;
const LIVE_MODEL_KEY: &str = "live_model";

/// What identifies the model file in use: its path, size and modification
/// time (a promotion rewrites the same path).
fn model_fingerprint(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return "heuristic".to_string();
    }
    let (len, modified) = std::fs::metadata(path)
        .map(|m| {
            (
                m.len(),
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs()),
            )
        })
        .unwrap_or((0, 0));
    format!("{path}:{len}:{modified}")
}

/// Record the model now live; when it differs from the one before, bring
/// forward the re-check of the verdicts the old model made (see
/// [`AiStore::stagger_rechecks`]). Never fails the caller.
fn note_live_model(store: &AiStore, path: &str, logs: &LogStore) {
    let fingerprint = model_fingerprint(path);
    let before = store.meta(LIVE_MODEL_KEY).ok().flatten();
    if before.as_deref() == Some(fingerprint.as_str()) {
        return;
    }
    if before.is_some() {
        match store.stagger_rechecks(chrono::Utc::now().timestamp(), MODEL_CHANGE_RECHECK_SECS)
        {
            Ok(0) => {}
            Ok(n) => logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!(
                    "a different model is live: {n} verdict(s) will be re-checked over the next {} days",
                    MODEL_CHANGE_RECHECK_SECS / 86_400
                ),
            ),
            Err(e) => tracing::warn!(error = %e, "could not schedule re-checks after a model change"),
        }
    }
    if let Err(e) = store.set_meta(LIVE_MODEL_KEY, &fingerprint) {
        tracing::warn!(error = %e, "could not record the live model");
    }
}

/// Whether a learned model should be preferred over the configured one: it
/// exists and is at least as new (or nothing is configured).
fn prefer_learned(learned: &Path, configured: &str) -> bool {
    if !learned.is_file() {
        return false;
    }
    match Path::new(configured.trim())
        .metadata()
        .and_then(|m| m.modified())
    {
        Ok(configured_at) => learned
            .metadata()
            .and_then(|m| m.modified())
            .map(|learned_at| learned_at >= configured_at)
            .unwrap_or(false),
        // No configured model file (heuristic backend): the trained one is
        // all there is.
        Err(_) => true,
    }
}

fn announce(logs: &Arc<LogStore>, learned: bool, what: &str, file: &str) {
    logs.push(
        daygle_dns_core::LogLevel::Info,
        "ai",
        if learned {
            format!("the retrained {what} is now in use")
        } else {
            format!("the configured {what} is in use again: {file}")
        },
    );
}

/// The verifier reference the scanner refreshes from operator truth, beside
/// `ai.db`.
pub const LEARNED_REFERENCE_FILE: &str = "learned-centroids.json";

#[cfg(feature = "verifier-onnx")]
fn refresh_verifier_reference(
    store: &AiStore,
    settings: &AiSettings,
    out: &Path,
    logs: &Arc<LogStore>,
) -> bool {
    match reference::refresh(store, settings, out) {
        Ok(Some(note)) => {
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!("AI refreshed the verifier's reference from your corrections: {note}"),
            );
            true
        }
        Ok(None) => false,
        Err(e) => {
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "ai",
                format!("verifier reference not refreshed: {e}"),
            );
            false
        }
    }
}

#[cfg(not(feature = "verifier-onnx"))]
fn refresh_verifier_reference(
    _store: &AiStore,
    _settings: &AiSettings,
    _out: &Path,
    _logs: &Arc<LogStore>,
) -> bool {
    false
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
    learned_reference: &Path,
) -> Box<dyn DomainClassifier + Send + Sync> {
    // Trimmed as the emptiness checks are: a path pasted with a trailing
    // space was "configured" yet failed to load.
    let model_path = settings.verifier_model_path.trim();
    if model_path.is_empty() {
        return inner;
    }
    // A configured reference wins; else the one refreshed from your
    // corrections; else the one shipped beside the verifier model.
    let learned = learned_reference.to_string_lossy();
    let configured_reference = settings.verifier_reference_path.trim();
    let reference = if !configured_reference.is_empty() {
        Some(configured_reference)
    } else if learned_reference.is_file() {
        Some(learned.as_ref())
    } else {
        None
    };
    match verifier_onnx::MiniLmVerifier::load(model_path, reference) {
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
            |s: &mut AiSettings| s.model_path = "/m/other.bin".to_string(),
            |s: &mut AiSettings| s.database = "/d/ai.db".to_string(),
        ] {
            let mut new = old.clone();
            change(&mut new);
            assert!(needs_restart(&old, &new));
        }
        // The verifier is reloaded in place, not at a restart.
        for change in [
            |s: &mut AiSettings| s.verifier_model_path = "/m/v.onnx".to_string(),
            |s: &mut AiSettings| s.verifier_threshold += 0.1,
        ] {
            let mut new = old.clone();
            change(&mut new);
            assert!(!needs_restart(&old, &new));
            assert!(verifier_changed(&old, &new));
        }
    }
}
