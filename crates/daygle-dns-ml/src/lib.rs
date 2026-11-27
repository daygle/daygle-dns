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
pub mod assessment;
pub mod authority;
pub mod backend;
pub mod calibration;
pub mod candidate;
pub mod channel;
pub mod evidence;
pub mod fasttext_backend;
pub mod fusion;
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
pub mod signals;
pub mod store;
pub mod threshold;
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

/// How many scored verdicts one threshold trial reads.
const THRESHOLD_SAMPLES: u32 = 50_000;

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
    install_model: ModelInstaller,
}

/// Loads a model path into both live channels: what a candidate promotion and a
/// candidate rollback use to put the version's artifact in force.
type ModelInstaller = Arc<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// One verdict's structured evidence, for the console and the API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalReport {
    pub domain: String,
    pub observations: Vec<assessment::SignalObservation>,
    pub observed_at: i64,
    pub confidence: f32,
    pub threat_score: f32,
    pub severity: String,
    /// The fused view of the observations.
    pub fusion: fusion::Fusion,
    /// The calibrated score, when a calibration map is in force.
    pub calibrated: Option<f32>,
    pub calibration_version: String,
    /// The score the gate compares under the live fusion mode: the calibrated
    /// assessment when a map was in force, else the assessment score (the fused
    /// one when fusion decides, the confidence otherwise).
    pub gate_score: f32,
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
        let install_model: ModelInstaller = {
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
            Arc::new(move |path: &Path| {
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
        };
        shared.retrainer.set_installer({
            let install = install_model.clone();
            Box::new(move |path: &Path| install(path))
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
        scanner.set_intel(intel.clone());
        // A promoted candidate is already in force at startup: its calibration
        // map and signal weights are what the scanner applies from the first
        // cycle. With no active candidate (every existing install) these stay
        // the identity map and the default weights.
        if let Ok(Some(map)) = store.active_calibration() {
            scanner.set_calibration(Some(map));
        }
        if let Ok(Some(active)) = store.active_candidate() {
            scanner.set_signal_weights(active.signal_weights.clone());
        }
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
            install_model,
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

    /// The evidence inputs behind a stored threat verdict, each scored on its
    /// own: what the console shows as the Signals column and in the explain
    /// panel. None of them decides anything yet (see [`crate::signals`]).
    pub fn verdict_signals(
        &self,
        domain: &str,
        threat_score: f32,
        evidence: &str,
    ) -> Vec<signals::Signal> {
        let index = self.intel.index();
        signals::for_verdict(
            &signals::Context {
                store: &self.store,
                intel: &index,
            },
            domain,
            threat_score,
            evidence,
        )
    }

    /// The threshold trial in force (if any) and the most recent trials.
    pub fn threshold_status(
        &self,
        limit: u32,
    ) -> Result<(Option<store::ThresholdTrial>, Vec<store::ThresholdTrial>)> {
        Ok((
            self.store.applied_threshold_trial()?,
            self.store.threshold_trials(limit)?,
        ))
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
        // With autonomy off the AI does not build, trial or promote models on
        // its own; the operator's explicit retrain still runs.
        if !self.settings.load().autonomy {
            return None;
        }
        self.maintenance.run()
    }

    /// Run a threshold trial over the stored verdicts and the operator's
    /// corrections, and record it. It changes nothing: the candidate is
    /// applied only when the operator says so.
    pub fn run_threshold_trial(&self) -> Result<store::ThresholdTrial> {
        let settings = self.settings.load_full();
        let index = self.intel.index();
        let samples = threshold::collect(&self.store, &index, &settings, THRESHOLD_SAMPLES)?;
        let report = threshold::run(
            &samples,
            settings.threshold_fpr_target,
            settings.block_threshold,
        );
        let record = store::NewThresholdTrial {
            model: threshold::model_version(&self.live_model_path()),
            base_threshold: settings.block_threshold,
            candidate: report.candidate.unwrap_or(settings.block_threshold),
            fpr_target: settings.threshold_fpr_target,
            passed: report.passed,
            report: serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string()),
        };
        self.store.save_threshold_trial(&record)
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
        // Fusion decides which score the gate compares, so a mode change makes
        // every stored assessment describe the previous rule. Re-score them
        // before the snapshots are rebuilt: enforcement never compares a score
        // another mode produced, and the trial and the export then read the
        // numbers the gate uses.
        if old.fusion != new.fusion {
            match self.scanner.rescore_assessments(new) {
                Ok(0) => {}
                Ok(rescored) => tracing::info!(
                    rescored,
                    fusion = new.fusion.as_str(),
                    "re-scored stored verdicts for the new fusion mode"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    "could not re-score stored verdicts for the changed fusion mode; they keep their confidence until reclassified"
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
            .export_threats(now, cfg.block_threshold, cfg.fusion)?
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

impl AiEngine {
    /// The structured observations behind one threat verdict, with the fused
    /// view and the score the gate compares. Stored observations are returned
    /// as they were recorded; a verdict from before observations existed has
    /// them rebuilt from the sources available now, which the report marks
    /// with its `observed_at`.
    pub fn signal_report(&self, domain: &str) -> Result<Option<SignalReport>> {
        let Some(row) = self.store.verdict(domain, "threat")? else {
            return Ok(None);
        };
        let (observations, observed_at) = match self.store.observations(domain, "threat")? {
            Some((at, observations)) => (observations, at),
            None => {
                let index = self.intel.index();
                let now = chrono::Utc::now().timestamp();
                (
                    assessment::observe(
                        &assessment::Context {
                            store: &self.store,
                            intel: &index,
                        },
                        &assessment::AssessmentInput {
                            domain,
                            threat_score: row.threat_score,
                            confidence: row.confidence,
                            severity: &row.severity,
                            evidence: &row.evidence,
                            page: None,
                            now,
                        },
                    ),
                    now,
                )
            }
        };
        // The version, not the value, says whether a map was in force: a map
        // may legitimately calibrate a name to zero.
        let (calibrated, calibration_version) = self
            .store
            .verdict_scores(domain, "threat")?
            .map(|(score, version, _)| {
                if version.is_empty() {
                    (None, version)
                } else {
                    (Some(score), version)
                }
            })
            .unwrap_or((None, String::new()));
        // The number the gate compares for this verdict, read through the same
        // expression the gate, the trial and the export use.
        let gate_score = self
            .store
            .gate_score(domain, "threat", self.settings.load().fusion)?
            .unwrap_or(row.confidence);
        Ok(Some(SignalReport {
            domain: domain.to_string(),
            fusion: fusion::fuse(&observations, &self.scanner.signal_weights()),
            observations,
            observed_at,
            confidence: row.confidence,
            threat_score: row.threat_score,
            severity: row.severity,
            calibrated,
            calibration_version,
            gate_score,
        }))
    }

    /// The calibration map in force, the recorded candidates and the note
    /// that an uncalibrated confidence is not a real-world probability.
    pub fn calibration_status(&self) -> Result<serde_json::Value> {
        let active = self.store.active_calibration()?;
        let records = self.store.calibrations(50)?;
        Ok(serde_json::json!({
            "live_model": threshold::model_version(&self.live_model_path()),
            "active": active.as_ref().map(calibration_json),
            "calibration_active": active.is_some(),
            "candidates": records
                .iter()
                .map(|record| serde_json::json!({
                    "version": record.map.version,
                    "method": calibration_method(record.map.method),
                    "active": record.active,
                    "created_at": record.created_at,
                    "fitted_on": record.map.fitted_on,
                    "source_model": record.map.source_model,
                    "metrics": record.metrics,
                }))
                .collect::<Vec<_>>(),
            "note": "until a calibration map is active, the score is an assessment score, not a calibrated probability",
        }))
    }

    /// Fit a calibration map on the tuning split and evaluate it on the
    /// held-out split. It is recorded only when it is no worse than the map in
    /// force, and never activated: applying is a separate operator step.
    pub fn fit_calibration(&self) -> Result<serde_json::Value> {
        let settings = self.settings.load_full();
        let index = self.intel.index();
        let samples =
            threshold::collect_for_calibration(&self.store, &index, &settings, THRESHOLD_SAMPLES)?;
        let (mut tuning, mut holdout) = (Vec::new(), Vec::new());
        for sample in &samples {
            let Some(threat) = sample.threat else {
                continue;
            };
            let labelled = calibration::Labelled {
                score: sample.score,
                threat,
            };
            if threshold::held_out(&sample.domain) {
                holdout.push(labelled);
            } else {
                tuning.push(labelled);
            }
        }
        let source_model = threshold::model_version(&self.live_model_path());
        let Some(mut map) =
            calibration::fit(&tuning, &source_model, chrono::Utc::now().timestamp())
        else {
            return Ok(serde_json::json!({
                "fitted": false,
                "accepted": false,
                "reason": format!(
                    "not enough labelled evidence to fit a calibration: {} tuning and {} held-out sample(s)",
                    tuning.len(),
                    holdout.len()
                ),
                "tuning_samples": tuning.len(),
                "holdout_samples": holdout.len(),
            }));
        };
        let metrics = calibration::evaluate(&holdout, &map);
        let incumbent = self.store.active_calibration()?.and_then(|m| m.metrics);
        let acceptance = calibration::accept(&metrics, incumbent.as_ref());
        map.metrics = Some(metrics.clone());
        let recorded = if acceptance.accepted {
            self.store.save_calibration(&map, Some(&metrics))?
        } else {
            false
        };
        Ok(serde_json::json!({
            "fitted": true,
            "accepted": acceptance.accepted,
            "recorded": recorded,
            "reason": acceptance.reason,
            "version": map.version,
            "map": calibration_json(&map),
            "tuning_samples": tuning.len(),
            "holdout_samples": holdout.len(),
        }))
    }

    /// Put a recorded calibration map in force. A map that scores worse than
    /// the one in force on its held-out report is refused.
    pub fn apply_calibration(&self, version: &str) -> Result<serde_json::Value> {
        let records = self.store.calibrations(200)?;
        let record = records
            .into_iter()
            .find(|record| record.map.version == version)
            .ok_or_else(|| DaygleError::NotFound(format!("no calibration map {version}")))?;
        // A map is fitted to one model's score distribution. A retrain after
        // the fit replaces that distribution, so the held-out report no longer
        // describes the scores the map would be applied to.
        let live = threshold::model_version(&self.live_model_path());
        if record.map.source_model != live {
            return Err(DaygleError::Config(format!(
                "that calibration map was fitted for {}, but the live model is {live}: fit it again",
                record.map.source_model
            )));
        }
        let Some(metrics) = record
            .metrics
            .clone()
            .or_else(|| record.map.metrics.clone())
        else {
            return Err(DaygleError::Config(
                "that calibration map has no held-out report, so it cannot be compared with the one in force"
                    .to_string(),
            ));
        };
        let incumbent = self.store.active_calibration()?.and_then(|m| m.metrics);
        let acceptance = calibration::accept(&metrics, incumbent.as_ref());
        if !acceptance.accepted {
            return Err(DaygleError::Config(acceptance.reason));
        }
        let previous = self.store.active_calibration()?;
        self.store.activate_calibration(Some(version))?;
        self.scanner.set_calibration(Some(record.map.clone()));
        // The scores stored beside each verdict were produced with whatever map
        // was in force when it was classified. Apply the new map to all of them
        // before the snapshot is rebuilt, so enforcement never compares a
        // mixture of calibrated and uncalibrated scores. The re-score is one
        // transaction, so a failure leaves every row as it was and the previous
        // map can go back.
        if let Err(e) = self.rescore_stored_verdicts("the calibration map changed") {
            let mut failures = Vec::new();
            if let Err(undo) = self
                .store
                .activate_calibration(previous.as_ref().map(|m| m.version.as_str()))
            {
                failures.push(format!("could not put the previous map back: {undo}"));
            }
            self.scanner.set_calibration(previous.clone());
            return Err(failed_change(
                "could not apply the calibration map to the stored verdicts",
                e,
                &failures,
            ));
        }
        self.refresh_snapshot_now();
        Ok(serde_json::json!({
            "active": calibration_json(&record.map),
            "reason": acceptance.reason,
            "metrics": metrics,
        }))
    }

    /// Go back to the uncalibrated score: the confidence the gate compared
    /// before any map existed.
    pub fn disable_calibration(&self) -> Result<serde_json::Value> {
        let previous = self.store.active_calibration()?;
        self.store.activate_calibration(None)?;
        self.scanner.set_calibration(None);
        // Turning the map off makes every calibrated score describe a rule that
        // no longer applies, exactly as activating one does.
        if let Err(e) = self.rescore_stored_verdicts("calibration was turned off") {
            let mut failures = Vec::new();
            if let Some(map) = previous.as_ref() {
                if let Err(undo) = self.store.activate_calibration(Some(&map.version)) {
                    failures.push(format!("could not put the previous map back: {undo}"));
                }
                self.scanner.set_calibration(Some(map.clone()));
            }
            return Err(failed_change(
                "could not return the stored verdicts to the uncalibrated score",
                e,
                &failures,
            ));
        }
        self.refresh_snapshot_now();
        Ok(serde_json::json!({
            "active": null,
            "message": "calibration is off; the assessment score is compared directly, as before",
        }))
    }

    /// Record the complete scoring system as it stands now as a candidate
    /// version. Nothing is promoted.
    pub fn snapshot_candidate(&self) -> Result<store::CandidateVersion> {
        let settings = self.settings.load_full();
        let calibration = self.store.active_calibration()?;
        let validation = self
            .store
            .threshold_trials(1)?
            .into_iter()
            .next()
            .map(|trial| trial.report)
            .unwrap_or(serde_json::Value::Null);
        let metrics = calibration.as_ref().and_then(|m| m.metrics.clone());
        candidate::build(
            &self.store,
            &candidate::CandidateSpec {
                model_path: self.live_model_path(),
                block_threshold: settings.block_threshold,
                calibration,
                signal_weights: self.scanner.signal_weights(),
                // The AI overlay shape, so a promotion can restore these
                // fields through the same settings path the console uses.
                scoring_config: serde_json::json!({
                    "block_threshold": settings.block_threshold,
                    "fusion": settings.fusion,
                    "threshold_fpr_target": settings.threshold_fpr_target,
                    "confidence_floor": settings.confidence_floor,
                    "authority": settings.authority,
                    "auto_block_categories": settings.auto_block_categories,
                    "auto_block_removals": settings.auto_block_removals,
                    "threat_labels": settings.threat_labels(),
                }),
                validation_report: validation,
                metrics,
            },
        )
    }

    /// Every recorded candidate version, newest first.
    pub fn candidates_status(&self) -> Result<serde_json::Value> {
        let candidates = self.store.candidates(50)?;
        Ok(serde_json::json!({
            "active": candidates.iter().find(|c| c.is_active()).map(candidate_json),
            "candidates": candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        }))
    }

    /// Activate a candidate as one version: its artifact is written back and
    /// loaded, and its calibration and signal weights are published. The
    /// caller publishes the candidate's threshold through the config path (the
    /// engine does not own the configuration).
    pub fn promote_candidate(&self, id: i64) -> Result<store::CandidateVersion> {
        let Some(candidate) = self.store.candidate(id)? else {
            return Err(DaygleError::NotFound(format!("no candidate version {id}")));
        };
        // The version in force now, so a promotion that cannot be completed
        // puts exactly that back instead of leaving the candidate half applied.
        let previous = self.store.active_candidate()?;
        let live_model = self.live_model_path();
        // Write the artifact and load it *before* the store says the version is
        // in force: a model that does not load is not a version, and while it is
        // tried the store still describes the previous one.
        candidate::restore_artifact(&self.store, &candidate)?;
        if let Err(e) = (self.install_model)(Path::new(&candidate.model_path)) {
            return Err(self.undo_promotion(
                previous.as_ref(),
                &live_model,
                "could not load the candidate's model",
                e,
            ));
        }
        let promoted = match self.store.promote_candidate(id) {
            Ok(promoted) => promoted,
            Err(e) => {
                return Err(self.undo_promotion(
                    previous.as_ref(),
                    &live_model,
                    "could not record the promotion",
                    e,
                ));
            }
        };
        self.scanner
            .set_signal_weights(promoted.signal_weights.clone());
        let calibration = self.store.active_calibration()?;
        self.scanner.set_calibration(calibration);
        // A version is its whole scoring system, calibration included: the
        // stored scores describe the previous one until they are re-scored.
        if let Err(e) = self.rescore_stored_verdicts("a candidate was promoted") {
            let mut failures = Vec::new();
            match self.store.rollback_active_candidate() {
                Ok(Some(restored)) => failures.extend(self.restore_version(&restored)),
                Ok(None) => {
                    failures.push("there was no previous version to restore".to_string());
                }
                Err(e) => {
                    failures.push(format!("could not restore the previous version: {e}"));
                }
            }
            return Err(failed_change(
                "could not apply the new version's scores to the stored verdicts",
                e,
                &failures,
            ));
        }
        self.refresh_snapshot_now();
        self.trigger_rescan();
        Ok(promoted)
    }

    /// Restore the complete previous version: artifact bytes, threshold (the
    /// caller publishes it), calibration and signal weights together.
    pub fn rollback_candidate(&self) -> Result<Option<store::CandidateVersion>> {
        let Some(active) = self.store.active_candidate()? else {
            return Ok(None);
        };
        let Some(restored) = self.store.rollback_active_candidate()? else {
            return Ok(None);
        };
        candidate::restore_artifact(&self.store, &restored)?;
        (self.install_model)(Path::new(&restored.model_path))?;
        self.scanner
            .set_signal_weights(restored.signal_weights.clone());
        let calibration = self.store.active_calibration()?;
        self.scanner.set_calibration(calibration);
        if let Err(e) = self.rescore_stored_verdicts("a candidate was rolled back") {
            // The restored version is only in force once the stored scores
            // describe it: put the version that was rolled back from back.
            let mut failures = Vec::new();
            match self.store.promote_candidate(active.id) {
                Ok(_) => failures.extend(self.restore_version(&active)),
                Err(e) => failures.push(format!(
                    "could not put candidate {} back: {e}",
                    active.version
                )),
            }
            return Err(failed_change(
                "could not apply the restored version's scores to the stored verdicts",
                e,
                &failures,
            ));
        }
        self.refresh_snapshot_now();
        self.trigger_rescan();
        Ok(Some(restored))
    }

    /// Re-score every stored threat verdict from the observations kept beside it
    /// under the calibration map and fusion mode in force now. A score is a
    /// function of both, so rows scored before either changed would otherwise be
    /// compared - and fitted - under a rule that no longer applies.
    fn rescore_stored_verdicts(&self, what: &str) -> Result<usize> {
        let rescored = self
            .scanner
            .rescore_assessments(&self.settings.load_full())?;
        if rescored > 0 {
            tracing::info!(rescored, "re-scored stored verdicts: {what}");
        }
        Ok(rescored)
    }

    /// Undo a promotion that failed before the store changed: the file the
    /// candidate's artifact was written to takes the previous version's bytes
    /// back, and the channels load the model that was in force again. Returns
    /// the original failure, naming anything that could not be undone.
    ///
    /// With no previous candidate there is no earlier artifact in the store to
    /// write back; the configured model is reloaded from disk so the runtime
    /// keeps running, and the error says which file was left holding the failed
    /// version's bytes.
    fn undo_promotion(
        &self,
        previous: Option<&store::CandidateVersion>,
        live_model: &str,
        what: &str,
        cause: DaygleError,
    ) -> DaygleError {
        let mut failures = Vec::new();
        match previous {
            Some(previous) => {
                if let Err(e) = candidate::restore_artifact(&self.store, previous) {
                    failures.push(format!(
                        "could not write candidate {}'s artifact back: {e}",
                        previous.version
                    ));
                }
            }
            None => failures.push(format!(
                "no candidate was active, so the file holding the failed version's bytes ({live_model}) has no stored artifact to restore"
            )),
        }
        if let Err(e) = (self.install_model)(Path::new(live_model)) {
            failures.push(format!(
                "could not load the model that was in force again: {e}"
            ));
        }
        failed_change(what, cause, &failures)
    }

    /// Put one recorded version back into force: its artifact bytes, the loaded
    /// model, its signal weights and the calibration map the store holds for it.
    /// Returns what failed, so the caller can report it rather than drop it.
    fn restore_version(&self, version: &store::CandidateVersion) -> Vec<String> {
        let mut failures = Vec::new();
        if let Err(e) = candidate::restore_artifact(&self.store, version) {
            failures.push(format!(
                "could not write candidate {}'s artifact: {e}",
                version.version
            ));
        }
        if let Err(e) = (self.install_model)(Path::new(&version.model_path)) {
            failures.push(format!("could not load candidate {}: {e}", version.version));
        }
        self.scanner
            .set_signal_weights(version.signal_weights.clone());
        match self.store.active_calibration() {
            Ok(map) => self.scanner.set_calibration(map),
            Err(e) => failures.push(format!("could not read the calibration map in force: {e}")),
        }
        failures
    }

    /// Each source's graduated authority, its measured performance and the
    /// stage in force.
    pub fn authority_status(&self) -> Result<serde_json::Value> {
        let settings = self.settings.load_full();
        let decisions = authority::evaluate(&self.store, &settings.authority)?;
        Ok(serde_json::json!({
            "enabled": settings.authority.enabled,
            "settings": {
                "feed_stage": settings.authority.feed_stage.as_str(),
                "model_stage": settings.authority.model_stage.as_str(),
                "operator_stage": settings.authority.operator_stage.as_str(),
                "max_new_blocks_per_refresh": settings.authority.max_new_blocks_per_refresh,
                "safety_limit": crate::scanner::MAX_NEW_BLOCKS_PER_REFRESH,
                "demote_fp_rate": settings.authority.demote_fp_rate,
                "demote_min_samples": settings.authority.demote_min_samples,
            },
            "sources": decisions
                .iter()
                .map(|decision| serde_json::json!({
                    "source": decision.source.as_str(),
                    "configured": decision.configured.as_str(),
                    "effective": decision.effective.as_str(),
                    "false_positives": decision.false_positives,
                    "true_positives": decision.true_positives,
                    "demoted": decision.demoted,
                    "reason": decision.reason,
                }))
                .collect::<Vec<_>>(),
            "recorded": self
                .store
                .authority()?
                .iter()
                .map(|row| serde_json::json!({
                    "source": row.source,
                    "stage": row.stage,
                    "false_positives": row.false_positives,
                    "true_positives": row.true_positives,
                    "demoted_at": row.demoted_at,
                }))
                .collect::<Vec<_>>(),
            "note": "operator labels and overrides are never filtered or demoted by this",
        }))
    }
}

fn calibration_method(method: calibration::Method) -> &'static str {
    match method {
        calibration::Method::Identity => "identity",
        calibration::Method::Isotonic => "isotonic",
    }
}

fn calibration_json(map: &calibration::CalibrationMap) -> serde_json::Value {
    serde_json::json!({
        "version": map.version,
        "method": calibration_method(map.method),
        "points": map.points,
        "source_model": map.source_model,
        "fitted_on": map.fitted_on,
        "fitted_at": map.fitted_at,
        "metrics": map.metrics,
    })
}

pub fn candidate_json(candidate: &store::CandidateVersion) -> serde_json::Value {
    serde_json::json!({
        "id": candidate.id,
        "version": candidate.version,
        "status": candidate.status,
        "model_path": candidate.model_path,
        "model_sha256": candidate.model_sha256,
        "model_size": candidate.model_size,
        "block_threshold": candidate.block_threshold,
        "calibration_version": candidate.calibration_version,
        "calibration": candidate.calibration.as_ref().map(calibration_json),
        "signal_weights": candidate.signal_weights,
        "scoring_config": candidate.scoring_config,
        "validation_report": candidate.validation_report,
        "metrics": candidate.metrics,
        "superseded_id": candidate.superseded_id,
        "created_at": candidate.created_at,
        "promoted_at": candidate.promoted_at,
        "rolled_back_at": candidate.rolled_back_at,
    })
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
/// An error for a scoring change that could not be applied everywhere: the
/// original failure, plus whatever also failed while putting the previous
/// version back. Both are named, so a half-applied change is never silent.
fn failed_change(what: &str, cause: DaygleError, restorations: &[String]) -> DaygleError {
    let mut message = format!("{what}: {cause}");
    if !restorations.is_empty() {
        message.push_str("; putting the previous version back did not fully succeed: ");
        message.push_str(&restorations.join("; "));
    }
    tracing::error!(error = %message, "a scoring change could not be applied");
    DaygleError::Internal(message)
}

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
