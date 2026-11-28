//! The scanner's own model maintenance: retraining, shadow trials, promotion
//! and rollback.
//!
//! A [`Retrainer`] looks after the classifier. Its scheduled step ([`Retrainer::maybe_retrain`]) works in two stages:
//!
//! 1. **Candidate.** When a retrain is due it trains a candidate from the
//!    store ([`crate::learn`]) and runs the offline gates against the model
//!    in use: held-out corrections, held-out threat families, and every
//!    threat label the model in use can report.
//! 2. **Shadow trial.** A candidate that passes does *not* go live. It sits
//!    beside the live model for the trial window (half the retrain interval,
//!    one hour to a day) while the live model keeps classifying and
//!    blocking. When the window ends both are scored on what happened during
//!    it - held-out threats, the threats each finds among the domains the
//!    network looked up, the corrections the operator filed, and labels an
//!    independent source (the page, the verifier model) confirmed - and the
//!    candidate is promoted only if it is no worse on every one. A rejected
//!    candidate never affected a single answer; retraining then pauses and
//!    an alert says why.
//!
//! "Retrain Now" is the operator's explicit choice, so it skips the trial and
//! goes live at once; the previous model is always kept for a rollback.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::{LogLevel, LogStore};
use serde::{Deserialize, Serialize};

use crate::backend::{ClassificationInput, DomainClassifier};
use crate::evidence::NetworkEvidence;
use crate::intel::wanted_label;
use crate::learn::{
    bundled_starter_corpus, collect_dataset_with, held_out_variant, is_threat_label, model_labels,
    predict_all, previous_model_path, previous_stats_path, probe_accuracy, probe_threat_model,
    refuse_forgotten_threats, refuse_lost_threats, stats_path, top_label, train, Anchor, Dataset,
    Sources, TrainingStats, BENIGN_LABEL, MIN_ACCURACY, MIN_EXAMPLES, MIN_LABELS, VALIDATION_SLACK,
};
use crate::store::AiStore;

const ROTATION_KEY: &str = "manifest";

#[derive(Deserialize, Serialize)]
struct SavedFile {
    digest: String,
    modified: Option<std::time::SystemTime>,
}

fn rotation_files(learned: &Path) -> [PathBuf; 4] {
    [
        learned.to_path_buf(),
        previous_model_path(learned),
        stats_path(learned),
        previous_stats_path(learned),
    ]
}

fn begin_rotation(store: &AiStore, learned: &Path) -> Result<()> {
    let mut saved = Vec::new();
    let mut files = Vec::new();
    for path in rotation_files(learned) {
        let entry = match std::fs::read(&path) {
            Ok(bytes) => {
                use sha2::{Digest, Sha256};
                let digest = crate::candidate::hex(&Sha256::digest(&bytes));
                files.push((digest.clone(), bytes));
                Some(SavedFile {
                    digest,
                    modified: std::fs::metadata(&path)?.modified().ok(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        saved.push(entry);
    }
    let journal = serde_json::to_vec(&saved).map_err(|error| {
        DaygleError::Internal(format!("could not record model rotation: {error}"))
    })?;
    store.record_model_rotation(&journal, &files)
}

/// A rotation with a durable marker was interrupted. Restore its original
/// files before choosing a model. Keep the marker if any recovery step fails.
pub(crate) fn recover_rotation(store: &AiStore, learned: &Path) -> Result<bool> {
    let Some(journal) = store.model_rotation_backup(ROTATION_KEY)? else {
        return Ok(false);
    };
    let saved: [Option<SavedFile>; 4] = serde_json::from_slice(&journal).map_err(|error| {
        DaygleError::Database(format!("invalid model rotation journal: {error}"))
    })?;
    for (path, entry) in rotation_files(learned).into_iter().zip(saved) {
        if let Some(entry) = entry {
            let bytes = store.model_rotation_backup(&entry.digest)?.ok_or_else(|| {
                DaygleError::Database(format!("model rotation backup {} is missing", entry.digest))
            })?;
            if !crate::candidate::artifact_matches(&bytes, &entry.digest) {
                return Err(DaygleError::Database(format!(
                    "model rotation backup {} failed its digest check",
                    entry.digest
                )));
            }
            crate::candidate::write_artifact(&path, &bytes)?;
            if let Some(modified) = entry.modified {
                std::fs::File::options()
                    .write(true)
                    .open(&path)?
                    .set_modified(modified)?;
            }
        } else if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
    }
    store.finish_model_rotation()?;
    Ok(true)
}

/// Loads an accepted model file into the running channels. Set by the engine,
/// so every way a model goes live - a promotion, a manual retrain or a
/// rollback - goes live the same way.
pub type Installer = Box<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Runs once a model this retrainer installed is live, with the model now in
/// use: the engine retires a calibration map fitted for the model it replaced.
/// Never fails the install - the new model is already serving.
pub type InstalledHook = Box<dyn Fn(&Path) + Send + Sync>;
pub(crate) type ShadowScoring =
    Box<dyn Fn(&Path, &AiSettings, i64, i64) -> Result<serde_json::Value> + Send + Sync>;

/// What a passed replay says to put in force with the model: the calibration
/// map fitted on the tuning half and the threshold it validated. The engine
/// applies all of it through the candidate ledger, so a scheduled promotion is
/// the same recoverable record a manual promotion uses.
#[derive(Debug, Clone)]
pub struct TrialActivation {
    pub calibration: Option<crate::calibration::CalibrationMap>,
    pub threshold: f32,
    pub signal_weights: crate::fusion::SignalWeights,
    pub report: serde_json::Value,
}

/// Puts the validated scoring in force before the model is installed, and
/// hands back the step that takes it back out if the install then fails. The
/// activation is called with the candidate artifact and the path it will live
/// at, so the record it writes refers to the model that is about to be loaded
/// rather than a file that is about to be rotated away.
pub type Activation =
    Box<dyn Fn(&Path, &Path, &TrialActivation) -> Result<ActivationUndo> + Send + Sync>;

/// Takes a passed trial's scoring back out of force after the model it was
/// recorded for could not be installed. Returns what could not be restored, so
/// the caller can report a half-undone activation instead of dropping it.
pub struct ActivationUndo {
    undo: Box<dyn FnOnce() -> Vec<String> + Send + Sync>,
    complete: Box<dyn FnOnce() -> Result<()> + Send + Sync>,
}

impl ActivationUndo {
    pub fn new(
        undo: impl FnOnce() -> Vec<String> + Send + Sync + 'static,
        complete: impl FnOnce() -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            undo: Box::new(undo),
            complete: Box::new(complete),
        }
    }

    pub fn undo(self) -> Vec<String> {
        (self.undo)()
    }

    pub fn complete(self) -> Result<()> {
        (self.complete)()
    }
}

/// A maintenance step with nothing to report (the verifier refresh).
pub type Step = Box<dyn Fn() + Send + Sync>;

/// Everything the scan loop runs after a cycle: the model's scheduled step,
/// then the verifier reference refresh.
pub struct Maintenance {
    retrainer: Arc<Retrainer>,
    after: Step,
    scoring_change: tokio::sync::Mutex<()>,
}

impl Maintenance {
    pub fn new(retrainer: Arc<Retrainer>, after: Step) -> Self {
        Self {
            retrainer,
            after,
            scoring_change: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) async fn lock_scoring_change(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.scoring_change.lock().await
    }

    /// Run every due step. Returns the build, if one ran.
    pub fn run(&self) -> Option<Result<TrainingStats>> {
        // Leave due work queued while the API is publishing or restoring a
        // scoring change. DNS queries do not acquire this lock.
        let _scoring_change = self.scoring_change.try_lock().ok()?;
        let built = self.retrainer.maybe_retrain();
        (self.after)();
        built
    }
}

/// Trial outcomes kept for the console.
const TRIAL_HISTORY: usize = 20;
/// Fewest threats the live model must find on the trial's traffic before a
/// drop in detections counts as evidence.
const TRIAL_MIN_THREATS: usize = 10;
/// Fewest corrections, or independently confirmed labels, in the trial window
/// before scoring on them counts.
const TRIAL_MIN_TRUTHS: usize = 3;
/// How long a model promoted without the operator is watched after it goes
/// live (see [`Retrainer::check_watch`]).
pub const WATCH_SECS: i64 = 3 * 86_400;
/// "Not a threat" marks on a watched model's own detections that undo it.
const WATCH_MARKS: u64 = 3;
/// A watched model is undone when the share of scanned domains it blocks
/// grows past this multiple of the week before...
const WATCH_RATE_FACTOR: f64 = 2.0;
/// ...by at least this many domains (a handful is noise)...
const WATCH_RATE_MIN_EXTRA: f64 = 10.0;
/// ...judged once each side has classified this many domains.
const WATCH_MIN_CLASSIFIED: u64 = 200;
/// The week before a promotion, as the watch's baseline.
const WATCH_BASELINE_SECS: i64 = 7 * 86_400;
/// Rejected trials in a row after which retraining backs off further.
const REJECTION_STREAK: usize = 3;
/// The longest retraining pauses after repeated rejections.
const MAX_PAUSE_SECS: i64 = 7 * 86_400;

/// Most recent domains a trial compares the two models on.
const TRIAL_DOMAINS: u32 = 5_000;

/// Where a candidate on trial waits.
pub fn candidate_path(learned: &Path) -> PathBuf {
    learned.with_extension("candidate.bin")
}

/// Where the trial of a candidate (and the history of past ones) is kept.
pub fn trial_path(learned: &Path) -> PathBuf {
    learned.with_extension("trial.json")
}

/// How long a candidate is on trial: half the retrain interval, between one
/// hour and a day.
pub fn trial_secs(settings: &AiSettings) -> i64 {
    (settings.retrain_interval_secs / 2).clamp(3_600, 86_400) as i64
}

/// One concluded trial, for the console's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialEntry {
    pub at: i64,
    pub outcome: String,
}

/// The state of a model's trials: a candidate in progress (`started_at` /
/// `ends_at`), a pause on retraining after a rejection, and past outcomes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trial {
    pub started_at: Option<i64>,
    pub ends_at: Option<i64>,
    /// No scheduled retrain before this.
    pub retry_after: Option<i64>,
    pub last_outcome: Option<String>,
    /// Newest first, at most [`TRIAL_HISTORY`].
    pub history: Vec<TrialEntry>,
    /// The held-out replay's report for the last concluded trial, as JSON
    /// text, kept even when the candidate was rejected: it is the diagnostic
    /// result the operator can read.
    pub shadow_scoring: Option<String>,
}

impl Trial {
    /// Read a trial record ([`Self::to_json`]'s shape, as the status API
    /// reports it).
    pub fn from_json(value: &serde_json::Value) -> Self {
        let int = |key: &str| value.get(key).and_then(|v| v.as_i64());
        Self {
            started_at: int("started_at"),
            ends_at: int("ends_at"),
            retry_after: int("retry_after"),
            last_outcome: value
                .get("last_outcome")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            shadow_scoring: value.get("shadow_scoring").map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            }),
            history: value
                .get("history")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| {
                            Some(TrialEntry {
                                at: entry.get("at")?.as_i64()?,
                                outcome: entry.get("outcome")?.as_str()?.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The record as JSON, also what the status API reports.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "started_at": self.started_at,
            "ends_at": self.ends_at,
            "retry_after": self.retry_after,
            "last_outcome": self.last_outcome,
            "shadow_scoring": self
                .shadow_scoring
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok()),
            "history": self
                .history
                .iter()
                .map(|entry| serde_json::json!({ "at": entry.at, "outcome": entry.outcome }))
                .collect::<Vec<_>>(),
        })
    }

    /// Whether a candidate is on trial now.
    pub fn in_progress(&self) -> bool {
        self.started_at.is_some() && self.ends_at.is_some()
    }

    /// End any trial in progress with `outcome`, recorded in the history.
    fn concluded(&self, outcome: String, retry_after: Option<i64>) -> Self {
        let mut history = self.history.clone();
        history.insert(
            0,
            TrialEntry {
                at: chrono::Utc::now().timestamp(),
                outcome: outcome.clone(),
            },
        );
        history.truncate(TRIAL_HISTORY);
        Self {
            started_at: None,
            ends_at: None,
            retry_after,
            last_outcome: Some(outcome),
            history,
            shadow_scoring: None,
        }
    }

    /// Attach the replay report to the record the status API reports.
    fn with_scoring(mut self, scoring: Option<&serde_json::Value>) -> Self {
        self.shadow_scoring = scoring.map(|value| value.to_string());
        self
    }
}

/// A model that classifies a domain the way the live channel does: a fastText
/// file, or the built-in heuristic rules when there is no model file (which
/// is what a channel falls back to, too).
pub(crate) enum Predictor {
    FastText(Box<fasttext::FastText>),
    Heuristic,
}

impl Predictor {
    pub(crate) fn load(path: &str) -> Result<Self> {
        let path = path.trim();
        if path.is_empty() || !Path::new(path).is_file() {
            return Ok(Self::Heuristic);
        }
        fasttext::FastText::load_model(path)
            .map(|model| Self::FastText(Box::new(model)))
            .map_err(|e| DaygleError::Config(format!("model load failed: {e:?}")))
    }

    pub(crate) fn label(&self, domain: &str) -> String {
        match self {
            Self::FastText(model) => top_label(model, domain).unwrap_or_default(),
            Self::Heuristic => crate::heuristic::HeuristicBackend
                .classify(&ClassificationInput::domain_only(domain))
                .map(|verdict| verdict.category.to_ascii_lowercase())
                .unwrap_or_default(),
        }
    }
}

/// What a candidate build produced.
struct Built {
    temp: PathBuf,
    stats: TrainingStats,
    train_accuracy: f32,
    validation_examples: usize,
    validation_accuracy: Option<f32>,
    threat_validation_examples: usize,
    intel_validation_examples: usize,
    established_probe_examples: usize,
    binary_training: Option<serde_json::Value>,
}

impl Built {
    fn record(&self) -> serde_json::Value {
        serde_json::json!({
            "trained_at": chrono::Utc::now().to_rfc3339(),
            "examples": self.stats.examples,
            "labels": self.stats.labels,
            "corrections": self.stats.corrections,
            "verdicts": self.stats.verdicts,
            "negatives": self.stats.negatives,
            "starter": self.stats.starter,
            "unconfirmed": self.stats.unconfirmed,
            "train_accuracy": (self.train_accuracy * 100.0).round() / 100.0,
            "validation_examples": self.validation_examples,
            "validation_accuracy": self.validation_accuracy
                .map(|a| (a * 100.0).round() / 100.0),
            "threat_validation_examples": self.threat_validation_examples,
            "intel": self.stats.intel,
            "intel_validation_examples": self.intel_validation_examples,
            "established_probe_examples": self.established_probe_examples,
            "binary_training": self.binary_training,
        })
    }
}

/// Maintains one model: builds candidates, trials them in the shadow of the
/// live model, promotes or rejects them, and rolls back on request.
pub struct Retrainer {
    store: Arc<AiStore>,
    settings: Arc<ArcSwap<AiSettings>>,
    logs: Arc<LogStore>,
    learned: PathBuf,
    /// The model file the live channel loaded: the baseline every candidate
    /// is judged against.
    current_model: Arc<ArcSwap<String>>,
    last_attempt: Mutex<Option<i64>>,
    /// One build, promotion or rollback at a time: they share the temp file
    /// and rotate the same model files.
    running: Mutex<()>,
    binary_name_model: std::sync::atomic::AtomicBool,
    installer: OnceLock<Installer>,
    installed: OnceLock<InstalledHook>,
    shadow_scoring: OnceLock<ShadowScoring>,
    activation: OnceLock<Activation>,
    /// Threat feeds and this network's usage: confirmation, probes and trial
    /// truths that do not depend on the operator.
    evidence: OnceLock<Arc<NetworkEvidence>>,
}

impl Retrainer {
    pub fn new(
        store: Arc<AiStore>,
        settings: Arc<ArcSwap<AiSettings>>,
        logs: Arc<LogStore>,
        learned: PathBuf,
        current_model: Arc<ArcSwap<String>>,
    ) -> Self {
        Self {
            store,
            settings,
            logs,
            learned,
            current_model,
            last_attempt: Mutex::new(None),
            running: Mutex::new(()),
            binary_name_model: std::sync::atomic::AtomicBool::new(false),
            installer: OnceLock::new(),
            installed: OnceLock::new(),
            shadow_scoring: OnceLock::new(),
            activation: OnceLock::new(),
            evidence: OnceLock::new(),
        }
    }

    /// Hand the retrainer the network evidence (threat feeds, established
    /// domains). Without it only the operator's corrections and the page
    /// confirm, probe and judge.
    pub fn set_evidence(&self, evidence: Arc<NetworkEvidence>) {
        let _ = self.evidence.set(evidence);
    }

    /// Hand the retrainer the step that loads a model into the running
    /// channels. Without one (tests of the files alone) a model is only
    /// written to disk.
    pub fn set_installer(&self, installer: Installer) {
        let _ = self.installer.set(installer);
    }

    pub(crate) fn set_binary_name_model(&self, active: bool) {
        self.binary_name_model
            .store(active, std::sync::atomic::Ordering::Relaxed);
    }

    fn uses_binary_name_model(&self) -> bool {
        self.binary_name_model
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Hand the retrainer a step that runs once a model it installed is live.
    pub fn set_installed(&self, installed: InstalledHook) {
        let _ = self.installed.set(installed);
    }

    pub(crate) fn set_shadow_scoring(&self, scoring: ShadowScoring) {
        let _ = self.shadow_scoring.set(scoring);
    }

    /// Hand the retrainer the step that puts a passed replay's calibration and
    /// threshold in force with the model, as one recorded version.
    pub fn set_activation(&self, activation: Activation) {
        let _ = self.activation.set(activation);
    }

    /// The model file this retrainer maintains.
    pub fn learned_model(&self) -> &Path {
        &self.learned
    }

    /// The model the operator configured: the fixed reference.
    fn configured_model(&self, settings: &AiSettings) -> String {
        if settings.model_path.trim() == crate::learn::BUILTIN_BINARY_MODEL {
            return self
                .learned
                .with_file_name(crate::learn::BINARY_STARTER_FILE)
                .to_string_lossy()
                .into_owned();
        }
        settings.model_path.trim().to_string()
    }

    fn log(&self, level: LogLevel, message: String) {
        self.logs.push(level, "ai", message);
    }

    // ── Building a candidate ────────────────────────────────────────────

    /// The configured model as the fixed reference for anchored training:
    /// only a loadable fastText file that is not the learned model itself.
    fn anchor_model(&self, settings: &AiSettings) -> Option<fasttext::FastText> {
        let configured = self.configured_model(settings);
        let path = Path::new(&configured);
        if configured.is_empty() || !path.is_file() || path == self.learned {
            return None;
        }
        fasttext::FastText::load_model(path).ok()
    }

    /// Train a candidate into the temp file and run every offline gate on it
    /// against the live model. The caller decides what happens to it.
    fn build(&self, settings: &AiSettings) -> Result<Built> {
        if self.uses_binary_name_model() {
            return self.build_binary(settings);
        }
        let current_path = self.current_model.load_full().to_string();
        let current_model = (!current_path.trim().is_empty()).then(|| PathBuf::from(&current_path));
        let current_labels = current_model.as_deref().and_then(model_labels);
        // The configured model is the fixed reference the scanner's own
        // verdicts are checked against, and the corpus beside it - when a
        // models bundle shipped one - is the starter set that matches it.
        let anchor = self.anchor_model(settings);
        let corpus = bundled_starter_corpus(&self.configured_model(settings));
        let confirmations = self.store.independent_labels().unwrap_or_default();
        let evidence = self.evidence.get().cloned();
        let intel = evidence.as_ref().map(|e| e.intel());
        let established = evidence
            .as_ref()
            .map(|e| e.established_sample())
            .unwrap_or_default();
        let Dataset {
            pairs,
            validation,
            threat_validation,
            intel_validation,
            stats,
        } = collect_dataset_with(
            &self.store,
            settings,
            &Sources {
                known: current_labels.as_ref(),
                starter: corpus.as_deref(),
                // No configured model: the keyword rules are the fixed
                // reference, never nothing.
                anchor: Some(anchor.as_ref().map_or(Anchor::Rules, Anchor::Model)),
                confirmations: Some(&confirmations),
                intel: intel.as_deref(),
            },
        )?;
        // The starter corpus is always there, so what decides whether a
        // retrain is worth running is what this network contributed.
        // Threat-feed names count: they are current material the shipped
        // model has not seen, so an install with few corrections still keeps
        // its threat labels up to date.
        if stats.local() + stats.intel < MIN_EXAMPLES || stats.labels < MIN_LABELS {
            return Err(DaygleError::Config(format!(
                "not enough training data yet: {} examples across {} labels (a retrain needs {} and {})",
                stats.local() + stats.intel,
                stats.labels,
                MIN_EXAMPLES,
                MIN_LABELS
            )));
        }

        let temp = self.learned.with_extension("tmp");
        let judged = self.gates(
            settings,
            &temp,
            &pairs,
            &validation,
            &threat_validation,
            &Probes {
                intel: &intel_validation,
                established: &established,
            },
            current_model.as_deref(),
            current_labels.as_ref(),
        );
        match judged {
            Ok((train_accuracy, validation_accuracy)) => Ok(Built {
                temp,
                stats,
                train_accuracy,
                validation_examples: validation.len(),
                validation_accuracy,
                threat_validation_examples: threat_validation.len(),
                intel_validation_examples: intel_validation.len(),
                established_probe_examples: established.len(),
                binary_training: None,
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                Err(e)
            }
        }
    }

    fn build_binary(&self, settings: &AiSettings) -> Result<Built> {
        let intel = self
            .evidence
            .get()
            .map(|evidence| evidence.intel())
            .unwrap_or_default();
        let now = chrono::Utc::now().timestamp();
        let outcomes = crate::learn::binary_outcomes(&self.store, settings, &intel, false, now)?;
        let threats = outcomes.iter().filter(|(_, threat, _)| *threat).count();
        let intel_examples = outcomes
            .iter()
            .filter(|(_, _, source)| *source == crate::threshold::LabelSource::FeedListing)
            .count();
        let direct_page_examples = outcomes
            .iter()
            .filter(|(_, _, source)| *source == crate::threshold::LabelSource::DirectPage)
            .count();
        let negatives = outcomes.len() - threats;
        if threats < 20 || negatives < 20 {
            return Err(DaygleError::Config(format!(
                "binary retraining needs 20 independent training names per class ({threats} threat, {negatives} ordinary)"
            )));
        }
        let mut pairs: Vec<_> = outcomes
            .into_iter()
            .map(|(domain, threat, _)| crate::learn::binary_pair(domain, threat))
            .collect();
        let starter: Vec<_> = crate::learn::binary_starter_pairs()
            .into_iter()
            .filter(|(_, domain)| !crate::threshold::held_out(domain))
            .collect();
        let stats = TrainingStats {
            examples: pairs.len() + starter.len(),
            labels: 2,
            intel: intel_examples,
            negatives,
            starter: starter.len(),
            ..TrainingStats::default()
        };
        pairs.extend(starter);
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for (label, domain) in &pairs {
            hash.update(label);
            hash.update(b" ");
            hash.update(domain);
            hash.update(b"\n");
        }
        let digest = crate::candidate::hex(&hash.finalize());
        let reference = settings.model_path.trim();
        let training = serde_json::json!({ "reference": reference, "digest": digest,
            "independent_threats": threats, "independent_ordinary": negatives,
            "direct_page_threats": direct_page_examples });
        if crate::learn::binary_training_record(&self.learned).as_ref() == Some(&training) {
            return Err(DaygleError::Config(
                "no new independent binary training outcomes".to_string(),
            ));
        }
        let temp = self.learned.with_extension("tmp");
        let trained = train(&pairs, &temp).and_then(|()| probe_accuracy(&temp, &pairs));
        let train_accuracy = match trained {
            Ok(accuracy) if accuracy >= MIN_ACCURACY => accuracy,
            result => {
                let _ = std::fs::remove_file(&temp);
                return Err(result.err().unwrap_or_else(|| {
                    DaygleError::Config(
                        "binary model did not pass the training sanity check".to_string(),
                    )
                }));
            }
        };
        Ok(Built {
            temp,
            stats,
            train_accuracy,
            validation_examples: 0,
            validation_accuracy: None,
            threat_validation_examples: 0,
            intel_validation_examples: 0,
            established_probe_examples: 0,
            binary_training: Some(training),
        })
    }

    /// The offline gates: train accuracy, held-out corrections, held-out
    /// threat families, and threat labels the live model can report.
    #[allow(clippy::too_many_arguments)]
    fn gates(
        &self,
        settings: &AiSettings,
        temp: &Path,
        pairs: &[(String, String)],
        validation: &[(String, String)],
        threat_validation: &[(String, String)],
        probes: &Probes<'_>,
        current_model: Option<&Path>,
        current_labels: Option<&HashSet<String>>,
    ) -> Result<(f32, Option<f32>)> {
        train(pairs, temp)?;
        let train_accuracy = probe_accuracy(temp, pairs)?;

        // A candidate that forgot a threat label can never report it again.
        let candidate_labels = model_labels(temp).unwrap_or_default();
        refuse_forgotten_threats(settings, current_labels, &candidate_labels)?;

        let mut validation_accuracy = None;
        if validation.is_empty() {
            if train_accuracy < MIN_ACCURACY {
                return Err(DaygleError::Config(format!(
                    "the retrained model reproduced only {:.0}% of its own training data, so the current model was kept",
                    train_accuracy * 100.0
                )));
            }
        } else {
            let candidate = probe_accuracy(temp, validation)?;
            let baseline = current_model.and_then(|model| probe_accuracy(model, validation).ok());
            if candidate < MIN_ACCURACY {
                return Err(DaygleError::Config(format!(
                    "the retrained model scored {:.0}% on {} held-out corrections, so the current model was kept",
                    candidate * 100.0,
                    validation.len()
                )));
            }
            if let Some(baseline) = baseline {
                if candidate + VALIDATION_SLACK < baseline {
                    return Err(DaygleError::Config(format!(
                        "the retrained model scored {:.0}% on {} held-out corrections against {:.0}% for the model in use, so the current model was kept",
                        candidate * 100.0,
                        validation.len(),
                        baseline * 100.0
                    )));
                }
            }
            validation_accuracy = Some(candidate);
        }

        // However well the candidate scores overall, it may not stop reading
        // a held-out threat as a threat - as `benign` or as any label that
        // would not block - more often than the live model does.
        if !threat_validation.is_empty() {
            let probe: Vec<(String, String)> = threat_validation
                .iter()
                .map(|(label, domain)| (label.clone(), held_out_variant(domain)))
                .collect();
            let predicted = predict_all(temp, &probe)?;
            let is_threat = |label: &str| is_threat_label(settings, label);
            let (mut benign, mut downgraded, mut checked) = (0usize, 0usize, 0usize);
            for ((label, _), got) in probe.iter().zip(&predicted) {
                if !is_threat(label) {
                    continue;
                }
                checked += 1;
                if got == BENIGN_LABEL {
                    benign += 1;
                } else if !is_threat(got) {
                    downgraded += 1;
                }
            }
            let baseline_lost = match current_model.map(|model| predict_all(model, &probe)) {
                Some(Ok(baseline)) => baseline
                    .iter()
                    .zip(&probe)
                    .filter(|(got, (label, _))| {
                        is_threat(label) && (*got == BENIGN_LABEL || !is_threat(got))
                    })
                    .count(),
                _ => 0,
            };
            refuse_lost_threats(checked, benign, downgraded, baseline_lost)?;
        }

        // Evidence the operator did not have to provide: threat-feed names
        // held out of training, and domains this network has relied on for
        // weeks. The candidate may not detect fewer of the first or flag more
        // of the second than the model in use.
        if !probes.is_empty() {
            let candidate = Predictor::load(&temp.to_string_lossy())?;
            let live = Predictor::load(
                &current_model
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )?;
            let is_threat = |label: &str| is_threat_label(settings, label);
            probes.judge(&candidate, &live, &is_threat).map_err(|why| {
                DaygleError::Config(format!("{why}, so the current model was kept"))
            })?;
        }
        Ok((train_accuracy, validation_accuracy))
    }

    // ── Going live ──────────────────────────────────────────────────────

    fn with_rotation(&self, change: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.store.model_rotation_backup(ROTATION_KEY)?.is_some() {
            return Err(DaygleError::Database(
                "a model rotation still needs recovery; restart before changing classifiers"
                    .to_string(),
            ));
        }
        begin_rotation(&self.store, &self.learned)?;
        match change() {
            Ok(()) => self.store.finish_model_rotation(),
            Err(cause) => {
                if let Err(recovery) = recover_rotation(&self.store, &self.learned) {
                    return Err(DaygleError::Internal(format!(
                        "model rotation failed: {cause}; recovery also failed: {recovery}"
                    )));
                }
                Err(cause)
            }
        }
    }

    fn install(&self) -> Result<()> {
        self.install_path(&self.learned)
    }

    fn install_path(&self, path: &Path) -> Result<()> {
        if let Some(install) = self.installer.get() {
            install(path)?;
        }
        // The model is live now: whatever the engine keys to the identity of
        // the model it replaced is stale (see [`Self::set_installed`]).
        if let Some(installed) = self.installed.get() {
            installed(path);
        }
        Ok(())
    }

    /// Put `file` in place as the learned model and load it: the model it
    /// replaces becomes the previous one, and every failure puts the files
    /// back the way they were.
    fn promote(&self, file: &Path, record: &serde_json::Value) -> Result<()> {
        self.with_rotation(|| self.promote_files(file, record))
    }

    fn promote_files(&self, file: &Path, record: &serde_json::Value) -> Result<()> {
        let previous = previous_model_path(&self.learned);
        if self.learned.is_file() {
            std::fs::rename(&self.learned, &previous)?;
            swap_stats(&self.learned, StatsMove::CurrentToPrevious);
        }
        std::fs::rename(file, &self.learned)?;
        self.install().map_err(|error| {
            DaygleError::Config(format!("the new model could not be loaded: {error}"))
        })?;
        match serde_json::to_vec_pretty(record) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(stats_path(&self.learned), bytes) {
                    self.log(
                        LogLevel::Warn,
                        format!("could not record the retrain result: {e}"),
                    );
                }
            }
            Err(e) => self.log(
                LogLevel::Warn,
                format!("could not encode the retrain result: {e}"),
            ),
        }
        Ok(())
    }

    /// Retrain now and put the result live at once: the operator's explicit
    /// choice, so no shadow trial. A candidate on trial is discarded.
    pub fn retrain(&self) -> Result<TrainingStats> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if self.uses_binary_name_model() {
            return Err(DaygleError::Config("train binary name models from explicit binary outcomes with train-binary-name-model".to_string()));
        }
        let settings = self.settings.load_full();
        let built = self.build(&settings)?;
        if self.discard_candidate() {
            self.write_trial(
                &self
                    .trial()
                    .concluded("candidate replaced by a manual retrain".to_string(), None),
            );
        }
        let record = built.record();
        if let Err(e) = self.promote(&built.temp, &record) {
            let _ = std::fs::remove_file(&built.temp);
            return Err(e);
        }
        // The operator put this model live: it is not watched.
        let _ = std::fs::remove_file(self.watch_path());
        self.log(
            LogLevel::Info,
            format!(
                "AI retrained its classifier from {} examples across {} labels ({} from your corrections, {} from the starter corpus, {} unconfirmed verdicts left out); it is in use now",
                built.stats.examples,
                built.stats.labels,
                built.stats.corrections,
                built.stats.starter,
                built.stats.unconfirmed
            ),
        );
        Ok(built.stats)
    }

    /// Whether a previous model is kept and can be restored.
    pub fn has_previous(&self) -> bool {
        previous_model_path(&self.learned).is_file()
    }

    /// Swap the previous model back in for the current one and load it.
    /// Both files are kept, so this is itself reversible.
    pub fn rollback(&self) -> Result<()> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        // The operator chose the model now: nothing is left to watch.
        let _ = std::fs::remove_file(self.watch_path());
        let previous = previous_model_path(&self.learned);
        if !previous.is_file() {
            return Err(DaygleError::Config(
                "there is no previous model to restore".to_string(),
            ));
        }
        self.with_rotation(|| {
            self.swap_with_previous()?;
            self.install().map_err(|error| {
                DaygleError::Config(format!("the previous model could not be loaded: {error}"))
            })
        })?;
        // A candidate was judged against the model just replaced; it is
        // no longer a fair comparison.
        if self.discard_candidate() {
            self.write_trial(
                &self
                    .trial()
                    .concluded("candidate discarded by a manual restore".to_string(), None),
            );
        }
        self.log(
            LogLevel::Info,
            "restored the previous classifier".to_string(),
        );
        Ok(())
    }

    fn swap_with_previous(&self) -> Result<()> {
        let previous = previous_model_path(&self.learned);
        let staged = self.learned.with_extension("rolled-back.bin");
        std::fs::rename(&self.learned, &staged)?;
        std::fs::rename(&previous, &self.learned)?;
        std::fs::rename(&staged, &previous)?;
        swap_stats(&self.learned, StatsMove::Exchange);
        Ok(())
    }

    // ── The scheduled step and the shadow trial ─────────────────────────

    /// The trial state beside the model.
    pub fn trial(&self) -> Trial {
        std::fs::read(trial_path(&self.learned))
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
            .map(|value| Trial::from_json(&value))
            .unwrap_or_default()
    }

    /// Finish durable trial/watch bookkeeping after startup recovered a
    /// scheduled activation. Idempotent so a second interruption retries it.
    pub(crate) fn complete_recovered_activation(
        &self,
        candidate: &crate::store::CandidateVersion,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let watch_path = self.watch_path();
        let existing_watch = std::fs::read(&watch_path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok());
        let same_watch = existing_watch
            .as_ref()
            .and_then(|watch| watch.get("candidate_id"))
            .and_then(serde_json::Value::as_i64)
            == Some(candidate.id);
        let watch = if same_watch {
            existing_watch.unwrap_or_default()
        } else {
            serde_json::json!({
                "candidate_id": candidate.id,
                "promoted_at": now,
                "until": now + WATCH_SECS,
            })
        };
        let watch_bytes = serde_json::to_vec_pretty(&watch).map_err(|error| {
            DaygleError::Internal(format!("could not encode model watch: {error}"))
        })?;
        std::fs::write(&watch_path, watch_bytes)?;

        let trial = self.trial();
        let concluded_scoring = trial
            .shadow_scoring
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
        let already_concluded = trial
            .last_outcome
            .as_deref()
            .is_some_and(|outcome| outcome.starts_with("promoted:"))
            && concluded_scoring.as_ref() == Some(&candidate.validation_report);
        if !already_concluded {
            let reason = candidate
                .validation_report
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("validated scheduled replay");
            let concluded = trial
                .concluded(format!("promoted: {reason}; completed after restart"), None)
                .with_scoring(Some(&candidate.validation_report));
            let trial_bytes = serde_json::to_vec_pretty(&concluded.to_json()).map_err(|error| {
                DaygleError::Internal(format!("could not encode completed model trial: {error}"))
            })?;
            std::fs::write(trial_path(&self.learned), trial_bytes)?;
        }
        self.store.finish_scheduled_activation(candidate.id)
    }

    fn write_trial(&self, trial: &Trial) {
        let written = serde_json::to_vec_pretty(&trial.to_json())
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(trial_path(&self.learned), bytes));
        if let Err(e) = written {
            self.log(
                LogLevel::Warn,
                format!("could not record the model trial: {e}"),
            );
        }
    }

    /// Whether a candidate is waiting on trial.
    pub fn has_candidate(&self) -> bool {
        candidate_path(&self.learned).is_file()
    }

    /// Drop a waiting candidate; true when there was one.
    fn discard_candidate(&self) -> bool {
        let candidate = candidate_path(&self.learned);
        let existed = candidate.is_file();
        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_file(candidate.with_extension("json"));
        existed
    }

    /// The scheduled step: judge a candidate whose trial has ended, or build
    /// a new one when automatic retraining is on and one is due. `None`
    /// means nothing was built. Failures are logged and returned; they never
    /// disturb the scan loop.
    pub fn maybe_retrain(&self) -> Option<Result<TrainingStats>> {
        let settings = self.settings.load_full();
        if !settings.enabled {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        if self.check_watch(&settings, now) {
            return None;
        }
        let trial = self.trial();
        if trial.in_progress() {
            if trial.ends_at.is_some_and(|ends| now >= ends) {
                self.conclude_trial(&settings, &trial);
            }
            return None;
        }
        if trial.retry_after.is_some_and(|after| now < after) {
            return None;
        }
        if !settings.auto_retrain {
            return None;
        }
        let interval = settings.retrain_interval_secs.max(3_600) as i64;
        {
            let mut last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
            // The first attempt after a start waits for the last recorded
            // retrain's interval, so restarts do not each cost a retrain.
            if last.is_none() {
                *last = self.last_trained_at();
            }
            if let Some(at) = *last {
                if now - at < interval {
                    return None;
                }
            }
            *last = Some(now);
        }
        let outcome = self.start_candidate(&settings, &trial);
        if let Err(e) = &outcome {
            // Info, not Warn: "not enough data yet" is the normal state for a
            // young install, not a fault.
            // The reason alone: "configuration error:" (the error type's
            // prefix) read as if a setting were wrong.
            let why = match e {
                DaygleError::Config(why) => why.clone(),
                other => other.to_string(),
            };
            self.log(LogLevel::Info, format!("AI retrain skipped: {why}"));
        }
        Some(outcome)
    }

    /// Build a candidate and put it on trial - or, with trials off, live.
    fn start_candidate(&self, settings: &AiSettings, trial: &Trial) -> Result<TrainingStats> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let built = self.build(settings)?;
        let record = built.record();
        if !settings.trial_new_models && !self.uses_binary_name_model() {
            if let Err(e) = self.promote(&built.temp, &record) {
                let _ = std::fs::remove_file(&built.temp);
                return Err(e);
            }
            self.start_watch(chrono::Utc::now().timestamp());
            self.log(
                LogLevel::Info,
                format!(
                    "AI retrained its classifier from {} examples across {} labels; it is in use now (trials are off) and watched for {} days",
                    built.stats.examples, built.stats.labels, WATCH_SECS / 86_400
                ),
            );
            return Ok(built.stats);
        }
        let candidate = candidate_path(&self.learned);
        if let Err(e) = std::fs::rename(&built.temp, &candidate) {
            let _ = std::fs::remove_file(&built.temp);
            return Err(DaygleError::Io(e));
        }
        let _ = std::fs::write(
            candidate.with_extension("json"),
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        );
        let now = chrono::Utc::now().timestamp();
        let window = trial_secs(settings);
        self.write_trial(&Trial {
            started_at: Some(now),
            ends_at: Some(now + window),
            retry_after: None,
            last_outcome: trial.last_outcome.clone(),
            history: trial.history.clone(),
            shadow_scoring: trial.shadow_scoring.clone(),
        });
        self.log(
            LogLevel::Info,
            format!(
                "AI built a candidate classifier from {} examples across {} labels ({} unconfirmed verdicts left out); it runs in the shadow of the live model for {}h before it can replace it",
                built.stats.examples,
                built.stats.labels,
                built.stats.unconfirmed,
                window / 3600
            ),
        );
        Ok(built.stats)
    }

    /// Judge the candidate against the live model on the trial window, then
    /// promote it or set it aside.
    fn conclude_trial(&self, settings: &AiSettings, trial: &Trial) {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let candidate = candidate_path(&self.learned);
        if !candidate.is_file() {
            self.write_trial(
                &trial.concluded("candidate missing; nothing to judge".to_string(), None),
            );
            return;
        }
        let (Some(started), Some(ends)) = (trial.started_at, trial.ends_at) else {
            return;
        };
        let live = self.current_model.load_full().to_string();
        // The live model may have changed during the trial (a models bundle,
        // a manual restore): the candidate has to beat whatever is live now,
        // including keeping every threat label it can report.
        let verdict = refuse_forgotten_threats(
            settings,
            Path::new(live.trim())
                .is_file()
                .then(|| model_labels(Path::new(live.trim())))
                .flatten()
                .as_ref(),
            &model_labels(&candidate).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())
        .and_then(|()| {
            judge_shadow(
                &self.store,
                settings,
                &candidate,
                &live,
                started,
                ends,
                self.evidence.get().map(Arc::as_ref),
            )
        });
        let now = chrono::Utc::now().timestamp();
        match verdict {
            Ok(why) => {
                let mut record = std::fs::read(candidate.with_extension("json"))
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                // The held-out replay decides, not the trial's automatic
                // signals alone. Without a replay there is no held-out
                // evidence, and the incumbent stays in force.
                let scoring = self
                    .shadow_scoring
                    .get()
                    .map(|replay| {
                        replay(&candidate, settings, started, ends).unwrap_or_else(|error| {
                            serde_json::json!({ "passed": false, "reason": error.to_string() })
                        })
                    })
                    .unwrap_or_else(|| {
                        serde_json::json!({
                            "passed": false,
                            "reason": "no candidate replay is configured, so the held-out results were not validated"
                        })
                    });
                if let Some(record) = record.as_object_mut() {
                    record.insert("shadow_scoring".to_string(), scoring.clone());
                }
                if !scoring
                    .get("passed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                {
                    let reason = scoring
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("the candidate replay did not validate the held-out results")
                        .to_string();
                    self.reject(
                        settings,
                        trial,
                        format!("candidate replay did not validate: {reason}"),
                        now,
                        Some(&scoring),
                    );
                    return;
                }
                // A passed replay carries the calibration map it fitted and
                // the threshold it validated on the held-out half. Promoting
                // without either would leave the old scoring in force.
                let calibration = scoring.get("calibration").and_then(|value| {
                    serde_json::from_value::<crate::calibration::CalibrationMap>(value.clone()).ok()
                });
                let threshold = scoring
                    .pointer("/threshold/candidate")
                    .and_then(serde_json::Value::as_f64)
                    .map(|value| value as f32);
                let signal_weights = scoring
                    .get("signal_weights")
                    .and_then(|value| serde_json::from_value(value.clone()).ok())
                    .unwrap_or_default();
                let (Some(calibration), Some(threshold)) = (calibration, threshold) else {
                    self.reject(
                        settings,
                        trial,
                        "candidate replay passed without a validated calibration map and threshold"
                            .to_string(),
                        now,
                        Some(&scoring),
                    );
                    return;
                };
                let _ = std::fs::remove_file(candidate.with_extension("json"));
                let activation = TrialActivation {
                    calibration: Some(calibration),
                    threshold,
                    signal_weights,
                    report: scoring.clone(),
                };
                // The version is recorded and its scoring applied *before* the
                // model is installed. Until that record exists there is nothing
                // for the new model to belong to, so a failed write leaves the
                // incumbent live with the scoring that describes it.
                let activated = match self.activation.get() {
                    Some(activate) => activate(&candidate, &self.learned, &activation).map(Some),
                    None => Ok(None),
                };
                let undo = match activated {
                    Ok(undo) => undo,
                    Err(e) => {
                        self.reject(
                            settings,
                            trial,
                            format!(
                                "it passed its trial but its validated scoring could not be recorded: {e}"
                            ),
                            now,
                            Some(&scoring),
                        );
                        return;
                    }
                };
                if let Err(e) = self.promote(&candidate, &record) {
                    // Activation came first, so the files were put back by the
                    // rotation's recovery and the model was never loaded. Take
                    // the version and scoring back out too, or the incumbent
                    // would keep answering under the failed candidate's
                    // calibration and threshold.
                    let failures = undo.map(|undo| undo.undo()).unwrap_or_default();
                    let suffix = if failures.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "; putting the previous scoring back did not fully succeed: {}",
                            failures.join("; ")
                        )
                    };
                    self.reject(
                        settings,
                        trial,
                        format!("it passed its trial but could not be loaded: {e}{suffix}"),
                        now,
                        Some(&scoring),
                    );
                    return;
                }
                self.start_watch(chrono::Utc::now().timestamp());
                self.log(
                    LogLevel::Info,
                    format!(
                        "AI promoted its candidate classifier after a shadow trial: {why}. It is watched for {} days and undone if it misbehaves",
                        WATCH_SECS / 86_400
                    ),
                );
                self.write_trial(
                    &trial
                        .concluded(format!("promoted: {why}"), None)
                        .with_scoring(Some(&scoring)),
                );
                if let Some(activation) = undo {
                    if let Err(error) = activation.complete() {
                        self.log(
                            LogLevel::Warn,
                            format!(
                                "the scheduled model is live but its activation recovery marker could not be cleared: {error}"
                            ),
                        );
                    }
                }
            }
            Err(why) => self.reject(settings, trial, why, now, None),
        }
    }

    /// Set a candidate aside, pause retraining and tell the operator. The
    /// live model was never touched.
    fn reject(
        &self,
        settings: &AiSettings,
        trial: &Trial,
        why: String,
        now: i64,
        scoring: Option<&serde_json::Value>,
    ) {
        let candidate = candidate_path(&self.learned);
        let _ = std::fs::rename(&candidate, self.learned.with_extension("rejected.bin"));
        let _ = std::fs::remove_file(candidate.with_extension("json"));
        // Rejections in a row (this one included): each one past the streak
        // doubles the pause, so a retrain that keeps failing stops costing
        // CPU every day while the live model carries on.
        let streak = 1 + trial
            .history
            .iter()
            .take_while(|entry| entry.outcome.starts_with("rejected"))
            .count();
        let pause = rejection_pause(settings.retrain_interval_secs, streak);
        self.log(
            LogLevel::Warn,
            format!(
                "AI rejected its candidate classifier after a shadow trial: {why}. The live model is unchanged; retraining pauses for {}h.",
                pause / 3600
            ),
        );
        let (title, detail) = if streak >= REJECTION_STREAK {
            (
                "AI keeps rejecting its retrained models",
                format!(
                    " This is rejection {streak} in a row, so retraining now waits {}h between tries. The live model is fine; if this goes on, look at your recent \"not a threat\" marks or turn Learn \"Not a Threat\" off.",
                    pause / 3600
                ),
            )
        } else {
            (
                "AI rejected a retrained model",
                format!(" Retraining resumes in {}h.", pause / 3600),
            )
        };
        daygle_dns_core::alerts::raise(
            daygle_dns_core::alerts::AlertKind::AiModel,
            format!("ai-model:{now}"),
            title,
            format!(
                "The model the AI retrained did worse than the live model during its shadow trial ({why}), so it was set aside. Nothing changed for your clients.{detail}",
            ),
        );
        self.write_trial(
            &trial
                .concluded(format!("rejected: {why}"), Some(now + pause))
                .with_scoring(scoring),
        );
    }

    // ── The watch after an automatic promotion ──────────────────────────

    fn watch_path(&self) -> PathBuf {
        self.learned.with_extension("watch.json")
    }

    /// Start watching the model that just went live on its own (a trial
    /// promotion, or a scheduled retrain with trials off).
    fn start_watch(&self, now: i64) {
        let watch = serde_json::json!({ "promoted_at": now, "until": now + WATCH_SECS });
        if let Err(e) = std::fs::write(
            self.watch_path(),
            serde_json::to_vec_pretty(&watch).unwrap_or_default(),
        ) {
            self.log(
                LogLevel::Warn,
                format!("could not start watching the new model: {e}"),
            );
        }
    }

    /// The watch in progress: `(promoted_at, until)`.
    pub fn watching(&self) -> Option<(i64, i64)> {
        let raw = std::fs::read(self.watch_path()).ok()?;
        let watch: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        Some((
            watch.get("promoted_at")?.as_i64()?,
            watch.get("until")?.as_i64()?,
        ))
    }

    /// Judge a model that went live without the operator, for
    /// [`WATCH_SECS`] after it did: when it blocks a much larger share of the
    /// domains it scans than the live model did the week before, or the
    /// operator marks [`WATCH_MARKS`] of its new detections "not a threat",
    /// it is undone - the model before it goes back live - and the operator
    /// is told. The trial judged it on a few hours of traffic; this catches
    /// what only shows on days of it. Returns whether it undid the model.
    pub fn check_watch(&self, settings: &AiSettings, now: i64) -> bool {
        let Some((promoted_at, until)) = self.watching() else {
            return false;
        };
        if now >= until {
            let _ = std::fs::remove_file(self.watch_path());
            self.log(
                LogLevel::Info,
                format!(
                    "AI's new classifier passed its {}-day watch",
                    WATCH_SECS / 86_400
                ),
            );
            return false;
        }
        match self.watch_verdict(promoted_at, now) {
            Some(why) => {
                self.undo_promotion(settings, &why, now);
                true
            }
            None => false,
        }
    }

    /// Why the watched model should be undone, if it should.
    fn watch_verdict(&self, promoted_at: i64, now: i64) -> Option<String> {
        let marks = self.store.not_threat_marks_since(promoted_at).unwrap_or(0);
        if marks >= WATCH_MARKS {
            return Some(format!(
                "you marked {marks} of its new detections \"not a threat\""
            ));
        }
        let (before_classified, before_threats) = self
            .store
            .threat_rate(promoted_at - WATCH_BASELINE_SECS, promoted_at)
            .ok()?;
        let (after_classified, after_threats) =
            self.store.threat_rate(promoted_at, now + 1).ok()?;
        if before_classified < WATCH_MIN_CLASSIFIED || after_classified < WATCH_MIN_CLASSIFIED {
            return None;
        }
        let expected = before_threats as f64 / before_classified as f64 * after_classified as f64;
        let after = after_threats as f64;
        (after > expected * WATCH_RATE_FACTOR && after - expected >= WATCH_RATE_MIN_EXTRA).then(
            || {
                format!(
                    "it blocked {after_threats} of {after_classified} domains it scanned, where the model before it would have blocked about {:.0}",
                    expected
                )
            },
        )
    }

    /// Put back the model the watched one replaced (the previous learned
    /// model, or the configured one after a first promotion), pause
    /// retraining and tell the operator.
    fn undo_promotion(&self, settings: &AiSettings, why: &str, now: i64) {
        let undone = {
            let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
            self.with_rotation(|| {
                let previous = previous_model_path(&self.learned);
                let predecessor = if self.uses_binary_name_model() {
                    self.store.active_candidate()?.and_then(|active| {
                        active.scoring_config["binary_previous_scoring"]["model"]
                            .as_str()
                            .map(str::to_owned)
                    })
                } else {
                    None
                };
                if previous.is_file()
                    && predecessor.as_ref().is_none_or(|digest| {
                        crate::threshold::model_version(&previous.to_string_lossy()) == *digest
                    })
                {
                    self.swap_with_previous().and_then(|()| self.install())
                } else {
                    // The first model it learned: back to the configured one.
                    let configured = self.configured_model(settings);
                    if predecessor.as_ref().is_some_and(|digest| {
                        crate::threshold::model_version(&configured) != *digest
                    }) {
                        return Err(DaygleError::Config(
                            "the binary model's rollback artifact is unavailable".to_string(),
                        ));
                    }
                    let set_aside = self.learned.with_extension("rolled-back.bin");
                    std::fs::rename(&self.learned, &set_aside)?;
                    self.install_path(Path::new(&configured))
                }
            })
        };
        let _ = std::fs::remove_file(self.watch_path());
        if let Err(e) = undone {
            self.log(
                LogLevel::Warn,
                format!("AI could not undo its new classifier ({why}): {e}"),
            );
            return;
        }
        let pause = settings.retrain_interval_secs.max(3_600) as i64 * 2;
        let outcome = format!("rolled back after going live: {why}");
        self.log(
            LogLevel::Warn,
            format!(
                "AI rolled back its new classifier: {why}. The model before it is in use again; retraining pauses for {}h.",
                pause / 3600
            ),
        );
        daygle_dns_core::alerts::raise(
            daygle_dns_core::alerts::AlertKind::AiModel,
            format!("ai-model-rollback:{now}"),
            "AI rolled back a new model",
            format!(
                "The model the AI put live misbehaved within its first days ({why}), so the model before it is back in use. Nothing else is needed; retraining resumes in {}h.",
                pause / 3600
            ),
        );
        self.write_trial(&self.trial().concluded(outcome, Some(now + pause)));
    }

    fn last_trained_at(&self) -> Option<i64> {
        let raw = std::fs::read(stats_path(&self.learned)).ok()?;
        let record: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let at = record.get("trained_at")?.as_str()?;
        chrono::DateTime::parse_from_rfc3339(at)
            .ok()
            .map(|t| t.timestamp())
    }
}

/// [`judge_shadow`] for the shared model, for integration tests.
#[doc(hidden)]
pub fn judge_for_tests(
    store: &AiStore,
    settings: &AiSettings,
    candidate: &Path,
    live: &str,
    started: i64,
    ends: i64,
) -> std::result::Result<String, String> {
    judge_shadow(store, settings, candidate, live, started, ends, None)
}

/// [`judge_shadow`] with network evidence, for integration tests.
#[doc(hidden)]
pub fn judge_with_evidence_for_tests(
    store: &AiStore,
    settings: &AiSettings,
    candidate: &Path,
    live: &str,
    started: i64,
    ends: i64,
    evidence: &NetworkEvidence,
) -> std::result::Result<String, String> {
    judge_shadow(
        store,
        settings,
        candidate,
        live,
        started,
        ends,
        Some(evidence),
    )
}

/// How long retraining pauses after the `streak`-th rejection in a row:
/// twice the retrain interval, doubling from the [`REJECTION_STREAK`]-th
/// on, at most [`MAX_PAUSE_SECS`].
fn rejection_pause(interval_secs: u64, streak: usize) -> i64 {
    let base = interval_secs.max(3_600) as i64 * 2;
    if streak < REJECTION_STREAK {
        return base;
    }
    let doublings = (streak + 1 - REJECTION_STREAK).min(8) as u32;
    base.saturating_mul(1 << doublings).min(MAX_PAUSE_SECS)
}

/// Allowed shortfall on an automatic probe of `n` names: noise, not a
/// regression (2%, at least one).
fn slack(n: usize) -> usize {
    (n / 50).max(1)
}

/// The automatic probes every candidate is checked against.
pub(crate) struct Probes<'a> {
    /// Threat-feed names held out of training, with their labels.
    pub intel: &'a [(String, String)],
    /// Domains this network has relied on for weeks.
    pub established: &'a [String],
}

impl Probes<'_> {
    fn is_empty(&self) -> bool {
        self.intel.is_empty() && self.established.is_empty()
    }

    /// Compare `candidate` with `live` on both probes. `Ok` carries notes for
    /// the trial record; `Err` says why the candidate is worse.
    fn judge(
        &self,
        candidate: &Predictor,
        live: &Predictor,
        is_threat: &dyn Fn(&str) -> bool,
    ) -> std::result::Result<Vec<String>, String> {
        let mut notes = Vec::new();
        let feed: Vec<&String> = self
            .intel
            .iter()
            .filter(|(label, _)| is_threat(label))
            .map(|(_, domain)| domain)
            .collect();
        if !feed.is_empty() {
            let found = |model: &Predictor| {
                feed.iter()
                    .filter(|domain| is_threat(&model.label(domain)))
                    .count()
            };
            let (with_candidate, with_live) = (found(candidate), found(live));
            if with_candidate + slack(feed.len()) < with_live {
                return Err(format!(
                    "it detected {with_candidate} of {} held-out threat-feed names against {with_live} for the model in use",
                    feed.len()
                ));
            }
            notes.push(format!(
                "{with_candidate} of {} held-out threat-feed names detected (live {with_live})",
                feed.len()
            ));
        }
        if !self.established.is_empty() {
            let flagged = |model: &Predictor| {
                self.established
                    .iter()
                    .filter(|domain| is_threat(&model.label(domain)))
                    .count()
            };
            let (with_candidate, with_live) = (flagged(candidate), flagged(live));
            if with_candidate > with_live + slack(self.established.len()) {
                return Err(format!(
                    "it flagged {with_candidate} of {} established domains as threats against {with_live} for the model in use",
                    self.established.len()
                ));
            }
            notes.push(format!(
                "{with_candidate} of {} established domains flagged (live {with_live})",
                self.established.len()
            ));
        }
        Ok(notes)
    }
}

/// Score a candidate against the live model on what happened during its
/// trial. Four signals, each needing enough evidence to count; the candidate
/// must be no worse on every one that does:
///
/// * held-out threat families (where this model detects threats);
/// * the threats each finds among the domains looked up during the trial:
///   fewer than half, or more than twice as many (and ten more), rejects;
/// * the corrections the operator filed during the trial;
/// * labels an independent source - the page, the verifier model, a threat
///   feed - confirmed for domains seen during the trial;
/// * with network evidence: held-out threat-feed names and established
///   domains (see [`Probes`]), and the established domains looked up during
///   the trial, which neither model may flag more often than the other.
///
/// The automatic signals are what keep a trial meaningful on an install
/// nobody corrects: without them a quiet trial ended "no evidence against
/// it" and promoted the candidate.
#[allow(clippy::too_many_arguments)]
fn judge_shadow(
    store: &AiStore,
    settings: &AiSettings,
    candidate: &Path,
    live: &str,
    started: i64,
    ends: i64,
    evidence: Option<&NetworkEvidence>,
) -> std::result::Result<String, String> {
    let candidate_model =
        Predictor::load(&candidate.to_string_lossy()).map_err(|e| e.to_string())?;
    let live_model = Predictor::load(live).map_err(|e| e.to_string())?;
    let binary = crate::learn::is_binary_model(candidate);
    let is_threat = |label: &str| {
        is_threat_label(settings, label) || (binary && label == crate::backend::BINARY_THREAT_LABEL)
    };
    let mut notes: Vec<String> = Vec::new();
    let intel = evidence.map(|e| e.intel());

    if let Some(evidence) = evidence {
        let (_, intel_probe) = intel
            .as_deref()
            .map(|index| index.sample(|label| wanted_label(settings, None, label)))
            .unwrap_or_default();
        let established = evidence.established_sample();
        notes.extend(
            Probes {
                intel: &intel_probe,
                established: &established,
            }
            .judge(&candidate_model, &live_model, &is_threat)?,
        );
    }

    if let Ok(probe) = probe_threat_model(store, settings, candidate) {
        let live_lost = probe
            .sample
            .iter()
            .filter(|(label, domain)| {
                let got = live_model.label(domain);
                is_threat(label) && (got == BENIGN_LABEL || !is_threat(&got))
            })
            .count();
        if probe.lost() > live_lost {
            return Err(format!(
                "it lost {} of {} held-out threat names against {live_lost} for the live model",
                probe.lost(),
                probe.checked
            ));
        }
        if probe.checked > 0 {
            notes.push(format!(
                "{} of {} held-out threats lost (live {live_lost})",
                probe.lost(),
                probe.checked
            ));
        }
    }

    let domains = store
        .domains_classified_between(started, ends, TRIAL_DOMAINS)
        .unwrap_or_default();
    if !domains.is_empty() {
        let count = |model: &Predictor| {
            domains
                .iter()
                .filter(|d| is_threat(&model.label(d)))
                .count()
        };
        let (with_candidate, with_live) = (count(&candidate_model), count(&live_model));
        if with_live >= TRIAL_MIN_THREATS && with_candidate * 2 < with_live {
            return Err(format!(
                "it found {with_candidate} threats among {} domains looked up during the trial where the live model finds {with_live}",
                domains.len()
            ));
        }
        if with_candidate > with_live * 2 + TRIAL_MIN_THREATS {
            return Err(format!(
                "it flagged {with_candidate} threats among {} domains looked up during the trial where the live model flags {with_live}",
                domains.len()
            ));
        }
        notes.push(format!(
            "{with_candidate} threats on {} live domains (live {with_live})",
            domains.len()
        ));
    }

    // The operator's corrections filed during the trial: fresh labels
    // neither model was trained on.
    let mut truths: Vec<(String, Truth)> = Vec::new();
    for correction in store.corrections().map_err(|e| e.to_string())? {
        if correction.created_at < started || correction.created_at >= ends {
            continue;
        }
        let domain = correction
            .domain
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        match correction.action.as_str() {
            "category" => truths.push((
                domain,
                Truth::Label(correction.category.trim().to_ascii_lowercase()),
            )),
            "not_threat" => truths.push((domain, Truth::NotThreat)),
            _ => {}
        }
    }
    score(
        "your corrections during the trial",
        &truths,
        &candidate_model,
        &live_model,
        &is_threat,
        &mut notes,
    )?;

    // Independent confirmations for the domains seen during the trial: the
    // page or the verifier, and (for a model that detects threats) the
    // threat feeds.
    let seen: HashSet<&String> = domains.iter().collect();
    let mut confirmed: std::collections::HashMap<String, String> = store
        .independent_labels()
        .unwrap_or_default()
        .into_iter()
        .filter(|(domain, _)| seen.contains(domain))
        .collect();
    if let Some(index) = intel.as_deref() {
        for domain in &domains {
            if let Some(label) = index.label_for(domain).filter(|l| is_threat(l)) {
                confirmed
                    .entry(domain.clone())
                    .or_insert_with(|| label.to_string());
            }
        }
    }
    let mut confirmed: Vec<(String, Truth)> = confirmed
        .into_iter()
        .map(|(domain, label)| (domain, Truth::Label(label)))
        .collect();
    confirmed.sort_by(|a, b| a.0.cmp(&b.0));
    score(
        "independently confirmed labels",
        &confirmed,
        &candidate_model,
        &live_model,
        &is_threat,
        &mut notes,
    )?;

    // Established domains looked up during the trial: plentiful on any
    // network, so there is always something to judge a threat detector on.
    if let Some(evidence) = evidence {
        let established: Vec<(String, Truth)> = domains
            .iter()
            .filter(|domain| evidence.is_known_ordinary(domain))
            .map(|domain| (domain.clone(), Truth::NotThreat))
            .collect();
        score_with_slack(
            "ordinary domains (established or popular) looked up during the trial",
            &established,
            &candidate_model,
            &live_model,
            &is_threat,
            slack(established.len()),
            &mut notes,
        )?;
    }

    if notes.is_empty() {
        notes.push("no evidence against it".to_string());
    }
    Ok(notes.join("; "))
}

enum Truth {
    /// The domain is this label (or, for a threat, any threat label).
    Label(String),
    /// The domain is not a threat.
    NotThreat,
}

/// How many of `truths` each model gets right; the candidate must not get
/// fewer. Skipped below [`TRIAL_MIN_TRUTHS`].
fn score(
    what: &str,
    truths: &[(String, Truth)],
    candidate: &Predictor,
    live: &Predictor,
    is_threat: &dyn Fn(&str) -> bool,
    notes: &mut Vec<String>,
) -> std::result::Result<(), String> {
    score_with_slack(what, truths, candidate, live, is_threat, 0, notes)
}

/// [`score`], allowing the candidate `slack` fewer right: for automatic
/// truths, plentiful and slightly noisy, where one name is not a regression.
fn score_with_slack(
    what: &str,
    truths: &[(String, Truth)],
    candidate: &Predictor,
    live: &Predictor,
    is_threat: &dyn Fn(&str) -> bool,
    slack: usize,
    notes: &mut Vec<String>,
) -> std::result::Result<(), String> {
    if truths.len() < TRIAL_MIN_TRUTHS {
        return Ok(());
    }
    let right = |model: &Predictor| {
        truths
            .iter()
            .filter(|(domain, truth)| {
                let got = model.label(domain);
                match truth {
                    Truth::NotThreat => !is_threat(&got),
                    Truth::Label(label) => got == *label || (is_threat(label) && is_threat(&got)),
                }
            })
            .count()
    };
    let (with_candidate, with_live) = (right(candidate), right(live));
    if with_candidate + slack < with_live {
        return Err(format!(
            "it got {with_candidate} of {} {what} right against {with_live} for the live model",
            truths.len()
        ));
    }
    notes.push(format!(
        "{with_candidate} of {} {what} right (live {with_live})",
        truths.len()
    ));
    Ok(())
}

#[derive(Clone, Copy)]
enum StatsMove {
    CurrentToPrevious,
    Exchange,
}

/// Keep each model's record with the model: moved with it on a rotation,
/// exchanged on a rollback, and dropped rather than left describing the
/// wrong file when one side has none.
fn swap_stats(learned: &Path, how: StatsMove) {
    let current = stats_path(learned);
    let previous = previous_stats_path(learned);
    match how {
        StatsMove::CurrentToPrevious => {
            let _ = std::fs::remove_file(&previous);
            let _ = std::fs::rename(&current, &previous);
        }
        StatsMove::Exchange => {
            let staged = learned.with_extension("rolled-back.json");
            let _ = std::fs::remove_file(&staged);
            let had_current = std::fs::rename(&current, &staged).is_ok();
            let _ = std::fs::rename(&previous, &current);
            if had_current {
                let _ = std::fs::rename(&staged, &previous);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_restores_files_from_an_interrupted_learned_model_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("ai.db");
        let learned = crate::learn::learned_model_path(&database);
        let previous = previous_model_path(&learned);
        let stats = stats_path(&learned);
        let expected = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/daygle-starter.bin"
        ))
        .unwrap();
        std::fs::write(&learned, &expected).unwrap();
        std::fs::write(&previous, b"original previous").unwrap();
        std::fs::write(&stats, b"original stats").unwrap();
        {
            let store = AiStore::open(&database).unwrap();
            begin_rotation(&store, &learned).unwrap();
            std::fs::rename(&learned, &previous).unwrap();
            std::fs::write(previous_stats_path(&learned), b"unexpected stats").unwrap();
        }

        let settings = AiSettings {
            database: database.to_string_lossy().into_owned(),
            ..AiSettings::default()
        };
        let ai = crate::AiEngine::new(
            &settings,
            ":memory:",
            Arc::new(daygle_dns_authoritative::ZoneStore::open(":memory:").unwrap()),
            Arc::new(LogStore::new(64)),
        )
        .unwrap();
        assert_eq!(ai.live_model_path(), learned.to_string_lossy());
        assert_eq!(std::fs::read(&learned).unwrap(), expected);
        assert_eq!(std::fs::read(&previous).unwrap(), b"original previous");
        assert_eq!(std::fs::read(&stats).unwrap(), b"original stats");
        assert!(!previous_stats_path(&learned).exists());
        assert!(!recover_rotation(&ai.store, &learned).unwrap());
    }

    /// A passed trial is recorded and its scoring applied before the model is
    /// installed, so a failure writing that version rejects the candidate
    /// without ever loading it. Injecting the activation failure here proves
    /// the install is behind it.
    #[test]
    fn a_failed_scheduled_activation_never_installs_the_candidate() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("ai.db");
        let learned = crate::learn::learned_model_path(&database);
        let live = dir.path().join("live.bin");
        let starter = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/daygle-starter.bin"
        );
        std::fs::copy(starter, &live).unwrap();
        std::fs::copy(starter, candidate_path(&learned)).unwrap();
        let store = Arc::new(AiStore::open(&database).unwrap());
        let settings = Arc::new(ArcSwap::from_pointee(AiSettings {
            mode: daygle_dns_core::config::AiMode::Enforce,
            block_threshold: 0.5,
            ..AiSettings::default()
        }));
        let retrainer = Retrainer::new(
            store,
            settings.clone(),
            Arc::new(LogStore::new(64)),
            learned.clone(),
            Arc::new(ArcSwap::from_pointee(live.to_string_lossy().into_owned())),
        );
        retrainer.set_shadow_scoring(Box::new(|candidate, _, _, ends| {
            let model = crate::threshold::model_version(&candidate.to_string_lossy());
            Ok(serde_json::json!({
                "passed": true,
                "calibration": crate::calibration::CalibrationMap::identity(&model, ends),
                "threshold": { "candidate": 0.9 },
                "signal_weights": crate::fusion::SignalWeights::default(),
            }))
        }));
        let installs = Arc::new(AtomicUsize::new(0));
        let counted = installs.clone();
        retrainer.set_installer(Box::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        retrainer.set_activation(Box::new(|_, _, _| {
            Err(DaygleError::Database(
                "injected scheduled activation failure".to_string(),
            ))
        }));

        let now = chrono::Utc::now().timestamp();
        let trial = Trial {
            started_at: Some(now - 600),
            ends_at: Some(now + 1),
            ..Default::default()
        };
        std::fs::write(
            trial_path(&learned),
            serde_json::to_vec(&trial.to_json()).unwrap(),
        )
        .unwrap();
        let current = settings.load_full();
        retrainer.conclude_trial(&current, &trial);

        assert_eq!(
            installs.load(Ordering::SeqCst),
            0,
            "the version is recorded before the model is installed"
        );
        assert!(
            !learned.is_file(),
            "the failed candidate was set aside, not installed"
        );
        let outcome = retrainer.trial().last_outcome.unwrap_or_default();
        assert!(
            outcome.starts_with("rejected") && outcome.contains("could not be recorded"),
            "{outcome}"
        );
    }

    #[test]
    fn repeated_rejections_back_off() {
        let day = 86_400;
        assert_eq!(rejection_pause(day as u64, 1), 2 * day);
        assert_eq!(rejection_pause(day as u64, 2), 2 * day);
        assert_eq!(rejection_pause(day as u64, 3), 4 * day, "the third doubles");
        assert_eq!(
            rejection_pause(day as u64, 4),
            MAX_PAUSE_SECS,
            "capped at a week"
        );
        assert_eq!(rejection_pause(3_600, 3), 4 * 3_600);
    }
}
