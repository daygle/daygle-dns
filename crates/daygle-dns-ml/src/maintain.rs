//! The scanner's own model maintenance: retraining, shadow trials, promotion
//! and rollback.
//!
//! A [`Retrainer`] looks after one model - the shared classifier, or a
//! dedicated threat model when one is configured ([`Role`]). Its scheduled
//! step ([`Retrainer::maybe_retrain`]) works in two stages:
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

use crate::backend::{ClassificationInput, DomainClassifier};
use crate::learn::{
    bundled_starter_corpus, collect_dataset_with, held_out_variant, model_labels, predict_all,
    previous_model_path, previous_stats_path, probe_accuracy, probe_threat_model,
    refuse_forgotten_threats, refuse_lost_threats, stats_path, top_label, train, Dataset, Role,
    Sources, TrainingStats, BENIGN_LABEL, MIN_ACCURACY, MIN_EXAMPLES, MIN_LABELS, VALIDATION_SLACK,
};
use crate::store::AiStore;

/// Loads an accepted model file into the running channels. Set by the engine,
/// so every way a model goes live - a promotion, a manual retrain or a
/// rollback - goes live the same way.
pub type Installer = Box<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Run after a model is promoted (the engine refreshes what depends on it).
pub type AfterPromotion = Box<dyn Fn() + Send + Sync>;

/// A maintenance step with nothing to report (the verifier refresh).
pub type Step = Box<dyn Fn() + Send + Sync>;

/// Everything the scan loop runs after a cycle: each maintained model's
/// scheduled step, then the verifier reference refresh.
pub struct Maintenance {
    shared: Arc<Retrainer>,
    threat: Arc<Retrainer>,
    after: Step,
}

impl Maintenance {
    pub fn new(shared: Arc<Retrainer>, threat: Arc<Retrainer>, after: Step) -> Self {
        Self {
            shared,
            threat,
            after,
        }
    }

    /// Run every due step. Returns the shared model's build, if one ran.
    pub fn run(&self) -> Option<Result<TrainingStats>> {
        let shared = self.shared.maybe_retrain();
        let _ = self.threat.maybe_retrain();
        (self.after)();
        shared
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
}

impl Trial {
    fn from_json(value: &serde_json::Value) -> Self {
        let int = |key: &str| value.get(key).and_then(|v| v.as_i64());
        Self {
            started_at: int("started_at"),
            ends_at: int("ends_at"),
            retry_after: int("retry_after"),
            last_outcome: value
                .get("last_outcome")
                .and_then(|v| v.as_str())
                .map(str::to_string),
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
        }
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
        })
    }
}

/// Maintains one model: builds candidates, trials them in the shadow of the
/// live model, promotes or rejects them, and rolls back on request.
pub struct Retrainer {
    role: Role,
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
    installer: OnceLock<Installer>,
    after_promotion: OnceLock<AfterPromotion>,
}

impl Retrainer {
    pub fn new(
        role: Role,
        store: Arc<AiStore>,
        settings: Arc<ArcSwap<AiSettings>>,
        logs: Arc<LogStore>,
        learned: PathBuf,
        current_model: Arc<ArcSwap<String>>,
    ) -> Self {
        Self {
            role,
            store,
            settings,
            logs,
            learned,
            current_model,
            last_attempt: Mutex::new(None),
            running: Mutex::new(()),
            installer: OnceLock::new(),
            after_promotion: OnceLock::new(),
        }
    }

    /// Hand the retrainer the step that loads a model into the running
    /// channels. Without one (tests of the files alone) a model is only
    /// written to disk.
    pub fn set_installer(&self, installer: Installer) {
        let _ = self.installer.set(installer);
    }

    /// Something to run after each promotion.
    pub fn set_after_promotion(&self, hook: AfterPromotion) {
        let _ = self.after_promotion.set(hook);
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The model file this retrainer maintains.
    pub fn learned_model(&self) -> &Path {
        &self.learned
    }

    /// The model the operator configured for this role: the fixed reference.
    fn configured_model(&self, settings: &AiSettings) -> String {
        match self.role {
            Role::Shared => settings.model_path.trim().to_string(),
            Role::Threat => settings.threat_model_path.trim().to_string(),
        }
    }

    fn log(&self, level: LogLevel, message: String) {
        let message = match self.role {
            Role::Shared => message,
            Role::Threat => format!("[threat model] {message}"),
        };
        self.logs.push(level, "ai", message);
    }

    /// Whether this retrainer has anything to maintain: the threat role only
    /// exists while a dedicated threat model is configured.
    fn applies(&self, settings: &AiSettings) -> bool {
        self.role == Role::Shared || settings.dedicated_threat_model()
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
        let current_path = self.current_model.load_full().to_string();
        let current_model = (!current_path.trim().is_empty()).then(|| PathBuf::from(&current_path));
        let current_labels = current_model.as_deref().and_then(model_labels);
        // The configured model is the fixed reference the scanner's own
        // verdicts are checked against, and the corpus beside it - when a
        // models bundle shipped one - is the starter set that matches it.
        let anchor = self.anchor_model(settings);
        let corpus = bundled_starter_corpus(&self.configured_model(settings));
        let confirmations = self.store.independent_labels().unwrap_or_default();
        let Dataset {
            pairs,
            validation,
            threat_validation,
            stats,
        } = collect_dataset_with(
            &self.store,
            settings,
            &Sources {
                role: self.role,
                known: current_labels.as_ref(),
                starter: corpus.as_deref(),
                anchor: anchor.as_ref(),
                confirmations: Some(&confirmations),
            },
        )?;
        // The starter corpus is always there, so what decides whether a
        // retrain is worth running is what this network contributed.
        if stats.local() < MIN_EXAMPLES || stats.labels < MIN_LABELS {
            return Err(DaygleError::Config(format!(
                "not enough training data yet: {} examples across {} labels (a retrain needs {} and {})",
                stats.local(),
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
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                Err(e)
            }
        }
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
        current_model: Option<&Path>,
        current_labels: Option<&HashSet<String>>,
    ) -> Result<(f32, Option<f32>)> {
        train(pairs, temp)?;
        let train_accuracy = probe_accuracy(temp, pairs)?;

        // A candidate that forgot a threat label can never report it again.
        let candidate_labels = model_labels(temp).unwrap_or_default();
        refuse_forgotten_threats(self.role, settings, current_labels, &candidate_labels)?;

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
            let is_threat = |label: &str| self.role.is_threat_label(settings, label);
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
        Ok((train_accuracy, validation_accuracy))
    }

    // ── Going live ──────────────────────────────────────────────────────

    fn install(&self) -> Result<()> {
        match self.installer.get() {
            Some(install) => install(&self.learned),
            None => Ok(()),
        }
    }

    /// Put `file` in place as the learned model and load it: the model it
    /// replaces becomes the previous one, and every failure puts the files
    /// back the way they were.
    fn promote(&self, file: &Path, record: &serde_json::Value) -> Result<()> {
        let previous = previous_model_path(&self.learned);
        let had_learned = self.learned.is_file();
        if had_learned {
            std::fs::rename(&self.learned, &previous)?;
            swap_stats(&self.learned, StatsMove::CurrentToPrevious);
        }
        if let Err(e) = std::fs::rename(file, &self.learned) {
            self.restore_after_failed_rotation(had_learned);
            return Err(DaygleError::Io(e));
        }
        if let Err(e) = self.install() {
            let _ = std::fs::remove_file(&self.learned);
            self.restore_after_failed_rotation(had_learned);
            return Err(DaygleError::Config(format!(
                "the new model could not be loaded, so the current model was kept: {e}"
            )));
        }
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
        if let Some(hook) = self.after_promotion.get() {
            hook();
        }
        Ok(())
    }

    fn restore_after_failed_rotation(&self, had_learned: bool) {
        let previous = previous_model_path(&self.learned);
        if had_learned && previous.is_file() {
            let _ = std::fs::rename(&previous, &self.learned);
            swap_stats(&self.learned, StatsMove::PreviousToCurrent);
        }
    }

    /// Retrain now and put the result live at once: the operator's explicit
    /// choice, so no shadow trial. A candidate on trial is discarded.
    pub fn retrain(&self) -> Result<TrainingStats> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let settings = self.settings.load_full();
        if !self.applies(&settings) {
            return Err(DaygleError::Config(
                "no dedicated threat model is configured".to_string(),
            ));
        }
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
        let previous = previous_model_path(&self.learned);
        if !previous.is_file() {
            return Err(DaygleError::Config(
                "there is no previous model to restore".to_string(),
            ));
        }
        self.swap_with_previous()?;
        if let Err(e) = self.install() {
            if let Err(undo) = self.swap_with_previous() {
                self.log(
                    LogLevel::Warn,
                    format!("could not undo a failed model restore: {undo}"),
                );
            }
            return Err(DaygleError::Config(format!(
                "the previous model could not be loaded, so the current model was kept: {e}"
            )));
        }
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
        if let Err(e) = std::fs::rename(&previous, &self.learned) {
            let _ = std::fs::rename(&staged, &self.learned);
            return Err(DaygleError::Io(e));
        }
        if let Err(e) = std::fs::rename(&staged, &previous) {
            self.log(
                LogLevel::Warn,
                format!("the replaced model was left at {}: {e}", staged.display()),
            );
        }
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
        if !settings.enabled || !self.applies(&settings) {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
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
            self.log(LogLevel::Info, format!("AI retrain skipped: {e}"));
        }
        Some(outcome)
    }

    /// Build a candidate and put it on trial - or, with trials off, live.
    fn start_candidate(&self, settings: &AiSettings, trial: &Trial) -> Result<TrainingStats> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let built = self.build(settings)?;
        let record = built.record();
        if !settings.trial_new_models {
            if let Err(e) = self.promote(&built.temp, &record) {
                let _ = std::fs::remove_file(&built.temp);
                return Err(e);
            }
            self.log(
                LogLevel::Info,
                format!(
                    "AI retrained its classifier from {} examples across {} labels; it is in use now (trials are off)",
                    built.stats.examples, built.stats.labels
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
            self.role,
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
                self.role,
                &candidate,
                &live,
                started,
                ends,
            )
        });
        let now = chrono::Utc::now().timestamp();
        match verdict {
            Ok(why) => {
                let record = std::fs::read(candidate.with_extension("json"))
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                let _ = std::fs::remove_file(candidate.with_extension("json"));
                match self.promote(&candidate, &record) {
                    Ok(()) => {
                        self.log(
                            LogLevel::Info,
                            format!(
                                "AI promoted its candidate classifier after a shadow trial: {why}"
                            ),
                        );
                        self.write_trial(&trial.concluded(format!("promoted: {why}"), None));
                    }
                    Err(e) => {
                        self.reject(
                            settings,
                            trial,
                            format!("it passed its trial but could not be loaded: {e}"),
                            now,
                        );
                    }
                }
            }
            Err(why) => self.reject(settings, trial, why, now),
        }
    }

    /// Set a candidate aside, pause retraining and tell the operator. The
    /// live model was never touched.
    fn reject(&self, settings: &AiSettings, trial: &Trial, why: String, now: i64) {
        let candidate = candidate_path(&self.learned);
        let _ = std::fs::rename(&candidate, self.learned.with_extension("rejected.bin"));
        let _ = std::fs::remove_file(candidate.with_extension("json"));
        let pause = settings.retrain_interval_secs.max(3_600) as i64 * 2;
        self.log(
            LogLevel::Warn,
            format!(
                "AI rejected its candidate classifier after a shadow trial: {why}. The live model is unchanged; retraining pauses for {}h.",
                pause / 3600
            ),
        );
        daygle_dns_core::alerts::raise(
            daygle_dns_core::alerts::AlertKind::AiModel,
            format!("ai-model:{}:{now}", self.role.as_str()),
            "AI rejected a retrained model",
            format!(
                "The {} model the AI retrained did worse than the live model during its shadow trial ({why}), so it was set aside. Nothing changed for your clients; retraining resumes in {}h.",
                self.role.as_str(),
                pause / 3600
            ),
        );
        self.write_trial(&trial.concluded(format!("rejected: {why}"), Some(now + pause)));
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
    judge_shadow(
        store,
        settings,
        Role::Shared,
        candidate,
        live,
        started,
        ends,
    )
}

/// Score a candidate against the live model on what happened during its
/// trial. Four signals, each needing enough evidence to count; the candidate
/// must be no worse on every one that does:
///
/// * held-out threat families (where this model detects threats);
/// * the threats each finds among the domains looked up during the trial:
///   fewer than half, or more than twice as many (and ten more), rejects;
/// * the corrections the operator filed during the trial;
/// * labels an independent source - the page, the verifier model -
///   confirmed for domains seen during the trial.
fn judge_shadow(
    store: &AiStore,
    settings: &AiSettings,
    role: Role,
    candidate: &Path,
    live: &str,
    started: i64,
    ends: i64,
) -> std::result::Result<String, String> {
    let candidate_model =
        Predictor::load(&candidate.to_string_lossy()).map_err(|e| e.to_string())?;
    let live_model = Predictor::load(live).map_err(|e| e.to_string())?;
    let detects_threats = role == Role::Threat || !settings.dedicated_threat_model();
    let is_threat = |label: &str| role.is_threat_label(settings, label);
    let mut notes: Vec<String> = Vec::new();

    if detects_threats {
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
    }

    let domains = store
        .domains_classified_between(started, ends, TRIAL_DOMAINS)
        .unwrap_or_default();
    if detects_threats && !domains.is_empty() {
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
            "category" if role == Role::Shared => truths.push((
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

    // Independent confirmations for the domains seen during the trial.
    let seen: HashSet<&String> = domains.iter().collect();
    let confirmed: Vec<(String, Truth)> = store
        .independent_labels()
        .unwrap_or_default()
        .into_iter()
        .filter(|(domain, _)| seen.contains(domain))
        .map(|(domain, label)| (domain, Truth::Label(label)))
        .collect();
    score(
        "independently confirmed labels",
        &confirmed,
        &candidate_model,
        &live_model,
        &is_threat,
        &mut notes,
    )?;

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
    if with_candidate < with_live {
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
    PreviousToCurrent,
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
        StatsMove::PreviousToCurrent => {
            let _ = std::fs::remove_file(&current);
            let _ = std::fs::rename(&previous, &current);
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
