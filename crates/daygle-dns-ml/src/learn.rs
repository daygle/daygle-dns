//! The scanner's own model maintenance: retraining the classifier from what
//! the scanner has already learned.
//!
//! A fastText model is immutable once trained - there is no online update - so
//! "maintained by the AI" means periodic retraining from the data the scanner
//! itself produces:
//!
//! * the operator's category corrections, which are authoritative;
//! * confident, unexpired verdicts, which keep the model current with what the
//!   network actually resolves.
//!
//! Corrections that say "do not block this" (`allow`, `not_threat`) are left
//! out: a single-label classifier cannot express a negative, and inventing a
//! "benign" label would make the threat channel report it as a threat.
//!
//! A candidate is judged before it can replace anything: every fifth correction
//! is held back from training, and the candidate must not score worse on those
//! held-out labels than the model currently in use. Once accepted, the engine
//! loads it into the running channels - no restart.
//!
//! The model is written beside `ai.db` as `learned.bin` and preferred over
//! `ai.model_path` from then on, unless a channel names its own model or the
//! configured model file is newer. Deleting the file reverts.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::{LogLevel, LogStore};

use crate::scanner::looks_like_domain;
use crate::store::AiStore;

/// A retrain needs this many examples, across at least [`MIN_LABELS`] labels,
/// before it may replace a model.
pub const MIN_EXAMPLES: usize = 200;
/// One label alone cannot train a classifier.
pub const MIN_LABELS: usize = 2;
/// One label contributes at most this many examples, so a lopsided corpus
/// cannot drown the others.
const MAX_PER_LABEL: usize = 2_000;
/// Verdicts read per retrain, strongest first.
const MAX_VERDICTS: u32 = 20_000;
/// A candidate must reproduce at least this share of whatever it is judged on.
const MIN_ACCURACY: f32 = 0.5;
/// A candidate may trail the model in use by this much on held-out labels
/// before it is rejected: small differences are noise, a real regression is
/// not.
const VALIDATION_SLACK: f32 = 0.02;
/// Every fifth correction is held back for validation, once there are enough.
const HOLDOUT_EVERY: usize = 5;

/// What one collection pass produced.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TrainingStats {
    pub examples: usize,
    pub labels: usize,
    /// Examples that came from an operator relabel.
    pub corrections: usize,
    /// Examples that came from the scanner's own confident verdicts.
    pub verdicts: usize,
}

/// The training set plus the labels held back to judge the result.
pub struct Dataset {
    pub pairs: Vec<(String, String)>,
    pub validation: Vec<(String, String)>,
    pub stats: TrainingStats,
}

/// The model the scanner maintains for itself: beside the verdict store, so it
/// travels with the data rather than with the install.
pub fn learned_model_path(database: &Path) -> PathBuf {
    database.with_file_name("learned.bin")
}

/// Where the outcome of the last successful retrain is recorded.
pub fn stats_path(learned: &Path) -> PathBuf {
    learned.with_extension("json")
}

/// The training set and its held-out slice: corrections first, then confident
/// verdicts.
pub fn collect_dataset(store: &AiStore, settings: &AiSettings) -> Result<Dataset> {
    let now = chrono::Utc::now().timestamp();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut validation: Vec<(String, String)> = Vec::new();
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut corrected: HashSet<String> = HashSet::new();
    let mut stats = TrainingStats::default();

    // Operator labels, oldest-filed last: deterministic enough, and the
    // holdout is what makes the gate meaningful.
    let mut corrections: Vec<(String, String)> = Vec::new();
    for correction in store.corrections()? {
        let label = correction.category.trim().to_ascii_lowercase();
        let domain = correction
            .domain
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if correction.action != "category" || label.is_empty() || !looks_like_domain(&domain) {
            continue;
        }
        corrected.insert(domain.clone());
        corrections.push((label, domain));
    }
    let hold_out = corrections.len() >= HOLDOUT_EVERY;
    for (index, (label, domain)) in corrections.into_iter().enumerate() {
        if hold_out && index % HOLDOUT_EVERY == HOLDOUT_EVERY - 1 {
            validation.push((label, domain));
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            stats.corrections += 1;
        }
    }

    for (_channel, label, domain) in store.confident_verdicts(
        settings.category_confidence_floor,
        settings.block_threshold,
        now,
        MAX_VERDICTS,
    )? {
        let label = label.trim().to_ascii_lowercase();
        let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
        // A corrected domain never contributes its machine label, whether the
        // correction is training data or held-out validation.
        if label.is_empty() || corrected.contains(&domain) || !looks_like_domain(&domain) {
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            stats.verdicts += 1;
        }
    }

    stats.examples = pairs.len();
    stats.labels = labels.len();
    Ok(Dataset {
        pairs,
        validation,
        stats,
    })
}

/// The whole set, held-out labels included: what the tests and callers that
/// only want "everything known" should read.
pub fn collect(
    store: &AiStore,
    settings: &AiSettings,
) -> Result<(Vec<(String, String)>, TrainingStats)> {
    let mut dataset = collect_dataset(store, settings)?;
    let mut pairs = std::mem::take(&mut dataset.pairs);
    pairs.extend(dataset.validation.iter().cloned());
    Ok((pairs, dataset.stats))
}

fn push(
    pairs: &mut Vec<(String, String)>,
    labels: &mut BTreeMap<String, usize>,
    seen: &mut HashSet<(String, String)>,
    label: &str,
    domain: &str,
) -> bool {
    if labels.get(label).copied().unwrap_or(0) >= MAX_PER_LABEL {
        return false;
    }
    if !seen.insert((label.to_string(), domain.to_string())) {
        return false;
    }
    *labels.entry(label.to_string()).or_insert(0) += 1;
    pairs.push((label.to_string(), domain.to_string()));
    true
}

/// Train a supervised classifier into `out`. Settings match the shipped
/// starter model (small, CPU-only, character n-grams) so a retrained file is a
/// drop-in replacement.
pub fn train(pairs: &[(String, String)], out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let corpus = out.with_extension("fasttext");
    let mut expanded = String::new();
    for (label, domain) in pairs {
        for variant in variants(domain) {
            // fastText's supervised format: the prefix is what makes the first
            // token a label rather than a feature.
            expanded.push_str("__label__");
            expanded.push_str(label);
            expanded.push(' ');
            expanded.push_str(&variant);
            expanded.push('\n');
        }
    }
    std::fs::write(&corpus, expanded)?;

    let mut args = fasttext::args::Args {
        input: corpus.clone(),
        output: out.with_extension("model"),
        ..Default::default()
    };
    args.apply_supervised_defaults();
    args.dim = 24;
    args.lr = 0.3;
    args.epoch = 40;
    args.word_ngrams = 1;
    args.minn = 3;
    args.maxn = 5;
    args.bucket = 50_000;
    args.thread = 2;
    args.seed = 42;
    args.verbose = 0;

    let model = fasttext::FastText::train(args)
        .map_err(|e| DaygleError::Config(format!("model training failed: {e:?}")))?;
    model
        .save_model(out)
        .map_err(|e| DaygleError::Config(format!("model save failed: {e:?}")))?;
    let _ = std::fs::remove_file(&corpus);
    Ok(())
}

/// How much of `pairs` a model at `model` gets right (top-1).
pub fn probe_accuracy(model: &Path, pairs: &[(String, String)]) -> Result<f32> {
    if pairs.is_empty() {
        return Ok(0.0);
    }
    let trained = fasttext::FastText::load_model(model)
        .map_err(|e| DaygleError::Config(format!("model reload failed: {e:?}")))?;
    let mut right = 0usize;
    for (label, domain) in pairs {
        let got = trained
            .predict(domain, 1, 0.0)
            .first()
            .map(|p| p.label.trim_start_matches("__label__").to_ascii_lowercase())
            .unwrap_or_default();
        if &got == label {
            right += 1;
        }
    }
    Ok(right as f32 / pairs.len() as f32)
}

/// Tokenization variants of one domain, matching how the scanner hands names
/// to the classifier. Duplicated from `train-starter-model` on purpose: the
/// offline tool also verifies against a curated probe list, which a runtime
/// retrain has no business carrying.
fn variants(domain: &str) -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let plain = domain.to_string();
    if !domain.starts_with("www.") {
        out.insert(format!("www.{plain}"));
    }
    out.insert(plain.clone());
    out.insert(plain.replace('.', "-"));
    out.insert(domain.split(['.', '-']).collect::<Vec<_>>().join(" "));
    out.into_iter().collect()
}

/// Retrains the classifier from the store, judged against the model in use so
/// a bad run can never replace a working one.
pub struct Retrainer {
    store: Arc<AiStore>,
    settings: Arc<ArcSwap<AiSettings>>,
    logs: Arc<LogStore>,
    learned: PathBuf,
    /// The model file the running scanner loaded: the baseline the candidate
    /// has to match on held-out labels.
    current_model: Arc<ArcSwap<String>>,
    last_attempt: std::sync::Mutex<Option<i64>>,
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
            last_attempt: std::sync::Mutex::new(None),
        }
    }

    /// The model file this retrainer maintains.
    pub fn learned_model(&self) -> &Path {
        &self.learned
    }

    /// Retrain now. A rejected or failed run leaves the model in use
    /// untouched.
    pub fn retrain(&self) -> Result<TrainingStats> {
        let settings = self.settings.load_full();
        let Dataset {
            pairs,
            validation,
            stats,
        } = collect_dataset(&self.store, &settings)?;
        if pairs.len() < MIN_EXAMPLES || stats.labels < MIN_LABELS {
            return Err(DaygleError::Config(format!(
                "not enough training data yet: {} examples across {} labels (a retrain needs {} and {})",
                pairs.len(),
                stats.labels,
                MIN_EXAMPLES,
                MIN_LABELS
            )));
        }

        let temp = self.learned.with_extension("tmp");
        train(&pairs, &temp)?;
        let train_accuracy = match probe_accuracy(&temp, &pairs) {
            Ok(accuracy) => accuracy,
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        };

        // The gate: judge the candidate on labels it never saw, against the
        // model that is actually classifying right now.
        let mut validation_accuracy = None;
        if validation.is_empty() {
            if train_accuracy < MIN_ACCURACY {
                let _ = std::fs::remove_file(&temp);
                return Err(DaygleError::Config(format!(
                    "the retrained model reproduced only {:.0}% of its own training data, so the current model was kept",
                    train_accuracy * 100.0
                )));
            }
        } else {
            let candidate = match probe_accuracy(&temp, &validation) {
                Ok(accuracy) => accuracy,
                Err(e) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(e);
                }
            };
            let current_path = self.current_model.load_full().to_string();
            let baseline = if current_path.trim().is_empty() {
                None
            } else {
                probe_accuracy(Path::new(&current_path), &validation).ok()
            };
            if candidate < MIN_ACCURACY {
                let _ = std::fs::remove_file(&temp);
                return Err(DaygleError::Config(format!(
                    "the retrained model scored {:.0}% on {} held-out corrections, so the current model was kept",
                    candidate * 100.0,
                    validation.len()
                )));
            }
            if let Some(baseline) = baseline {
                if candidate + VALIDATION_SLACK < baseline {
                    let _ = std::fs::remove_file(&temp);
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
        std::fs::rename(&temp, &self.learned)?;

        let record = serde_json::json!({
            "trained_at": chrono::Utc::now().to_rfc3339(),
            "examples": stats.examples,
            "labels": stats.labels,
            "corrections": stats.corrections,
            "verdicts": stats.verdicts,
            "train_accuracy": (train_accuracy * 100.0).round() / 100.0,
            "validation_examples": validation.len(),
            "validation_accuracy": validation_accuracy
                .map(|a| (a * 100.0).round() / 100.0),
        });
        match serde_json::to_vec_pretty(&record) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(stats_path(&self.learned), bytes) {
                    self.logs.push(
                        LogLevel::Warn,
                        "ai",
                        format!("could not record the retrain result: {e}"),
                    );
                }
            }
            Err(e) => self.logs.push(
                LogLevel::Warn,
                "ai",
                format!("could not encode the retrain result: {e}"),
            ),
        }
        let judged = match validation_accuracy {
            Some(accuracy) => format!(
                ", and kept {:.0}% on {} held-out corrections",
                accuracy * 100.0,
                validation.len()
            ),
            None => String::new(),
        };
        self.logs.push(
            LogLevel::Info,
            "ai",
            format!(
                "AI retrained its classifier from {} examples across {} labels ({} from your corrections{judged})",
                stats.examples, stats.labels, stats.corrections
            ),
        );
        Ok(stats)
    }

    /// Retrain when automatic maintenance is on, the interval has passed and
    /// there is enough material. `None` means "not due". Failures are logged
    /// and returned; they never disturb the scan loop.
    pub fn maybe_retrain(&self) -> Option<Result<TrainingStats>> {
        let settings = self.settings.load_full();
        if !settings.enabled || !settings.auto_retrain {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        let interval = settings.retrain_interval_secs.max(3_600) as i64;
        {
            let mut last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(at) = *last {
                if now - at < interval {
                    return None;
                }
            }
            *last = Some(now);
        }
        let outcome = self.retrain();
        if let Err(e) = &outcome {
            // Info, not Warn: "not enough data yet" is the normal state for a
            // young install, not a fault.
            self.logs
                .push(LogLevel::Info, "ai", format!("AI retrain skipped: {e}"));
        }
        Some(outcome)
    }
}
