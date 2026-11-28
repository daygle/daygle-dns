//! The page-text model: a fastText classifier over the text of pages the
//! page stage read, trained on this install from labels it did not invent.
//!
//! The page stage's own reader is a fixed table of weighted phrases
//! ([`crate::page::classify_text`]): predictable, but it only knows the
//! phrases someone wrote down. This model learns which page text goes with a
//! threat from the pages the server has already read:
//!
//! * a page whose domain a threat feed lists carries that feed's label;
//! * a page whose domain the operator marked "not a threat", or that this
//!   network has used for weeks ([`crate::store::Sighting::established`]),
//!   is `ordinary`;
//! * every other page is unlabelled and left out.
//!
//! It runs on the CPU with the fastText engine already in the binary and is
//! kept only while it beats the phrase table on pages held out of its
//! training ([`PageModel::maybe_retrain`]).
//!
//! What it may do is narrower than the phrase table, on purpose: it can add
//! a threat reading or strengthen one, never produce an "ordinary" reading
//! and never hide a threat phrase ([`PageModel::refine`]). The site writes
//! its own page, so a learned "this looks harmless" would be the easiest
//! thing for a site to game; a learned "this looks like the phishing pages
//! the feeds list" is not.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::{LogLevel, LogStore};

use crate::evidence::NetworkEvidence;
use crate::intel::INTEL_FEEDS;
use crate::learn::hash_selected;
use crate::page::{classify_text, TextVerdict};
use crate::store::AiStore;

/// The model file, beside `ai.db`.
pub const PAGE_MODEL_FILE: &str = "page-model.bin";
/// The label for pages known not to be threats.
pub const ORDINARY: &str = "ordinary";
/// Labelled pages needed in each class (ordinary, and threats together).
const MIN_PER_CLASS: usize = 20;
/// Held-out pages needed before the comparison with the phrase table counts.
const MIN_HELD_OUT: usize = 10;
/// The model's answer counts from this probability.
const MIN_PROBABILITY: f32 = 0.6;
/// A page reading never claims more than the phrase table can (below the
/// default block threshold, by construction).
const MAX_CONFIDENCE: f32 = 0.9;
/// Characters of page text the model reads.
const TEXT_CHARS: usize = 2_000;

/// The threat labels the model can learn: the feeds' labels.
fn threat_label(label: &str) -> Option<&'static str> {
    INTEL_FEEDS
        .iter()
        .map(|f| f.label)
        .find(|l| l.eq_ignore_ascii_case(label))
}

/// Normalised model input: title and opening text, lowercase words.
fn input(title: &str, text: &str) -> String {
    let joined = format!(
        "{title} {}",
        text.chars().take(TEXT_CHARS).collect::<String>()
    );
    let mut out = String::with_capacity(joined.len());
    let mut space = true;
    for ch in joined.chars().flat_map(char::to_lowercase) {
        if ch.is_alphanumeric() {
            out.push(ch);
            space = false;
        } else if !space {
            out.push(' ');
            space = true;
        }
    }
    out.trim().to_string()
}

/// The page-text model and its upkeep.
pub struct PageModel {
    path: PathBuf,
    store: Arc<AiStore>,
    evidence: Arc<NetworkEvidence>,
    logs: Arc<LogStore>,
    model: ArcSwap<Option<Arc<fasttext::FastText>>>,
    last_attempt: Mutex<Option<i64>>,
}

impl PageModel {
    /// Load the model at `path`, if one was trained before.
    pub fn new(
        path: PathBuf,
        store: Arc<AiStore>,
        evidence: Arc<NetworkEvidence>,
        logs: Arc<LogStore>,
    ) -> Arc<Self> {
        let loaded = path
            .is_file()
            .then(|| fasttext::FastText::load_model(&path).ok())
            .flatten()
            .map(Arc::new);
        Arc::new(Self {
            path,
            store,
            evidence,
            logs,
            model: ArcSwap::from_pointee(loaded),
            last_attempt: Mutex::new(None),
        })
    }

    fn record_path(&self) -> PathBuf {
        self.path.with_extension("json")
    }

    /// The model's state, for the status API.
    pub fn status(&self) -> serde_json::Value {
        let record = std::fs::read(self.record_path())
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok());
        serde_json::json!({
            "active": self.model.load().is_some(),
            "last": record,
        })
    }

    /// The reader in force, as a stable identity for provenance: the trained
    /// model's training time, or `phrases` while the phrase table still reads
    /// pages. A review is only comparable with a finding made by the same
    /// reader.
    pub fn version(&self) -> String {
        if self.model.load().is_none() {
            return "phrases".to_string();
        }
        std::fs::read(self.record_path())
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
            .and_then(|record| record.get("trained_at").and_then(|v| v.as_i64()))
            .map_or_else(|| "model".to_string(), |trained| format!("model:{trained}"))
    }

    /// What the model says about a page: a threat label and its probability,
    /// or `None` (no model, an ordinary page, or not sure enough).
    pub fn predict(&self, title: &str, text: &str) -> Option<(&'static str, f32)> {
        let model = self.model.load_full();
        let model = model.as_ref().as_ref()?;
        predict(model, &input(title, text))
    }

    /// Combine the phrase table's reading of a page with the model's. The
    /// model can add a threat reading or raise one; it never removes a
    /// threat phrase and never makes a page read as ordinary.
    pub fn refine(
        &self,
        reading: Option<TextVerdict>,
        title: &str,
        text: &str,
    ) -> (Option<TextVerdict>, Option<String>) {
        match self.predict(title, text) {
            Some((label, probability)) => {
                let note = format!("page model: {label} {:.0}%", probability * 100.0);
                (Some(combine(reading, label, probability)), Some(note))
            }
            None => (reading, None),
        }
    }

    /// Retrain when due (at most once per retrain interval), and keep the new
    /// model only if it reads held-out pages better than the phrase table
    /// and no worse than the model in use.
    pub fn maybe_retrain(&self, settings: &AiSettings) {
        if !settings.auto_retrain || !settings.fetch_pages {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        {
            let mut last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
            let interval = settings.retrain_interval_secs.max(3_600) as i64;
            let trained_at = self.trained_at();
            if last.is_some_and(|at| now - at < interval)
                || trained_at.is_some_and(|at| now - at < interval)
            {
                return;
            }
            *last = Some(now);
        }
        match self.retrain() {
            Ok(Some(note)) => self.logs.push(LogLevel::Info, "ai", note),
            Ok(None) => {}
            Err(e) => self.logs.push(
                LogLevel::Info,
                "ai",
                format!("page-text model not retrained: {e}"),
            ),
        }
    }

    fn trained_at(&self) -> Option<i64> {
        let raw = std::fs::read(self.record_path()).ok()?;
        let record: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        record.get("trained_at")?.as_i64()
    }

    /// The labelled pages: `(label, model input, domain)`.
    fn labelled(&self) -> Result<Vec<(String, String, String)>> {
        let intel = self.evidence.intel();
        let not_threats: HashSet<String> = self.store.not_threat_overrides()?;
        let mut out = Vec::new();
        for (domain, title, text) in self.store.page_texts()? {
            let label = if not_threats.contains(&domain) {
                Some(ORDINARY)
            } else if let Some(label) = intel.label_for(&domain) {
                Some(label)
            } else if self.evidence.is_known_ordinary(&domain) {
                Some(ORDINARY)
            } else {
                None
            };
            let text = input(&title, &text);
            if let Some(label) = label.filter(|_| !text.is_empty()) {
                out.push((label.to_string(), text, domain));
            }
        }
        Ok(out)
    }

    /// Train, judge and (if better) install a new model. `Ok(None)`: not
    /// enough labelled pages yet.
    pub fn retrain(&self) -> Result<Option<String>> {
        let labelled = self.labelled()?;
        let ordinary = labelled.iter().filter(|(l, ..)| l == ORDINARY).count();
        let threats = labelled.len() - ordinary;
        if ordinary < MIN_PER_CLASS || threats < MIN_PER_CLASS {
            return Ok(None);
        }
        let (held, training): (Vec<_>, Vec<_>) = labelled
            .into_iter()
            .partition(|(_, _, domain)| hash_selected(domain));
        if held.len() < MIN_HELD_OUT {
            return Ok(None);
        }

        let temp = self.path.with_extension("tmp");
        train(&training, &temp)?;
        let candidate = fasttext::FastText::load_model(&temp)
            .map_err(|e| DaygleError::Config(format!("page model reload failed: {e:?}")))?;
        let score = |guess: &dyn Fn(&str) -> bool| {
            held.iter()
                .filter(|(label, text, _)| guess(text) == (label != ORDINARY))
                .count()
        };
        let with_candidate = score(&|text: &str| predict(&candidate, text).is_some());
        // The phrase table on the same pages: a threat category at all.
        let with_phrases = score(&|text: &str| {
            classify_text("", text).is_some_and(|r| threat_label(r.category).is_some())
        });
        let current = self.model.load_full();
        let with_current = current
            .as_ref()
            .as_ref()
            .map(|model| score(&|text: &str| predict(model, text).is_some()));
        let n = held.len();
        let keep = with_candidate * 10 >= n * 7
            && with_candidate >= with_phrases
            && with_current.is_none_or(|current| with_candidate >= current);
        if !keep {
            let _ = std::fs::remove_file(&temp);
            return Err(DaygleError::Config(format!(
                "the new page-text model read {with_candidate} of {n} held-out pages right (phrase table {with_phrases}{}), so it was not used",
                with_current
                    .map(|c| format!(", model in use {c}"))
                    .unwrap_or_default()
            )));
        }
        std::fs::rename(&temp, &self.path)?;
        let record = serde_json::json!({
            "trained_at": chrono::Utc::now().timestamp(),
            "pages": training.len() + n,
            "ordinary": ordinary,
            "threats": threats,
            "held_out": n,
            "held_out_right": with_candidate,
            "phrase_table_right": with_phrases,
        });
        let _ = std::fs::write(
            self.record_path(),
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        );
        self.model.store(Arc::new(Some(Arc::new(candidate))));
        Ok(Some(format!(
            "AI trained its page-text model on {} pages; it read {with_candidate} of {n} held-out pages right (phrase table {with_phrases})",
            training.len() + n
        )))
    }
}

/// The model's threat label for `text`, when sure enough.
fn predict(model: &fasttext::FastText, text: &str) -> Option<(&'static str, f32)> {
    let best = model.predict(text, 1, 0.0).into_iter().next()?;
    let label = best.label.trim_start_matches("__label__");
    let probability = best.prob.clamp(0.0, 1.0);
    if probability < MIN_PROBABILITY {
        return None;
    }
    threat_label(label).map(|label| (label, probability))
}

/// See [`PageModel::refine`].
fn combine(reading: Option<TextVerdict>, label: &'static str, probability: f32) -> TextVerdict {
    let confidence = probability.min(MAX_CONFIDENCE);
    match reading {
        Some(mut reading) if threat_label(reading.category).is_some() => {
            reading.confidence = reading.confidence.max(confidence);
            reading.cues.push("page model");
            reading
        }
        other => {
            let mut also: Vec<&'static str> = Vec::new();
            if let Some(reading) = other {
                also.push(reading.category);
                also.extend(reading.also);
            }
            TextVerdict {
                category: label,
                confidence,
                cues: vec!["page model"],
                also,
            }
        }
    }
}

fn train(pairs: &[(String, String, String)], out: &std::path::Path) -> Result<()> {
    let corpus = out.with_extension("txt");
    let mut text = String::new();
    for (label, input, _) in pairs {
        text.push_str("__label__");
        text.push_str(label);
        text.push(' ');
        text.push_str(input);
        text.push('\n');
    }
    std::fs::write(&corpus, text)?;
    let mut args = fasttext::args::Args {
        input: corpus.clone(),
        output: out.with_extension("model"),
        ..Default::default()
    };
    args.apply_supervised_defaults();
    args.dim = 32;
    args.lr = 0.5;
    args.epoch = 25;
    args.word_ngrams = 2;
    args.minn = 3;
    args.maxn = 5;
    args.bucket = 100_000;
    args.thread = 2;
    args.seed = 42;
    args.verbose = 0;
    let trained = fasttext::FastText::train(args)
        .map_err(|e| DaygleError::Config(format!("page model training failed: {e:?}")))
        .and_then(|model| {
            model
                .save_model(out)
                .map_err(|e| DaygleError::Config(format!("page model save failed: {e:?}")))
        });
    let _ = std::fs::remove_file(&corpus);
    trained
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(category: &'static str, confidence: f32) -> TextVerdict {
        TextVerdict {
            category,
            confidence,
            cues: vec!["cue"],
            also: vec![],
        }
    }

    #[test]
    fn the_model_adds_or_raises_threats_only() {
        // No reading: the model's threat reading stands.
        let got = combine(None, "phishing", 0.95);
        assert_eq!(got.category, "phishing");
        assert_eq!(got.confidence, MAX_CONFIDENCE);
        // An ordinary reading: the threat wins, the ordinary category is kept
        // as `also`, so Decide can never cap on it.
        let got = combine(Some(reading("shopping", 0.8)), "scam", 0.7);
        assert_eq!(got.category, "scam");
        assert_eq!(got.also, vec!["shopping"]);
        // A threat reading: kept, raised.
        let got = combine(Some(reading("phishing", 0.5)), "malware", 0.8);
        assert_eq!(got.category, "phishing");
        assert_eq!(got.confidence, 0.8);
        assert!(got.cues.contains(&"page model"));
    }

    #[test]
    fn it_trains_on_labelled_pages_and_beats_the_phrase_table() {
        use crate::intel::Intel;
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(AiStore::open(&dir.path().join("ai.db")).unwrap());
        let settings = Arc::new(ArcSwap::from_pointee(AiSettings::default()));
        let logs = Arc::new(LogStore::new(16));
        let listed: std::collections::BTreeSet<String> =
            (0..60).map(|i| format!("wallet-sync{i}.example")).collect();
        store.replace_intel("phishing_army", &listed).unwrap();
        let intel = Intel::new(store.clone(), settings.clone(), logs.clone());
        let evidence = NetworkEvidence::new(store.clone(), intel, settings);
        // Phishing pages in words the phrase table does not know.
        for (i, domain) in listed.iter().enumerate() {
            store
                .save_page_text(
                    domain,
                    "Wallet sync",
                    &format!("enter your twelve word recovery phrase to resync wallet node {i}"),
                )
                .unwrap();
        }
        // Ordinary pages the operator vouched for.
        for i in 0..60 {
            let domain = format!("kitchen{i}.example");
            store.set_override(&domain, "not_threat", "").unwrap();
            store
                .save_page_text(
                    &domain,
                    "Recipes",
                    &format!("slow cooked stew with root vegetables and fresh herbs serves {i}"),
                )
                .unwrap();
        }
        let model = PageModel::new(dir.path().join(PAGE_MODEL_FILE), store, evidence, logs);
        assert!(model.predict("x", "y").is_none(), "no model yet");
        let note = model.retrain().unwrap().expect("enough labelled pages");
        assert!(note.contains("held-out pages"), "{note}");
        let (label, _) = model
            .predict("Wallet", "enter your recovery phrase to resync your wallet")
            .expect("reads as a threat");
        assert_eq!(label, "phishing");
        assert!(model
            .predict("Dinner", "stew with root vegetables and herbs")
            .is_none());
        assert_eq!(model.status()["active"], true);
    }

    #[test]
    fn input_is_normalised_and_bounded() {
        let got = input("Sign In!", &"Verify your ACCOUNT now. ".repeat(500));
        assert!(got.starts_with("sign in verify your account now"));
        assert!(got.len() <= TEXT_CHARS + 10);
    }
}
