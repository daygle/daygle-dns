//! fastText backend: loads a supervised `.bin` model and classifies inputs.
//!
//! Models are trained out-of-process: a starter model ships under
//! `models/` (regenerate with the `train-starter-model` bin; see
//! `models/README.md`), and operators can point `ai.model_path` at any
//! supervised fastText `.bin`. Labels inside the model use the fastText
//! convention `__label__<category>`; the `__label__` prefix is stripped here.
//!
//! The backend is thread-safe: `FastText` inference in the pure-Rust crate
//! is `Send + Sync` (immutable model weights, per-call scratch state).

use daygle_dns_core::error::{DaygleError, Result};

use crate::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};

/// Category names that a real model may emit which count as threats (as in
/// the heuristic backend). Everything else is `info` severity. Severity sets
/// the verdict TTL and which verdicts the verifier re-checks; whether a
/// category auto-blocks is `ai.auto_block_categories`.
const DEFAULT_THREAT_CATEGORIES: &[&str] = &["malware", "phishing"];

/// fastText supervised classifier over a trained `.bin` model.
pub struct FastTextBackend {
    model: fasttext::FastText,
    threat_categories: Vec<String>,
}

impl FastTextBackend {
    /// Load the model file. Errors surface as config errors at startup so a
    /// bad path fails fast instead of silently degrading to heuristics.
    pub fn load(model_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let model = fasttext::FastText::load_model(model_path.as_ref()).map_err(|e| {
            DaygleError::Config(format!(
                "ai.model_path cannot load fastText model {}: {e}",
                model_path.as_ref().display()
            ))
        })?;
        // Autodetect category→severity: labels emitted by the model. A
        // feedback-friendly generic mapping: known threat names are threats,
        // the rest is info. (The exact auto-block category list is config's
        // job - `ai.auto_block_categories`.)
        let labels = model.get_labels().0;
        let threat_categories = labels
            .into_iter()
            .filter_map(|l| {
                // Lowercase, as `classify` compares lowercased labels: a
                // model labelled `__label__Malware` emitted `info` verdicts.
                let cat = l.strip_prefix("__label__")?.to_ascii_lowercase();
                DEFAULT_THREAT_CATEGORIES
                    .contains(&cat.as_str())
                    .then_some(cat)
            })
            .collect();
        Ok(Self {
            model,
            threat_categories,
        })
    }
}

impl DomainClassifier for FastTextBackend {
    fn name(&self) -> &str {
        "fasttext"
    }

    fn categories(&self) -> Vec<String> {
        self.model
            .get_labels()
            .0
            .iter()
            .filter_map(|l| l.strip_prefix("__label__"))
            .map(|c| c.to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        // fastText expects prose-ish text; tokens separated by spaces.
        // Domains are passed as-is (dots/hyphens are its word-token
        // boundaries), title/text (when the fetch stage lands) appended.
        let text = if input.title.is_empty() && input.text.is_empty() {
            input.domain.clone()
        } else {
            format!("{} {} {}", input.domain, input.title, input.text)
        };
        let predictions = self.model.predict(&text, 1, 0.0);
        let best = predictions.into_iter().next()?;
        let category = best
            .label
            .strip_prefix("__label__")
            .unwrap_or(&best.label)
            .to_ascii_lowercase();
        if category.is_empty() {
            return None;
        }
        let severity = if self.threat_categories.contains(&category) {
            Severity::Threat
        } else {
            Severity::Info
        };
        let evidence = format!(
            "fastText label '{}' (probability {:.3})",
            category, best.prob
        );
        Some(Verdict {
            category,
            confidence: best.prob,
            severity,
            evidence,
        })
    }
}
