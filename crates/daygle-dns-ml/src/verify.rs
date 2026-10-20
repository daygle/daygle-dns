//! The verifying second pass: a cheap primary classifier's *threat* verdicts
//! get re-checked against an independent (more expensive) classifier.
//!
//! Design table from [`crate::backend`]: the fastText/heuristic classifier is
//! the primary; the MiniLM/ONNX verifier corroborates or refutes threat
//! verdicts. Content-category verdicts (severity `Info`) pass through
//! untouched — the verifier's job is to raise confidence in (or veto)
//! something that could auto-block.
//!
//! Rules (deliberately conservative, train-first stays the default):
//!
//! | Verifier result                                  | Effect                              |
//! |--------------------------------------------------|-------------------------------------|
//! | same threat category, above its confidence floor | confidence raise + corroboration    |
//! | same threat category, below floor                | annotation only (`unverified` tone) |
//! | different category, confident                    | severity downgrade to `Info`        |
//! | no verdict (below epsilon / no centroid match)   | annotation (`unverified`), keep base |
//!
//! A downgrade never destroys information: the original category is kept in
//! `evidence`, verdicts remain visible in the console, and the operator
//! allowlist still outranks anything derived here.

use crate::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};

/// Any primary + verifier pair. The verifier's own match threshold decides
/// where "confident" begins (`MiniLmVerifier` defaults to 0.35 cosine).
///
/// The classifier name recorded on verdicts is composed from the inner
/// backends at construction time (e.g. `fasttext+minilm-onnx`), so the
/// console's Backend column names the actual pipeline rather than the
/// opaque stage it implements.
pub struct VerifyingBackend<B, V> {
    pub base: B,
    pub verifier: V,
    name: String,
}

impl<B, V> VerifyingBackend<B, V>
where
    B: DomainClassifier,
    V: DomainClassifier,
{
    pub fn new(base: B, verifier: V) -> Self {
        let name = format!("{}+{}", base.name(), verifier.name());
        Self {
            base,
            verifier,
            name,
        }
    }
}

fn corroborated(v: Verdict, base: Verdict) -> Verdict {
    Verdict {
        confidence: base.confidence.max(v.confidence),
        evidence: format!(
            "{}, corroborated by {} ({})",
            base.evidence, v.category, v.evidence
        ),
        ..base
    }
}

fn downgraded(mut base: Verdict, verifier: Verdict) -> Verdict {
    if base.severity == Severity::Threat {
        base.severity = Severity::Info;
    }
    base.evidence = format!(
        "{}, {} disagrees (category '{}', {}): downgraded",
        base.evidence, "verifier", verifier.category, verifier.evidence
    );
    base
}

fn annotated(base: Verdict, verifier_name: &str) -> Verdict {
    Verdict {
        evidence: format!("{}, unverified by {verifier_name}", base.evidence),
        ..base
    }
}

impl<B, V> DomainClassifier for VerifyingBackend<B, V>
where
    B: DomainClassifier,
    V: DomainClassifier,
{
    fn name(&self) -> &str {
        &self.name
    }

    // The verifier never emits categories of its own; the primary backend's
    // list is the pipeline's.
    fn categories(&self) -> Vec<String> {
        self.base.categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        let base = self.base.classify(input)?;
        if base.severity != Severity::Threat {
            return Some(base);
        }
        match self.verifier.classify(input) {
            Some(v) if v.category == base.category => Some(corroborated(v, base)),
            Some(v) => {
                // A confident disagreement on the category destroys the
                // threat's plausibility even if the verifier is itself just
                // a heuristic: two cheap signals disagreeing is noise, and
                // this stage feeds enforce mode.
                Some(downgraded(base, v))
            }
            None => Some(annotated(base, self.verifier.name())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ClassificationInput;

    fn verdict(category: &str, confidence: f32, severity: Severity) -> Verdict {
        Verdict {
            category: category.to_string(),
            confidence,
            severity,
            evidence: format!("test '{category}'"),
        }
    }

    struct Fixed(Option<Verdict>);
    impl DomainClassifier for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn classify(&self, _input: &ClassificationInput) -> Option<Verdict> {
            self.0.clone()
        }
    }

    fn threat_input() -> ClassificationInput {
        ClassificationInput::domain_only("evil.example")
    }

    #[test]
    fn info_verdicts_pass_through_untouched() {
        let backend = VerifyingBackend::new(
            Fixed(Some(verdict("news", 0.8, Severity::Info))),
            Fixed(Some(verdict("shopping", 0.9, Severity::Info))),
        );
        let v = backend.classify(&threat_input()).unwrap();
        // Base info verdict survives even though the verifier disagrees, and
        // no second-pass annotation is applied.
        assert_eq!(v.category, "news");
        assert_eq!(v.severity, Severity::Info);
        assert!(!v.evidence.contains("disagrees"));
    }

    #[test]
    fn agreement_raises_confidence() {
        let backend = VerifyingBackend::new(
            Fixed(Some(verdict("phishing", 0.55, Severity::Threat))),
            Fixed(Some(verdict("phishing", 0.9, Severity::Threat))),
        );
        let v = backend.classify(&threat_input()).unwrap();
        assert_eq!(v.category, "phishing");
        assert_eq!(v.severity, Severity::Threat);
        assert_eq!(v.confidence, 0.9);
        assert!(v.evidence.contains("corroborated"));
    }

    #[test]
    fn disagreement_downgrades_threat() {
        let backend = VerifyingBackend::new(
            Fixed(Some(verdict("phishing", 0.99, Severity::Threat))),
            Fixed(Some(verdict("news", 0.7, Severity::Info))),
        );
        let v = backend.classify(&threat_input()).unwrap();
        assert_eq!(v.category, "phishing", "original category stays visible");
        assert_eq!(v.severity, Severity::Info, "verifier veto downgrades");
        assert!(v.evidence.contains("disagrees"));
    }

    #[test]
    fn no_verifier_verdict_annotates_but_keeps_base() {
        let backend = VerifyingBackend::new(
            Fixed(Some(verdict("malware", 0.99, Severity::Threat))),
            Fixed(None),
        );
        let v = backend.classify(&threat_input()).unwrap();
        assert_eq!(v.severity, Severity::Threat);
        assert!(v.evidence.contains("unverified"));
    }

    #[test]
    fn no_base_verdict_stays_none() {
        let backend = VerifyingBackend::new(
            Fixed(None),
            Fixed(Some(verdict("adult", 0.9, Severity::Info))),
        );
        assert!(backend.classify(&threat_input()).is_none());
    }
}
