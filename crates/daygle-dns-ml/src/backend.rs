//! The classifier abstraction shared by every AI backend.
//!
//! A [`DomainClassifier`] turns observed input (a domain name, and later page
//! text snippets) into an optional [`Verdict`] (category + confidence). Two
//! implementations ship today:
//!
//! | Backend           | Model                                              | Cost       |
//! |-------------------|----------------------------------------------------|------------|
//! | [`crate::heuristic::HeuristicBackend`] | built-in keyword tables                      | µs, 0 MB   |
//! | [`crate::fasttext_backend::FastTextBackend`] | supervised fastText `.bin` model | ms, ~1-20 MB |
//!
//! The planned MiniLM/ONNX verifier (next milestone) plugs in the same way:
//! flagged or low-evidence domains get a second, more expensive pass.

/// Severity attached to a verdict category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Ordinary content category (news, shopping, ...): never auto-blocks.
    Info,
    /// Threat category (malware, phishing): eligible to auto-block in
    /// enforce mode when confidence and corroboration are sufficient.
    Threat,
}

/// One classification verdict produced by a backend.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Lowercase category label, e.g. `malware`, `phishing`, `news`.
    pub category: String,
    /// Backend confidence in `[0, 1]`.
    pub confidence: f32,
    /// Threat vs ordinary content.
    pub severity: Severity,
    /// Short human-readable explanation (matched keywords, label name, ...).
    pub evidence: String,
}

/// Input delivered to a backend for one domain.
#[derive(Debug, Clone, Default)]
pub struct ClassificationInput {
    /// Observed query name (lowercase, no trailing dot).
    pub domain: String,
    /// Page `<title>` when a page fetch ran (empty until the page-fetch
    /// stage lands).
    pub title: String,
    /// Extracted page text when a page fetch ran (empty until then).
    pub text: String,
}

impl ClassificationInput {
    /// Input for a domain-only classification.
    pub fn domain_only(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            ..Default::default()
        }
    }
}

/// A pluggable classification backend. Cheap to share: implementations are
/// interior-mutated (`Arc` every `Send + Sync`).
pub trait DomainClassifier: Send + Sync {
    /// Backend name recorded on verdicts (e.g. `fasttext`, `heuristic`).
    fn name(&self) -> &str;
    /// Classify one input. `None` = "no signal" (the domain is not skipped:
    /// the scanner records the attempt without a verdict).
    fn classify(&self, input: &ClassificationInput) -> Option<Verdict>;
}
