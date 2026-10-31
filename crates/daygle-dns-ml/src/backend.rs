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
//! A MiniLM/ONNX verifier (see
//! [`crate::verifier_onnx`] / [`crate::verify`]) plugs in the same way:
//! threat verdicts from the primary get a second, more expensive pass that
//! corroborates or downgrades them.
//!
//! Every backend is scoped to a [`Channel`]: the scanner runs two of them, a
//! categorizer and a threat detector, each with its own model, thresholds and
//! verdict TTL. A label is only ever a threat because the *threat* channel
//! said so - see [`crate::channel`].

/// Which of the scanner's two jobs a backend performs.
///
/// The jobs have different precision requirements, so they are separate
/// passes with separate models, thresholds and TTLs rather than one label
/// that has to serve both: a categorizer wants coverage (label as much as it
/// can), a threat detector wants precision (say nothing when unsure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Content categorization: which kind of site is this (`news`,
    /// `shopping`, ...). Verdicts are informational and never auto-block.
    Content,
    /// Threat detection: is this site one an operator declared block-worthy
    /// (`ai.auto_block_categories`)? Only this channel can auto-block.
    Threat,
}

impl Channel {
    /// The name recorded on verdict rows and used in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Content => "content",
            Channel::Threat => "threat",
        }
    }

    /// Parse a channel name as stored in the verdict database (unknown
    /// values are `None`).
    pub fn from_stored(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "content" => Some(Channel::Content),
            "threat" => Some(Channel::Threat),
            _ => None,
        }
    }

    /// Both channels, in the order the scanner classifies them.
    pub fn all() -> [Channel; 2] {
        [Channel::Content, Channel::Threat]
    }
}
/// Severity attached to a verdict category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Ordinary content category (news, shopping, ...): never auto-blocks.
    Info,
    /// Threat category (malware, phishing): eligible to auto-block in
    /// enforce mode when confidence and corroboration are sufficient.
    Threat,
    /// A threat verdict an independent verifier disagreed with: kept and
    /// shown, never auto-blocked, and re-checked on the threat schedule.
    Disputed,
}

impl Severity {
    /// The short name stored in the verdict database and shown by the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Threat => "threat",
            Severity::Disputed => "disputed",
        }
    }
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
    /// Category identifiers this backend can emit (e.g. `malware`), used for
    /// category pickers in the console. Empty means "unknown" (the picker
    /// then only shows configured categories).
    fn categories(&self) -> Vec<String> {
        Vec::new()
    }
    /// Classify one input. `None` = "no signal" (the domain is not skipped:
    /// the scanner records the attempt without a verdict).
    fn classify(&self, input: &ClassificationInput) -> Option<Verdict>;
}

impl<T: DomainClassifier + ?Sized> DomainClassifier for Box<T> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn categories(&self) -> Vec<String> {
        (**self).categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        (**self).classify(input)
    }
}
