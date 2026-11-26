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
    /// Threat detection: is this site a threat? The built-in families
    /// (`ai.auto_block_categories` plus the defaults, minus
    /// `ai.auto_block_removals`) decide. Only this channel can auto-block.
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
    /// The model's own threat score: the highest probability it gave any
    /// threat label, whether or not that label was the one it reported.
    /// `None` when the backend cannot score labels individually.
    pub threat_score: Option<f32>,
}

/// Input delivered to a backend for one domain.
#[derive(Debug, Clone, Default)]
pub struct ClassificationInput {
    /// Observed query name (lowercase, no trailing dot). Classifiers see
    /// only the name; what a page says is read separately by the page stage
    /// ([`crate::page`]).
    pub domain: String,
}

impl ClassificationInput {
    /// Input for one domain.
    pub fn domain_only(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
        }
    }
}
/// A pluggable classification backend. Cheap to share: every implementation
/// is `Send + Sync`, and one that can be swapped at runtime hides its interior
/// mutability behind [`Reloadable`].
pub trait DomainClassifier: Send + Sync {
    /// Backend name recorded on verdicts (e.g. `fasttext`, `heuristic`).
    /// Owned, not borrowed: a reloadable backend composes it from whichever
    /// classifier is currently installed.
    fn name(&self) -> String;
    /// Category identifiers this backend can emit (e.g. `malware`), used for
    /// category pickers in the console. Empty means "unknown" (the picker
    /// then only shows configured categories).
    fn categories(&self) -> Vec<String> {
        Vec::new()
    }
    /// Classify one input. `None` = "no signal" (the domain is not skipped:
    /// the scanner records the attempt without a verdict).
    fn classify(&self, input: &ClassificationInput) -> Option<Verdict>;
    /// Every label's probability for one input, as the model scored it.
    /// The default is the single reported verdict, for backends that only
    /// expose their top label; the threat channel uses this to score the
    /// threat labels even when the model's top label is an ordinary one.
    fn label_scores(&self, input: &ClassificationInput) -> Vec<(String, f32)> {
        self.classify(input)
            .map(|v| vec![(v.category, v.confidence)])
            .unwrap_or_default()
    }
}

/// A channel backend that can be replaced while the server is running: model
/// maintenance installs a retrained classifier here, so no restart is needed.
pub struct Reloadable {
    inner: arc_swap::ArcSwap<Box<dyn DomainClassifier + Send + Sync>>,
}

impl Reloadable {
    pub fn new(backend: Box<dyn DomainClassifier + Send + Sync>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            inner: arc_swap::ArcSwap::from_pointee(backend),
        })
    }

    /// Install `backend` for every subsequent classification.
    pub fn replace(&self, backend: Box<dyn DomainClassifier + Send + Sync>) {
        self.inner.store(std::sync::Arc::new(backend));
    }
}

impl DomainClassifier for Reloadable {
    fn name(&self) -> String {
        self.inner.load().name()
    }

    fn categories(&self) -> Vec<String> {
        self.inner.load().categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        self.inner.load().classify(input)
    }

    fn label_scores(&self, input: &ClassificationInput) -> Vec<(String, f32)> {
        self.inner.load().label_scores(input)
    }
}

impl<T: DomainClassifier + ?Sized> DomainClassifier for std::sync::Arc<T> {
    fn name(&self) -> String {
        (**self).name()
    }

    fn categories(&self) -> Vec<String> {
        (**self).categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        (**self).classify(input)
    }

    fn label_scores(&self, input: &ClassificationInput) -> Vec<(String, f32)> {
        (**self).label_scores(input)
    }
}

impl<T: DomainClassifier + ?Sized> DomainClassifier for Box<T> {
    fn name(&self) -> String {
        (**self).name()
    }

    fn categories(&self) -> Vec<String> {
        (**self).categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        (**self).classify(input)
    }

    fn label_scores(&self, input: &ClassificationInput) -> Vec<(String, f32)> {
        (**self).label_scores(input)
    }
}
