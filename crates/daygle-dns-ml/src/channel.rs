//! Channel scoping: binds a classifier to exactly one of the scanner's two
//! jobs, so a label can never mean two things at once.
//!
//! The scanner runs a [`Channel::Content`] pass and a [`Channel::Threat`]
//! pass over every domain. Each pass can have its own model
//! (`ai.category_model_path` / `ai.threat_model_path`), its own confidence
//! floor and its own verdict TTL. This wrapper is what makes the two passes
//! mean different things:
//!
//! | Channel   | Verdict it reports                                      |
//! |-----------|---------------------------------------------------------|
//! | `Content` | whatever the categorizer said, always severity `Info`   |
//! | `Threat`  | only the labels in `ai.auto_block_categories` (severity `Threat`), nothing otherwise |
//!
//! The threat channel reads its category list from the *live* settings, so
//! editing `auto_block_categories` changes what the next scan treats as a
//! threat without a restart. A content verdict is informational by
//! construction: categorization never blocks, and only the threat channel
//! feeds the block snapshot.
//!
//! Composition order matters. The threat wrapper sits *inside* the verifier
//! ([`crate::verify`]): it first decides "is this label a threat at all",
//! then the verifier corroborates or disputes that threat. Anything the
//! wrapper drops never reaches the verifier, so a content label costs no
//! embedding work.

use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;

use crate::backend::{Channel, ClassificationInput, DomainClassifier, Severity, Verdict};

/// A classifier restricted to one channel.
pub struct ChannelBackend {
    inner: Box<dyn DomainClassifier + Send + Sync>,
    channel: Channel,
    /// The threat channel's live settings (its category list). `None` for
    /// the content channel, which needs no configuration.
    settings: Option<Arc<ArcSwap<AiSettings>>>,
}

impl ChannelBackend {
    /// The categorization pass: labels sites, reports them as `Info`, never
    /// blocks.
    pub fn content(inner: Box<dyn DomainClassifier + Send + Sync>) -> Self {
        Self {
            inner,
            channel: Channel::Content,
            settings: None,
        }
    }

    /// The threat pass: reports only the labels `ai.auto_block_categories`
    /// names, promoted to `Severity::Threat`. Everything else is no signal.
    pub fn threat(
        inner: Box<dyn DomainClassifier + Send + Sync>,
        settings: Arc<ArcSwap<AiSettings>>,
    ) -> Self {
        Self {
            inner,
            channel: Channel::Threat,
            settings: Some(settings),
        }
    }

    /// Which channel this backend serves.
    pub fn channel(&self) -> Channel {
        self.channel
    }
}

impl DomainClassifier for ChannelBackend {
    /// The underlying pipeline's name (`fasttext`, `heuristic`, ...): the
    /// verdict row records the channel separately from the model that ran.
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn categories(&self) -> Vec<String> {
        self.inner.categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        let verdict = self.inner.classify(input)?;
        match self.channel {
            Channel::Content => Some(Verdict {
                severity: Severity::Info,
                ..verdict
            }),
            Channel::Threat => {
                // Settings are always present for this channel; no settings
                // means no declared threats, which is the safe reading.
                let settings = self.settings.as_ref()?.load();
                if !settings.is_auto_block_category(&verdict.category) {
                    return None;
                }
                Some(Verdict {
                    severity: Severity::Threat,
                    ..verdict
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn input() -> ClassificationInput {
        ClassificationInput::domain_only("example.com")
    }

    fn settings_with(categories: &[&str]) -> Arc<ArcSwap<AiSettings>> {
        Arc::new(ArcSwap::from_pointee(AiSettings {
            auto_block_categories: categories.iter().map(|c| c.to_string()).collect(),
            ..AiSettings::default()
        }))
    }

    #[test]
    fn content_verdicts_are_informational_even_for_threat_labels() {
        // The categorizer is allowed to notice "malware"; that is a label,
        // not a decision to block.
        let backend = ChannelBackend::content(Box::new(Fixed(Some(verdict(
            "malware",
            0.99,
            Severity::Threat,
        )))));
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.category, "malware");
        assert_eq!(v.severity, Severity::Info);
    }

    #[test]
    fn threat_channel_promotes_a_declared_category() {
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("phishing", 0.7, Severity::Info)))),
            settings_with(&["phishing"]),
        );
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.category, "phishing");
        assert_eq!(v.severity, Severity::Threat);
    }

    #[test]
    fn threat_channel_ignores_undeclared_categories() {
        // A content label is not a threat, so the threat channel has no
        // verdict to report for it.
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("news", 0.9, Severity::Info)))),
            settings_with(&["phishing"]),
        );
        assert!(backend.classify(&input()).is_none());
    }

    #[test]
    fn threat_channel_follows_live_category_changes() {
        let settings = settings_with(&["gambling"]);
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("news", 0.9, Severity::Info)))),
            settings.clone(),
        );
        assert!(backend.classify(&input()).is_none());

        // Declaring `news` block-worthy takes effect without rebuilding the
        // backend: the next classification treats it as a threat.
        settings.store(Arc::new(AiSettings {
            auto_block_categories: vec!["news".to_string()],
            ..AiSettings::default()
        }));
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.severity, Severity::Threat);
    }

    #[test]
    fn empty_category_list_means_no_threats() {
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("malware", 1.0, Severity::Threat)))),
            settings_with(&[]),
        );
        assert!(backend.classify(&input()).is_none());
    }

    #[test]
    fn names_and_categories_come_from_the_wrapped_backend() {
        let backend = ChannelBackend::content(Box::new(Fixed(None)));
        assert_eq!(backend.name(), "fixed");
        assert!(backend.categories().is_empty());
        assert_eq!(backend.channel(), Channel::Content);
    }
}
