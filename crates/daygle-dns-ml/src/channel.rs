//! Channel scoping: binds a classifier to exactly one of the scanner's two
//! jobs, so a label can never mean two things at once.
//!
//! The scanner runs a [`Channel::Content`] pass and a [`Channel::Threat`]
//! pass over every domain with the same model; each pass has its own
//! confidence floor and verdict TTL. This wrapper is what makes the two passes
//! mean different things:
//!
//! | Channel   | Verdict it reports                                      |
//! |-----------|---------------------------------------------------------|
//! | `Content` | whatever the categorizer said, always severity `Info`   |
//! | `Threat`  | a threat label, or any label when the threat score reaches the threshold |
//!
//! The threat channel reads its label set from the *live* settings, so
//! editing `auto_block_categories` or `auto_block_removals` changes what the
//! next scan treats as a threat without a restart. Detection and blocking are separate decisions:
//! this wrapper decides what is *reported* as a threat, and the scanner's
//! block snapshot applies `auto_block_categories`, `block_threshold`, the
//! verifier verdict and the mode before anything blocks. A content verdict is
//! informational by construction: categorization never blocks, and only the
//! threat channel feeds the block snapshot.
//!
//! Composition order matters. The threat wrapper sits *inside* the verifier
//! ([`crate::verify`]): it first decides "is this label a threat at all",
//! then the verifier corroborates or disputes that threat. Anything the
//! wrapper drops never reaches the verifier, so a content label costs no
//! embedding work.

use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::{AiSettings, LabelRole};

use crate::backend::{Channel, ClassificationInput, DomainClassifier, Severity, Verdict};
use crate::learn::BENIGN_LABEL;

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

    /// The threat pass: reports only threat labels (`AiSettings::threat_labels`),
    /// promoted to `Severity::Threat`. Everything else is no signal.
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
    fn name(&self) -> String {
        self.inner.name()
    }

    fn categories(&self) -> Vec<String> {
        let mut all = self.inner.categories();
        // `benign` is a categorization label. It is never a threat, so the
        // threat channel does not offer it to the auto-block list.
        if self.channel == Channel::Threat {
            all.retain(|label| label != BENIGN_LABEL);
        }
        all
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        let verdict = self.inner.classify(input)?;
        match self.channel {
            Channel::Content => Some(Verdict {
                severity: Severity::Info,
                threat_score: None,
                ..verdict
            }),
            Channel::Threat => {
                // "Not a threat" is the one negative the model can carry: a
                // learned label, never a finding - not even from an
                // auto-block list that names it.
                if verdict.category == BENIGN_LABEL {
                    return None;
                }
                // Settings are always present for this channel; no settings
                // means no declared threats, which is the safe reading.
                let settings = self.settings.as_ref()?.load();
                let role = settings.label_role(&verdict.category);
                // Never a threat: the operator's removal suppresses the
                // model's own verdict on that label, so nothing is reported.
                if role == LabelRole::Suppressed {
                    return None;
                }
                // The model's own threat score: its highest probability for
                // any threat label, even one it ranked below its top guess.
                // A threat label carries the verdict on its own; a
                // *classification* label only does when that score reaches
                // `block_threshold`, so the label list no longer decides
                // whether a suspicious domain can be reported at all.
                let strongest = self.strongest_threat_label(input, &settings);
                let score = strongest.as_ref().map(|(_, probability)| *probability);
                let verdict = if role == LabelRole::Threat {
                    Verdict {
                        severity: Severity::Threat,
                        threat_score: Some(score.unwrap_or(verdict.confidence)),
                        ..verdict
                    }
                } else {
                    // The classification is what the model named; the
                    // assessment names the family it actually scored, so the
                    // verifier corroborates like with like and enforcement
                    // applies `block_threshold` to the reported confidence.
                    let (label, probability) = strongest?;
                    if probability < settings.block_threshold {
                        return None;
                    }
                    let classification = verdict.category.clone();
                    Verdict {
                        category: label.to_ascii_lowercase(),
                        confidence: probability,
                        severity: Severity::Threat,
                        threat_score: Some(probability),
                        evidence: format!(
                            "{}; the model scored '{}' {:.0}% although it labelled this '{}'",
                            verdict.evidence,
                            label,
                            probability * 100.0,
                            classification
                        ),
                    }
                };
                Some(match self.cleared_parent(input, &settings) {
                    Some(parent) => parent_disputes(verdict, &parent),
                    None => verdict,
                })
            }
        }
    }
}

/// How sure the model must be that a subdomain's registered domain is an
/// ordinary site before that reading disputes the subdomain's threat.
const PARENT_CLEAR_FLOOR: f32 = 0.5;

/// A flagged subdomain's registered domain, as the model reads it.
struct ParentReading {
    domain: String,
    category: String,
    confidence: f32,
}

impl ChannelBackend {
    /// The highest probability the model gave any threat label, with the
    /// label that produced it. `None` when the backend cannot score labels
    /// individually.
    fn strongest_threat_label(
        &self,
        input: &ClassificationInput,
        settings: &AiSettings,
    ) -> Option<(String, f32)> {
        let labels = settings.threat_labels();
        self.inner
            .label_scores(input)
            .into_iter()
            .filter(|(label, _)| labels.iter().any(|t| t.eq_ignore_ascii_case(label)))
            .reduce(|best, candidate| if candidate.1 > best.1 { candidate } else { best })
    }

    /// When `input` is a subdomain, classify the registered domain it sits
    /// under (`employmenthero.com` for `secure.employmenthero.com`, per the
    /// Public Suffix List) and return that reading if it is an ordinary site.
    ///
    /// The model sees only the name. On a subdomain of an ordinary site the
    /// threat can only come from the added labels, and words like `secure`,
    /// `login`, `verify` or `download` are as common on real services as on
    /// phishing. A phishing name is chosen by whoever registered it, so its
    /// registered domain reads as a threat on its own
    /// (`secure-paypal-verify.info`). Free hosting under a PSL private
    /// suffix (`*.github.io`, `*.web.app`) counts the user's label as the
    /// registered domain, so those names are judged on their own.
    fn cleared_parent(
        &self,
        input: &ClassificationInput,
        settings: &AiSettings,
    ) -> Option<ParentReading> {
        let name = input
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let parent = psl::domain_str(&name)?;
        if parent == name {
            return None;
        }
        let reading = self
            .inner
            .classify(&ClassificationInput::domain_only(parent.to_string()))?;
        // Any label outside the block list is an ordinary site.
        let ordinary =
            reading.category == BENIGN_LABEL || !settings.is_auto_block_category(&reading.category);
        (ordinary && reading.confidence >= PARENT_CLEAR_FLOOR).then(|| ParentReading {
            domain: parent.to_string(),
            category: reading.category,
            confidence: reading.confidence,
        })
    }
}

/// The threat stays on record for review, but `Disputed` never blocks and
/// never trains the next model.
fn parent_disputes(mut verdict: Verdict, parent: &ParentReading) -> Verdict {
    verdict.severity = Severity::Disputed;
    verdict.evidence = format!(
        "{}, but its registered domain {} reads as '{}' ({:.0}%): disputed",
        verdict.evidence,
        parent.domain,
        parent.category,
        parent.confidence * 100.0
    );
    verdict
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
            threat_score: None,
        }
    }

    struct Fixed(Option<Verdict>);

    impl DomainClassifier for Fixed {
        fn name(&self) -> String {
            "fixed".to_string()
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
    fn the_threat_channel_never_reports_the_benign_label() {
        // Learned from `not_threat` corrections, `benign` says "this is not a
        // threat". Reporting it as one would turn the operator's correction
        // into a block, even with `benign` on the list.
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("benign", 0.99, Severity::Info)))),
            settings_with(&["benign"]),
        );
        assert!(backend.classify(&input()).is_none());

        // The categorizer may still say it: it is an ordinary label there.
        let content = ChannelBackend::content(Box::new(Fixed(Some(verdict(
            "benign",
            0.9,
            Severity::Info,
        )))));
        assert_eq!(content.classify(&input()).unwrap().category, "benign");
    }

    #[test]
    fn the_threat_channel_does_not_offer_benign_for_blocking() {
        struct Labels;
        impl DomainClassifier for Labels {
            fn name(&self) -> String {
                "labels".to_string()
            }
            fn categories(&self) -> Vec<String> {
                vec!["benign".to_string(), "phishing".to_string()]
            }
            fn classify(&self, _input: &ClassificationInput) -> Option<Verdict> {
                None
            }
        }
        let threat = ChannelBackend::threat(Box::new(Labels), settings_with(&["phishing"]));
        assert_eq!(threat.categories(), vec!["phishing".to_string()]);
        let content = ChannelBackend::content(Box::new(Labels));
        assert_eq!(content.categories().len(), 2);
    }

    #[test]
    fn the_list_overrides_the_built_in_threat_families() {
        // The model decides first: an empty list no longer means "no
        // threats", because malware, phishing and scam are built in.
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("malware", 1.0, Severity::Threat)))),
            settings_with(&[]),
        );
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.severity, Severity::Threat);

        // Removing a family is how the operator turns it off, and the same
        // backend picks that up on the next classification.
        let settings = settings_with(&[]);
        let backend = ChannelBackend::threat(
            Box::new(Fixed(Some(verdict("malware", 1.0, Severity::Threat)))),
            settings.clone(),
        );
        settings.store(Arc::new(AiSettings {
            auto_block_removals: vec!["malware".to_string()],
            ..AiSettings::default()
        }));
        assert!(backend.classify(&input()).is_none());
    }

    #[test]
    fn a_threat_score_is_recorded_from_the_models_own_probabilities() {
        // The model reported `malware`, but its own distribution put more
        // weight on `phishing`: the score is the strongest threat signal it
        // produced, not just the confidence of the label it named.
        let scores = vec![
            ("malware".to_string(), 0.31),
            ("phishing".to_string(), 0.72),
            ("news".to_string(), 0.05),
        ];
        struct Scored(Vec<(String, f32)>);
        impl DomainClassifier for Scored {
            fn name(&self) -> String {
                "scored".to_string()
            }
            fn classify(&self, _input: &ClassificationInput) -> Option<Verdict> {
                Some(verdict("malware", 0.31, Severity::Threat))
            }
            fn label_scores(&self, _input: &ClassificationInput) -> Vec<(String, f32)> {
                self.0.clone()
            }
        }
        let backend = ChannelBackend::threat(Box::new(Scored(scores)), settings_with(&[]));
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.category, "malware");
        assert_eq!(v.confidence, 0.31);
        assert_eq!(v.threat_score, Some(0.72));
    }

    /// Scores by table, names one label: the shape of a multi-label model
    /// whose top guess is an ordinary category.
    struct Scored(Vec<(String, f32)>, &'static str, f32);

    impl DomainClassifier for Scored {
        fn name(&self) -> String {
            "scored".to_string()
        }
        fn classify(&self, _input: &ClassificationInput) -> Option<Verdict> {
            Some(verdict(self.1, self.2, Severity::Info))
        }
        fn label_scores(&self, _input: &ClassificationInput) -> Vec<(String, f32)> {
            self.0.clone()
        }
    }

    #[test]
    fn a_threat_score_reports_a_domain_the_label_list_would_have_skipped() {
        // The model names `news`, which is a classification and never a
        // threat, but its own distribution puts `phishing` over the block
        // threshold. The score carries the verdict, so the label list no
        // longer decides whether a suspicious domain can be reported.
        let backend = ChannelBackend::threat(
            Box::new(Scored(
                vec![("news".to_string(), 0.02), ("phishing".to_string(), 0.995)],
                "news",
                0.02,
            )),
            settings_with(&[]),
        );
        let v = backend.classify(&input()).unwrap();
        assert_eq!(v.category, "phishing");
        assert_eq!(v.severity, Severity::Threat);
        assert_eq!(v.confidence, 0.995);
        assert_eq!(v.threat_score, Some(0.995));
        assert!(
            v.evidence.contains("labelled this 'news'"),
            "{}",
            v.evidence
        );
    }

    #[test]
    fn a_threat_score_below_the_block_threshold_leaves_a_classification_alone() {
        let backend = ChannelBackend::threat(
            Box::new(Scored(
                vec![("news".to_string(), 0.5), ("phishing".to_string(), 0.6)],
                "news",
                0.5,
            )),
            settings_with(&[]),
        );
        assert!(backend.classify(&input()).is_none());
    }

    #[test]
    fn a_suppressed_family_is_not_reported_even_with_a_high_score() {
        let settings = settings_with(&[]);
        settings.store(Arc::new(AiSettings {
            auto_block_removals: vec!["phishing".to_string()],
            ..AiSettings::default()
        }));
        let backend = ChannelBackend::threat(
            Box::new(Scored(
                vec![("news".to_string(), 0.01), ("phishing".to_string(), 1.0)],
                "news",
                0.01,
            )),
            settings,
        );
        assert!(backend.classify(&input()).is_none());
    }

    /// Answers by name: the registered domain and the subdomain can read
    /// differently, as they do with a name-only model.
    struct ByName(&'static [(&'static str, &'static str, f32)]);

    impl DomainClassifier for ByName {
        fn name(&self) -> String {
            "by-name".to_string()
        }
        fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
            self.0
                .iter()
                .find(|(name, _, _)| *name == input.domain)
                .map(|(_, category, confidence)| verdict(category, *confidence, Severity::Info))
        }
    }

    #[test]
    fn an_ordinary_registered_domain_disputes_its_subdomains_threat() {
        // The reported false positive: `secure.` on a payroll vendor.
        let backend = ChannelBackend::threat(
            Box::new(ByName(&[
                ("secure.employmenthero.com", "phishing", 0.995),
                ("employmenthero.com", "business", 0.99),
            ])),
            settings_with(&["phishing"]),
        );
        let v = backend
            .classify(&ClassificationInput::domain_only(
                "secure.employmenthero.com",
            ))
            .unwrap();
        assert_eq!(v.category, "phishing", "the finding stays on record");
        assert_eq!(v.severity, Severity::Disputed, "but never blocks");
        assert!(v
            .evidence
            .contains("employmenthero.com reads as 'business'"));
    }

    #[test]
    fn a_threatening_registered_domain_keeps_the_threat() {
        let backend = ChannelBackend::threat(
            Box::new(ByName(&[
                ("login.secure-paypal-verify.info", "phishing", 0.99),
                ("secure-paypal-verify.info", "phishing", 0.99),
            ])),
            settings_with(&["phishing"]),
        );
        let v = backend
            .classify(&ClassificationInput::domain_only(
                "login.secure-paypal-verify.info",
            ))
            .unwrap();
        assert_eq!(v.severity, Severity::Threat);
    }

    #[test]
    fn registered_domains_and_unsure_parents_are_judged_alone() {
        let model: &[(&str, &str, f32)] = &[
            ("secure-paypal-verify.info", "phishing", 0.99),
            ("x.unsure.com", "phishing", 0.99),
            ("unsure.com", "business", 0.3),
            // A PSL private suffix: the user's label is the registered domain.
            ("paypal-login.github.io", "phishing", 0.99),
            ("github.io", "developer", 0.99),
        ];
        let backend = ChannelBackend::threat(Box::new(ByName(model)), settings_with(&["phishing"]));
        for name in [
            "secure-paypal-verify.info",
            "x.unsure.com",
            "paypal-login.github.io",
        ] {
            let v = backend
                .classify(&ClassificationInput::domain_only(name))
                .unwrap();
            assert_eq!(v.severity, Severity::Threat, "{name}");
        }
    }

    #[test]
    fn names_and_categories_come_from_the_wrapped_backend() {
        let backend = ChannelBackend::content(Box::new(Fixed(None)));
        assert_eq!(backend.name(), "fixed");
        assert!(backend.categories().is_empty());
        assert_eq!(backend.channel(), Channel::Content);
    }
}
