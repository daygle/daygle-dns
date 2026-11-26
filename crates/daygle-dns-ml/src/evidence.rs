//! Network evidence: the second opinion a CPU-only install has without the
//! ONNX verifier, and an extra one beside it.
//!
//! The classifiers only ever see a domain's spelling. Two things the server
//! knows that spelling does not show:
//!
//! * whether a maintained threat feed lists the domain ([`crate::intel`]);
//! * how this network has used it - for how many days and by how many
//!   clients ([`crate::store::Sighting`]).
//!
//! [`EvidenceBackend`] wraps the threat channel (outside the MiniLM verifier,
//! when there is one) and applies them to every threat verdict:
//!
//! | Evidence                                   | Effect                                |
//! |--------------------------------------------|---------------------------------------|
//! | a feed lists it under a threat label       | corroborated at blocking confidence   |
//! | ... and the model saw no threat at all     | a threat on the listing alone         |
//! | its registered domain is a popular site    | disputed - never blocks on its name   |
//! | established: many clients, for weeks       | disputed - never blocks on its name   |
//! | a machine-generated name first seen today  | noted, small raise, never to blocking |
//! | none of these                              | unchanged                             |
//!
//! A feed listing wins over everything else, a MiniLM dispute included: the
//! feeds are curated by people looking at the actual sites. An established
//! domain is disputed because a name this network has relied on for weeks is
//! far more likely a false positive of a name-only model than a threat - the
//! case the scanner's own comments mention, a Windows Update host blocked on
//! a 77% guess. The operator's allowlist and corrections still outrank all of
//! it.
//!
//! The same evidence serves model maintenance: feed names and established
//! domains are the labels a trial scores candidates on when nobody filed a
//! correction, and the probes every candidate is checked against.

use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;

use crate::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};
use crate::intel::{Intel, IntelIndex};
use crate::store::{AiStore, Sighting};

/// The confidence a feed listing corroborates a threat verdict at: the
/// default block threshold, so a flagged and listed domain blocks in enforce
/// mode.
pub const LISTED_CONFIDENCE: f32 = 0.99;
/// What a feed listing writes into a verdict's evidence.
pub const LISTED_NOTE: &str = ", listed by ";
/// How a threat verdict made from a feed listing alone begins: the model
/// saw no threat in the name. Such verdicts block, but never train the name
/// model - their names are, by definition, ones that read as ordinary, and
/// teaching them as threats taught it that ordinary names are threats.
pub const UNFLAGGED_NOTE: &str = "no threat in the name";
/// How much a machine-generated name first seen today raises a threat
/// verdict, and the most it can raise it to: never to blocking on its own.
const GENERATED_RAISE: f32 = 0.05;
const GENERATED_CAP: f32 = 0.95;
/// "First seen today".
const NEW_SECS: i64 = 86_400;
/// Established domains used to probe a candidate model, at most.
pub const MAX_ESTABLISHED_PROBE: u32 = 500;

/// What the AI knows about a domain beyond its name.
pub struct NetworkEvidence {
    store: Arc<AiStore>,
    intel: Arc<Intel>,
    settings: Arc<ArcSwap<AiSettings>>,
}

impl NetworkEvidence {
    pub fn new(
        store: Arc<AiStore>,
        intel: Arc<Intel>,
        settings: Arc<ArcSwap<AiSettings>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            intel,
            settings,
        })
    }

    /// The threat feeds as they should be used now (empty while off).
    pub fn intel(&self) -> Arc<IntelIndex> {
        self.intel.index()
    }

    /// How this network has used `domain`.
    pub fn sighting(&self, domain: &str) -> Option<Sighting> {
        self.store.sighting(domain).ok().flatten()
    }

    /// Ordinary domains no feed lists, for probing candidate models: this
    /// network's established domains, then popular sites. With both, a new
    /// install has an ordinary probe from its first download, before weeks
    /// of traffic make any domain established.
    pub fn established_sample(&self) -> Vec<String> {
        let intel = self.intel();
        let mut sample: Vec<String> = self
            .store
            .established_domains(MAX_ESTABLISHED_PROBE * 2)
            .unwrap_or_default()
            .into_iter()
            .filter(|domain| intel.label_for(domain).is_none())
            .take(MAX_ESTABLISHED_PROBE as usize)
            .collect();
        let seen: std::collections::HashSet<String> = sample.iter().cloned().collect();
        sample.extend(
            intel
                .popular_sample()
                .into_iter()
                .filter(|domain| intel.label_for(domain).is_none() && !seen.contains(domain)),
        );
        sample
    }

    /// Whether `domain` is known ordinary: established on this network, or a
    /// popular site, and listed by no threat feed.
    pub fn is_known_ordinary(&self, domain: &str) -> bool {
        let intel = self.intel();
        intel.label_for(domain).is_none()
            && (intel.is_popular(domain) || self.sighting(domain).is_some_and(|s| s.established()))
    }

    /// A threat verdict from a feed listing alone, for a domain the model
    /// saw no threat in: the feeds are curated by people who looked at the
    /// site, so a listed name is a threat whatever its spelling suggests.
    /// Only for labels the operator ticked, and only while the network
    /// evidence is on.
    pub fn listed(&self, domain: &str) -> Option<Verdict> {
        if !self.settings.load().network_evidence {
            return None;
        }
        let feed = self.intel().feed_for(domain)?;
        if !self.settings.load().is_auto_block_category(feed.label) {
            return None;
        }
        Some(Verdict {
            category: feed.label.to_string(),
            confidence: LISTED_CONFIDENCE,
            severity: Severity::Threat,
            evidence: format!(
                "{UNFLAGGED_NOTE}{LISTED_NOTE}{} as {}",
                feed.source, feed.label
            ),
            threat_score: Some(LISTED_CONFIDENCE),
        })
    }

    /// Apply the evidence to one verdict (see the module table).
    pub fn judge(&self, domain: &str, base: Verdict) -> Verdict {
        if !matches!(base.severity, Severity::Threat | Severity::Disputed) {
            return base;
        }
        let settings = self.settings.load();
        if !settings.network_evidence {
            return base;
        }
        if let Some(feed) = self.intel().feed_for(domain) {
            if settings.is_auto_block_category(feed.label) {
                return Verdict {
                    confidence: base.confidence.max(LISTED_CONFIDENCE),
                    severity: Severity::Threat,
                    evidence: format!(
                        "{}{LISTED_NOTE}{} as {}",
                        base.evidence, feed.source, feed.label
                    ),
                    ..base
                };
            }
        }
        if base.severity != Severity::Threat {
            return base;
        }
        if self.intel().is_popular(domain) {
            return Verdict {
                severity: Severity::Disputed,
                evidence: format!(
                    "{}, but it is a popular site ({}): disputed",
                    base.evidence,
                    crate::intel::POPULAR.source
                ),
                ..base
            };
        }
        let seen = self.sighting(domain);
        if let Some(seen) = seen.as_ref().filter(|s| s.established()) {
            return Verdict {
                severity: Severity::Disputed,
                evidence: format!(
                    "{}, established on this network (looked up on {} days by {}+ clients): disputed",
                    base.evidence, seen.days, seen.clients
                ),
                ..base
            };
        }
        let now = chrono::Utc::now().timestamp();
        let new = seen.as_ref().is_none_or(|s| now - s.first_seen < NEW_SECS);
        if new && looks_machine_generated(domain) {
            let raised = (base.confidence + GENERATED_RAISE).min(GENERATED_CAP);
            return Verdict {
                confidence: base.confidence.max(raised),
                evidence: format!(
                    "{}, machine-generated-looking name first seen today",
                    base.evidence
                ),
                ..base
            };
        }
        base
    }
}

/// The threat channel with [`NetworkEvidence`] applied to its verdicts.
pub struct EvidenceBackend<B> {
    inner: B,
    evidence: Arc<NetworkEvidence>,
}

impl<B> EvidenceBackend<B> {
    pub fn new(inner: B, evidence: Arc<NetworkEvidence>) -> Self {
        Self { inner, evidence }
    }
}

impl<B: DomainClassifier> DomainClassifier for EvidenceBackend<B> {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn categories(&self) -> Vec<String> {
        self.inner.categories()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        match self.inner.classify(input) {
            Some(base) => Some(self.evidence.judge(&input.domain, base)),
            // The model saw no threat: a feed listing is one on its own.
            None => self.evidence.listed(&input.domain),
        }
    }
}

/// Whether a domain's registrable label reads like a domain generation
/// algorithm's output rather than a word: long, few vowels or long
/// consonant runs, and spread over many distinct characters.
pub fn looks_machine_generated(domain: &str) -> bool {
    let name = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let registrable = psl::domain_str(&name).unwrap_or(&name);
    let label = registrable.split('.').next().unwrap_or("");
    let letters: Vec<char> = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if letters.len() < 12 || label.contains('-') {
        return false;
    }
    let vowels = letters.iter().filter(|c| "aeiouy".contains(**c)).count();
    let digits = letters.iter().filter(|c| c.is_ascii_digit()).count();
    let mut run = 0usize;
    let mut longest = 0usize;
    for c in &letters {
        if c.is_ascii_alphabetic() && !"aeiouy".contains(*c) {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let mut counts = [0usize; 36];
    for c in &letters {
        let at = if c.is_ascii_digit() {
            (*c as u8 - b'0') as usize + 26
        } else {
            (*c as u8 - b'a') as usize
        };
        counts[at] += 1;
    }
    let n = letters.len() as f32;
    let entropy: f32 = counts
        .iter()
        .filter(|&&k| k > 0)
        .map(|&k| {
            let p = k as f32 / n;
            -p * p.log2()
        })
        .sum();
    let vowel_share = vowels as f32 / n;
    entropy >= 3.3 && (vowel_share < 0.25 || longest >= 5 || digits * 4 >= letters.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygle_dns_core::LogStore;

    fn threat(category: &str, confidence: f32) -> Verdict {
        Verdict {
            category: category.into(),
            confidence,
            severity: Severity::Threat,
            evidence: "model".into(),
            threat_score: None,
        }
    }

    fn evidence(settings: AiSettings) -> (tempfile::TempDir, Arc<AiStore>, Arc<NetworkEvidence>) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(AiStore::open(&dir.path().join("ai.db")).unwrap());
        let settings = Arc::new(ArcSwap::from_pointee(settings));
        let intel = Intel::new(store.clone(), settings.clone(), Arc::new(LogStore::new(10)));
        store
            .replace_intel(
                "phishing_army",
                &["paypa1-login.example".to_string()].into_iter().collect(),
            )
            .unwrap();
        intel.reload();
        let evidence = NetworkEvidence::new(store.clone(), intel, settings);
        (dir, store, evidence)
    }

    /// A listed domain is a threat even when the model saw none, under the
    /// feed's label; an unticked label or the evidence switched off leaves
    /// it alone.
    #[test]
    fn a_feed_listing_is_a_threat_on_its_own() {
        let (_dir, _store, judge) = evidence(AiSettings::default());
        let got = judge.listed("paypa1-login.example").unwrap();
        assert_eq!(got.category, "phishing");
        assert_eq!(got.severity, Severity::Threat);
        assert_eq!(got.confidence, LISTED_CONFIDENCE);
        assert!(got.evidence.contains("listed by Phishing Army as phishing"));
        assert!(judge.listed("news.example").is_none());

        // `phishing` is a built-in family, so removing it from the list is
        // what stops a phishing feed listing from being a threat.
        let (_dir, _store, judge) = evidence(AiSettings {
            auto_block_removals: vec!["phishing".into()],
            ..AiSettings::default()
        });
        assert!(judge.listed("paypa1-login.example").is_none());
        let (_dir, _store, judge) = evidence(AiSettings {
            network_evidence: false,
            ..AiSettings::default()
        });
        assert!(judge.listed("paypa1-login.example").is_none());
    }

    #[test]
    fn a_feed_listing_corroborates_even_a_dispute() {
        let (_dir, _store, evidence) = evidence(AiSettings::default());
        let got = evidence.judge("paypa1-login.example", threat("scam", 0.6));
        assert_eq!(got.confidence, LISTED_CONFIDENCE);
        assert_eq!(got.severity, Severity::Threat);
        assert!(got.evidence.contains("listed by Phishing Army as phishing"));
        let disputed = Verdict {
            severity: Severity::Disputed,
            ..threat("phishing", 0.8)
        };
        assert_eq!(
            evidence.judge("paypa1-login.example", disputed).severity,
            Severity::Threat
        );
        // Content verdicts are never touched.
        let info = Verdict {
            severity: Severity::Info,
            ..threat("news", 0.5)
        };
        assert_eq!(evidence.judge("paypa1-login.example", info.clone()), info);
    }

    #[test]
    fn established_domains_are_disputed() {
        let (_dir, store, evidence) = evidence(AiSettings::default());
        let start = chrono::Utc::now().timestamp() - 30 * 86_400;
        let clients: Vec<String> = (0..5).map(|i| format!("10.0.0.{i}")).collect();
        for d in 0..20 {
            store
                .record_sightings_at(
                    &[("update.vendor.example".into(), clients.clone())],
                    start + d * 86_400,
                )
                .unwrap();
        }
        let got = evidence.judge("update.vendor.example", threat("malware", 0.995));
        assert_eq!(got.severity, Severity::Disputed);
        assert!(got.evidence.contains("established on this network"));
        assert_eq!(evidence.established_sample(), vec!["update.vendor.example"]);
    }

    #[test]
    fn popular_sites_are_disputed_but_feeds_win() {
        let (_dir, store, evidence) = evidence(AiSettings::default());
        store
            .replace_intel(
                crate::intel::POPULAR.id,
                &[
                    "bigbank.example".to_string(),
                    "paypa1-login.example".to_string(),
                ]
                .into_iter()
                .collect(),
            )
            .unwrap();
        evidence.intel.reload();
        let got = evidence.judge("secure.bigbank.example", threat("phishing", 0.995));
        assert_eq!(got.severity, Severity::Disputed);
        assert!(got.evidence.contains("popular site"), "{}", got.evidence);
        assert!(evidence.is_known_ordinary("bigbank.example"));
        // A feed listing still confirms a popular name.
        let listed = evidence.judge("paypa1-login.example", threat("phishing", 0.6));
        assert_eq!(listed.severity, Severity::Threat);
        assert!(!evidence.is_known_ordinary("paypa1-login.example"));
        assert!(evidence
            .established_sample()
            .contains(&"bigbank.example".to_string()));
    }

    #[test]
    fn switched_off_it_changes_nothing() {
        let (_dir, _store, evidence) = evidence(AiSettings {
            network_evidence: false,
            ..AiSettings::default()
        });
        let base = threat("phishing", 0.6);
        assert_eq!(evidence.judge("paypa1-login.example", base.clone()), base);
    }

    #[test]
    fn feeds_switched_off_are_not_consulted() {
        let (_dir, _store, evidence) = evidence(AiSettings {
            threat_feeds: false,
            ..AiSettings::default()
        });
        let got = evidence.judge("paypa1-login.example", threat("phishing", 0.6));
        assert_eq!(got.confidence, 0.6);
    }

    #[test]
    fn generated_names_are_noted_but_never_block() {
        let (_dir, _store, evidence) = evidence(AiSettings::default());
        let got = evidence.judge("xkqzvbtrwplmn7f3.example", threat("malware", 0.93));
        assert!(got.evidence.contains("machine-generated"));
        assert!((got.confidence - GENERATED_CAP).abs() < 1e-6);
        let high = evidence.judge("xkqzvbtrwplmn7f3.example", threat("malware", 0.97));
        assert_eq!(
            high.confidence, 0.97,
            "never lowered, never raised past the cap"
        );
    }

    #[test]
    fn generated_name_heuristic() {
        for generated in [
            "xkqzvbtrwplmn7f3.com",
            "qwkjhzxcvbnmlkj.net",
            "a8f3k2p9x7q1z5m4.org",
        ] {
            assert!(looks_machine_generated(generated), "{generated}");
        }
        for word in [
            "wikipedia.org",
            "microsoftonline.com",
            "stackoverflow.com",
            "my-long-company-name.co.uk",
            "googleusercontent.com",
            "short.io",
        ] {
            assert!(!looks_machine_generated(word), "{word}");
        }
    }
}
