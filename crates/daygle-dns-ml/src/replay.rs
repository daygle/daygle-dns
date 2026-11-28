//! Candidate replay: score a candidate model on reviewed findings the same
//! way the live enforcement gate would score them.
//!
//! The shadow trial used to measure the candidate on its name reading alone.
//! The gate does more than that: it fuses the evidence kept beside the verdict,
//! applies the page rule and the language model's adjustment, filters the
//! finding through the operator's exemptions and category overrides, holds a
//! source to its measured authority stage, and compares the result with the
//! block threshold. A candidate that only looked good on the name could
//! therefore be promoted into a gate that would never block its findings, or
//! that would block findings the live gate suppresses.
//!
//! This module rebuilds that decision for one domain with a candidate
//! backend. It never writes a verdict: the replay is diagnostic and feeds the
//! shadow report.

use std::collections::{HashMap, HashSet};

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::Result;

use crate::assessment;
use crate::authority;
use crate::backend::{self, DomainClassifier, Severity, Verdict};
use crate::calibration::CalibrationMap;
use crate::fusion::{self, SignalWeights};
use crate::store::AiStore;

/// The one domain-specific decision the live gate makes, rebuilt for a
/// candidate.
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    /// The assessment score before calibration: the fused score when fusion
    /// decides, else the candidate's confidence. A trial fits and validates
    /// its own map on this, then chooses the threshold on the calibrated
    /// result, which is the order the live gate scores in.
    pub score: f32,
    /// The policy rail that would stop the finding from blocking, if any.
    pub policy_blocked: Option<String>,
    /// Whether the candidate reported a threat at all.
    pub threat: bool,
    /// The category the candidate's verdict carries.
    pub category: String,
    /// The observations the assessment was built from.
    pub observations: Vec<assessment::SignalObservation>,
    /// The fused view, when fusion ran.
    pub fusion: Option<fusion::Fusion>,
    /// The calibrated score, when a map was applied.
    pub calibrated: Option<f32>,
    /// The map version that produced `calibrated`.
    pub calibration_version: String,
}

impl ReplayOutcome {
    /// The score of record the live gate compares: the calibration map's
    /// output when one is in force, else the assessment score.
    pub fn gate_score(&self) -> f32 {
        self.calibrated.unwrap_or(self.score)
    }

    /// Whether the gate would block the name at `threshold`: the score of
    /// record clears it and no policy rail denies the finding.
    pub fn would_block(&self, threshold: f32) -> bool {
        self.policy_blocked.is_none() && self.gate_score() >= threshold
    }
}

/// The live policy state one replay needs. Loaded once per shadow trial so a
/// batch of reviewed domains reads the same exemptions and stages.
pub struct ReplayContext<'a> {
    store: &'a AiStore,
    settings: &'a AiSettings,
    calibration: Option<&'a CalibrationMap>,
    weights: SignalWeights,
    /// `allow` overrides, on the domain and its parents.
    exemptions: HashSet<String>,
    /// Every operator override, exact domain.
    overrides: HashMap<String, String>,
    /// Operator category relabels, exact domain.
    category_overrides: HashMap<String, String>,
    /// The stage in force per automated source, when authority is enabled.
    authority: Vec<authority::AuthorityDecision>,
}

impl<'a> ReplayContext<'a> {
    pub fn new(
        store: &'a AiStore,
        settings: &'a AiSettings,
        calibration: Option<&'a CalibrationMap>,
        weights: SignalWeights,
    ) -> Result<Self> {
        let exemptions = store.allow_overrides()?;
        let mut overrides = HashMap::new();
        for row in store.list_overrides()? {
            overrides.insert(row.domain, row.action);
        }
        let category_overrides = store.category_overrides()?;
        let authority = if settings.authority.enabled {
            authority::evaluate_for_scoring(
                store,
                &settings.authority,
                calibration.map(|map| map.version.as_str()).unwrap_or(""),
                settings.fusion.as_str(),
            )?
        } else {
            Vec::new()
        };
        Ok(Self {
            store,
            settings,
            calibration,
            weights,
            exemptions,
            overrides,
            category_overrides,
            authority,
        })
    }

    /// Replay one domain with `backend` as the candidate's threat channel.
    /// `verdict` is the candidate's name reading, or `None` when it saw
    /// nothing. The evidence kept beside the live verdict - the page reading,
    /// the page rule's adjustment, the language model's raise - is applied so
    /// the assessment is the one the gate would build.
    pub fn replay(
        &self,
        domain: &str,
        verdict: Option<&Verdict>,
        intel: &crate::intel::IntelIndex,
        now: i64,
    ) -> ReplayOutcome {
        self.replay_inner(domain, verdict, intel, now, false)
    }

    pub(crate) fn replay_review(
        &self,
        domain: &str,
        verdict: Option<&Verdict>,
        intel: &crate::intel::IntelIndex,
        now: i64,
    ) -> ReplayOutcome {
        self.replay_inner(domain, verdict, intel, now, true)
    }

    fn replay_inner(
        &self,
        domain: &str,
        verdict: Option<&Verdict>,
        intel: &crate::intel::IntelIndex,
        now: i64,
        reviewed: bool,
    ) -> ReplayOutcome {
        // No candidate verdict is a miss, not the incumbent's finding: the
        // live gate would have no row for the name at all, so there is nothing
        // to score. Reading the stored row here would let a candidate that saw
        // nothing inherit the model it is meant to replace.
        let Some(verdict) = verdict else {
            return ReplayOutcome {
                score: 0.0,
                policy_blocked: Some("the candidate reported no signal for the name".to_string()),
                threat: false,
                category: String::new(),
                observations: Vec::new(),
                fusion: None,
                calibrated: None,
                calibration_version: String::new(),
            };
        };
        // The page rule, the language model and the verifier write their notes
        // and confidence onto the stored verdict. The candidate supplies its
        // own severity, name score and confidence; the stored notes are the
        // later evidence every candidate meets.
        let mut evidence = verdict.evidence.clone();
        let mut confidence = verdict.confidence;
        // The page rule's adjustment is stored as the value it moved the
        // confidence to: a raise targets the page's own reading, and a Decide
        // cap targets the ceiling the ordinary page imposes. Replaying that
        // target against the candidate's confidence applies the same rule.
        if let Ok(Some(adjustment)) = self.store.page_adjustment(domain) {
            if adjustment.confidence > adjustment.prior {
                confidence = confidence.max(adjustment.confidence);
            } else if adjustment.confidence < adjustment.prior {
                confidence = confidence.min(adjustment.confidence);
            }
        }
        if self.settings.llm_enabled {
            if let Ok(Some(reading)) = self.store.threat_llm_reading(domain) {
                if let Some(raised) = crate::scanner::llm_raise(self.settings, confidence, &reading)
                {
                    confidence = raised;
                    evidence.push_str(", language model corroborated");
                }
            }
        }
        let severity = verdict.severity;
        let threat_score = verdict.threat_score.unwrap_or(confidence);
        let category = verdict.category.clone();
        let page = self
            .store
            .page_reading(domain)
            .ok()
            .flatten()
            .map(|reading| assessment::PageNote {
                category: reading.category,
                confidence: reading.confidence,
                cues: reading.cues,
                read_at: reading.read_at,
                adjusted: self
                    .store
                    .page_adjustment(domain)
                    .ok()
                    .flatten()
                    .map(|adjustment| (adjustment.prior, adjustment.confidence)),
            });
        let observations = assessment::observe(
            &assessment::Context {
                store: self.store,
                intel,
            },
            &assessment::AssessmentInput {
                domain,
                threat_score,
                confidence,
                severity: severity.as_str(),
                evidence: &evidence,
                page,
                now,
            },
        );
        let fused = (self.settings.fusion != daygle_dns_core::config::FusionMode::Off)
            .then(|| fusion::fuse(&observations, &self.weights));
        let score = assessment::score_of_record(
            self.settings.fusion,
            confidence,
            fused.as_ref(),
            self.calibration,
        );
        let threat = severity == Severity::Threat;
        let eligible_label = self.settings.is_auto_block_category(&category)
            || (category == crate::backend::BINARY_THREAT_LABEL
                && self.settings.label_role(&category)
                    != daygle_dns_core::config::LabelRole::Suppressed);
        let mut blocked = None;
        if severity == Severity::Disputed {
            blocked = Some("a dispute blocks the finding".to_string());
        } else if !threat {
            blocked = Some(format!(
                "candidate did not report a threat ({})",
                severity.as_str()
            ));
        } else if crate::scanner::exempt(domain, &self.exemptions) {
            blocked = Some("operator exemption".to_string());
        } else if self
            .overrides
            .get(domain)
            .is_some_and(|action| action == "allow" || (!reviewed && action == "not_threat"))
        {
            blocked = Some(format!(
                "operator {} override",
                self.overrides
                    .get(domain)
                    .map(String::as_str)
                    .unwrap_or("allow")
            ));
        } else if !reviewed && self.category_overrides.contains_key(domain) {
            blocked = Some("operator category override".to_string());
        } else if !eligible_label {
            blocked = Some(format!(
                "category '{category}' is not an enabled threat family"
            ));
        } else if !reviewed && self.settings.authority.enabled {
            let source = if evidence.contains(", listed by ") {
                authority::Source::Feed
            } else {
                authority::Source::Model
            };
            let decision = authority::decision_for(&self.authority, source);
            if !decision.is_some_and(|decision| decision.may_block()) {
                blocked = Some("the finding's source is held below enforce".to_string());
            }
        }
        ReplayOutcome {
            // The block query reads only `severity = 'threat'`, so a verdict
            // the gate never treats as a finding scores zero even when its
            // evidence would fuse above the threshold. That keeps a
            // classification from being counted as a threat the gate caught.
            score: if threat { score.assessment } else { 0.0 },
            policy_blocked: blocked,
            threat,
            category,
            observations,
            fusion: fused,
            calibrated: score.calibrated,
            calibration_version: score.calibration_version,
        }
    }

    /// The policy rails a replay report lists, so a trial's diagnostic result
    /// says which ones were exercised.
    pub fn rails(&self) -> serde_json::Value {
        serde_json::json!({
            "exemptions": self.exemptions.len(),
            "overrides": self.overrides.len(),
            "category_overrides": self.category_overrides.len(),
            "authority": self.settings.authority.enabled,
            "fusion": self.settings.fusion.as_str(),
            "calibration": self.calibration.map(|map| map.version.clone()),
        })
    }
}

/// Classify `domain` with `backend` and replay the gate's decision.
pub fn replay_with(
    context: &ReplayContext<'_>,
    backend: &dyn DomainClassifier,
    domain: &str,
    intel: &crate::intel::IntelIndex,
    now: i64,
) -> ReplayOutcome {
    let verdict = backend.classify(&backend::ClassificationInput::domain_only(
        domain.to_string(),
    ));
    context.replay(domain, verdict.as_ref(), intel, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Channel, Verdict};
    use daygle_dns_core::config::{AiSettings, PageRule};

    fn context<'a>(
        store: &'a AiStore,
        settings: &'a AiSettings,
        weights: SignalWeights,
    ) -> ReplayContext<'a> {
        ReplayContext::new(store, settings, None, weights).unwrap()
    }

    fn stored_threat(store: &AiStore, domain: &str, confidence: f32) {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                Channel::Threat,
                domain,
                "phishing",
                "threat",
                "classified",
                confidence,
                "fasttext",
                "model, phishing",
                3_600,
            )
            .unwrap();
    }

    fn reading(confidence: f32) -> Verdict {
        Verdict {
            category: "phishing".to_string(),
            confidence,
            severity: Severity::Threat,
            evidence: "model, phishing".to_string(),
            threat_score: Some(confidence),
        }
    }

    fn settings() -> AiSettings {
        AiSettings {
            auto_block_categories: vec!["phishing".to_string()],
            ..AiSettings::default()
        }
    }

    #[test]
    fn a_candidate_that_sees_nothing_does_not_inherit_the_stored_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        stored_threat(&store, "phish.example", 0.99);
        let settings = settings();
        let now = chrono::Utc::now().timestamp();
        let outcome = context(&store, &settings, SignalWeights::default()).replay(
            "phish.example",
            None,
            &crate::intel::IntelIndex::default(),
            now,
        );
        assert!(!outcome.threat);
        assert_eq!(outcome.score, 0.0, "a miss is not the incumbent's score");
        assert!(outcome.policy_blocked.is_some());
    }

    #[test]
    fn reviewed_labels_measure_predictions_without_reapplying_the_review() {
        let dir = tempfile::tempdir().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        store
            .set_category_override("positive.example", "phishing")
            .unwrap();
        store
            .set_override("negative.example", "not_threat", "reviewed")
            .unwrap();
        store
            .set_override("allow.example", "allow", "policy")
            .unwrap();
        let settings = settings();
        let context = context(&store, &settings, SignalWeights::default());
        let intel = crate::intel::IntelIndex::default();
        let now = chrono::Utc::now().timestamp();
        for domain in ["positive.example", "negative.example"] {
            assert!(!context
                .replay(domain, Some(&reading(0.9)), &intel, now)
                .would_block(0.8));
            assert!(context
                .replay_review(domain, Some(&reading(0.9)), &intel, now)
                .would_block(0.8));
        }
        assert!(!context
            .replay_review("sub.allow.example", Some(&reading(0.9)), &intel, now)
            .would_block(0.8));
    }

    #[test]
    fn llm_replay_applies_the_reading_to_the_candidate_score() {
        let dir = tempfile::tempdir().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        let domain = "llm.example";
        stored_threat(&store, domain, 0.99);
        store
            .record_llm_reading(
                domain,
                "threat",
                "language model",
                None,
                None,
                &crate::llm::LlmReading {
                    category: Some("phishing".to_string()),
                    threat: true,
                    confidence: 0.9,
                    reason: String::new(),
                },
            )
            .unwrap();
        let mut settings = settings();
        settings.llm_enabled = true;
        settings.page_rule = PageRule::Corroborate;
        let replay = context(&store, &settings, SignalWeights::default());
        let intel = crate::intel::IntelIndex::default();
        let now = chrono::Utc::now().timestamp();
        let outcome = replay.replay(domain, Some(&reading(0.3)), &intel, now);
        assert!((outcome.score - 0.4).abs() < 1e-5, "{outcome:?}");
    }

    #[test]
    fn reviewed_replay_can_pass_and_rejects_held_out_false_positives() {
        use crate::threshold::{self, Group, LabelSource, Sample};

        let dir = tempfile::tempdir().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        let settings = settings();
        let intel = crate::intel::IntelIndex::default();
        let now = chrono::Utc::now().timestamp();
        let domains: Vec<_> = (0..400)
            .map(|i| (format!("review-{i}.example"), i % 2 == 0))
            .collect();
        for (domain, threat) in &domains {
            if *threat {
                store.set_category_override(domain, "phishing").unwrap();
            } else {
                store.set_override(domain, "not_threat", "review").unwrap();
            }
        }
        let context = context(&store, &settings, SignalWeights::default());
        let samples = |false_positives: bool| {
            domains
                .iter()
                .map(|(domain, threat)| {
                    let flagged = *threat || (false_positives && threshold::held_out(domain));
                    let verdict = reading(if flagged { 0.9 } else { 0.3 });
                    let result = context.replay_review(domain, Some(&verdict), &intel, now);
                    Sample {
                        domain: domain.clone(),
                        registrable: assessment::registrable(domain),
                        score: result.score,
                        group: Group::Correction,
                        label: LabelSource::OperatorCorrection,
                        threat: Some(*threat),
                        scored_at: now,
                        policy_blocked: result.policy_blocked,
                    }
                })
                .collect()
        };
        let good = threshold::tune_replayed_scores(samples(false), "candidate", &settings, now);
        assert_eq!(good["passed"], true, "{good}");
        let bad = threshold::tune_replayed_scores(samples(true), "candidate", &settings, now);
        assert_eq!(bad["passed"], false, "{bad}");
    }

    #[test]
    fn the_page_rules_adjustment_applies_to_the_candidates_score() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        stored_threat(&store, "raised.example", 0.6);
        // The page rule raised the stored verdict to the page's reading.
        store
            .record_page_adjustment("raised.example", PageRule::Corroborate, 0.6, 0.9)
            .unwrap();
        let settings = settings();
        let now = chrono::Utc::now().timestamp();
        let outcome = context(&store, &settings, SignalWeights::default()).replay(
            "raised.example",
            Some(&reading(0.6)),
            &crate::intel::IntelIndex::default(),
            now,
        );
        assert!(
            (outcome.score - 0.9).abs() < 1e-4,
            "the page's raise is measured, got {}",
            outcome.score
        );
        assert!(outcome.would_block(0.85));

        // An exemption still wins over the raised score.
        store
            .set_override("raised.example", "allow", "exempt")
            .unwrap();
        let outcome = context(&store, &settings, SignalWeights::default()).replay(
            "raised.example",
            Some(&reading(0.6)),
            &crate::intel::IntelIndex::default(),
            now,
        );
        assert!(!outcome.would_block(0.85));
        assert_eq!(
            outcome.policy_blocked.as_deref(),
            Some("operator exemption")
        );
    }
}
