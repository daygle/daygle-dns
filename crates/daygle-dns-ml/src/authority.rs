//! Graduated threat authority: who may enforce what, and when that is taken
//! away again.
//!
//! Autonomy and DNS enforcement authority are separate things. The scanner
//! may investigate whatever it likes; what may *block* depends on the source
//! of the finding and on measured behaviour:
//!
//! | Stage     | Effect |
//! |-----------|--------|
//! | `monitor` | The finding is recorded and shown; it never reaches the block snapshot. |
//! | `propose` | The finding is listed as a proposal for the operator; it still does not block. |
//! | `enforce` | The finding may block, subject to every existing rail. |
//!
//! Defaults are `monitor` for every source with `authority.enabled = false`,
//! so an install that does not opt in behaves exactly as it did. A source
//! that has enforcement authority loses it automatically when its measured
//! false-positive rate passes `demote_fp_rate` with at least
//! `demote_min_samples` observations.
//!
//! Operator labels and operator overrides are never demoted by this module:
//! they are the operator's own decisions, not the AI's.

use daygle_dns_core::config::{AuthoritySettings, AuthorityStage};
use daygle_dns_core::error::Result;

use crate::store::{AiStore, BlockSource};

/// Where a block came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A threat feed listing corroborated it.
    Feed,
    /// The primary model (with whatever independent evidence) found it.
    Model,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Feed => "feed",
            Self::Model => "model",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "feed" => Some(Self::Feed),
            "model" => Some(Self::Model),
            _ => None,
        }
    }

    pub fn of(block: &BlockSource) -> Self {
        match block {
            BlockSource::Feed => Self::Feed,
            BlockSource::Model => Self::Model,
        }
    }
}

/// What the configured authority says about one source.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityDecision {
    pub source: Source,
    /// The stage the operator configured.
    pub configured: AuthorityStage,
    /// The stage in force, after measurement.
    pub effective: AuthorityStage,
    pub false_positives: i64,
    pub true_positives: i64,
    pub demoted: bool,
    pub reason: String,
}

impl AuthorityDecision {
    /// Whether findings from this source may reach the block snapshot.
    pub fn may_block(&self) -> bool {
        self.effective == AuthorityStage::Enforce
    }

    /// Whether findings from this source are shown as proposals.
    pub fn is_proposal(&self) -> bool {
        self.effective == AuthorityStage::Propose
    }
}

/// The configured stage for a source.
pub fn stage_for(settings: &AuthoritySettings, source: Source) -> AuthorityStage {
    match source {
        Source::Feed => settings.feed_stage,
        Source::Model => settings.model_stage,
    }
}

/// Measure every source and decide its stage. With authority disabled all
/// sources stay at `Enforce`, which is the pre-authority behaviour: the
/// global `ai.mode` alone decides, and no block is filtered here.
pub fn evaluate(store: &AiStore, settings: &AuthoritySettings) -> Result<Vec<AuthorityDecision>> {
    evaluate_for_scoring(store, settings, "", "")
}

/// The stage `steps` steps closer to enforcing: advancement never skips a
/// step and never goes past the ceiling.
fn advance(stage: AuthorityStage, steps: i64) -> AuthorityStage {
    let mut stage = stage;
    for _ in 0..steps {
        stage = match stage {
            AuthorityStage::Monitor => AuthorityStage::Propose,
            AuthorityStage::Propose => AuthorityStage::Enforce,
            AuthorityStage::Enforce => AuthorityStage::Enforce,
        };
    }
    stage
}

/// The configured stage as a numbered rung, so a partial advance can be
/// capped at the operator's ceiling without naming every pair.
fn rung(stage: AuthorityStage) -> u8 {
    match stage {
        AuthorityStage::Monitor => 0,
        AuthorityStage::Propose => 1,
        AuthorityStage::Enforce => 2,
    }
}

/// Evaluate the sources under the scoring version in force. Advancement is
/// opt-in: with `settings.advancement` off each source runs at its configured
/// stage exactly as before. With it on, a source starts at `monitor` and moves
/// toward its configured ceiling one step for each
/// `advance_min_reviews` findings under this scoring version that were
/// explicitly reviewed, provided at least one review confirmed the finding and
/// corrections stay within `advance_fp_rate`. Unreviewed findings (including an
/// `allow` exemption) are not reviews and supply no credit. The configured
/// stage is the ceiling, so advancement never exceeds it, and demotion still
/// applies to measured false positives afterwards.
pub fn evaluate_for_scoring(
    store: &AiStore,
    settings: &AuthoritySettings,
    calibration_version: &str,
    assessment_mode: &str,
) -> Result<Vec<AuthorityDecision>> {
    if !settings.enabled {
        return Ok(vec![]);
    }
    let measurements = store.authority_measurements()?;
    let now = chrono::Utc::now().timestamp();
    let reviews = store.authority_reviews_for_scoring(now, calibration_version, assessment_mode)?;
    let mut decisions = Vec::new();
    for source in [Source::Feed, Source::Model] {
        let (false_positives, true_positives) = measurements
            .iter()
            .find(|(name, _, _)| name == source.as_str())
            .map(|(_, fp, tp)| (*fp, *tp))
            .unwrap_or((0, 0));
        let (reviewed_findings, corrected_reviews, confirmed_reviews) = reviews
            .iter()
            .find(|(name, _, _, _)| name == source.as_str())
            .map(|(_, total, corrected, confirmed)| (*total, *corrected, *confirmed))
            .unwrap_or((0, 0, 0));
        let configured = stage_for(settings, source);
        let total = false_positives + true_positives;
        let rate = if total > 0 {
            false_positives as f32 / total as f32
        } else {
            0.0
        };
        let reviewed = corrected_reviews + confirmed_reviews;
        let reviewed_rate = if reviewed > 0 {
            corrected_reviews as f32 / reviewed as f32
        } else {
            0.0
        };
        let start = if settings.advancement && configured != AuthorityStage::Monitor {
            AuthorityStage::Monitor
        } else {
            configured
        };
        let minimum = i64::from(settings.advance_min_reviews.max(1));
        let steps = if settings.advancement
            && configured != AuthorityStage::Monitor
            && confirmed_reviews > 0
            && reviewed_rate <= settings.advance_fp_rate
        {
            reviewed / minimum
        } else {
            0
        };
        let may_advance = steps > 0;
        let ceiling = rung(configured);
        let advanced = advance(start, steps);
        let advanced = if rung(advanced) > ceiling {
            configured
        } else {
            advanced
        };
        let demote = total >= i64::from(settings.demote_min_samples.max(1))
            && rate > settings.demote_fp_rate;
        let effective = if demote {
            AuthorityStage::Monitor
        } else {
            advanced
        };
        let reason = if demote {
            format!(
                "demoted to monitor: {false_positives} of {total} measured findings were corrected as false positives ({:.1}% > {:.1}%)",
                rate * 100.0,
                settings.demote_fp_rate * 100.0
            )
        } else if settings.advancement && configured != AuthorityStage::Monitor {
            let reviewed_note = format!(
                "{confirmed_reviews} confirmed and {corrected_reviews} corrected of {reviewed_findings} findings reviewed under this scoring version"
            );
            if may_advance && advanced == configured {
                format!(
                    "advanced to the configured ceiling {}: {reviewed_note}",
                    configured.as_str()
                )
            } else if advanced == configured {
                format!(
                    "at the configured ceiling {}: {reviewed_note}",
                    configured.as_str()
                )
            } else if may_advance {
                format!(
                    "advanced to {} of the configured {}: {reviewed_note}",
                    advanced.as_str(),
                    configured.as_str()
                )
            } else {
                format!(
                    "staying at {}: each step needs {} independently reviewed findings with at most {:.0}% corrected: {reviewed_note}",
                    advanced.as_str(),
                    settings.advance_min_reviews.max(1),
                    settings.advance_fp_rate * 100.0
                )
            }
        } else if total == 0 {
            format!(
                "no measured findings yet; stage is the configured {}",
                configured.as_str()
            )
        } else {
            format!(
                "{false_positives} of {total} measured findings were false positives ({:.1}%)",
                rate * 100.0
            )
        };
        decisions.push(AuthorityDecision {
            source,
            configured,
            effective,
            false_positives,
            true_positives,
            demoted: demote,
            reason,
        });
    }
    Ok(decisions)
}

/// The decision for one block, or `None` when authority is off (the caller
/// then keeps the pre-authority behaviour).
pub fn decision_for(decisions: &[AuthorityDecision], source: Source) -> Option<&AuthorityDecision> {
    decisions.iter().find(|d| d.source == source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Channel;
    use crate::store::AiStore;

    fn store() -> (tempfile::TempDir, AiStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        (dir, store)
    }

    fn verdict(store: &AiStore, domain: &str, evidence: &str, confidence: f32) {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                Channel::Threat,
                domain,
                "malware",
                "threat",
                "classified",
                confidence,
                "fasttext",
                evidence,
                3_600,
            )
            .unwrap();
    }

    #[test]
    fn authority_off_changes_nothing() {
        let (_dir, store) = store();
        let decisions = evaluate(&store, &AuthoritySettings::default()).expect("evaluation");
        assert!(decisions.is_empty(), "off means no filtering at all");
    }

    #[test]
    fn only_explicit_reviews_count_and_survive_reopening() {
        let (dir, store) = store();
        for domain in [
            "confirmed.example",
            "corrected.example",
            "allowed.example",
            "unreviewed.example",
            "old-review.example",
        ] {
            verdict(&store, domain, "model, malware", 0.99);
        }
        verdict(&store, "listed.example", "model, listed by feed", 0.99);
        store
            .set_category_override("confirmed.example", "malware")
            .unwrap();
        store
            .set_category_override("old-review.example", "malware")
            .unwrap();
        store
            .set_override("corrected.example", "not_threat", "reviewed")
            .unwrap();
        store
            .set_override("allowed.example", "allow", "exempt")
            .unwrap();
        drop(store);
        rusqlite::Connection::open(dir.path().join("ai.db")).unwrap().execute(
            "UPDATE ai_category_overrides SET created_at = 0 WHERE domain = 'old-review.example'",
            [],
        ).unwrap();

        let reopened = AiStore::open(&dir.path().join("ai.db")).unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut reviews = reopened.authority_reviews(now).unwrap();
        reviews.sort();
        assert_eq!(
            reviews,
            [
                ("feed".to_string(), 1, 0, 0),
                ("model".to_string(), 5, 1, 1)
            ]
        );
        assert!(reopened.authority_reviews(now + 7_200).unwrap().is_empty());
    }

    #[test]
    fn a_source_is_demoted_when_its_corrections_pass_the_limit() {
        let (_dir, store) = store();
        // Ten model-only findings, four of them corrected as false positives:
        // 40% measured, over the 20% default.
        for i in 0..10 {
            verdict(&store, &format!("m{i}.example"), "model, malware", 0.99);
        }
        for i in 0..4 {
            store
                .set_override(&format!("m{i}.example"), "not_threat", "wrong")
                .unwrap();
        }
        let settings = AuthoritySettings {
            enabled: true,
            model_stage: AuthorityStage::Enforce,
            demote_fp_rate: 0.2,
            demote_min_samples: 5,
            ..AuthoritySettings::default()
        };
        let decisions = evaluate(&store, &settings).unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        assert!(model.demoted);
        assert_eq!(model.effective, AuthorityStage::Monitor);
        assert!(!model.may_block());
        assert!(model.reason.contains("demoted"), "{}", model.reason);
        // A feed source with no measured findings keeps its configured stage.
        let feed = decision_for(&decisions, Source::Feed).unwrap();
        assert!(!feed.demoted);
    }

    #[test]
    fn a_clean_source_keeps_its_authority() {
        let (_dir, store) = store();
        for i in 0..10 {
            verdict(&store, &format!("f{i}.example"), "model, malware", 0.99);
        }
        let settings = AuthoritySettings {
            enabled: true,
            model_stage: AuthorityStage::Propose,
            demote_fp_rate: 0.2,
            demote_min_samples: 5,
            ..AuthoritySettings::default()
        };
        let decisions = evaluate(&store, &settings).unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        assert!(!model.demoted);
        assert_eq!(model.effective, AuthorityStage::Propose);
        assert!(model.is_proposal());
        assert!(!model.may_block());
    }

    #[test]
    fn advancement_starts_at_monitor_without_reviewed_evidence() {
        let (_dir, store) = store();
        for i in 0..10 {
            verdict(&store, &format!("u{i}.example"), "model, malware", 0.99);
        }
        let settings = AuthoritySettings {
            enabled: true,
            model_stage: AuthorityStage::Propose,
            advancement: true,
            advance_min_reviews: 5,
            ..AuthoritySettings::default()
        };
        let decisions = evaluate_for_scoring(&store, &settings, "", "").unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        // The configured stage is the ceiling, not the starting point.
        assert_eq!(model.configured, AuthorityStage::Propose);
        assert_eq!(model.effective, AuthorityStage::Monitor);
        assert!(
            model.reason.contains("staying at monitor"),
            "{}",
            model.reason
        );

        // An allow exemption is a policy decision, not a review: it supplies
        // no advancement credit.
        store.set_override("u0.example", "allow", "exempt").unwrap();
        let decisions = evaluate_for_scoring(&store, &settings, "", "").unwrap();
        assert_eq!(
            decision_for(&decisions, Source::Model).unwrap().effective,
            AuthorityStage::Monitor
        );
    }

    #[test]
    fn confirmed_reviews_advance_one_step_under_the_scoring_version() {
        let (_dir, store) = store();
        for i in 0..10 {
            verdict(&store, &format!("r{i}.example"), "model, malware", 0.99);
        }
        for i in 0..5 {
            store
                .set_category_override(&format!("r{i}.example"), "malware")
                .unwrap();
        }
        let settings = AuthoritySettings {
            enabled: true,
            model_stage: AuthorityStage::Propose,
            advancement: true,
            advance_min_reviews: 5,
            ..AuthoritySettings::default()
        };
        let decisions = evaluate_for_scoring(&store, &settings, "", "").unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        assert_eq!(model.effective, AuthorityStage::Propose);
        assert!(model.is_proposal());
        assert!(!model.may_block(), "advancement never skips to enforce");
        assert!(
            model
                .reason
                .contains("advanced to the configured ceiling propose"),
            "{}",
            model.reason
        );

        // The same reviews say nothing about another scoring version's
        // findings, so that version stays at the floor.
        let decisions = evaluate_for_scoring(&store, &settings, "newer", "decide").unwrap();
        assert_eq!(
            decision_for(&decisions, Source::Model).unwrap().effective,
            AuthorityStage::Monitor
        );
    }

    #[test]
    fn advancement_never_passes_the_operator_ceiling() {
        let (_dir, store) = store();
        for i in 0..20 {
            verdict(&store, &format!("e{i}.example"), "model, malware", 0.99);
        }
        for i in 0..10 {
            store
                .set_category_override(&format!("e{i}.example"), "malware")
                .unwrap();
        }
        let settings = AuthoritySettings {
            enabled: true,
            model_stage: AuthorityStage::Enforce,
            advancement: true,
            advance_min_reviews: 5,
            demote_min_samples: 100,
            ..AuthoritySettings::default()
        };
        // Five reviews is one step: propose, not enforce.
        let mut trimmed = settings.clone();
        trimmed.advance_min_reviews = 10;
        let decisions = evaluate_for_scoring(&store, &trimmed, "", "").unwrap();
        assert_eq!(
            decision_for(&decisions, Source::Model).unwrap().effective,
            AuthorityStage::Propose
        );
        // Ten reviews is two steps, which is the ceiling, never past it.
        let decisions = evaluate_for_scoring(&store, &settings, "", "").unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        assert_eq!(model.effective, AuthorityStage::Enforce);
        assert!(model.may_block());
        // A proposal ceiling is never exceeded however much evidence arrives.
        let mut proposal_ceiling = settings.clone();
        proposal_ceiling.model_stage = AuthorityStage::Propose;
        let decisions = evaluate_for_scoring(&store, &proposal_ceiling, "", "").unwrap();
        let model = decision_for(&decisions, Source::Model).unwrap();
        assert_eq!(model.effective, AuthorityStage::Propose);
        assert!(!model.may_block());
    }
}
