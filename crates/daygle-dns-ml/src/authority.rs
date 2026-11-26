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
    if !settings.enabled {
        return Ok(vec![]);
    }
    let measurements = store.authority_measurements()?;
    let mut decisions = Vec::new();
    for source in [Source::Feed, Source::Model] {
        let (false_positives, true_positives) = measurements
            .iter()
            .find(|(name, _, _)| name == source.as_str())
            .map(|(_, fp, tp)| (*fp, *tp))
            .unwrap_or((0, 0));
        let configured = stage_for(settings, source);
        let total = false_positives + true_positives;
        let rate = if total > 0 {
            false_positives as f32 / total as f32
        } else {
            0.0
        };
        let demote = total >= i64::from(settings.demote_min_samples.max(1))
            && rate > settings.demote_fp_rate;
        let effective = if demote {
            AuthorityStage::Monitor
        } else {
            configured
        };
        let reason = if demote {
            format!(
                "demoted to monitor: {false_positives} of {total} measured findings were corrected as false positives ({:.1}% > {:.1}%)",
                rate * 100.0,
                settings.demote_fp_rate * 100.0
            )
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
pub fn decision_for(
    decisions: &[AuthorityDecision],
    source: Source,
) -> Option<&AuthorityDecision> {
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
}
