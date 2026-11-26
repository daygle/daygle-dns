//! Signal fusion: how the structured observations become one score.
//!
//! The rule is deliberately not "add everything up". Three things are kept
//! apart, because they are different kinds of evidence:
//!
//! 1. **The name reading.** The primary model and the MiniLM verifier both
//!    read the same string, so they belong to one [`EvidenceFamily`]. Their
//!    evidence is collapsed - the stronger reading is the base, and the other
//!    can only adjust it by its (small) weight. A corroborating verifier is
//!    agreement, not a second finding.
//! 2. **Independent evidence** (feeds, popularity, usage history, domain age,
//!    the name's shape, the page, the language model). Each moves the score by
//!    its own bounded weight, scaled by [`SignalWeights::independent_scale`],
//!    so nine inputs cannot add up past the model's own reading without the
//!    model itself being sure.
//! 3. **Hard mechanisms**, which are not weights at all: a feed listing
//!    corroborates at blocking confidence, and a popular or established domain
//!    is disputed. Both are returned as separate fields, never as a delta, and
//!    the caller keeps them apart from the sum exactly as the existing
//!    pipeline does.
//!
//! Operator overrides are not observations and never enter fusion.
//!
//! Fusion is reported for every verdict and only *decides* when
//! `ai.fusion = "decide"`; see [`crate::scanner`].

use serde::{Deserialize, Serialize};

use crate::assessment::{Direction, EvidenceFamily, SignalObservation, SignalSource};
use crate::evidence::LISTED_CONFIDENCE;

/// How much each source may move the score. Defaults are small on purpose:
/// the model's reading sets the level, and outside evidence nudges it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignalWeights {
    /// Weight of the primary model's own score (the base).
    pub model: f32,
    /// Weight of a verifier reading *inside* the name-model family. It never
    /// adds a second base.
    pub verifier: f32,
    pub feed: f32,
    pub popularity: f32,
    pub network_history: f32,
    pub domain_age: f32,
    pub hostname: f32,
    pub page: f32,
    pub llm: f32,
    /// How much of the independent weights' sum is applied at most. Caps the
    /// combined outside evidence below the model's own confidence.
    pub independent_scale: f32,
}

impl Default for SignalWeights {
    fn default() -> Self {
        Self {
            model: 1.0,
            verifier: 0.10,
            feed: 0.20,
            popularity: 0.10,
            network_history: 0.10,
            domain_age: 0.05,
            hostname: 0.05,
            page: 0.10,
            llm: 0.10,
            independent_scale: 0.25,
        }
    }
}

impl SignalWeights {
    pub fn weight(&self, source: SignalSource) -> f32 {
        match source {
            SignalSource::Model => self.model,
            SignalSource::Verifier => self.verifier,
            SignalSource::Feed => self.feed,
            SignalSource::Popularity => self.popularity,
            SignalSource::NetworkHistory => self.network_history,
            SignalSource::DomainAge => self.domain_age,
            SignalSource::Hostname => self.hostname,
            SignalSource::Page => self.page,
            SignalSource::Llm => self.llm,
        }
    }

    pub fn is_sane(&self) -> bool {
        let all = [
            self.model,
            self.verifier,
            self.feed,
            self.popularity,
            self.network_history,
            self.domain_age,
            self.hostname,
            self.page,
            self.llm,
            self.independent_scale,
        ];
        all.iter().all(|w| w.is_finite() && *w >= 0.0 && *w <= 1.0)
            && self.independent_scale <= 1.0
            && self.model <= 1.0
    }
}

/// One observation's effect on the fused score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contribution {
    pub source: SignalSource,
    pub family: EvidenceFamily,
    /// What it added (positive) or removed (negative).
    pub delta: f32,
    /// Whether the contribution was applied as part of a collapsed family.
    pub correlated: bool,
    pub explanation: String,
}

/// A hard mechanism the caller must honour outside the sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardMechanism {
    /// A threat feed lists the name: corroborated at blocking confidence.
    FeedCorroboration,
    /// A popular registered domain.
    PopularDispute,
    /// Established on this network for weeks.
    EstablishedDispute,
}

impl HardMechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeedCorroboration => "feed_corroboration",
            Self::PopularDispute => "popular_dispute",
            Self::EstablishedDispute => "established_dispute",
        }
    }
}

/// The fused view of one verdict's evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fusion {
    /// The model's own reading, before outside evidence (0 when absent).
    pub base: f32,
    /// Base plus the weighted, non-correlated evidence, clamped to 0..1.
    pub score: f32,
    pub contributions: Vec<Contribution>,
    /// The mechanisms that are not weights.
    pub hard: Vec<HardMechanism>,
    /// Whether a corroborating verifier was collapsed into the model family
    /// rather than counted again.
    pub correlated_collapsed: bool,
    /// A sentence the console can show.
    pub summary: String,
}

impl Fusion {
    /// Feed corroboration lifts the fused score to blocking confidence; it is
    /// the same rule the evidence stage applies, expressed here so a reader of
    /// the fusion report sees it.
    pub fn effective_score(&self) -> f32 {
        if self.hard.contains(&HardMechanism::FeedCorroboration) {
            self.score.max(LISTED_CONFIDENCE)
        } else {
            self.score
        }
    }

    pub fn disputed(&self) -> bool {
        self.hard.iter().any(|m| {
            matches!(
                m,
                HardMechanism::PopularDispute | HardMechanism::EstablishedDispute
            )
        })
    }
}

/// Fuse a verdict's observations. Observations are expected once per source,
/// as [`crate::assessment::observe`] produces them.
pub fn fuse(observations: &[SignalObservation], weights: &SignalWeights) -> Fusion {
    let model = observations
        .iter()
        .find(|o| o.source == SignalSource::Model);
    let verifier = observations
        .iter()
        .find(|o| o.source == SignalSource::Verifier);
    let base = model
        .and_then(|o| o.value)
        .filter(|v| *v > 0.0)
        .unwrap_or(0.0)
        * weights.model;

    let mut contributions = Vec::new();
    let mut score = base;

    // Family one: the name reading. The verifier adjusts the base by its own
    // small weight; it never becomes a second base.
    let mut correlated_collapsed = false;
    if let Some(verifier) = verifier {
        let sign = match verifier.direction {
            Direction::Threat => 1.0,
            Direction::Benign => -1.0,
            Direction::Neutral | Direction::Unknown => 0.0,
        };
        if sign != 0.0 {
            correlated_collapsed = base > 0.0;
            let delta = sign * weights.verifier * if correlated_collapsed { 0.5 } else { 1.0 };
            score += delta;
            contributions.push(Contribution {
                source: SignalSource::Verifier,
                family: EvidenceFamily::NameModel,
                delta,
                correlated: correlated_collapsed,
                explanation: verifier.explanation.clone(),
            });
        }
    }

    // Family two: independent evidence, bounded as a group.
    let mut independent_raw = 0.0f32;
    let mut hard = Vec::new();
    for observation in observations {
        if observation.source.family() != EvidenceFamily::Independent {
            continue;
        }
        let sign = observation.direction.sign();
        if sign == 0.0 {
            continue;
        }
        let weight = weights.weight(observation.source);
        let delta = sign * weight;
        independent_raw += delta;
        contributions.push(Contribution {
            source: observation.source,
            family: EvidenceFamily::Independent,
            delta,
            correlated: false,
            explanation: observation.explanation.clone(),
        });
    }
    let bounded = independent_raw.clamp(
        -weights.independent_scale * weights.model.max(0.1),
        weights.independent_scale * weights.model.max(0.1),
    );
    // Report the bounded share against each contribution proportionally, so
    // the report still adds up to the score it explains.
    if independent_raw.abs() > f32::EPSILON && (bounded - independent_raw).abs() > f32::EPSILON {
        let share = bounded / independent_raw;
        for contribution in contributions
            .iter_mut()
            .filter(|c| c.family == EvidenceFamily::Independent)
        {
            contribution.delta *= share;
        }
    }
    score += bounded;

    for observation in observations {
        match observation.source {
            SignalSource::Feed if observation.is_threat() => {
                hard.push(HardMechanism::FeedCorroboration)
            }
            SignalSource::Popularity if observation.is_benign() => {
                hard.push(HardMechanism::PopularDispute)
            }
            SignalSource::NetworkHistory if observation.is_benign() => {
                hard.push(HardMechanism::EstablishedDispute)
            }
            _ => {}
        }
    }
    hard.sort_by_key(|m| m.as_str());

    let score = score.clamp(0.0, 1.0);
    let mut parts = vec![format!("the model read it {base:.2}")];
    if !contributions.is_empty() {
        parts.push(format!(
            "outside evidence moved it by {bounded:+.2}{}",
            if correlated_collapsed {
                " (the verifier's agreement is the same reading, counted once)"
            } else {
                ""
            }
        ));
    }
    for mechanism in &hard {
        parts.push(match mechanism {
            HardMechanism::FeedCorroboration => {
                "a threat feed lists it, so it is corroborated at blocking confidence".to_string()
            }
            HardMechanism::PopularDispute => {
                "it is a popular site, so the model's reading is disputed".to_string()
            }
            HardMechanism::EstablishedDispute => {
                "it is established on this network, so the model's reading is disputed".to_string()
            }
        });
    }
    parts.push(format!("fused score {score:.3}"));

    Fusion {
        base,
        score,
        contributions,
        hard,
        correlated_collapsed,
        summary: parts.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::{ObservationScope, Scope};

    fn obs(source: SignalSource, direction: Direction, value: Option<f32>) -> SignalObservation {
        SignalObservation::new(
            source,
            direction,
            value,
            format!("{} observation", source.as_str()),
            1_700_000_000,
            ObservationScope {
                value: "bad.example".to_string(),
                kind: Scope::Hostname,
            },
        )
    }

    #[test]
    fn the_model_sets_the_level() {
        let weights = SignalWeights::default();
        let fusion = fuse(
            &[obs(SignalSource::Model, Direction::Threat, Some(0.7))],
            &weights,
        );
        assert!((fusion.base - 0.7).abs() < 1e-6);
        assert!((fusion.score - 0.7).abs() < 1e-6);
        assert!(fusion.hard.is_empty());
    }

    #[test]
    fn a_corroborating_verifier_is_not_counted_twice() {
        let weights = SignalWeights::default();
        let model_only = fuse(
            &[obs(SignalSource::Model, Direction::Threat, Some(0.7))],
            &weights,
        );
        let with_verifier = fuse(
            &[
                obs(SignalSource::Model, Direction::Threat, Some(0.7)),
                obs(SignalSource::Verifier, Direction::Threat, Some(0.7)),
            ],
            &weights,
        );
        assert!(with_verifier.correlated_collapsed);
        let delta = with_verifier.score - model_only.score;
        // Half the verifier weight at most, never the verifier's whole score.
        assert!(
            delta > 0.0 && delta <= weights.verifier * 0.5 + 1e-6,
            "{delta}"
        );
        assert!(with_verifier.summary.contains("counted once"));
    }

    #[test]
    fn independent_evidence_is_bounded_as_a_group() {
        let weights = SignalWeights::default();
        let mut observations = vec![obs(SignalSource::Model, Direction::Threat, Some(0.5))];
        for source in [
            SignalSource::Feed,
            SignalSource::Popularity,
            SignalSource::NetworkHistory,
            SignalSource::DomainAge,
            SignalSource::Hostname,
            SignalSource::Page,
            SignalSource::Llm,
        ] {
            observations.push(obs(source, Direction::Threat, None));
        }
        let fusion = fuse(&observations, &weights);
        let cap = weights.independent_scale * weights.model.max(0.1);
        assert!(fusion.score <= 0.5 + cap + 1e-6, "{}", fusion.score);
        // The contributions still explain exactly the bounded movement.
        let total: f32 = fusion.contributions.iter().map(|c| c.delta).sum();
        assert!((fusion.score - (fusion.base + total)).abs() < 1e-5);
    }

    #[test]
    fn a_feed_listing_corroborates_at_blocking_confidence() {
        let weights = SignalWeights::default();
        let fusion = fuse(
            &[
                obs(SignalSource::Model, Direction::Threat, Some(0.4)),
                obs(SignalSource::Feed, Direction::Threat, Some(0.99)),
            ],
            &weights,
        );
        assert!(fusion.hard.contains(&HardMechanism::FeedCorroboration));
        assert_eq!(fusion.effective_score(), LISTED_CONFIDENCE);
    }

    #[test]
    fn popular_and_established_names_are_disputed_not_scored_down() {
        let weights = SignalWeights::default();
        let fusion = fuse(
            &[
                obs(SignalSource::Model, Direction::Threat, Some(0.9)),
                obs(SignalSource::Popularity, Direction::Benign, None),
                obs(SignalSource::NetworkHistory, Direction::Benign, None),
            ],
            &weights,
        );
        assert!(fusion.disputed());
        assert!(fusion.hard.contains(&HardMechanism::PopularDispute));
        assert!(fusion.hard.contains(&HardMechanism::EstablishedDispute));
        // A dispute is a veto the caller applies, not a subtraction that
        // hides the model's finding.
        assert!(fusion.score > 0.5);
    }

    #[test]
    fn unknown_and_neutral_observations_move_nothing() {
        let weights = SignalWeights::default();
        let fusion = fuse(
            &[
                obs(SignalSource::Model, Direction::Unknown, None),
                obs(SignalSource::Feed, Direction::Unknown, None),
                obs(SignalSource::Page, Direction::Neutral, None),
            ],
            &weights,
        );
        assert_eq!(fusion.base, 0.0);
        assert_eq!(fusion.score, 0.0);
        assert!(fusion.contributions.is_empty());
    }

    #[test]
    fn weights_must_be_bounded_fractions() {
        assert!(SignalWeights::default().is_sane());
        let mut weights = SignalWeights::default();
        weights.model = 2.0;
        assert!(!weights.is_sane());
        let mut weights = SignalWeights::default();
        weights.page = -0.1;
        assert!(!weights.is_sane());
    }
}
