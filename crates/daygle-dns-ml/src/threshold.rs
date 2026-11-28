//! The threshold trial: choose a block threshold by false-positive rate on
//! one half of the evidence, then prove it on the other half.
//!
//! The threshold decides how much stacked evidence blocks a name, so moving
//! it trades one kind of mistake for the other. Overall accuracy is the wrong
//! way to choose it - almost every name is benign, so a threshold that blocks
//! nothing scores well - and a threshold picked on the same names it is
//! measured on always looks better than it is. So this module:
//!
//! - builds four separate populations from what the store already knows:
//!   names the network has used for weeks (`established`), names a threat feed
//!   confirmed (`confirmed`), names the operator corrected (`correction`), and
//!   names nobody has judged (`unseen`); the first two are benign and threat
//!   populations, the last two are reported but score nothing;
//! - splits the scored names into a tuning half and a held-out half by a
//!   stable hash of the domain, so the same name always lands on the same
//!   side;
//! - picks the *lowest* threshold whose false-positive rate on the tuning half
//!   meets the target (the most threats caught within the budget), and
//! - passes only when that same threshold keeps the target on the held-out
//!   half, with enough benign names there to mean something.
//!
//! Nothing here changes a setting: the caller records the result and the
//! operator applies it (see [`crate::store::ThresholdTrial`]).

use std::collections::{HashMap, HashSet};
use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::Result;

use crate::intel::IntelIndex;
use crate::store::AiStore;

/// Fit a candidate's map on its tuning names, compare it with identity on
/// held-out names, then select and validate its calibrated threshold.
/// A zero score means replay found no enforceable verdict for that name.
pub(crate) fn tune_replayed_scores(
    samples: Vec<Sample>,
    model: &str,
    settings: &AiSettings,
    now: i64,
) -> serde_json::Value {
    tune_replayed_scores_for_model(samples, model, settings, now, false)
}

pub(crate) fn tune_replayed_scores_for_model(
    mut samples: Vec<Sample>,
    model: &str,
    settings: &AiSettings,
    now: i64,
    include_no_signal: bool,
) -> serde_json::Value {
    use crate::calibration::{self, CalibrationMap, Labelled};

    let (holdout, tuning): (Vec<_>, Vec<_>) = samples
        .iter()
        .filter(|sample| include_no_signal || sample.score > 0.0)
        .filter_map(|sample| {
            Some((
                held_out(&sample.domain),
                Labelled {
                    score: sample.score,
                    threat: sample.threat?,
                },
            ))
        })
        .partition(|(held, _)| *held);
    let tuning: Vec<_> = tuning.into_iter().map(|(_, sample)| sample).collect();
    let holdout: Vec<_> = holdout.into_iter().map(|(_, sample)| sample).collect();
    let Some(mut map) = calibration::fit(&tuning, model, now) else {
        return serde_json::json!({
            "passed": false,
            "reason": "insufficient labelled candidate verdicts to fit a calibration map",
            "tuning_samples": tuning.len(),
            "holdout_samples": holdout.len(),
        });
    };
    let baseline = calibration::evaluate(&holdout, &CalibrationMap::identity(model, now));
    let metrics = calibration::evaluate(&holdout, &map);
    let acceptance = calibration::accept(&metrics, Some(&baseline));
    map.metrics = Some(metrics);
    if !acceptance.accepted
        || !holdout.iter().any(|sample| sample.threat)
        || !holdout.iter().any(|sample| !sample.threat)
    {
        return serde_json::json!({
            "passed": false,
            "reason": if acceptance.accepted { "held-out candidate verdicts need both classes" } else { &acceptance.reason },
            "calibration": map,
        });
    }
    for sample in &mut samples {
        if sample.score > 0.0 {
            sample.score = map.apply(sample.score);
        }
    }
    let report = run(
        &samples,
        settings.threshold_fpr_target,
        settings.block_threshold,
    );
    serde_json::json!({
        "passed": report.passed && report.holdout.caught > 0,
        "calibration": map,
        "threshold": report,
    })
}

/// The lowest threshold a trial may choose: below this the model's own score
/// stops meaning threat.
pub const MIN_THRESHOLD: f32 = 0.5;
/// The highest: a score of 1.0 or more is the model's full confidence.
pub const MAX_THRESHOLD: f32 = 1.0;
/// Step between candidate thresholds.
pub const GRID_STEP: f32 = 0.005;
/// Benign names needed on each half before a rate means anything.
pub const MIN_BENIGN: usize = 20;
/// One name in this many is held out, by registrable-domain hash: a whole
/// family of hostnames lands on the same side, so `login.bad.example` cannot
/// train the threshold that `pay.bad.example` is then tested on.
pub const HOLD_OUT_EVERY: u64 = 5;

/// Where a sample's label came from. A feed listing and an established domain
/// are evidence, not ground truth: they are kept apart so the report never
/// presents either as unquestionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    /// The operator said what the name is: the strongest label there is.
    OperatorCorrection,
    /// A maintained threat feed lists it.
    FeedListing,
    /// Many clients have used it for weeks: a presumption of benign, not a
    /// guarantee.
    Established,
    /// On the popular-sites ranking: a presumption of benign.
    Popular,
    /// Nobody has judged it.
    Unseen,
}

impl LabelSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorCorrection => "operator_correction",
            Self::FeedListing => "feed_listing",
            Self::Established => "established",
            Self::Popular => "popular",
            Self::Unseen => "unseen",
        }
    }

    /// How much the label may be trusted as ground truth.
    pub fn trust(self) -> &'static str {
        match self {
            Self::OperatorCorrection => "strong",
            Self::FeedListing => "moderate",
            Self::Established | Self::Popular => "weak",
            Self::Unseen => "none",
        }
    }

    /// The caveat the report repeats beside the count.
    pub fn note(self) -> &'static str {
        match self {
            Self::OperatorCorrection => "the operator's own decision",
            Self::FeedListing => {
                "a curated list, but feeds miss and over-list; not ground truth on its own"
            }
            Self::Established => {
                "long use on this network presumes benign; a compromised long-used host would be mislabelled"
            }
            Self::Popular => "popularity presumes benign; popular sites can be compromised or squatted",
            Self::Unseen => "no label; reported but never scored",
        }
    }
}

/// One provenance row: how many samples came from one label source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRow {
    pub label: String,
    pub trust: String,
    pub samples: usize,
    pub threats: usize,
    pub benign: usize,
    pub note: String,
}

/// A time-based evaluation: the candidate chosen on older verdicts, measured
/// again on the verdicts classified after the cutoff. This is how a threshold
/// is checked against newer domains and newer threats, which a random split
/// cannot show.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalReport {
    pub cutoff: i64,
    pub older: Side,
    pub newer: Side,
    pub summary: String,
}

/// Which population a scored name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Group {
    /// Used on this network for weeks by several clients: expected benign.
    Established,
    /// A threat feed lists it (directly or through a wildcard): expected a
    /// threat, and the reason the feeds are trusted.
    Confirmed,
    /// The operator said what it is: the strongest label there is.
    Correction,
    /// Nothing known about it: the population the threshold actually acts on.
    Unseen,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Established => "established",
            Group::Confirmed => "confirmed",
            Group::Correction => "correction",
            Group::Unseen => "unseen",
        }
    }

    /// The four rows, in report order.
    pub const ALL: [Group; 4] = [
        Group::Established,
        Group::Confirmed,
        Group::Correction,
        Group::Unseen,
    ];
}

/// One name, with the score the gate compares and what the store knows about
/// it.
#[derive(Debug, Clone)]
pub struct Sample {
    pub domain: String,
    /// The registrable domain: what the hold-out split is keyed on.
    pub registrable: String,
    pub score: f32,
    pub group: Group,
    /// Where the label came from.
    pub label: LabelSource,
    /// `Some(true)` when the name is known to be benign, `Some(false)` when
    /// known to be a threat, `None` when nobody has judged it.
    pub threat: Option<bool>,
    /// When the verdict was classified, for the time-based evaluation.
    pub scored_at: i64,
    /// The live policy rail that would stop this finding from blocking even
    /// when its score clears the threshold: an operator exemption, a
    /// category override, a dispute, or an authority stage below enforce.
    /// The replay records the rail so a trial measures the decision the gate
    /// would make, not just the number it would compare.
    pub policy_blocked: Option<String>,
}

impl Sample {
    pub fn benign(&self) -> Option<bool> {
        self.threat.map(|threat| !threat)
    }

    /// Whether the gate would block this name at `threshold`: the score has
    /// to clear the threshold *and* no policy rail may deny it.
    fn blocks_at(&self, threshold: f32) -> bool {
        self.policy_blocked.is_none() && self.score >= threshold
    }
}

/// One of the four populations, as the report shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRow {
    pub group: String,
    /// Whether the group counts towards the false-positive or recall rates.
    pub scored: bool,
    pub samples: usize,
    pub benign: usize,
    pub threats: usize,
    pub min_score: Option<f32>,
    pub median_score: Option<f32>,
    pub max_score: Option<f32>,
    /// Names at or above the candidate threshold.
    pub at_candidate: usize,
}

/// One half of the evidence, scored at one threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Side {
    pub benign: usize,
    pub false_positives: usize,
    /// False positives over benign names; `None` when there are none.
    pub fpr: Option<f32>,
    pub threats: usize,
    pub caught: usize,
    /// Threats at or above the threshold over threats; `None` when there are
    /// none.
    pub recall: Option<f32>,
    pub unseen: usize,
    pub unseen_blocked: usize,
    /// Whether this half had enough benign names for its rate to count.
    pub enough_benign: bool,
}

/// What a trial found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub samples: usize,
    pub fpr_target: f32,
    /// The threshold in force when the trial ran.
    pub base_threshold: f32,
    /// The lowest threshold whose tuning-half FPR met the target; `None` when
    /// no threshold in the grid did.
    pub candidate: Option<f32>,
    /// False-positive rate of the candidate on the tuning half.
    pub tuning_fpr: Option<f32>,
    /// Whether the candidate kept the target on the held-out half.
    pub passed: bool,
    /// One sentence the console can show as-is.
    pub summary: String,
    pub groups: Vec<GroupRow>,
    pub tuning: Side,
    pub holdout: Side,
    /// Where the labels came from, with the trust each deserves.
    pub provenance: Vec<ProvenanceRow>,
    /// Older-versus-newer performance of the candidate.
    pub temporal: Option<TemporalReport>,
}

/// Choose and validate a threshold over `samples`.
pub fn run(samples: &[Sample], fpr_target: f32, base_threshold: f32) -> Report {
    let fpr_target = fpr_target.clamp(0.0, 0.5);
    let tuning: Vec<&Sample> = samples.iter().filter(|s| !held_out(&s.domain)).collect();
    let holdout: Vec<&Sample> = samples.iter().filter(|s| held_out(&s.domain)).collect();

    let candidate = choose(&tuning, fpr_target);

    let groups = Group::ALL
        .into_iter()
        .map(|group| group_row(samples, group, candidate))
        .collect();

    let tuning_side = side(&tuning, candidate);
    let holdout_side = side(&holdout, candidate);
    let provenance = provenance_report(samples);
    let temporal = temporal_report(samples, candidate);

    let (passed, summary) = match candidate {
        _ if !tuning_side.enough_benign => (
            false,
            format!(
                "Too few established or corrected names to tune on: {} benign name(s), {} needed. \
                 Nothing was chosen.",
                tuning_side.benign, MIN_BENIGN
            ),
        ),
        None => (
            false,
            format!(
                "No threshold from {MIN_THRESHOLD:.2} to {MAX_THRESHOLD:.2} kept the false-positive \
                 rate at or under {:.1}% on the tuning half.",
                fpr_target * 100.0
            ),
        ),
        Some(candidate) if !holdout_side.enough_benign => (
            false,
            format!(
                "The candidate is {candidate:.3}, but the held-out half has only {} benign name(s), \
                 {} needed, so it could not be validated. Nothing was applied.",
                holdout_side.benign, MIN_BENIGN
            ),
        ),
        Some(candidate) => {
            let held = holdout_side.fpr.unwrap_or(0.0);
            if held <= fpr_target {
                (
                    true,
                    format!(
                        "Candidate {candidate:.3}: {:.2}% false positives on the tuning half and \
                         {:.2}% on the held-out half, against a {:.1}% target. Ready to apply.",
                        tuning_side.fpr.unwrap_or(0.0) * 100.0,
                        held * 100.0,
                        fpr_target * 100.0
                    ),
                )
            } else {
                (
                    false,
                    format!(
                        "Candidate {candidate:.3} kept the tuning half at {:.2}% but reached {:.2}% \
                         on the held-out half, over the {:.1}% target. Nothing was applied.",
                        tuning_side.fpr.unwrap_or(0.0) * 100.0,
                        held * 100.0,
                        fpr_target * 100.0
                    ),
                )
            }
        }
    };

    Report {
        samples: samples.len(),
        fpr_target,
        base_threshold,
        candidate,
        tuning_fpr: tuning_side.fpr,
        passed,
        summary,
        groups,
        tuning: tuning_side,
        holdout: holdout_side,
        provenance,
        temporal,
    }
}

/// Count the samples by label provenance.
fn provenance_report(samples: &[Sample]) -> Vec<ProvenanceRow> {
    let mut rows = Vec::new();
    for label in [
        LabelSource::OperatorCorrection,
        LabelSource::FeedListing,
        LabelSource::Popular,
        LabelSource::Established,
        LabelSource::Unseen,
    ] {
        let matching: Vec<&Sample> = samples.iter().filter(|s| s.label == label).collect();
        if matching.is_empty() {
            continue;
        }
        rows.push(ProvenanceRow {
            label: label.as_str().to_string(),
            trust: label.trust().to_string(),
            samples: matching.len(),
            threats: matching.iter().filter(|s| s.threat == Some(true)).count(),
            benign: matching.iter().filter(|s| s.threat == Some(false)).count(),
            note: label.note().to_string(),
        });
    }
    rows
}

/// Measure the candidate on verdicts from before and after the time cutoff.
/// The cutoff is the 70th percentile of classification times among labelled
/// samples, so the newer group is the most recent 30% and holds the domains
/// and threats the network met last.
fn temporal_report(samples: &[Sample], candidate: Option<f32>) -> Option<TemporalReport> {
    let mut times: Vec<i64> = samples
        .iter()
        .filter(|s| s.threat.is_some() && s.scored_at > 0)
        .map(|s| s.scored_at)
        .collect();
    if times.len() < MIN_BENIGN {
        return None;
    }
    times.sort_unstable();
    let cutoff = times[times.len() * 7 / 10];
    let older: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.scored_at > 0 && s.scored_at <= cutoff)
        .collect();
    let newer: Vec<&Sample> = samples.iter().filter(|s| s.scored_at > cutoff).collect();
    if older.is_empty() || newer.is_empty() {
        return None;
    }
    let older = side(&older, candidate);
    let newer = side(&newer, candidate);
    let summary = format!(
        "on verdicts up to the cutoff: {} benign, {} threat(s), {:.2}% false positives, {:.0}% recall; \
         after it: {} benign, {} threat(s), {:.2}% false positives, {:.0}% recall",
        older.benign,
        older.threats,
        older.fpr.unwrap_or(0.0) * 100.0,
        older.recall.unwrap_or(0.0) * 100.0,
        newer.benign,
        newer.threats,
        newer.fpr.unwrap_or(0.0) * 100.0,
        newer.recall.unwrap_or(0.0) * 100.0
    );
    Some(TemporalReport {
        cutoff,
        older,
        newer,
        summary,
    })
}

/// The lowest threshold whose tuning-half false-positive rate meets the
/// target: it catches the most threats the budget allows.
fn choose(tuning: &[&Sample], fpr_target: f32) -> Option<f32> {
    let benign = tuning.iter().filter(|s| s.benign() == Some(true)).count();
    if benign < MIN_BENIGN {
        return None;
    }
    let steps = ((MAX_THRESHOLD - MIN_THRESHOLD) / GRID_STEP).round() as u32;
    for step in 0..=steps {
        let threshold = MIN_THRESHOLD + step as f32 * GRID_STEP;
        let false_positives = tuning
            .iter()
            .filter(|s| s.benign() == Some(true) && s.blocks_at(threshold))
            .count();
        if false_positives as f32 / benign as f32 <= fpr_target {
            return Some((threshold * 1000.0).round() / 1000.0);
        }
    }
    None
}

/// Rate one half of the evidence at `candidate` (or at nothing, when the
/// trial chose none: then nothing counts as blocked).
fn side(samples: &[&Sample], candidate: Option<f32>) -> Side {
    let threshold = candidate.unwrap_or(f32::INFINITY);
    let benign = samples.iter().filter(|s| s.benign() == Some(true)).count();
    let false_positives = samples
        .iter()
        .filter(|s| s.benign() == Some(true) && s.blocks_at(threshold))
        .count();

    let threats = samples.iter().filter(|s| s.benign() == Some(false)).count();
    let caught = samples
        .iter()
        .filter(|s| s.benign() == Some(false) && s.blocks_at(threshold))
        .count();
    let unseen: Vec<&&Sample> = samples.iter().filter(|s| s.benign().is_none()).collect();
    let unseen_blocked = unseen.iter().filter(|s| s.blocks_at(threshold)).count();
    Side {
        benign,
        false_positives,
        fpr: (benign > 0).then(|| false_positives as f32 / benign as f32),
        threats,
        caught,
        recall: (threats > 0).then(|| caught as f32 / threats as f32),
        unseen: unseen.len(),
        unseen_blocked,
        enough_benign: benign >= MIN_BENIGN,
    }
}

fn group_row(samples: &[Sample], group: Group, candidate: Option<f32>) -> GroupRow {
    let mut scores: Vec<f32> = samples
        .iter()
        .filter(|s| s.group == group)
        .map(|s| s.score)
        .collect();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let threshold = candidate.unwrap_or(f32::INFINITY);
    GroupRow {
        group: group.as_str().to_string(),
        scored: matches!(group, Group::Established | Group::Confirmed),
        samples: scores.len(),
        benign: samples
            .iter()
            .filter(|s| s.group == group && s.benign() == Some(true))
            .count(),
        threats: samples
            .iter()
            .filter(|s| s.group == group && s.benign() == Some(false))
            .count(),
        min_score: scores.first().copied(),
        median_score: median(&scores),
        max_score: scores.last().copied(),
        at_candidate: samples
            .iter()
            .filter(|s| s.group == group && s.blocks_at(threshold))
            .count(),
    }
}

fn median(sorted: &[f32]) -> Option<f32> {
    match sorted.len() {
        0 => None,
        len if len % 2 == 1 => Some(sorted[len / 2]),
        len => Some((sorted[len / 2 - 1] + sorted[len / 2]) / 2.0),
    }
}

/// The stable split: one registrable domain in [`HOLD_OUT_EVERY`], decided by
/// the name itself so a rerun holds out the same names. Keying on the
/// registrable domain (not the hostname) keeps every subdomain of a family on
/// one side, which is what stops related hostnames leaking across the split.
pub fn held_out(domain: &str) -> bool {
    // FNV-1a, so the split does not depend on the hasher std happens to use.
    let key = crate::assessment::registrable(domain);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.is_multiple_of(HOLD_OUT_EVERY)
}

/// Read the evidence a trial runs on: every threat verdict, scored by the
/// confidence the block gate compares, labelled by what the store knows about
/// the name.
pub fn collect(
    store: &AiStore,
    intel: &IntelIndex,
    settings: &AiSettings,
    limit: u32,
) -> Result<Vec<Sample>> {
    collect_rows(
        store,
        intel,
        settings,
        store.gate_samples(limit, settings.fusion)?,
    )
}

/// [`collect`] on the score calibration is fitted against: the assessment
/// score before any map was applied, under the live fusion mode. Fitting on the
/// gate score while a map is already in force would learn from that map's own
/// output; fitting on the confidence would ignore a fused assessment.
pub fn collect_for_calibration(
    store: &AiStore,
    intel: &IntelIndex,
    settings: &AiSettings,
    limit: u32,
) -> Result<Vec<Sample>> {
    collect_rows(
        store,
        intel,
        settings,
        store.assessment_samples(limit, settings.fusion)?,
    )
}

fn collect_rows(
    store: &AiStore,
    intel: &IntelIndex,
    settings: &AiSettings,
    rows: Vec<(String, f32, i64)>,
) -> Result<Vec<Sample>> {
    let established: HashSet<String> = store
        .established_domains(u32::MAX)?
        .into_iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    // Newest first, so the first row for a domain is the operator's latest
    // word on it.
    let mut corrections: HashMap<String, (String, String)> = HashMap::new();
    for row in store.corrections()? {
        corrections
            .entry(row.domain.to_ascii_lowercase())
            .or_insert((row.action, row.category));
    }
    Ok(rows
        .into_iter()
        .map(|(domain, score, scored_at)| {
            let key = domain.to_ascii_lowercase();
            let (group, label, threat) = if let Some((action, category)) = corrections.get(&key) {
                let threat = if action == "category" {
                    settings.is_auto_block_category(category)
                        || (category == crate::backend::BINARY_THREAT_LABEL
                            && settings.label_role(category)
                                != daygle_dns_core::config::LabelRole::Suppressed)
                } else {
                    // `allow` and `not_threat` both mean "not a threat".
                    false
                };
                (
                    Group::Correction,
                    LabelSource::OperatorCorrection,
                    Some(threat),
                )
            } else if intel.attribution(&key).is_some() {
                (Group::Confirmed, LabelSource::FeedListing, Some(true))
            } else if intel.is_popular(&key) {
                (Group::Established, LabelSource::Popular, Some(false))
            } else if established.contains(&key) {
                (Group::Established, LabelSource::Established, Some(false))
            } else {
                (Group::Unseen, LabelSource::Unseen, None)
            };
            Sample {
                domain: key.clone(),
                registrable: crate::assessment::registrable(&key),
                score,
                group,
                label,
                threat,
                scored_at,
                policy_blocked: None,
            }
        })
        .collect())
}

/// The model's identity for calibration and threshold records. Restoring
/// identical bytes preserves the identity even when the path or stamp changes.
pub fn model_version(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return "builtin".to_string();
    }
    artifact_version(path).unwrap_or_else(|_| format!("unreadable:{path}"))
}

fn artifact_version(path: &str) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(format!(
                "sha256:{}",
                crate::candidate::hex(&hash.finalize())
            ));
        }
        hash.update(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_tunes_calibration_and_threshold_on_separate_splits() {
        let samples = (0..400)
            .map(|i| {
                let threat = i % 2 == 0;
                sample(
                    &format!("shadow-review-{i}.example"),
                    if threat { 0.8 } else { 0.3 },
                    Group::Correction,
                    Some(threat),
                )
            })
            .collect();
        let report = tune_replayed_scores(samples, "sha256:shadow", &AiSettings::default(), 1);
        assert_eq!(report["passed"], true, "{report}");
        assert_eq!(report["calibration"]["source_model"], "sha256:shadow");
        assert_eq!(report["threshold"]["holdout"]["false_positives"], 0);
        assert!(report["threshold"]["holdout"]["caught"].as_u64().unwrap() > 0);
    }

    #[test]
    fn replay_refuses_to_tune_without_labelled_candidate_verdicts() {
        let report = tune_replayed_scores(Vec::new(), "sha256:shadow", &AiSettings::default(), 1);
        assert_eq!(report["passed"], false);
        assert!(report.get("threshold").is_none());
    }

    fn sample(domain: &str, score: f32, group: Group, threat: Option<bool>) -> Sample {
        let label = match group {
            Group::Correction => LabelSource::OperatorCorrection,
            Group::Confirmed => LabelSource::FeedListing,
            Group::Established => LabelSource::Established,
            Group::Unseen => LabelSource::Unseen,
        };
        Sample {
            domain: domain.to_string(),
            registrable: crate::assessment::registrable(domain),
            score,
            group,
            label,
            threat,
            scored_at: 1_700_000_000,
            policy_blocked: None,
        }
    }

    /// Twenty benign names scoring low and twenty threats scoring high, all on
    /// the tuning half: every grid threshold meets a 5% target, so the trial
    /// must pick the lowest one.
    #[test]
    fn the_lowest_threshold_that_meets_the_target_wins() {
        let mut samples = Vec::new();
        let mut i = 0;
        let mut benign = 0;
        while benign < 60 {
            let domain = format!("benign{i}.example");
            i += 1;
            if held_out(&domain) {
                continue;
            }
            samples.push(sample(&domain, 0.30, Group::Established, Some(false)));
            benign += 1;
        }
        let mut threats = 0;
        while threats < 20 {
            let domain = format!("threat{i}.example");
            i += 1;
            if held_out(&domain) {
                continue;
            }
            samples.push(sample(&domain, 0.90, Group::Confirmed, Some(true)));
            threats += 1;
        }
        let report = run(&samples, 0.05, 0.99);
        // Nothing benign scores 0.50 or above; the lowest grid value is 0.50.
        assert_eq!(report.candidate, Some(MIN_THRESHOLD));
        assert_eq!(report.tuning.fpr, Some(0.0));
        assert_eq!(report.tuning.recall, Some(1.0));
        // Every scored name is on the tuning half here, so no held-out benign
        // names are left to validate on: the trial must not claim a pass.
        assert_eq!(report.holdout.fpr, None, "nothing scored is held out");
        assert!(!report.holdout.enough_benign);
        assert!(!report.passed, "{}", report.summary);
    }

    /// The same shape, split across both halves, so the held-out half can
    /// confirm the candidate.
    #[test]
    fn a_candidate_must_keep_the_target_on_the_held_out_half() {
        let mut samples = Vec::new();
        let mut benign = 0;
        let mut i = 0;
        while benign < 120 {
            let domain = format!("site{i}.example");
            i += 1;
            samples.push(sample(&domain, 0.30, Group::Established, Some(false)));
            benign += 1;
        }
        let mut threats = 0;
        while threats < 40 {
            let domain = format!("bad{i}.example");
            i += 1;
            samples.push(sample(&domain, 0.95, Group::Confirmed, Some(true)));
            threats += 1;
        }
        let report = run(&samples, 0.02, 0.99);
        assert!(report.holdout.enough_benign);
        assert!(report.passed, "{}", report.summary);
        assert_eq!(report.candidate, Some(MIN_THRESHOLD));
        assert_eq!(report.holdout.fpr, Some(0.0));
        assert_eq!(report.tuning.recall, Some(1.0));

        // One held-out benign name just above 0.5 breaks the held-out rate,
        // and with it the pass - even though the tuning half is unchanged.
        let mut leaky = samples.clone();
        let victim = leaky
            .iter()
            .find(|s| s.benign() == Some(true) && held_out(&s.domain))
            .map(|s| s.domain.clone())
            .expect("a held-out benign name");
        for s in leaky.iter_mut().filter(|s| s.domain == victim) {
            s.score = 0.7;
        }
        let report = run(&leaky, 0.02, 0.99);
        assert_eq!(report.candidate, Some(MIN_THRESHOLD));
        assert!(report.holdout.fpr.unwrap() > 0.0);
        assert!(!report.passed, "{}", report.summary);
        assert!(
            report.summary.contains("held-out half"),
            "{}",
            report.summary
        );
    }

    #[test]
    fn too_little_evidence_chooses_nothing() {
        let samples = vec![
            sample("a.example", 0.9, Group::Confirmed, Some(true)),
            sample("b.example", 0.2, Group::Established, Some(false)),
        ];
        let report = run(&samples, 0.01, 0.99);
        assert!(!report.passed);
        assert_eq!(report.candidate, None);
        assert!(report.summary.contains("Too few"), "{}", report.summary);
    }

    #[test]
    fn the_four_populations_are_separate_rows() {
        let samples = vec![
            sample("used.example", 0.1, Group::Established, Some(false)),
            sample("feed.example", 0.95, Group::Confirmed, Some(true)),
            sample("fixed.example", 0.4, Group::Correction, Some(false)),
            sample("new.example", 0.8, Group::Unseen, None),
        ];
        let report = run(&samples, 0.01, 0.99);
        let names: Vec<&str> = report.groups.iter().map(|g| g.group.as_str()).collect();
        assert_eq!(
            names,
            vec!["established", "confirmed", "correction", "unseen"]
        );
        assert_eq!(report.groups[0].benign, 1);
        assert_eq!(report.groups[1].threats, 1);
        assert_eq!(report.groups[2].benign, 1);
        assert_eq!(report.groups[3].samples, 1);
        // Only the judged populations feed the rates.
        assert!(report.groups[0].scored && report.groups[1].scored);
        assert!(!report.groups[2].scored && !report.groups[3].scored);
    }

    #[test]
    fn the_hold_out_split_is_stable_and_about_a_fifth() {
        let domains: Vec<String> = (0..500).map(|i| format!("d{i}.example")).collect();
        let first: Vec<bool> = domains.iter().map(|d| held_out(d)).collect();
        let second: Vec<bool> = domains.iter().map(|d| held_out(d)).collect();
        assert_eq!(first, second);
        let held = first.iter().filter(|h| **h).count();
        assert!((70..=130).contains(&held), "{held} of 500 held out");
    }

    /// Related hostnames are one family: the split is keyed on the
    /// registrable domain, so a subdomain cannot tune the threshold that its
    /// sibling is tested on.
    #[test]
    fn related_hostnames_stay_on_one_side_of_the_split() {
        for name in [
            "login.bad.example",
            "pay.bad.example",
            "deep.pay.bad.example",
        ] {
            assert_eq!(held_out(name), held_out("bad.example"), "{name}");
        }
        // A different registrable domain is a different family.
        let same = held_out("a.example");
        let shared = (0..200)
            .map(|i| format!("x{i}.example"))
            .filter(|d| held_out(d) != same)
            .count();
        assert!(shared > 0, "the split is not a constant");
        assert_eq!(held_out("A.EXAMPLE"), held_out("a.example"));
    }

    #[test]
    fn provenance_is_reported_with_the_trust_each_label_deserves() {
        let samples = vec![
            sample("fixed.example", 0.3, Group::Correction, Some(false)),
            sample("feed.example", 0.9, Group::Confirmed, Some(true)),
            sample("used.example", 0.2, Group::Established, Some(false)),
        ];
        let report = run(&samples, 0.01, 0.99);
        let rows: Vec<(&str, &str, usize)> = report
            .provenance
            .iter()
            .map(|row| (row.label.as_str(), row.trust.as_str(), row.samples))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("operator_correction", "strong", 1),
                ("feed_listing", "moderate", 1),
                ("established", "weak", 1),
            ]
        );
        assert!(report.provenance[1]
            .note
            .contains("not ground truth on its own"));
    }

    #[test]
    fn the_time_based_evaluation_compares_older_and_newer_verdicts() {
        let mut samples = Vec::new();
        let now = 1_700_000_000;
        for i in 0..60 {
            let mut sample = sample(
                &format!("old{i}.example"),
                0.2,
                Group::Established,
                Some(false),
            );
            sample.scored_at = now - 30 * 86_400 + i;
            samples.push(sample);
        }
        for i in 0..20 {
            let mut sample = sample(
                &format!("new{i}.example"),
                0.95,
                Group::Confirmed,
                Some(true),
            );
            sample.scored_at = now - i;
            samples.push(sample);
        }
        let report = run(&samples, 0.01, 0.99);
        let temporal = report.temporal.expect("a temporal report");
        assert!(temporal.cutoff > 0);
        assert!(temporal.newer.threats > 0, "the newer threats are there");
        assert!(temporal.summary.contains("after it"));
    }

    #[test]
    fn an_unreadable_artifact_has_no_content_identity() {
        assert_eq!(model_version(""), "builtin");
        assert_eq!(
            model_version("/nonexistent/model.bin"),
            "unreadable:/nonexistent/model.bin"
        );
    }

    #[test]
    fn model_identity_follows_the_bytes_across_restores() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.bin");
        let restored = dir.path().join("restored.bin");
        std::fs::write(&live, b"first").unwrap();
        let original = model_version(live.to_str().unwrap());
        std::fs::write(&restored, b"first").unwrap();
        assert_eq!(model_version(restored.to_str().unwrap()), original);
        std::fs::write(&live, b"other").unwrap();
        assert_ne!(model_version(live.to_str().unwrap()), original);
    }
}
