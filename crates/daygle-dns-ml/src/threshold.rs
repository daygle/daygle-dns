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

use serde::{Deserialize, Serialize};

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::Result;

use crate::intel::IntelIndex;
use crate::store::AiStore;

/// The lowest threshold a trial may choose: below this the model's own score
/// stops meaning threat.
pub const MIN_THRESHOLD: f32 = 0.5;
/// The highest: a score of 1.0 or more is the model's full confidence.
pub const MAX_THRESHOLD: f32 = 1.0;
/// Step between candidate thresholds.
pub const GRID_STEP: f32 = 0.005;
/// Benign names needed on each half before a rate means anything.
pub const MIN_BENIGN: usize = 20;
/// One name in this many is held out, by domain hash.
pub const HOLD_OUT_EVERY: u64 = 5;

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

/// One name, with the model's score and what the store knows about it.
#[derive(Debug, Clone)]
pub struct Sample {
    pub domain: String,
    pub score: f32,
    pub group: Group,
    /// `Some(true)` when the name is known to be benign, `Some(false)` when
    /// known to be a threat, `None` when nobody has judged it.
    pub threat: Option<bool>,
}

impl Sample {
    pub fn benign(&self) -> Option<bool> {
        self.threat.map(|threat| !threat)
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
    }
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
            .filter(|s| s.benign() == Some(true) && s.score >= threshold)
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
        .filter(|s| s.benign() == Some(true) && s.score >= threshold)
        .count();
    let threats = samples.iter().filter(|s| s.benign() == Some(false)).count();
    let caught = samples
        .iter()
        .filter(|s| s.benign() == Some(false) && s.score >= threshold)
        .count();
    let unseen: Vec<&&Sample> = samples.iter().filter(|s| s.benign().is_none()).collect();
    let unseen_blocked = unseen.iter().filter(|s| s.score >= threshold).count();
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
            .filter(|s| s.group == group && s.score >= threshold)
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

/// The stable split: one name in [`HOLD_OUT_EVERY`], decided by the name
/// itself so a rerun holds out the same names.
pub fn held_out(domain: &str) -> bool {
    // FNV-1a, so the split does not depend on the hasher std happens to use.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in domain.trim().trim_end_matches('.').as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.is_multiple_of(HOLD_OUT_EVERY)
}

/// Read the evidence a trial runs on: every threat verdict that carries a
/// model score, labelled by what the store knows about the name.
pub fn collect(
    store: &AiStore,
    intel: &IntelIndex,
    settings: &AiSettings,
    limit: u32,
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
    let rows = store.scored_threats(limit)?;
    Ok(rows
        .into_iter()
        .map(|(domain, score)| {
            let key = domain.to_ascii_lowercase();
            let (group, threat) = if let Some((action, category)) = corrections.get(&key) {
                let threat = if action == "category" {
                    settings.is_auto_block_category(category)
                } else {
                    // `allow` and `not_threat` both mean "not a threat".
                    false
                };
                (Group::Correction, Some(threat))
            } else if intel.attribution(&key).is_some() {
                (Group::Confirmed, Some(true))
            } else if established.contains(&key) {
                (Group::Established, Some(false))
            } else {
                (Group::Unseen, None)
            };
            Sample {
                domain: key,
                score,
                group,
                threat,
            }
        })
        .collect())
}

/// The model's identity for a trial record: `builtin` for the shipped
/// classifier, else the path with its stamp, so the threshold can always be
/// read beside the model it was measured with.
pub fn model_version(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return "builtin".to_string();
    }
    match std::fs::metadata(path) {
        Ok(meta) => {
            let stamp = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("{path}@{stamp}:{}", meta.len())
        }
        Err(_) => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(domain: &str, score: f32, group: Group, threat: Option<bool>) -> Sample {
        Sample {
            domain: domain.to_string(),
            score,
            group,
            threat,
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
        assert!(report.summary.contains("held-out half"), "{}", report.summary);
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
        assert_eq!(names, vec!["established", "confirmed", "correction", "unseen"]);
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

    #[test]
    fn a_model_path_is_part_of_the_candidate() {
        assert_eq!(model_version(""), "builtin");
        assert_eq!(
            model_version("/nonexistent/model.bin"),
            "/nonexistent/model.bin"
        );
    }
}
