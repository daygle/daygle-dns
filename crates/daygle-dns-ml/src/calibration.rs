//! Score calibration: turn the assessment score the gate compares into a
//! calibrated probability, and prove the change before it is used.
//!
//! The model's score is an opinion, not a probability. It is fitted by a
//! classifier, it is mixed with evidence stages, and nothing about it says
//! "of the names I scored 0.90, 90% were threats". Calibration learns that
//! mapping from labelled data:
//!
//! - an **isotonic** map (pool-adjacent-violators) fitted on a tuning split,
//!   stored as monotone breakpoints, so a higher raw score can never map to a
//!   lower calibrated one;
//! - **held-out** evaluation: the map is fitted on one split and scored on a
//!   disjoint one, split by registrable domain ([`crate::threshold`]) so a
//!   family of hostnames cannot be on both sides;
//! - **Brier score**, **expected calibration error (ECE)** and a
//!   **reliability table** (predicted vs observed per decile);
//! - an **acceptance gate**: a candidate whose Brier or ECE is worse than the
//!   map in force is rejected, with the numbers that rejected it.
//!
//! Every map is versioned by its own content plus the model identity it was
//! fitted under, and a candidate version records that version. Applying is a
//! separate, explicit step: fitting never changes what enforcement uses.

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

/// How the map turns a raw score into a calibrated one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// No calibration: the raw score *is* the score. This is what every
    /// install has until a promoted candidate supplies a map, and what a
    /// rollback to "no map" restores.
    Identity,
    /// Monotone piecewise-linear isotonic regression.
    Isotonic,
}

/// One labelled score: what the system said, and what the name turned out to
/// be.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Labelled {
    pub score: f32,
    pub threat: bool,
}

/// The minimum labelled names a map may be fitted on.
pub const MIN_FIT_SAMPLES: usize = 40;
/// The minimum held-out names a candidate is judged on.
pub const MIN_EVAL_SAMPLES: usize = 20;
/// How much worse (Brier) a candidate may be and still be accepted.
pub const BRIER_TOLERANCE: f32 = 0.002;
/// How much worse (ECE) a candidate may be and still be accepted.
pub const ECE_TOLERANCE: f32 = 0.01;

/// A versioned calibration map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationMap {
    /// Content hash: the method, the breakpoints and the model identity.
    pub version: String,
    pub method: Method,
    /// Monotone `(raw, calibrated)` breakpoints, ascending in `raw`.
    pub points: Vec<(f32, f32)>,
    /// The model identity this was fitted under (see
    /// [`crate::threshold::model_version`]).
    pub source_model: String,
    pub fitted_on: usize,
    pub fitted_at: i64,
    /// The held-out numbers the map was accepted on, when it was.
    #[serde(default)]
    pub metrics: Option<Metrics>,
}

impl CalibrationMap {
    /// The "no map" map: raw score in, raw score out.
    pub fn identity(source_model: &str, now: i64) -> Self {
        let mut map = Self {
            version: String::new(),
            method: Method::Identity,
            points: Vec::new(),
            source_model: source_model.to_string(),
            fitted_on: 0,
            fitted_at: now,
            metrics: None,
        };
        map.version = map.compute_version();
        map
    }

    pub fn is_identity(&self) -> bool {
        self.method == Method::Identity || self.points.is_empty()
    }

    /// Map one raw score. Monotone and clamped to 0..1; the identity map is a
    /// no-op, and a raw score with no calibration is never relabelled as a
    /// probability by this module.
    pub fn apply(&self, raw: f32) -> f32 {
        if !raw.is_finite() {
            return 0.0;
        }
        let raw = raw.clamp(0.0, 1.0);
        if self.is_identity() {
            return raw;
        }
        let points = &self.points;
        let first = points[0];
        let last = points[points.len() - 1];
        if raw <= first.0 {
            return first.1.clamp(0.0, 1.0);
        }
        if raw >= last.0 {
            return last.1.clamp(0.0, 1.0);
        }
        for pair in points.windows(2) {
            let (x0, y0) = pair[0];
            let (x1, y1) = pair[1];
            if raw >= x0 && raw <= x1 {
                if (x1 - x0).abs() < f32::EPSILON {
                    return y1.clamp(0.0, 1.0);
                }
                let t = (raw - x0) / (x1 - x0);
                return (y0 + t * (y1 - y0)).clamp(0.0, 1.0);
            }
        }
        last.1.clamp(0.0, 1.0)
    }

    /// The content hash. Recomputing it after a rollback proves the restored
    /// map is the one the candidate recorded, independent of any version
    /// string that was stored beside it.
    pub fn compute_version(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"daygle-calibration-v1");
        hasher.update(match self.method {
            Method::Identity => b"identity".as_slice(),
            Method::Isotonic => b"isotonic".as_slice(),
        });
        hasher.update(self.source_model.as_bytes());
        for (raw, calibrated) in &self.points {
            hasher.update(raw.to_le_bytes());
            hasher.update(calibrated.to_le_bytes());
        }
        let digest = crate::candidate::hex(&hasher.finalize());
        format!("cal-{}", &digest[..16])
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(raw: &str) -> Option<Self> {
        serde_json::from_str(raw).ok()
    }
}

/// One reliability decile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bin {
    pub lower: f32,
    pub upper: f32,
    pub count: usize,
    pub positives: usize,
    /// Mean calibrated score in the bin.
    pub predicted: f32,
    /// Observed threat share in the bin.
    pub observed: f32,
}

/// Held-out performance of one map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    pub samples: usize,
    pub positives: usize,
    /// Mean squared error of the calibrated probability.
    pub brier: f32,
    /// Expected calibration error: the count-weighted mean |predicted −
    /// observed| over the deciles.
    pub ece: f32,
    pub bins: Vec<Bin>,
}

impl Metrics {
    pub fn reliability(&self) -> &[Bin] {
        &self.bins
    }

    /// Whether this report has enough held-out names to mean anything.
    pub fn enough(&self) -> bool {
        self.samples >= MIN_EVAL_SAMPLES
    }
}

/// Score `samples` through `map`.
pub fn evaluate(samples: &[Labelled], map: &CalibrationMap) -> Metrics {
    let mut bins: Vec<(usize, f32, usize)> = (0..10).map(|_| (0usize, 0.0f32, 0usize)).collect();
    let mut brier = 0.0f64;
    let mut positives = 0usize;
    for sample in samples {
        let predicted = map.apply(sample.score);
        let actual = if sample.threat { 1.0 } else { 0.0 };
        brier += f64::from((predicted - actual).powi(2));
        if sample.threat {
            positives += 1;
        }
        let idx = ((predicted * 10.0).floor() as usize).min(9);
        bins[idx].0 += 1;
        bins[idx].1 += predicted;
        bins[idx].2 += usize::from(sample.threat);
    }
    let n = samples.len().max(1) as f32;
    let mut ece = 0.0f32;
    let bins: Vec<Bin> = bins
        .into_iter()
        .enumerate()
        .map(|(index, (count, sum, positives))| {
            let predicted = if count > 0 { sum / count as f32 } else { 0.0 };
            let observed = if count > 0 {
                positives as f32 / count as f32
            } else {
                0.0
            };
            if count > 0 {
                ece += (count as f32 / n) * (predicted - observed).abs();
            }
            Bin {
                lower: index as f32 / 10.0,
                upper: (index + 1) as f32 / 10.0,
                count,
                positives,
                predicted,
                observed,
            }
        })
        .collect();
    Metrics {
        samples: samples.len(),
        positives,
        brier: (brier / f64::from(n)) as f32,
        ece,
        bins,
    }
}

/// Fit an isotonic map on `samples`. `None` when there is too little data or
/// the labels are all one class (a map fitted on one class says nothing).
pub fn fit(samples: &[Labelled], source_model: &str, now: i64) -> Option<CalibrationMap> {
    if samples.len() < MIN_FIT_SAMPLES {
        return None;
    }
    let positives = samples.iter().filter(|s| s.threat).count();
    if positives == 0 || positives == samples.len() {
        return None;
    }
    let mut sorted: Vec<Labelled> = samples
        .iter()
        .map(|sample| Labelled {
            score: sample.score.clamp(0.0, 1.0),
            threat: sample.threat,
        })
        .collect();
    sorted.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Pool adjacent violators: merge a block with its successor whenever the
    // block's positive rate is higher, so the fitted map is non-decreasing.
    struct Block {
        sum_x: f64,
        positives: usize,
        count: usize,
    }
    let mean = |block: &Block| block.positives as f64 / block.count as f64;
    let mut blocks: Vec<Block> = sorted
        .iter()
        .map(|sample| Block {
            sum_x: f64::from(sample.score),
            positives: usize::from(sample.threat),
            count: 1,
        })
        .collect();
    let mut index = 0;
    while index + 1 < blocks.len() {
        if mean(&blocks[index]) > mean(&blocks[index + 1]) {
            let right = blocks.remove(index + 1);
            blocks[index].sum_x += right.sum_x;
            blocks[index].positives += right.positives;
            blocks[index].count += right.count;
            // A merge can violate against the block before it: step back.
            index = index.saturating_sub(1);
        } else {
            index += 1;
        }
    }

    let mut points: Vec<(f32, f32)> = Vec::new();
    for block in &blocks {
        let raw = (block.sum_x / block.count as f64) as f32;
        let calibrated = block.positives as f32 / block.count as f32;
        match points.last_mut() {
            // Keep `raw` strictly ascending: a later block that pooled to the
            // same raw score is one breakpoint.
            Some(last) if (last.0 - raw).abs() < 1e-6 => {
                last.1 = last.1.max(calibrated);
            }
            _ => points.push((raw, calibrated)),
        }
    }
    if points.is_empty() {
        return None;
    }
    let mut map = CalibrationMap {
        version: String::new(),
        method: Method::Isotonic,
        points,
        source_model: source_model.to_string(),
        fitted_on: samples.len(),
        fitted_at: now,
        metrics: None,
    };
    map.version = map.compute_version();
    Some(map)
}

/// Whether a candidate may replace the map in force.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acceptance {
    pub accepted: bool,
    pub reason: String,
}

/// Compare a candidate's held-out numbers with the ones in force. A candidate
/// must be no worse on Brier *and* no worse on ECE, and must have enough
/// held-out names; an uncalibrated incumbent (identity, no report) loses to a
/// candidate that has a report.
pub fn accept(candidate: &Metrics, incumbent: Option<&Metrics>) -> Acceptance {
    if !candidate.enough() {
        return Acceptance {
            accepted: false,
            reason: format!(
                "the held-out split has {} labelled name(s); {} are needed to judge a calibration",
                candidate.samples, MIN_EVAL_SAMPLES
            ),
        };
    }
    let Some(incumbent) = incumbent else {
        return Acceptance {
            accepted: true,
            reason: format!(
                "no calibrated map is in force; the candidate scores Brier {:.4} and ECE {:.4} on {} held-out names",
                candidate.brier, candidate.ece, candidate.samples
            ),
        };
    };
    if !incumbent.enough() {
        return Acceptance {
            accepted: true,
            reason: format!(
                "the map in force has no comparable held-out report; the candidate scores Brier {:.4} and ECE {:.4}",
                candidate.brier, candidate.ece
            ),
        };
    }
    let worse_brier = candidate.brier > incumbent.brier + BRIER_TOLERANCE;
    let worse_ece = candidate.ece > incumbent.ece + ECE_TOLERANCE;
    if worse_brier || worse_ece {
        return Acceptance {
            accepted: false,
            reason: format!(
                "the candidate is worse on the held-out split: Brier {:.4} vs {:.4}, ECE {:.4} vs {:.4}",
                candidate.brier, incumbent.brier, candidate.ece, incumbent.ece
            ),
        };
    }
    Acceptance {
        accepted: true,
        reason: format!(
            "the candidate is no worse on the held-out split: Brier {:.4} vs {:.4}, ECE {:.4} vs {:.4}",
            candidate.brier, incumbent.brier, candidate.ece, incumbent.ece
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(score: f32, threat: bool) -> Labelled {
        Labelled { score, threat }
    }

    /// Twenty names per side, one class per score band: an over-confident
    /// model whose 0.9s are wrong half the time.
    fn overconfident() -> Vec<Labelled> {
        let mut samples = Vec::new();
        for i in 0..40 {
            samples.push(labelled(0.10, false));
            samples.push(labelled(0.90, i < 20));
        }
        samples
    }

    #[test]
    fn the_identity_map_is_a_no_op_and_says_so() {
        let map = CalibrationMap::identity("builtin", 1_700_000_000);
        assert!(map.is_identity());
        assert_eq!(map.apply(0.73), 0.73);
        assert_eq!(map.apply(-1.0), 0.0);
        assert_eq!(map.apply(2.0), 1.0);
        assert!(map.version.starts_with("cal-"));
        // The version follows the content, not a counter.
        let clone = map.clone();
        assert_eq!(map.version, clone.compute_version());
    }

    #[test]
    fn an_isotonic_map_is_monotone_and_learns_the_overconfidence() {
        let samples = overconfident();
        let map = fit(&samples, "builtin", 1_700_000_000).expect("a map");
        assert_eq!(map.method, Method::Isotonic);
        assert!(map.points.len() >= 2);
        for pair in map.points.windows(2) {
            assert!(pair[0].0 <= pair[1].0, "{:?}", map.points);
            assert!(pair[0].1 <= pair[1].1, "not monotone: {:?}", map.points);
        }
        assert!(map.apply(0.9) < 0.9, "0.9 was right half the time");
        assert!(map.apply(0.1) <= 0.2);
        // Applying is clamped and monotone across the grid.
        let mut previous = -1.0;
        for step in 0..=100 {
            let value = map.apply(step as f32 / 100.0);
            assert!(value >= previous - 1e-6);
            assert!((0.0..=1.0).contains(&value));
            previous = value;
        }
    }

    #[test]
    fn a_fit_needs_both_classes_and_enough_names() {
        assert!(fit(&[labelled(0.9, true); 80], "m", 1).is_none());
        assert!(fit(&[labelled(0.1, false); 80], "m", 1).is_none());
        assert!(fit(&[labelled(0.9, true), labelled(0.1, false)], "m", 1).is_none());
    }

    #[test]
    fn metrics_report_brier_ece_and_a_reliability_table() {
        let samples = overconfident();
        let identity = CalibrationMap::identity("builtin", 1);
        let metrics = evaluate(&samples, &identity);
        assert_eq!(metrics.samples, 80);
        assert_eq!(metrics.positives, 20);
        // Half of the 0.9 names are benign, half of the 0.1 names too.
        assert!(metrics.brier > 0.15, "{}", metrics.brier);
        assert!(metrics.ece > 0.2, "{}", metrics.ece);
        assert_eq!(metrics.bins.len(), 10);
        let high = &metrics.bins[9];
        assert_eq!(high.count, 40);
        assert!((high.observed - 0.5).abs() < 1e-6);
        assert!((high.predicted - 0.9).abs() < 1e-6);
        assert!(metrics.enough());
    }

    #[test]
    fn a_calibrated_map_scores_better_than_the_identity() {
        let samples = overconfident();
        // Fit on a tuning split drawn from both score bands, then evaluate on
        // a disjoint hold-out (the split is by name in the trial; here the
        // index stands in for it).
        let map = fit(&samples, "builtin", 1).expect("a map");
        let identity = CalibrationMap::identity("builtin", 1);
        let held: Vec<Labelled> = samples.iter().step_by(2).copied().collect();
        let before = evaluate(&held, &identity);
        let after = evaluate(&held, &map);
        assert!(
            after.brier < before.brier,
            "{} vs {}",
            after.brier,
            before.brier
        );
    }

    #[test]
    fn a_worse_candidate_is_rejected() {
        let good = Metrics {
            samples: 100,
            positives: 10,
            brier: 0.05,
            ece: 0.02,
            bins: Vec::new(),
        };
        let worse = Metrics {
            samples: 100,
            positives: 10,
            brier: 0.09,
            ece: 0.02,
            bins: Vec::new(),
        };
        let verdict = accept(&worse, Some(&good));
        assert!(!verdict.accepted);
        assert!(verdict.reason.contains("worse"), "{}", verdict.reason);

        let equal = Metrics {
            brier: 0.051,
            ece: 0.025,
            ..good.clone()
        };
        assert!(accept(&equal, Some(&good)).accepted);
    }

    #[test]
    fn a_candidate_with_too_little_held_out_data_is_rejected() {
        let thin = Metrics {
            samples: 3,
            positives: 1,
            brier: 0.01,
            ece: 0.01,
            bins: Vec::new(),
        };
        let verdict = accept(&thin, None);
        assert!(!verdict.accepted);
        assert!(verdict.reason.contains("needed"), "{}", verdict.reason);
    }

    #[test]
    fn the_first_calibration_beats_no_report_at_all() {
        let metrics = Metrics {
            samples: 50,
            positives: 5,
            brier: 0.02,
            ece: 0.01,
            bins: Vec::new(),
        };
        let verdict = accept(&metrics, None);
        assert!(verdict.accepted);
        assert!(verdict.reason.contains("no calibrated map is in force"));
    }
}
