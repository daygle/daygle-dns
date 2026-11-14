//! Does the `benign` class swallow threats?
//!
//! `ai.learn_negatives` lets "not a threat" corrections train a `benign`
//! label. The risk is the obvious one: a small single-label model that has
//! learned "benign" from the names an operator marked can start applying it
//! to threats it would otherwise have reported. This example measures that
//! instead of arguing about it.
//!
//! It builds a deterministic synthetic corpus, runs the production pipeline
//! (`AiStore` -> [`learn::collect`] -> [`learn::train`]), and trains the same
//! corpus twice - `learn_negatives` off and on - then scores both on threat
//! domains that were never trained on:
//!
//! * **detected**: the model still gives a threat label;
//! * **swallowed**: the model now says `benign`;
//! * **missed**: the model gives some ordinary category.
//!
//! Two scenarios, because the risk depends entirely on where the negatives
//! come from:
//!
//! 1. **ordinary negatives** - the operator marked harmless sites. The benign
//!    class is a clean "ordinary" class with little overlap with the threat
//!    vocabulary.
//! 2. **flagged lookalikes** - the operator marked domains the model had
//!    already flagged (a false-positive correction, which is what
//!    `not_threat` exists for). The benign examples now look like threats,
//!    which is the case where a negative class can start swallowing them.
//!
//! Run with:
//!
//! ```text
//! cargo run -p daygle-dns-ml --example negatives_eval
//! ```
//!
//! The corpus is synthetic: it shows whether the mechanism can swallow threats
//! and roughly how much, not what any particular network will see.

use std::collections::BTreeMap;

use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_ml::backend::{Channel, ClassificationInput, DomainClassifier};
use daygle_dns_ml::fasttext_backend::FastTextBackend;
use daygle_dns_ml::learn::{self, BENIGN_LABEL};
use daygle_dns_ml::store::AiStore;

/// Threat families: label and the word pairs that name them.
const THREAT_LABELS: &[(&str, &[&str]); 3] = &[
    (
        "malware",
        &[
            "malware-download",
            "ransomware-payment",
            "keylogger-setup",
            "trojan-installer",
            "virus-scan",
        ],
    ),
    (
        "phishing",
        &[
            "secure-login",
            "account-verify",
            "credential-update",
            "phish-gateway",
            "login-alert",
        ],
    ),
    (
        "scam",
        &[
            "free-crypto",
            "prize-claim",
            "wallet-connect",
            "gift-card-offer",
            "double-deposit",
        ],
    ),
];

/// Ordinary sites, with the label the categorizer would give them. Several
/// share a word with a threat family (`secure-login` / `secure-mail`,
/// `wallet-connect` / `wallet-guide`), so the benign class is not a clean
/// distant class even in the first scenario.
const ORDINARY: &[(&str, &[&str]); 7] = &[
    ("news", &["daily-news", "crypto-news", "world-report"]),
    ("shopping", &["gift-guide", "home-goods", "garden-store"]),
    ("docs", &["wallet-guide", "api-reference", "user-manual"]),
    ("travel", &["travel-guide", "hotel-booking", "rail-times"]),
    ("bank", &["secure-mail", "credit-union", "account-support"]),
    (
        "forum",
        &["payment-help", "community-board", "support-thread"],
    ),
    (
        "software",
        &["download-guide", "open-source", "file-manager"],
    ),
];

const TRAIN_PER_STEM: usize = 6;
const HELD_OUT_PER_STEM: usize = 2;
const BENIGN_SITES: usize = 240;
const NEGATIVES: usize = 60;
const FRESH_ORDINARY: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegativeKind {
    /// Harmless sites the operator marked.
    Ordinary,
    /// Domains the model flagged, which the operator corrected.
    FlaggedLookalike,
}

impl NegativeKind {
    fn title(self) -> &'static str {
        match self {
            NegativeKind::Ordinary => "scenario 1: negatives are harmless sites",
            NegativeKind::FlaggedLookalike => {
                "scenario 2: negatives are flagged lookalikes (false-positive corrections)"
            }
        }
    }
}

/// One model's results.
struct Row {
    learn_negatives: bool,
    pairs: usize,
    stats: learn::TrainingStats,
    labels: BTreeMap<String, usize>,
    /// `[detected, swallowed, missed]`.
    threats: [usize; 3],
    /// `[benign, threat label, ordinary]` on fresh harmless names.
    ordinary: [usize; 3],
}

fn main() {
    if let Err(error) = run() {
        eprintln!("evaluation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    for kind in [NegativeKind::Ordinary, NegativeKind::FlaggedLookalike] {
        println!("== {}", kind.title());
        let dir = std::env::temp_dir().join(format!(
            "daygle-negatives-eval-{}-{}",
            std::process::id(),
            match kind {
                NegativeKind::Ordinary => "ordinary",
                NegativeKind::FlaggedLookalike => "flagged",
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let (store, held_out_threats, fresh_ordinary, marked) = seed(&dir, kind)?;
        let rows = measure(&store, &held_out_threats, &fresh_ordinary, &dir)?;
        println!(
            "   {} {} marked not-a-threat; {} threat domains never trained on; {} fresh harmless names",
            marked,
            match kind {
                NegativeKind::Ordinary => "harmless sites",
                NegativeKind::FlaggedLookalike => "flagged threat domains",
            },
            held_out_threats.len(),
            fresh_ordinary.len()
        );
        report(&rows, held_out_threats.len(), fresh_ordinary.len());
        verdict(&rows, held_out_threats.len());
        println!();
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!(
        "The corpus is synthetic. Treat these numbers as a bound on the mechanism, not as a \
         measurement of your network."
    );
    Ok(())
}

/// What [`seed`] produced: the store, the held-out threats, the fresh harmless
/// names, and how many domains were marked not-a-threat.
type Seeded = (AiStore, Vec<(String, String)>, Vec<String>, usize);

/// Seed one store for one scenario. Returns the store, the held-out threats,
/// the fresh harmless names and how many threat domains were marked.
fn seed(dir: &std::path::Path, kind: NegativeKind) -> Result<Seeded, String> {
    let store = AiStore::open(&dir.join("ai.db")).map_err(|e| e.to_string())?;
    let mut train_threats = Vec::new();
    let mut held_out_threats = Vec::new();
    for (label, stems) in THREAT_LABELS {
        for stem in *stems {
            for i in 0..TRAIN_PER_STEM {
                let domain = format!("{stem}-{}.example", i + 1);
                store.observe(&domain).map_err(|e| e.to_string())?;
                store
                    .save_verdict(
                        Channel::Threat,
                        &domain,
                        label,
                        "threat",
                        "classified",
                        1.0,
                        "corpus",
                        "synthetic",
                        86_400,
                    )
                    .map_err(|e| e.to_string())?;
                train_threats.push(domain);
            }
            // Held out: never observed, so they cannot appear in training or
            // validation. The words are the same; the order is not.
            for i in 0..HELD_OUT_PER_STEM {
                let reversed = stem.split('-').rev().collect::<Vec<_>>().join("-");
                held_out_threats.push((label.to_string(), format!("{reversed}-{}.example", i + 1)));
            }
        }
    }

    let mut benign_sites = Vec::new();
    for i in 0..BENIGN_SITES {
        let (label, words) = ORDINARY[i % ORDINARY.len()];
        let word = words[(i / ORDINARY.len()) % words.len()];
        let domain = format!("{word}-{}.example", i + 1);
        store.observe(&domain).map_err(|e| e.to_string())?;
        store
            .save_verdict(
                Channel::Content,
                &domain,
                label,
                "info",
                "classified",
                0.95,
                "corpus",
                "synthetic",
                86_400,
            )
            .map_err(|e| e.to_string())?;
        benign_sites.push(domain);
    }

    let marked: Vec<String> = match kind {
        NegativeKind::Ordinary => benign_sites.iter().take(NEGATIVES).cloned().collect(),
        // Every third flagged threat domain, which is what a "no, this one is
        // fine" correction looks like after the model has already spoken.
        NegativeKind::FlaggedLookalike => train_threats
            .iter()
            .step_by(3)
            .take(NEGATIVES)
            .cloned()
            .collect(),
    };
    for domain in &marked {
        store
            .set_override(domain, "not_threat", "operator said so")
            .map_err(|e| e.to_string())?;
    }

    let fresh_ordinary: Vec<String> = (0..FRESH_ORDINARY)
        .map(|i| {
            let (_, words) = ORDINARY[i % ORDINARY.len()];
            let word = words[(i / ORDINARY.len()) % words.len()];
            format!("fresh-{word}-{}.example", i + 1)
        })
        .collect();

    Ok((store, held_out_threats, fresh_ordinary, marked.len()))
}

/// Train both models on one corpus and score them.
fn measure(
    store: &AiStore,
    held_out_threats: &[(String, String)],
    fresh_ordinary: &[String],
    dir: &std::path::Path,
) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for learn_negatives in [false, true] {
        let settings = AiSettings {
            enabled: true,
            mode: AiMode::Train,
            learn_negatives,
            ..Default::default()
        };
        let (pairs, stats) = learn::collect(store, &settings).map_err(|e| e.to_string())?;
        let labels: BTreeMap<String, usize> =
            pairs
                .iter()
                .fold(BTreeMap::new(), |mut counts, (label, _)| {
                    *counts.entry(label.clone()).or_insert(0) += 1;
                    counts
                });
        let model_path = dir.join(if learn_negatives {
            "negatives.bin"
        } else {
            "baseline.bin"
        });
        learn::train(&pairs, &model_path).map_err(|e| e.to_string())?;
        let model = FastTextBackend::load(&model_path).map_err(|e| e.to_string())?;

        let mut threats = [0usize; 3];
        for (_, domain) in held_out_threats {
            match reading(&model, domain)? {
                Reading::Detected => threats[0] += 1,
                Reading::Swallowed => threats[1] += 1,
                Reading::Missed => threats[2] += 1,
            }
        }
        let mut ordinary = [0usize; 3];
        for domain in fresh_ordinary {
            let category = category(&model, domain)?;
            match category.as_deref() {
                Some(BENIGN_LABEL) => ordinary[0] += 1,
                Some(label) if is_threat_label(label) => ordinary[1] += 1,
                _ => ordinary[2] += 1,
            }
        }
        rows.push(Row {
            learn_negatives,
            pairs: pairs.len(),
            stats,
            labels,
            threats,
            ordinary,
        });
    }
    Ok(rows)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    Detected,
    Swallowed,
    Missed,
}

fn reading(model: &FastTextBackend, domain: &str) -> Result<Reading, String> {
    Ok(match category(model, domain)?.as_deref() {
        Some(BENIGN_LABEL) => Reading::Swallowed,
        Some(label) if is_threat_label(label) => Reading::Detected,
        _ => Reading::Missed,
    })
}

fn is_threat_label(label: &str) -> bool {
    THREAT_LABELS.iter().any(|(threat, _)| *threat == label)
}

fn category(model: &FastTextBackend, domain: &str) -> Result<Option<String>, String> {
    Ok(model
        .classify(&ClassificationInput::domain_only(domain))
        .map(|verdict| verdict.category))
}

fn report(rows: &[Row], held_out: usize, fresh: usize) {
    println!(
        "{:<20} {:>6} {:>6} {:>9} {:>10} {:>7} {:>12}",
        "learn_negatives", "pairs", "benign", "detected", "swallowed", "missed", "fresh benign"
    );
    for row in rows {
        println!(
            "{:<20} {:>6} {:>6} {:>9} {:>10} {:>7} {:>12}",
            if row.learn_negatives {
                "on"
            } else {
                "off (baseline)"
            },
            row.pairs,
            row.labels.get(BENIGN_LABEL).copied().unwrap_or(0),
            format!("{}/{}", row.threats[0], held_out),
            format!("{}/{}", row.threats[1], held_out),
            format!("{}/{}", row.threats[2], held_out),
            format!("{}/{}", row.ordinary[0], fresh),
        );
    }
    for row in rows {
        println!(
            "   {}: {} pairs ({} corrections, {} verdicts, {} negatives); labels: {}; fresh names read as threat: {}",
            if row.learn_negatives { "on       " } else { "baseline " },
            row.pairs,
            row.stats.corrections,
            row.stats.verdicts,
            row.stats.negatives,
            row.labels
                .iter()
                .map(|(label, count)| format!("{label}={count}"))
                .collect::<Vec<_>>()
                .join(", "),
            row.ordinary[1],
        );
    }
}

fn verdict(rows: &[Row], held_out: usize) {
    let baseline = &rows[0];
    let negatives = &rows[1];
    let swallowed = negatives.threats[1];
    let lost = baseline.threats[0].saturating_sub(negatives.threats[0]);
    if swallowed == 0 {
        println!(
            "   verdict: no held-out threat read as benign; {} detection(s) lost to other labels.",
            lost
        );
    } else {
        println!(
            "   verdict: the benign class swallowed {swallowed}/{held_out} held-out threats ({}%), \
             {} fewer detection(s) than the baseline.",
            percent(swallowed, held_out),
            lost
        );
    }
}

fn percent(part: usize, whole: usize) -> usize {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}
