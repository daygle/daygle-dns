//! The verifier's reference, kept current from operator truth.
//!
//! The MiniLM verifier labels a domain by the nearest category centroid in a
//! reference file. That reference ships with the model, built from the
//! starter corpus. This module rebuilds it from the starter corpus **plus
//! the operator's category corrections** whenever those change, so the
//! verifier learns the categories this network's operator taught - and
//! deliberately **never** from the scanner's own verdicts: the verifier is the
//! independent second opinion, and training it on the primary classifier's
//! labels would make it agree with the primary by construction.
//!
//! A rebuilt reference must hold up before it is used: on corrections held
//! back from it (one in five, by domain) it must do at least as well as the
//! reference in use, and it must not do worse on the starter corpus by more
//! than two points. It is written beside `ai.db` and preferred over the
//! shipped reference unless `ai.verifier_reference_path` pins one.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};

use crate::learn::{bundled_starter_corpus, hash_selected, starter_pairs, starter_pairs_from};
use crate::scanner::looks_like_domain;
use crate::store::AiStore;
use crate::verifier_onnx::{load_centroids, CentroidMap, MiniLmVerifier, CENTROIDS_FILE};

/// How far a rebuilt reference may trail the one in use on the starter
/// corpus before it is refused.
const STARTER_SLACK: f32 = 0.02;

/// The fingerprint file beside the reference: what it was built from, so an
/// unchanged set of corrections is not embedded again.
fn meta_path(out: &Path) -> PathBuf {
    out.with_extension("meta")
}

/// Rebuild the reference at `out` when the operator's corrections changed.
/// `Ok(None)`: nothing to do (no verifier, a pinned reference, no
/// corrections, or nothing changed). `Ok(Some(note))`: a new reference is in
/// place. `Err`: it was built but would have been worse, or could not be
/// built; the reference in use is unchanged.
pub fn refresh(store: &AiStore, settings: &AiSettings, out: &Path) -> Result<Option<String>> {
    let verifier_model = settings.verifier_model_path.trim();
    if verifier_model.is_empty() || !settings.verifier_reference_path.trim().is_empty() {
        return Ok(None);
    }

    // The operator's category labels, newest first; one per domain.
    let mut seen: HashSet<String> = HashSet::new();
    let mut corrections: Vec<(String, String)> = Vec::new();
    let mut newest = 0i64;
    for correction in store.corrections()? {
        if correction.action != "category" {
            continue;
        }
        let domain = correction
            .domain
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        let label = correction.category.trim().to_ascii_lowercase();
        if label.is_empty() || !looks_like_domain(&domain) || !seen.insert(domain.clone()) {
            continue;
        }
        newest = newest.max(correction.created_at);
        corrections.push((label, domain));
    }
    if corrections.is_empty() {
        return Ok(None);
    }
    let corpus = bundled_starter_corpus(&settings.model_path);
    let starter = match corpus.as_deref() {
        Some(text) => starter_pairs_from(text),
        None => starter_pairs(),
    };
    let fingerprint = format!(
        "{}:{newest}:{}:{}",
        corrections.len(),
        starter.len(),
        verifier_model
    );
    if std::fs::read_to_string(meta_path(out)).ok().as_deref() == Some(fingerprint.as_str()) {
        return Ok(None);
    }
    // Whatever happens below, this set of corrections has been considered.
    let remember = || std::fs::write(meta_path(out), &fingerprint);

    let embedder = MiniLmVerifier::load_embedder(verifier_model)?;
    let embed = |text: &str| -> Result<Vec<f32>> { embedder.embed_text(text) };

    // Starter and training corrections build the centroids; held-out
    // corrections judge them.
    let (held, taught): (Vec<_>, Vec<_>) = corrections
        .into_iter()
        .partition(|(_, domain)| hash_selected(domain));
    let mut sums: BTreeMap<String, (Vec<f32>, usize)> = BTreeMap::new();
    let mut starter_embedded: Vec<(String, Vec<f32>)> = Vec::new();
    let mut add = |label: &str, embedding: &[f32]| {
        let entry = sums
            .entry(label.to_string())
            .or_insert_with(|| (vec![0.0; embedding.len()], 0));
        for (sum, value) in entry.0.iter_mut().zip(embedding) {
            *sum += value;
        }
        entry.1 += 1;
    };
    for (label, domain) in &starter {
        let plain = embed(domain)?;
        let spaced = embed(&domain.split(['.', '-']).collect::<Vec<_>>().join(" "))?;
        add(label, &plain);
        add(label, &spaced);
        starter_embedded.push((label.clone(), plain));
    }
    for (label, domain) in &taught {
        // Weighted like a starter example per variant: corrections are few,
        // and each one is the operator's word.
        add(label, &embed(domain)?);
        add(
            label,
            &embed(&domain.split(['.', '-']).collect::<Vec<_>>().join(" "))?,
        );
    }
    let mut rebuilt: CentroidMap = BTreeMap::new();
    for (label, (sum, _)) in sums {
        let norm: f32 = sum.iter().map(|v| v * v).sum::<f32>().sqrt();
        if !norm.is_finite() || norm == 0.0 {
            continue;
        }
        rebuilt.insert(label, sum.iter().map(|v| v / norm).collect());
    }
    if rebuilt.is_empty() {
        let _ = remember();
        return Err(DaygleError::Config(
            "no usable centroid could be built".to_string(),
        ));
    }

    // The reference in use: the one this module wrote before, else the one
    // shipped beside the verifier model.
    let shipped = Path::new(verifier_model)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CENTROIDS_FILE);
    let current = if out.is_file() {
        load_centroids(out).ok()
    } else {
        load_centroids(&shipped).ok()
    };
    let held_embedded: Vec<(String, Vec<f32>)> = held
        .iter()
        .map(|(label, domain)| Ok((label.clone(), embed(domain)?)))
        .collect::<Result<_>>()?;
    let rebuilt_starter = accuracy(&rebuilt, &starter_embedded);
    let rebuilt_held = accuracy(&rebuilt, &held_embedded);
    if let Some(current) = &current {
        let current_starter = accuracy(current, &starter_embedded);
        let current_held = accuracy(current, &held_embedded);
        if !held_embedded.is_empty() && rebuilt_held < current_held {
            let _ = remember();
            return Err(DaygleError::Config(format!(
                "a reference rebuilt from your corrections scored {:.0}% on {} held-out corrections against {:.0}% for the one in use, so it was not used",
                rebuilt_held * 100.0,
                held_embedded.len(),
                current_held * 100.0
            )));
        }
        if rebuilt_starter + STARTER_SLACK < current_starter {
            let _ = remember();
            return Err(DaygleError::Config(format!(
                "a reference rebuilt from your corrections scored {:.0}% on the starter corpus against {:.0}% for the one in use, so it was not used",
                rebuilt_starter * 100.0,
                current_starter * 100.0
            )));
        }
    }

    let temp = out.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(&rebuilt)
        .map_err(|e| DaygleError::Config(format!("cannot encode the verifier reference: {e}")))?;
    std::fs::write(&temp, bytes)?;
    // Only a file the verifier itself accepts goes into place.
    if let Err(e) = load_centroids(&temp) {
        let _ = std::fs::remove_file(&temp);
        let _ = remember();
        return Err(e);
    }
    std::fs::rename(&temp, out)?;
    let _ = remember();
    Ok(Some(format!(
        "{} categories from the starter corpus and {} of your corrections ({} held out: {:.0}% right)",
        rebuilt.len(),
        taught.len(),
        held_embedded.len(),
        rebuilt_held * 100.0
    )))
}

/// Share of `examples` whose nearest centroid carries their label.
fn accuracy(centroids: &CentroidMap, examples: &[(String, Vec<f32>)]) -> f32 {
    if examples.is_empty() {
        return 0.0;
    }
    let right = examples
        .iter()
        .filter(|(label, embedding)| {
            centroids
                .iter()
                .map(|(category, centroid)| {
                    let score: f32 = embedding.iter().zip(centroid).map(|(a, b)| a * b).sum();
                    (category, score)
                })
                .max_by(|a, b| a.1.total_cmp(&b.1))
                .is_some_and(|(category, _)| category == label)
        })
        .count();
    right as f32 / examples.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODELS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../models");

    #[test]
    fn a_reference_is_rebuilt_once_per_set_of_corrections() {
        let model = Path::new(MODELS).join("all-MiniLM-L6-v2-int8.onnx");
        if !model.is_file() {
            eprintln!("bundled MiniLM model missing; skipped");
            return;
        }
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        for (domain, label) in [
            ("dailynews-local.example", "news"),
            ("bigshop-local.example", "shopping"),
            ("casino-local.example", "gambling"),
        ] {
            store.set_category_override(domain, label).unwrap();
        }
        let settings = AiSettings {
            verifier_model_path: model.display().to_string(),
            ..AiSettings::default()
        };
        let out = dir.path().join("learned-centroids.json");
        let first = refresh(&store, &settings, &out);
        // Built and either used or refused for a stated reason; either way
        // the same corrections are not embedded again.
        match &first {
            Ok(Some(_)) => assert!(load_centroids(&out).is_ok()),
            Ok(None) => panic!("corrections exist, so a rebuild was due"),
            Err(e) => assert!(e.to_string().contains("not used"), "{e}"),
        }
        assert!(matches!(refresh(&store, &settings, &out), Ok(None)));

        // A pinned reference is the operator's choice: never rebuilt.
        let pinned = AiSettings {
            verifier_reference_path: "/pinned.json".to_string(),
            ..settings
        };
        store
            .set_category_override("another.example", "news")
            .unwrap();
        assert!(matches!(refresh(&store, &pinned, &out), Ok(None)));
    }
}
