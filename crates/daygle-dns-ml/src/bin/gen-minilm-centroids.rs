//! Generate `models/minilm-centroids.json` from `models/starter-training.txt`.
//!
//! `cargo run --release -p daygle-dns-ml --bin gen-minilm-centroids`
//!
//! Embeds every (expanded) dataset domain with the bundled MiniLM ONNX
//! model, averages per category, L2-normalizes, and writes the centroid map
//! the verifier classifies against. Commit the JSON alongside the model -
//! the pair must be regenerated together.

#[cfg(feature = "verifier-onnx")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "verifier-onnx")]
use std::path::PathBuf;

#[cfg(feature = "verifier-onnx")]
use daygle_dns_ml::verifier_onnx::MiniLmVerifier;

#[cfg(feature = "verifier-onnx")]
const REPO_MODELS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../models");

/// Tokenization variants matching the fastText trainer's expansion.
#[cfg(feature = "verifier-onnx")]
fn variants(domain: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    if !domain.starts_with("www.") {
        out.insert(format!("www.{domain}"));
    }
    out.insert(domain.to_string());
    out.insert(domain.replace('.', "-"));
    out.insert(domain.split(['.', '-']).collect::<Vec<_>>().join(" "));
    out.into_iter().collect()
}

/// Without the verifier feature the tool has nothing to embed with.
#[cfg(not(feature = "verifier-onnx"))]
fn main() {
    eprintln!("gen-minilm-centroids requires the daygle-dns-ml `verifier-onnx` feature");
    std::process::exit(1);
}

/// Everything below needs the MiniLM/ONNX verifier backend.
#[cfg(feature = "verifier-onnx")]
fn main() {
    let models_dir = PathBuf::from(REPO_MODELS);
    let data_path = models_dir.join("starter-training.txt");
    let model_path = models_dir.join("all-MiniLM-L6-v2-int8.onnx");
    let out_path = models_dir.join("minilm-centroids.json");

    let verifier =
        MiniLmVerifier::load_embedder(&model_path).expect("load bundled MiniLM verifier model");

    let raw = std::fs::read_to_string(&data_path).expect("read starter training data");
    let mut per_category: BTreeMap<String, Vec<Vec<f32>>> = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((label, domain)) = line.split_once(char::is_whitespace) else {
            eprintln!("skipping malformed line: {line:?}");
            continue;
        };
        let category = label.trim_start_matches("__label__").to_string();
        for variant in variants(domain) {
            let embedding = verifier.embed_text(&variant).expect("embed variant");
            if embedding.is_empty() {
                eprintln!("empty embedding for {variant:?}; skipped");
                continue;
            }
            per_category
                .entry(category.clone())
                .or_default()
                .push(embedding);
        }
    }

    let mut centroids: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for (category, embeddings) in per_category {
        let dim = embeddings[0].len();
        let mut mean = vec![0f32; dim];
        for e in &embeddings {
            for d in 0..dim {
                mean[d] += e[d];
            }
        }
        let norm: f32 = mean.iter().map(|v| v * v).sum::<f32>().sqrt();
        if !norm.is_finite() || norm == 0.0 {
            panic!("degenerate centroid for {category}");
        }
        for v in &mut mean {
            *v /= norm;
        }
        println!("{}: {} examples", category, embeddings.len());
        centroids.insert(category, mean);
    }

    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&centroids).expect("serialize centroids"),
    )
    .expect("write centroids");
    println!(
        "wrote {} centroids to {}",
        centroids.len(),
        out_path.display()
    );

    // Self-check: category separation with fresh, held-out probes.
    for (probe, want) in [
        ("secure-login-verify-account.info", "phishing"),
        ("casino-slot-bonus-spin.win", "gambling"),
        ("www.wikipedia.org", "education"),
    ] {
        let e = verifier.embed_text(probe).expect("embed probe");
        let (best, score) = centroids
            .iter()
            .map(|(c, v)| (c.clone(), e.iter().zip(v).map(|(a, b)| a * b).sum::<f32>()))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .unwrap();
        println!("probe {probe} -> {best} ({score:.3})");
        assert_eq!(best, want, "centroid separation broken for {probe}");
    }
    println!("probe checks passed");
}
