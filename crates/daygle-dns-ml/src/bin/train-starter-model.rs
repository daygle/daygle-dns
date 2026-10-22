//! Regenerate `models/daygle-starter.bin` from `models/starter-training.txt`.
//!
//! The committed model was produced with this tool (a train-once step, not
//! part of any build). To rebuild after editing the dataset:
//!
//! ```sh
//! cargo run --release -p daygle-dns-ml --bin train-starter-model
//! ```
//!
//! The tool expands each dataset line into tokenization variants (www.-
//! prefix, hyphen-joined, space-joined) so the classifier is robust to the
//! label-boundary shapes the scanner feeds it, then trains a compact
//! supervised model (dim 24, 50k ngram buckets ⇒ a few MB) and saves it.

use std::collections::BTreeSet;
use std::path::PathBuf;

const REPO_MODELS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../models");
const DATA_FILE: &str = "starter-training.txt";
const OUTPUT_FILE: &str = "daygle-starter.bin";

/// Tokenization variants of one domain, deduplicated.
fn variants(domain: &str) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let plain = domain.to_string();
    if !domain.starts_with("www.") {
        out.insert(format!("www.{plain}"));
    }
    out.insert(plain.to_string());
    // Hyphen-joined: matches how a browser strips dots, e.g. www-example-com.
    out.insert(plain.replace('.', "-"));
    // Space-joined tokens: matches heuristic-style label splitting.
    let tokens = domain.split(['.', '-']).collect::<Vec<_>>().join(" ");
    out.insert(tokens);
    out.into_iter().collect()
}

fn main() {
    let data_path = PathBuf::from(REPO_MODELS).join(DATA_FILE);
    let output_path = PathBuf::from(REPO_MODELS).join(OUTPUT_FILE);

    let raw = std::fs::read_to_string(&data_path).expect("read training data");
    let mut expanded = String::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((label, domain)) = line.split_once(char::is_whitespace) else {
            panic!("line without label/domain pair: {line:?}");
        };
        for variant in variants(domain) {
            expanded.push_str(label);
            expanded.push(' ');
            expanded.push_str(&variant);
            expanded.push('\n');
        }
    }

    let temp = std::env::temp_dir().join("daygle-starter-expanded.fasttext");
    std::fs::write(&temp, expanded).expect("write expanded dataset");
    println!(
        "expanded dataset: {} lines",
        std::fs::read_to_string(&temp).unwrap().lines().count()
    );

    let mut args = fasttext::args::Args {
        input: temp.clone(),
        output: temp.with_extension("model"),
        ..Default::default()
    };
    args.apply_supervised_defaults();
    // A single-word-probe supervised classifier: distinct labels, small
    // corpus ⇒ deterministic settings matter more than a big one.
    args.dim = 24;
    args.lr = 0.3;
    args.epoch = 40;
    args.word_ngrams = 1;
    // Character n-grams generalize to unseen domains (the scanner meets far
    // more names than the dataset ever lists), using a bounded bucket so the
    // .bin stays a few MB instead of the ~1 GB default (2M buckets).
    args.minn = 3;
    args.maxn = 5;
    args.bucket = 50_000;
    args.thread = 4;
    args.seed = 42;
    args.verbose = 0;

    let model = fasttext::FastText::train(args).expect("fastText training failed");
    model.save_model(&output_path).expect("save model");

    // Round-trip check: the four menace-theater domains below must land in
    // their trained categories or the committed artifact is useless.
    let reload = fasttext::FastText::load_model(&output_path).expect("reload trained model");
    let probes = [
        ("secure-obviousaccount-verify-login.com", "phishing"),
        ("trojan-botnet-payload-download.click", "malware"),
        ("casino-slot-bonus-spin.win", "gambling"),
        ("wikipedia.org", "education"),
    ];
    let mut failures = 0;
    for (probe, want) in probes {
        let got = reload
            .predict(probe, 1, 0.0)
            .first()
            .map(|p| p.label.trim_start_matches("__label__").to_string())
            .unwrap_or_default();
        let ok = got == want;
        if !ok {
            failures += 1;
        }
        println!(
            "  probe: {probe} → {got}{}",
            if ok {
                String::new()
            } else {
                format!(" (wanted {want})")
            }
        );
    }
    panic_if_bad(failures);

    let size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    println!(
        "wrote {} ({} bytes); remove {} at your leisure",
        output_path.display(),
        size,
        temp.display()
    );
    std::fs::remove_file(&temp).ok();
}

fn panic_if_bad(failures: usize) {
    if failures > 0 {
        panic!("{failures} probe(s) misclassified - fix the dataset or keep the committed model");
    }
    println!("all probes classified as expected");
}
