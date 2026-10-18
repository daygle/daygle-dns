//! MiniLM/ONNX verifier backend: sentence embeddings via a quantized
//! `all-MiniLM-L6-v2` ONNX export, classified against per-category centroid
//! embeddings generated from the shipped starter dataset.
//!
//! This is the "second, more expensive pass" from the backend design table:
//! the fastText/heuristic classifier stays the cheap primary; the verifier
//! corroborates (or refutes) *threat* verdicts with an independent signal.
//! It never sees the DNS hot path — the scanner calls it from background
//! classification cycles only.
//!
//! Model artifacts (shipped under `models/`, installed to the config dir):
//!
//! | File                        | Role                                        |
//! |-----------------------------|---------------------------------------------|
//! | `all-MiniLM-L6-v2-int8.onnx`| int8-quantized sentence transformer         |
//! | `minilm-tokenizer.json`     | the model's full BERT tokenizer pipeline    |
//! | `minilm-centroids.json`     | one unit-norm centroid per trained category |
//!
//! The verifier expects its `minilm-tokenizer.json` and
//! `minilm-centroids.json` beside the ONNX file (or uses explicit reference
//! paths configured under `[ai]`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use daygle_dns_core::error::{DaygleError, Result};
use parking_lot::Mutex;

use crate::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};

const TOKENIZER_FILE: &str = "minilm-tokenizer.json";
const CENTROIDS_FILE: &str = "minilm-centroids.json";
// Embeddings are unit-norm; cosine ~0.5+ is a solid match for a category
// centroid, ~0.25 is noise for sentence-embedding geometry on short inputs.
pub const DEFAULT_MATCH_THRESHOLD: f32 = 0.35;

/// Embedding-based verifier over a bundled ONNX MiniLM model.
pub struct MiniLmVerifier {
    // Sessions are documented as single-threaded; the scanner classifies
    // from background workers, so all inference goes through this mutex.
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    centroids: Vec<(String, Vec<f32>)>,
}

/// Reference centroid set: category name -> unit-norm embedding.
type CentroidMap = BTreeMap<String, Vec<f32>>;

fn load_tokenizer(model_path: &Path) -> Result<tokenizers::Tokenizer> {
    let tokenizer_path = model_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(TOKENIZER_FILE);
    tokenizers::Tokenizer::from_file(&tokenizer_path).map_err(|e| {
        DaygleError::Config(format!(
            "cannot load MiniLM tokenizer {}: {e}",
            tokenizer_path.display()
        ))
    })
}

fn build_session(model_path: &Path) -> Result<ort::session::Session> {
    // ONNX Runtime permits exactly one Environment per process; share it so
    // multiple verifier loads (tests, the embedding tool) never collide.
    static ONNX_ENV: std::sync::OnceLock<
        std::result::Result<ort::environment::Environment, String>,
    > = std::sync::OnceLock::new();
    let environment = ONNX_ENV
        .get_or_init(|| {
            ort::init()
                .build()
                .map_err(|e| format!("ONNX Runtime init failed: {e}"))
        })
        .as_ref()
        .map_err(|e| DaygleError::Config(e.clone()))?;
    ort::session::Session::builder(environment)
        .map_err(|e| DaygleError::Config(format!("ONNX session builder failed: {e}")))?
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level1)
        .map_err(|e| DaygleError::Config(format!("ONNX optimizer level failed: {e}")))?
        .commit_from_file(model_path)
        .map_err(|e| {
            DaygleError::Config(format!(
                "cannot load MiniLM ONNX model {}: {e}",
                model_path.display()
            ))
        })
}

fn load_centroids(path: &Path) -> Result<CentroidMap> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        DaygleError::Config(format!(
            "cannot read MiniLM centroid file {}: {e}",
            path.display()
        ))
    })?;
    let map: CentroidMap = serde_json::from_str(&raw).map_err(|e| {
        DaygleError::Config(format!("bad MiniLM centroid file {}: {e}", path.display()))
    })?;
    if map.is_empty() {
        return Err(DaygleError::Config(format!(
            "MiniLM centroid file {} is empty",
            path.display()
        )));
    }
    for (category, centroid) in &map {
        let norm: f32 = centroid.iter().map(|v| v * v).sum::<f32>().sqrt();
        if !norm.is_finite() || !(0.7..=1.3).contains(&norm) {
            return Err(DaygleError::Config(format!(
                "MiniLM centroid for '{category}' is not a normalized embedding (norm {norm})"
            )));
        }
    }
    Ok(map)
}

#[cfg(feature = "verifier-onnx")]
impl MiniLmVerifier {
    /// Loader for tools that only need embeddings (the centroid generator).
    /// Otherwise identical to [`Self::load`], but the centroid reference is
    /// left empty — `classify` returns None on such an instance.
    pub fn load_embedder(model_path: impl AsRef<Path>) -> Result<Self> {
        let model_path = model_path.as_ref();
        let tokenizer = load_tokenizer(model_path)?;
        let session = build_session(model_path)?;
        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            centroids: Vec::new(),
        })
    }

    /// Load the verifier from an ONNX model path. The tokenizer and centroid
    /// reference files are looked up beside it unless explicit paths are
    /// given (`reference_path` wins; else `<model dir>/minilm-centroids.json`).
    pub fn load(model_path: impl AsRef<Path>, reference_path: Option<&str>) -> Result<Self> {
        let model_path = model_path.as_ref();
        let model_dir = model_path.parent().unwrap_or_else(|| Path::new("."));

        let tokenizer = load_tokenizer(model_path)?;

        let centroids_path = match reference_path {
            Some(p) if !p.trim().is_empty() => PathBuf::from(p),
            _ => model_dir.join(CENTROIDS_FILE),
        };
        let centroids = load_centroids(&centroids_path)?;

        let session = build_session(model_path)?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            centroids: centroids.into_iter().collect(),
        })
    }

    /// Public embedding API: unit-norm 384-d sentence embedding for one
    /// input string (also used by `gen-minilm-centroids`).
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        self.embed(text)
    }

    /// Unit-norm 384-d sentence embedding for one input string.
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| DaygleError::Internal(format!("MiniLM tokenization failed: {e}")))?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|&v| v as i64).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&v| v as i64)
            .collect();
        let type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&v| v as i64).collect();
        let seq_len = ids.len() as i64;
        if seq_len == 0 {
            return Ok(Vec::new());
        }
        let shape = vec![1, seq_len];

        // A `Tensor<i64>` *is* a `Value` in ort rc.14; sessions accept them
        // directly in the input map.
        let inputs: Vec<(&str, ort::value::Tensor<i64>)> = {
            let session = self.session.lock();
            let names: Vec<String> = session
                .inputs()
                .iter()
                .map(|o| o.name().to_string())
                .collect();
            let mut inputs = Vec::new();
            for (name, data) in [
                ("input_ids", ids),
                ("attention_mask", mask.clone()),
                ("token_type_ids", type_ids),
            ] {
                if names.iter().any(|n| n == name) {
                    let tensor =
                        ort::value::Tensor::from_array((shape.clone(), data)).map_err(|e| {
                            DaygleError::Internal(format!("MiniLM tensor '{name}': {e}"))
                        })?;
                    inputs.push((name, tensor));
                }
            }
            inputs
        };

        let mut session = self.session.lock();
        let outputs = session
            .run(inputs)
            .map_err(|e| DaygleError::Internal(format!("MiniLM inference failed: {e}")))?;

        // Prefer the pooled+normalized export; fall back to mean-pooling
        // last_hidden_state with the attention mask (mirrors MiniLM's pooler).
        if outputs.get("sentence_embedding").is_some() {
            let (shape, data) = outputs["sentence_embedding"]
                .try_extract_tensor::<f32>()
                .map_err(|e| DaygleError::Internal(format!("MiniLM pooling output: {e}")))?;
            let dim = shape.last().copied().unwrap_or(0) as usize;
            if dim == 0 || data.len() < dim {
                return Err(DaygleError::Internal(
                    "MiniLM sentence_embedding has wrong shape".into(),
                ));
            }
            Ok(data[(data.len() - dim)..].to_vec())
        } else if outputs.get("last_hidden_state").is_some() {
            let (shape, data) = outputs["last_hidden_state"]
                .try_extract_tensor::<f32>()
                .map_err(|e| DaygleError::Internal(format!("MiniLM hidden output: {e}")))?;
            let seq = shape[1] as usize;
            let dim = shape[2] as usize;
            let mut pooled = vec![0f32; dim];
            let mut weight = 0f32;
            for t in 0..seq {
                let token_weight = mask.get(t).copied().unwrap_or(0) as f32;
                for d in 0..dim {
                    pooled[d] += token_weight * data[t * dim + d];
                }
                weight += token_weight;
            }
            if weight <= 0.0 {
                return Err(DaygleError::Internal("MiniLM empty attention mask".into()));
            }
            for v in &mut pooled {
                *v /= weight;
            }
            let norm: f32 = pooled.iter().map(|v| v * v).sum::<f32>().sqrt();
            for v in &mut pooled {
                *v /= norm;
            }
            Ok(pooled)
        } else {
            Err(DaygleError::Internal(
                "MiniLM model exposes neither sentence_embedding nor last_hidden_state".into(),
            ))
        }
    }

    fn top_match(&self, embedding: &[f32]) -> Option<(String, f32)> {
        let dot = |a: &[f32], b: &[f32]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
        self.centroids
            .iter()
            .map(|(category, centroid)| (category.clone(), dot(embedding, centroid)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
    }
}

impl DomainClassifier for MiniLmVerifier {
    fn name(&self) -> &str {
        "minilm-onnx"
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        let text = if input.title.is_empty() && input.text.is_empty() {
            input.domain.clone()
        } else {
            format!("{} {} {}", input.domain, input.title, input.text)
        };
        let embedding = self.embed(&text).ok()?;
        let (category, cosine) = self.top_match(&embedding)?;
        if cosine < f32::EPSILON {
            return None;
        }
        Some(Verdict {
            category,
            confidence: cosine.clamp(0.0, 1.0),
            severity: Severity::Info,
            evidence: format!("MiniLM embedding cosine {cosine:.3}"),
        })
    }
}

/// Convenience constructor shared with the engine wiring.
pub fn load_verifier(
    settings: &daygle_dns_core::config::AiSettings,
) -> Result<Arc<MiniLmVerifier>> {
    Ok(Arc::new(MiniLmVerifier::load(
        &settings.verifier_model_path,
        Some(&settings.verifier_reference_path),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> MiniLmVerifier {
        let model = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/all-MiniLM-L6-v2-int8.onnx"
        );
        MiniLmVerifier::load(model, None).expect("bundled MiniLM verifier loads")
    }

    #[test]
    fn embeds_to_normalized_vector() {
        let v = verifier();
        let e = v.embed("www.pornhub.com").expect("embedding");
        assert_eq!(e.len(), 384);
        assert!(
            (e.iter().map(|x| x * x).sum::<f32>().sqrt() - 1.0).abs() < 1e-2,
            "embedding should be unit-norm"
        );
    }

    #[test]
    fn matches_trained_categories() {
        let v = verifier();
        for (domain, want) in [
            ("www.pornhub.com", "adult"),
            ("secure-account-login-verify.com", "phishing"),
            ("www.reuters.com", "news"),
            ("netflix.com", "streaming"),
        ] {
            let e = v.embed(domain).unwrap();
            let (cat, score) = v.top_match(&e).unwrap();
            println!("{domain} -> {cat} ({score:.3})");
            assert_eq!(cat, want, "{domain} should embed nearest '{want}'");
            assert!(score > 0.35, "{domain} cosine {score} too weak to verify");
        }
    }

    #[test]
    fn classify_via_domain_classifier() {
        let v = verifier();
        let verdict = v
            .classify(&ClassificationInput::domain_only("bet-casino-slots.win"))
            .expect("gambling-shaped domain hits a centroid above epsilon");
        assert_eq!(verdict.category, "gambling");
        assert_eq!(verdict.severity, Severity::Info);
    }

    #[test]
    fn engine_wires_primary_plus_verifier() {
        use crate::AiEngine;
        use daygle_dns_core::config::AiSettings;
        use daygle_dns_core::LogStore;
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().unwrap();
        let zones = Arc::new(
            daygle_dns_authoritative::ZoneStore::open(
                &dir.path().join("zones.db").display().to_string(),
            )
            .unwrap(),
        );
        let logs = Arc::new(LogStore::new(64));
        let engine = AiEngine::new(
            &AiSettings {
                enabled: true,
                model_path: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../models/daygle-starter.bin"
                )
                .into(),
                verifier_model_path: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../models/all-MiniLM-L6-v2-int8.onnx"
                )
                .into(),
                ..AiSettings::default()
            },
            &dir.path().join("daygle.db").display().to_string(),
            zones,
            logs.clone(),
        )
        .expect("primary + verifying backend compose into the engine");

        // The verifier reported itself as active...
        assert!(
            logs.entries()
                .iter()
                .any(|e| e.component == "ai" && e.message.contains("AI verifier active")),
            "expected an Info log noting the verifier"
        );
        // ...and the engine stays fully functional.
        engine
            .set_allow_override("allow.example.com", "wiring test")
            .unwrap();
    }

    #[test]
    fn engine_degrades_gracefully_when_verifier_model_is_missing() {
        use crate::AiEngine;
        use daygle_dns_core::config::AiSettings;
        use daygle_dns_core::LogStore;
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().unwrap();
        let zones = Arc::new(
            daygle_dns_authoritative::ZoneStore::open(
                &dir.path().join("zones.db").display().to_string(),
            )
            .unwrap(),
        );
        let logs = Arc::new(LogStore::new(64));
        AiEngine::new(
            &AiSettings {
                enabled: true,
                model_path: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../models/daygle-starter.bin"
                )
                .into(),
                verifier_model_path: "/definitely/not/a/real/model.onnx".into(),
                ..AiSettings::default()
            },
            &dir.path().join("daygle.db").display().to_string(),
            zones,
            logs.clone(),
        )
        .expect("verifier load failure degrades instead of failing the engine");
        assert!(
            logs.entries()
                .iter()
                .any(|e| e.component == "ai" && e.message.contains("MiniLM verifier not loaded")),
            "expected a Warn log about the failed verifier load"
        );
    }
}
