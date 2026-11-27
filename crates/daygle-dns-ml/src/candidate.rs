//! Atomic candidate versions: the whole scoring system, promoted as one.
//!
//! A model version string is not enough to restore anything. A candidate
//! therefore holds, and carries through promotion and rollback:
//!
//! - the model artifact *bytes* (hashed and kept in `ai_model_artifacts`) and
//!   the path it belongs at;
//! - the block threshold;
//! - the calibration map (or none);
//! - the signal weights and the scoring configuration;
//! - the validation report and held-out metrics that justified it.
//!
//! The version is a hash over all of that, so two candidates with the same
//! model but a different threshold or calibration are different versions.
//! Promotion records the version it replaces; a rollback restores that
//! version's artifact bytes, threshold and calibration together, not just its
//! name.

use sha2::{Digest, Sha256};

use daygle_dns_core::error::{DaygleError, Result};

use crate::calibration::CalibrationMap;
use crate::fusion::SignalWeights;
use crate::store::{AiStore, CandidateVersion, NewCandidate};

/// Lowercase hex, for the content hashes that identify an artifact, a
/// calibration map or a candidate. `sha2`'s digest is a byte array, which has
/// no `LowerHex` of its own.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Everything a candidate version is made of.
pub struct CandidateSpec {
    pub model_path: String,
    pub block_threshold: f32,
    pub calibration: Option<CalibrationMap>,
    pub signal_weights: SignalWeights,
    pub scoring_config: serde_json::Value,
    pub validation_report: serde_json::Value,
    pub metrics: Option<crate::calibration::Metrics>,
}

/// The identity of a candidate: a hash of its whole payload, not a label.
pub fn version_of(
    model_sha256: &str,
    block_threshold: f32,
    calibration: Option<&CalibrationMap>,
    weights: &SignalWeights,
    scoring_config: &serde_json::Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"daygle-candidate-v1");
    hasher.update(model_sha256.as_bytes());
    hasher.update(block_threshold.to_le_bytes());
    hasher.update(
        calibration
            .map(|c| c.version.as_str())
            .unwrap_or("identity")
            .as_bytes(),
    );
    hasher.update(
        serde_json::to_string(weights)
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(scoring_config.to_string().as_bytes());
    let digest = hex(&hasher.finalize());
    digest[..32].to_string()
}

/// Read the model file, keep its bytes, and record the candidate. Nothing is
/// promoted: the candidate is a record until the operator promotes it.
pub fn build(store: &AiStore, spec: &CandidateSpec) -> Result<CandidateVersion> {
    let path = spec.model_path.trim().to_string();
    let (sha, size) = if path.is_empty() || !std::path::Path::new(&path).is_file() {
        // The heuristic backend has no artifact: its identity is its absence,
        // which the rollback restores by writing nothing.
        ("builtin".to_string(), 0)
    } else {
        let bytes = std::fs::read(&path).map_err(DaygleError::Io)?;
        let sha = store.store_model_artifact(&path, &bytes)?;
        (sha, bytes.len() as i64)
    };
    let version = version_of(
        &sha,
        spec.block_threshold,
        spec.calibration.as_ref(),
        &spec.signal_weights,
        &spec.scoring_config,
    );
    if let Some(calibration) = spec.calibration.as_ref() {
        store.save_calibration(calibration, spec.metrics.as_ref())?;
    }
    store.save_candidate(&NewCandidate {
        version,
        model_path: path,
        model_sha256: sha,
        model_size: size,
        block_threshold: spec.block_threshold,
        calibration: spec.calibration.clone(),
        signal_weights: spec.signal_weights.clone(),
        scoring_config: spec.scoring_config.clone(),
        validation_report: spec.validation_report.clone(),
        metrics: spec.metrics.clone(),
    })
}

/// Write a candidate's stored model bytes back to its path, atomically, and
/// verify the hash. Returns whether the artifact needed restoring (false for
/// the built-in heuristic).
pub fn restore_artifact(store: &AiStore, candidate: &CandidateVersion) -> Result<bool> {
    if candidate.model_sha256.is_empty() || candidate.model_sha256 == "builtin" {
        return Ok(false);
    }
    let bytes = store
        .model_artifact(&candidate.model_sha256)?
        .ok_or_else(|| {
            DaygleError::NotFound(format!(
                "candidate {} has no stored artifact for model {}",
                candidate.version, candidate.model_sha256
            ))
        })?;
    let actual = hex(&Sha256::digest(&bytes));
    if actual != candidate.model_sha256 {
        return Err(DaygleError::Config(format!(
            "the stored artifact for candidate {} does not match its hash",
            candidate.version
        )));
    }
    let path = std::path::Path::new(&candidate.model_path);
    if path.as_os_str().is_empty() {
        return Ok(false);
    }
    write_artifact(path, &bytes)?;
    Ok(true)
}

/// Write artifact bytes to `path` atomically - a temporary file beside it,
/// renamed into place - so a reader never sees half a model. Used by a restore
/// and by a promotion that has to put back the bytes it displaced.
pub fn write_artifact(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        tracing::warn!(path = %parent.display(), %error, "could not flush the restored model directory");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{CalibrationMap, Method};

    fn store() -> (tempfile::TempDir, AiStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        (dir, store)
    }

    fn spec(path: &std::path::Path, threshold: f32) -> CandidateSpec {
        CandidateSpec {
            model_path: path.to_string_lossy().into_owned(),
            block_threshold: threshold,
            calibration: None,
            signal_weights: SignalWeights::default(),
            scoring_config: serde_json::json!({"fusion": "monitor"}),
            validation_report: serde_json::json!({"brier": 0.1}),
            metrics: None,
        }
    }

    #[test]
    fn the_version_covers_the_whole_system_not_just_the_model() {
        let weights = SignalWeights::default();
        let config = serde_json::json!({"fusion": "monitor"});
        let base = version_of("sha-a", 0.99, None, &weights, &config);
        assert_eq!(base, version_of("sha-a", 0.99, None, &weights, &config));
        // A different threshold is a different version.
        assert_ne!(base, version_of("sha-a", 0.95, None, &weights, &config));
        // So is a different model or a calibration map.
        assert_ne!(base, version_of("sha-b", 0.99, None, &weights, &config));
        let mut map = CalibrationMap::identity("builtin", 1);
        map.method = Method::Isotonic;
        map.points = vec![(0.5, 0.4)];
        map.version = map.compute_version();
        assert_ne!(
            base,
            version_of("sha-a", 0.99, Some(&map), &weights, &config)
        );
    }

    #[test]
    fn a_candidate_keeps_the_actual_model_bytes() {
        let (dir, store) = store();
        let model = dir.path().join("model.bin");
        std::fs::write(&model, b"weights-and-labels").unwrap();
        let candidate = build(&store, &spec(&model, 0.99)).unwrap();
        assert_eq!(candidate.model_size, 18);
        assert_eq!(
            store
                .model_artifact(&candidate.model_sha256)
                .unwrap()
                .unwrap(),
            b"weights-and-labels"
        );

        // The live file changes, then a rollback puts the stored bytes back.
        std::fs::write(&model, b"a-different-model").unwrap();
        build(&store, &spec(&model, 0.95)).unwrap();
        let restored = restore_artifact(&store, &candidate).unwrap();
        assert!(restored);
        assert_eq!(std::fs::read(&model).unwrap(), b"weights-and-labels");
    }

    #[test]
    fn the_builtin_backend_has_no_artifact_to_restore() {
        let (_dir, store) = store();
        let candidate = build(&store, &spec(std::path::Path::new(""), 0.99)).unwrap();
        assert_eq!(candidate.model_sha256, "builtin");
        assert!(!restore_artifact(&store, &candidate).unwrap());
    }

    #[test]
    fn an_interrupted_restore_does_not_reuse_its_temporary_file() {
        let (dir, _store) = store();
        let model = dir.path().join("model.bin");
        let interrupted = model.with_extension("restore-tmp");
        std::fs::create_dir(&interrupted).unwrap();
        std::fs::write(&model, b"old model").unwrap();

        write_artifact(&model, b"replacement model").unwrap();

        assert_eq!(std::fs::read(&model).unwrap(), b"replacement model");
        assert!(interrupted.is_dir());
    }

    #[test]
    fn a_missing_artifact_cannot_be_restored_silently() {
        let (_dir, store) = store();
        let mut candidate = build(&store, &spec(std::path::Path::new(""), 0.99)).unwrap();
        candidate.model_sha256 = "0000".to_string();
        assert!(restore_artifact(&store, &candidate).is_err());
    }
}
