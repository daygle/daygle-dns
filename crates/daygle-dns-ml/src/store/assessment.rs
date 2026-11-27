//! Assessment records: signal observations, calibration maps, atomic
//! candidate versions and the graduated-authority ledger.
//!
//! These are the tables behind [`crate::assessment`], [`crate::calibration`],
//! [`crate::candidate`] and [`crate::authority`]. Keeping them beside the
//! verdicts (one database, one writer) means a scan's verdict, its
//! observations and its calibrated score commit from the same process and are
//! read by the API from the same file.

use rusqlite::{params, Connection, OptionalExtension};

use daygle_dns_core::config::FusionMode;
use daygle_dns_core::error::{DaygleError, Result};

use super::{now_epoch, AiStore};
use crate::assessment::{score_of_record, AssessmentScore, SignalObservation};
use crate::calibration::{CalibrationMap, Metrics};
use crate::fusion::{self, SignalWeights};

pub(super) const TABLES: &str = "
CREATE TABLE IF NOT EXISTS ai_signal_observations (
    domain       TEXT NOT NULL,
    channel      TEXT NOT NULL,
    observed_at  INTEGER NOT NULL,
    observations TEXT NOT NULL,
    PRIMARY KEY (domain, channel)
);
CREATE TABLE IF NOT EXISTS ai_calibrations (
    version      TEXT PRIMARY KEY,
    method       TEXT NOT NULL,
    points       TEXT NOT NULL,
    source_model TEXT NOT NULL,
    fitted_on    INTEGER NOT NULL,
    fitted_at    INTEGER NOT NULL,
    metrics      TEXT NOT NULL DEFAULT '',
    active       INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_model_artifacts (
    sha256     TEXT PRIMARY KEY,
    path       TEXT NOT NULL DEFAULT '',
    size       INTEGER NOT NULL,
    bytes      BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_candidates (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    version             TEXT NOT NULL UNIQUE,
    status              TEXT NOT NULL DEFAULT 'candidate',
    model_path          TEXT NOT NULL DEFAULT '',
    model_sha256        TEXT NOT NULL DEFAULT '',
    model_size          INTEGER NOT NULL DEFAULT 0,
    block_threshold     REAL NOT NULL,
    calibration_version TEXT NOT NULL DEFAULT '',
    calibration         TEXT NOT NULL DEFAULT '',
    signal_weights      TEXT NOT NULL DEFAULT '',
    scoring_config      TEXT NOT NULL DEFAULT '',
    validation_report   TEXT NOT NULL DEFAULT '',
    metrics             TEXT NOT NULL DEFAULT '',
    superseded_id       INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    promoted_at         INTEGER NOT NULL DEFAULT 0,
    rolled_back_at      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_authority (
    source         TEXT PRIMARY KEY,
    stage          TEXT NOT NULL,
    false_positives INTEGER NOT NULL DEFAULT 0,
    true_positives INTEGER NOT NULL DEFAULT 0,
    demoted_at     INTEGER NOT NULL DEFAULT 0,
    updated_at     INTEGER NOT NULL
);
";

/// Add the verdict columns the assessment layer needs. Existing rows keep 0
/// and an empty version, which the gate reads as "use the confidence": a
/// database from before calibration behaves exactly as it did.
pub(super) fn upgrade(conn: &Connection) -> rusqlite::Result<()> {
    let has_column = |name: &str| -> rusqlite::Result<bool> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_verdicts') WHERE name = ?1)",
            params![name],
            |r| r.get(0),
        )
    };
    // The fusion mode whose assessment score is stored on the row. A row whose
    // stored assessment differs from its confidence was scored by fusion in
    // `decide` mode (the other modes store the confidence itself), so recording
    // that keeps it read by the same rule after the upgrade. Rows where the two
    // agree read the same under either mode. The column is added before the
    // assessment columns on a database older than them, where there is nothing
    // to backfill.
    //
    // A zero assessment is a real score - fusion clamps to the 0-1 range - so
    // a positive score alone would leave such a row reading its confidence and
    // keep blocking on it. A zero cannot be told from a row the assessment
    // layer never touched by value, so it counts only when the observations
    // recorded beside an assessment are there; a database older than the
    // assessment columns keeps every row at the default zero and must not be
    // read as decided.
    if !has_column("assessment_mode")? {
        conn.execute(
            "ALTER TABLE ai_verdicts ADD COLUMN assessment_mode TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        if has_column("assessment_score")? {
            conn.execute(
                "UPDATE ai_verdicts SET assessment_mode = 'decide'
                 WHERE abs(assessment_score - confidence) > 0.000001
                   AND (assessment_score > 0 OR EXISTS (
                       SELECT 1 FROM ai_signal_observations o
                       WHERE o.domain = ai_verdicts.domain
                         AND o.channel = ai_verdicts.channel
                   ))",
                [],
            )?;
        }
    }
    if !has_column("calibrated_score")? {
        conn.execute(
            "ALTER TABLE ai_verdicts ADD COLUMN calibrated_score REAL NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_column("calibration_version")? {
        conn.execute(
            "ALTER TABLE ai_verdicts ADD COLUMN calibration_version TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !has_column("fusion_score")? {
        conn.execute(
            "ALTER TABLE ai_verdicts ADD COLUMN fusion_score REAL NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_column("assessment_score")? {
        conn.execute(
            "ALTER TABLE ai_verdicts ADD COLUMN assessment_score REAL NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

/// One stored calibration map.
#[derive(Debug, Clone)]
pub struct CalibrationRecord {
    pub map: CalibrationMap,
    pub metrics: Option<Metrics>,
    pub active: bool,
    pub created_at: i64,
}

/// A candidate version about to be recorded.
pub struct NewCandidate {
    pub version: String,
    pub model_path: String,
    pub model_sha256: String,
    pub model_size: i64,
    pub block_threshold: f32,
    pub calibration: Option<CalibrationMap>,
    pub signal_weights: SignalWeights,
    pub scoring_config: serde_json::Value,
    pub validation_report: serde_json::Value,
    pub metrics: Option<Metrics>,
}

/// A complete scoring-system version: the model artifact, the threshold, the
/// calibration map, the signal weights, the scoring configuration and the
/// validation report that justified it.
#[derive(Debug, Clone)]
pub struct CandidateVersion {
    pub id: i64,
    /// Content hash over the whole payload, not a counter.
    pub version: String,
    /// `candidate`, `active`, `superseded` or `rolled_back`.
    pub status: String,
    pub model_path: String,
    pub model_sha256: String,
    pub model_size: i64,
    pub block_threshold: f32,
    pub calibration_version: String,
    pub calibration: Option<CalibrationMap>,
    pub signal_weights: SignalWeights,
    pub scoring_config: serde_json::Value,
    pub validation_report: serde_json::Value,
    pub metrics: Option<Metrics>,
    /// The candidate active when this one was promoted: what a rollback
    /// restores.
    pub superseded_id: i64,
    pub created_at: i64,
    pub promoted_at: i64,
    pub rolled_back_at: i64,
}

impl CandidateVersion {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// One source's graduated authority.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityRow {
    /// `feed`, `operator` or `model`.
    pub source: String,
    /// `monitor`, `propose` or `enforce`.
    pub stage: String,
    pub false_positives: i64,
    pub true_positives: i64,
    pub demoted_at: i64,
    pub updated_at: i64,
}

const CANDIDATE_COLUMNS: &str = "id, version, status, model_path, model_sha256, model_size, \
     block_threshold, calibration_version, calibration, signal_weights, scoring_config, \
     validation_report, metrics, superseded_id, created_at, promoted_at, rolled_back_at";

fn candidate_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateVersion> {
    let weights: String = r.get(9)?;
    let calibration: String = r.get(8)?;
    let report: String = r.get(11)?;
    let config: String = r.get(10)?;
    let metrics: String = r.get(12)?;
    Ok(CandidateVersion {
        id: r.get(0)?,
        version: r.get(1)?,
        status: r.get(2)?,
        model_path: r.get(3)?,
        model_sha256: r.get(4)?,
        model_size: r.get(5)?,
        block_threshold: r.get(6)?,
        calibration_version: r.get(7)?,
        calibration: CalibrationMap::from_json(&calibration),
        signal_weights: serde_json::from_str(&weights).unwrap_or_default(),
        scoring_config: serde_json::from_str(&config).unwrap_or(serde_json::Value::Null),
        validation_report: serde_json::from_str(&report).unwrap_or(serde_json::Value::Null),
        metrics: serde_json::from_str(&metrics).ok(),
        superseded_id: r.get(13)?,
        created_at: r.get(14)?,
        promoted_at: r.get(15)?,
        rolled_back_at: r.get(16)?,
    })
}

impl AiStore {
    /// Record the observations behind one verdict, replacing the previous
    /// set: they describe the verdict that is stored now.
    pub fn save_observations(
        &self,
        domain: &str,
        channel: &str,
        observed_at: i64,
        observations: &[SignalObservation],
    ) -> Result<()> {
        let json = serde_json::to_string(observations)
            .map_err(|e| DaygleError::Database(format!("cannot encode observations: {e}")))?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_signal_observations (domain, channel, observed_at, observations)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(domain, channel) DO UPDATE
             SET observed_at = ?3, observations = ?4",
            params![domain, channel, observed_at, json],
        )?;
        Ok(())
    }

    /// The observations stored for a verdict.
    pub fn observations(
        &self,
        domain: &str,
        channel: &str,
    ) -> Result<Option<(i64, Vec<SignalObservation>)>> {
        let conn = self.lock()?;
        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT observed_at, observations FROM ai_signal_observations
                 WHERE domain = ?1 AND channel = ?2",
                params![domain, channel],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(at, json)| {
            serde_json::from_str(&json)
                .ok()
                .map(|observations| (at, observations))
        }))
    }

    /// Store one verdict's score of record: the calibrated score when a map was
    /// in force, the assessment score it was computed from, the fused view, and
    /// the fusion mode that produced them. The gate compares this; recording the
    /// mode is what stops a verdict scored under another mode being read as if
    /// the current one had produced it.
    pub fn save_assessment(
        &self,
        domain: &str,
        channel: &str,
        fusion: FusionMode,
        score: &AssessmentScore,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE ai_verdicts
             SET calibrated_score = ?3, calibration_version = ?4, fusion_score = ?5,
                 assessment_score = ?6, assessment_mode = ?7
             WHERE domain = ?1 AND channel = ?2",
            params![
                domain,
                channel,
                score.calibrated.unwrap_or(0.0),
                score.calibration_version.as_str(),
                score.fused.unwrap_or(0.0),
                score.assessment,
                fusion.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Re-score every classified threat verdict under `fusion`, from the
    /// observations stored beside it: the score of record is a function of the
    /// mode, so a stored score describes the mode that produced it and must be
    /// rewritten when that changes. A verdict whose observations are gone has no
    /// fused score: it keeps its confidence (what it was compared by before
    /// fusion) rather than becoming a zero, and is recorded under the current
    /// mode so it is not read as a decided one. One transaction.
    pub fn rescore_assessments(
        &self,
        fusion: FusionMode,
        weights: &SignalWeights,
        calibration: Option<&CalibrationMap>,
    ) -> Result<usize> {
        let mut conn = self.lock()?;
        let rows: Vec<(String, f32, Option<String>)> = {
            let mut stmt = conn.prepare(
                "SELECT v.domain, v.confidence, o.observations
                 FROM ai_verdicts v
                 LEFT JOIN ai_signal_observations o
                   ON o.domain = v.domain AND o.channel = v.channel
                 WHERE v.channel = 'threat' AND v.status = 'classified'",
            )?;
            let collected = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, f64>(1)? as f32,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            collected
        };
        let tx = conn.transaction()?;
        let mut written = 0usize;
        {
            let mut update = tx.prepare(
                "UPDATE ai_verdicts
                 SET calibrated_score = ?2, calibration_version = ?3, fusion_score = ?4,
                     assessment_score = ?5, assessment_mode = ?6
                 WHERE domain = ?1 AND channel = 'threat'",
            )?;
            for (domain, confidence, observations) in &rows {
                let observations: Vec<SignalObservation> = observations
                    .as_deref()
                    .and_then(|json| serde_json::from_str(json).ok())
                    .unwrap_or_default();
                let fused = (fusion != FusionMode::Off && !observations.is_empty())
                    .then(|| fusion::fuse(&observations, weights));
                let score = score_of_record(fusion, *confidence, fused.as_ref(), calibration);
                written += update.execute(params![
                    domain,
                    score.calibrated.unwrap_or(0.0),
                    score.calibration_version.as_str(),
                    score.fused.unwrap_or(0.0),
                    score.assessment,
                    fusion.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(written)
    }

    /// What the assessment stored beside one verdict: `(calibrated score,
    /// calibration version, fused score)`. `None` when the verdict has no
    /// row.
    pub fn verdict_scores(
        &self,
        domain: &str,
        channel: &str,
    ) -> Result<Option<(f32, String, f32)>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT calibrated_score, calibration_version, fusion_score
                 FROM ai_verdicts WHERE domain = ?1 AND channel = ?2",
                params![domain, channel],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Record a calibration map. Recording never activates it.
    pub fn save_calibration(
        &self,
        map: &CalibrationMap,
        metrics: Option<&Metrics>,
    ) -> Result<bool> {
        let metrics = metrics
            .map(|m| serde_json::to_string(m).unwrap_or_default())
            .unwrap_or_default();
        let conn = self.lock()?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO ai_calibrations
                (version, method, points, source_model, fitted_on, fitted_at, metrics, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                map.version,
                format!("{:?}", map.method).to_ascii_lowercase(),
                serde_json::to_string(&map.points).unwrap_or_else(|_| "[]".to_string()),
                map.source_model,
                map.fitted_on as i64,
                map.fitted_at,
                metrics,
                now_epoch(),
            ],
        )?;
        Ok(inserted > 0)
    }

    /// Every recorded calibration map, newest first.
    pub fn calibrations(&self, limit: u32) -> Result<Vec<CalibrationRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT version, method, points, source_model, fitted_on, fitted_at, metrics,
                    active, created_at
             FROM ai_calibrations ORDER BY created_at DESC, version LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 200)], |r| {
                let points: String = r.get(2)?;
                let metrics: String = r.get(6)?;
                Ok(CalibrationRecord {
                    map: CalibrationMap {
                        version: r.get(0)?,
                        method: match r.get::<_, String>(1)?.as_str() {
                            "isotonic" => crate::calibration::Method::Isotonic,
                            _ => crate::calibration::Method::Identity,
                        },
                        points: serde_json::from_str(&points).unwrap_or_default(),
                        source_model: r.get(3)?,
                        fitted_on: r.get::<_, i64>(4)? as usize,
                        fitted_at: r.get(5)?,
                        metrics: serde_json::from_str(&metrics).ok(),
                    },
                    metrics: serde_json::from_str(&metrics).ok(),
                    active: r.get(7)?,
                    created_at: r.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The calibration map in force, if any.
    pub fn active_calibration(&self) -> Result<Option<CalibrationMap>> {
        let conn = self.lock()?;
        let row: Option<String> = conn
            .query_row(
                "SELECT version FROM ai_calibrations WHERE active = 1
                 ORDER BY created_at DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(version) = row else {
            return Ok(None);
        };
        let record: Option<String> = conn
            .query_row(
                "SELECT points FROM ai_calibrations WHERE version = ?1",
                params![version],
                |r| r.get(0),
            )
            .optional()?;
        let Some(points) = record else {
            return Ok(None);
        };
        let method: String = conn.query_row(
            "SELECT method FROM ai_calibrations WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        let source_model: String = conn.query_row(
            "SELECT source_model FROM ai_calibrations WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        let fitted_on: i64 = conn.query_row(
            "SELECT fitted_on FROM ai_calibrations WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        let fitted_at: i64 = conn.query_row(
            "SELECT fitted_at FROM ai_calibrations WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        let metrics: String = conn.query_row(
            "SELECT metrics FROM ai_calibrations WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        Ok(Some(CalibrationMap {
            version,
            method: if method == "isotonic" {
                crate::calibration::Method::Isotonic
            } else {
                crate::calibration::Method::Identity
            },
            points: serde_json::from_str(&points).unwrap_or_default(),
            source_model,
            fitted_on: fitted_on as usize,
            fitted_at,
            metrics: serde_json::from_str(&metrics).ok(),
        }))
    }

    /// Put `version` in force, or clear the active map when `None`. Only one
    /// map is ever active.
    pub fn activate_calibration(&self, version: Option<&str>) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("UPDATE ai_calibrations SET active = 0", [])?;
        if let Some(version) = version {
            let changed = conn.execute(
                "UPDATE ai_calibrations SET active = 1 WHERE version = ?1",
                params![version],
            )?;
            if changed == 0 {
                return Err(DaygleError::NotFound(format!(
                    "no calibration map {version}"
                )));
            }
        }
        Ok(())
    }

    /// Keep the bytes of a model artifact, keyed by their hash, so a rollback
    /// restores the model itself and not a name for it.
    pub fn store_model_artifact(&self, path: &str, bytes: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        let sha = crate::candidate::hex(&Sha256::digest(bytes));
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO ai_model_artifacts (sha256, path, size, bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sha, path, bytes.len() as i64, bytes, now_epoch()],
        )?;
        Ok(sha)
    }

    /// The stored bytes of a model artifact.
    pub fn model_artifact(&self, sha256: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT bytes FROM ai_model_artifacts WHERE sha256 = ?1",
                params![sha256],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Record a candidate version. Nothing is promoted.
    pub fn save_candidate(&self, candidate: &NewCandidate) -> Result<CandidateVersion> {
        let calibration = candidate
            .calibration
            .as_ref()
            .map(|c| c.to_json())
            .unwrap_or_default();
        let calibration_version = candidate
            .calibration
            .as_ref()
            .map(|c| c.version.clone())
            .unwrap_or_default();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_candidates
                (version, model_path, model_sha256, model_size, block_threshold,
                 calibration_version, calibration, signal_weights, scoring_config,
                 validation_report, metrics, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                candidate.version,
                candidate.model_path,
                candidate.model_sha256,
                candidate.model_size,
                candidate.block_threshold,
                calibration_version,
                calibration,
                serde_json::to_string(&candidate.signal_weights).unwrap_or_default(),
                candidate.scoring_config.to_string(),
                candidate.validation_report.to_string(),
                candidate
                    .metrics
                    .as_ref()
                    .map(|m| serde_json::to_string(m).unwrap_or_default())
                    .unwrap_or_default(),
                now_epoch(),
            ],
        )?;
        let id = conn.last_insert_rowid();
        let found = conn
            .query_row(
                &format!("SELECT {CANDIDATE_COLUMNS} FROM ai_candidates WHERE id = ?1"),
                params![id],
                candidate_row,
            )
            .optional()?;
        found.ok_or_else(|| {
            DaygleError::Database("the candidate disappeared after it was recorded".to_string())
        })
    }

    pub fn candidate(&self, id: i64) -> Result<Option<CandidateVersion>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!("SELECT {CANDIDATE_COLUMNS} FROM ai_candidates WHERE id = ?1"),
                params![id],
                candidate_row,
            )
            .optional()?)
    }

    pub fn candidates(&self, limit: u32) -> Result<Vec<CandidateVersion>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {CANDIDATE_COLUMNS} FROM ai_candidates ORDER BY id DESC LIMIT ?1"
        ))?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 100)], candidate_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn active_candidate(&self) -> Result<Option<CandidateVersion>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {CANDIDATE_COLUMNS} FROM ai_candidates
                     WHERE status = 'active' ORDER BY promoted_at DESC LIMIT 1"
                ),
                [],
                candidate_row,
            )
            .optional()?)
    }

    /// Promote a candidate as one version: every other active candidate is
    /// superseded, the calibration map that travels with it is activated (or
    /// cleared when it has none), and the candidate it replaces is recorded so
    /// a rollback finds it. The rows change in one transaction; the caller
    /// then restores the artifact and publishes the threshold.
    pub fn promote_candidate(&self, id: i64) -> Result<CandidateVersion> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT id FROM ai_candidates WHERE status = 'active' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let now = now_epoch();
        let changed = tx.execute(
            "UPDATE ai_candidates SET status = 'active', promoted_at = ?1,
                 rolled_back_at = 0, superseded_id = ?2
             WHERE id = ?3 AND status IN ('candidate', 'superseded', 'rolled_back')",
            params![now, previous.unwrap_or(0), id],
        )?;
        if changed == 0 {
            return Err(DaygleError::AlreadyExists(format!(
                "candidate {id} is already active or does not exist"
            )));
        }
        if let Some(previous) = previous.filter(|p| *p != id) {
            tx.execute(
                "UPDATE ai_candidates SET status = 'superseded' WHERE id = ?1",
                params![previous],
            )?;
        }
        let found = tx
            .query_row(
                &format!("SELECT {CANDIDATE_COLUMNS} FROM ai_candidates WHERE id = ?1"),
                params![id],
                candidate_row,
            )
            .optional()?;
        let Some(candidate) = found else {
            return Err(DaygleError::Database(
                "the candidate disappeared during promotion".to_string(),
            ));
        };
        tx.execute("UPDATE ai_calibrations SET active = 0", [])?;
        if !candidate.calibration_version.is_empty() {
            tx.execute(
                "UPDATE ai_calibrations SET active = 1 WHERE version = ?1",
                params![candidate.calibration_version],
            )?;
        }
        tx.commit()?;
        Ok(candidate)
    }

    /// Roll back the active candidate to the one it replaced. Returns the
    /// candidate now active, including its stored calibration map; the caller
    /// restores the artifact bytes and the threshold that travel with it.
    pub fn rollback_active_candidate(&self) -> Result<Option<CandidateVersion>> {
        let Some(active) = self.active_candidate()? else {
            return Ok(None);
        };
        if active.superseded_id == 0 {
            return Ok(None);
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let now = now_epoch();
        tx.execute(
            "UPDATE ai_candidates SET status = 'rolled_back', rolled_back_at = ?1 WHERE id = ?2",
            params![now, active.id],
        )?;
        tx.execute(
            "UPDATE ai_candidates SET status = 'active', promoted_at = ?1, rolled_back_at = 0
             WHERE id = ?2",
            params![now, active.superseded_id],
        )?;
        let found = tx
            .query_row(
                &format!("SELECT {CANDIDATE_COLUMNS} FROM ai_candidates WHERE id = ?1"),
                params![active.superseded_id],
                candidate_row,
            )
            .optional()?;
        let Some(restored) = found else {
            return Err(DaygleError::Database(
                "the candidate to restore disappeared".to_string(),
            ));
        };
        tx.execute("UPDATE ai_calibrations SET active = 0", [])?;
        if !restored.calibration_version.is_empty() {
            tx.execute(
                "UPDATE ai_calibrations SET active = 1 WHERE version = ?1",
                params![restored.calibration_version],
            )?;
        }
        tx.commit()?;
        Ok(Some(restored))
    }

    /// Record one source's authority stage.
    pub fn set_authority_stage(&self, source: &str, stage: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_authority (source, stage, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(source) DO UPDATE SET stage = ?2, updated_at = ?3",
            params![source, stage, now_epoch()],
        )?;
        Ok(())
    }

    /// Record measured outcomes for one source, demoting it when its
    /// false-positive performance has deteriorated.
    #[allow(clippy::too_many_arguments)]
    pub fn record_authority_outcome(
        &self,
        source: &str,
        stage: &str,
        false_positives: i64,
        true_positives: i64,
        demoted: bool,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_authority
                (source, stage, false_positives, true_positives, demoted_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(source) DO UPDATE
             SET stage = ?2, false_positives = ?3, true_positives = ?4,
                 demoted_at = CASE WHEN ?5 > 0 THEN ?5 ELSE demoted_at END,
                 updated_at = ?6",
            params![
                source,
                stage,
                false_positives,
                true_positives,
                if demoted { now_epoch() } else { 0 },
                now_epoch()
            ],
        )?;
        Ok(())
    }

    /// Measured outcomes per source, for graduated authority: how many of a
    /// source's stored threat findings the operator corrected as false
    /// positives (`allow` or `not_threat`), and how many stand. A relabel is
    /// the operator's own decision and is not counted as a false positive.
    pub fn authority_measurements(&self) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT CASE WHEN instr(v.evidence, ', listed by ') > 0
                         THEN 'feed' ELSE 'model' END AS source,
                    SUM(CASE WHEN EXISTS (
                        SELECT 1 FROM ai_overrides o
                        WHERE o.domain = v.domain AND o.action IN ('allow', 'not_threat')
                    ) THEN 1 ELSE 0 END) AS false_positives,
                    SUM(CASE WHEN EXISTS (
                        SELECT 1 FROM ai_overrides o
                        WHERE o.domain = v.domain AND o.action IN ('allow', 'not_threat')
                    ) THEN 0 ELSE 1 END) AS true_positives
             FROM ai_verdicts v
             WHERE v.channel = 'threat' AND v.status = 'classified'
               AND v.severity != 'disputed'
             GROUP BY source",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every source's authority, the tightest first.
    pub fn authority(&self) -> Result<Vec<AuthorityRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT source, stage, false_positives, true_positives, demoted_at, updated_at
             FROM ai_authority ORDER BY source",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AuthorityRow {
                    source: r.get(0)?,
                    stage: r.get(1)?,
                    false_positives: r.get(2)?,
                    true_positives: r.get(3)?,
                    demoted_at: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::SignalSource;
    use crate::assessment::{Direction, ObservationScope, Scope, SignalObservation};

    fn store() -> (tempfile::TempDir, AiStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        (dir, store)
    }

    fn observation() -> SignalObservation {
        SignalObservation::new(
            SignalSource::Model,
            Direction::Threat,
            Some(0.8),
            "the model scored it",
            1_700_000_000,
            ObservationScope {
                value: "bad.example".to_string(),
                kind: Scope::Hostname,
            },
        )
    }

    fn candidate(store: &AiStore, threshold: f32, calibration: Option<CalibrationMap>) -> i64 {
        let bytes = format!("model-bytes-{threshold}");
        let sha = store
            .store_model_artifact("/models/learned.bin", bytes.as_bytes())
            .unwrap();
        store
            .save_candidate(&NewCandidate {
                version: format!("cand-{}", (threshold * 1000.0) as i64),
                model_path: "/models/learned.bin".to_string(),
                model_sha256: sha,
                model_size: bytes.len() as i64,
                block_threshold: threshold,
                calibration,
                signal_weights: SignalWeights::default(),
                scoring_config: serde_json::json!({"fusion": "monitor"}),
                validation_report: serde_json::json!({"passed": true}),
                metrics: None,
            })
            .unwrap()
            .id
    }

    #[test]
    fn observations_are_replaced_with_the_verdict_they_describe() {
        let (_dir, store) = store();
        store
            .save_observations("bad.example", "threat", 1, &[observation()])
            .unwrap();
        let (at, rows) = store
            .observations("bad.example", "threat")
            .unwrap()
            .unwrap();
        assert_eq!(at, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, Some(0.8));

        store
            .save_observations("bad.example", "threat", 2, &[])
            .unwrap();
        let (at, rows) = store
            .observations("bad.example", "threat")
            .unwrap()
            .unwrap();
        assert_eq!(at, 2);
        assert!(rows.is_empty());
        assert!(store
            .observations("never.example", "threat")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_calibration_map_is_recorded_before_it_is_activated() {
        let (_dir, store) = store();
        let map = crate::calibration::fit(
            &vec![
                crate::calibration::Labelled {
                    score: 0.9,
                    threat: true,
                };
                40
            ]
            .into_iter()
            .chain((0..40).map(|_| crate::calibration::Labelled {
                score: 0.1,
                threat: false,
            }))
            .collect::<Vec<_>>(),
            "builtin",
            7,
        )
        .unwrap();
        assert!(store.save_calibration(&map, None).unwrap());
        assert!(store.active_calibration().unwrap().is_none());

        store.activate_calibration(Some(&map.version)).unwrap();
        let active = store.active_calibration().unwrap().unwrap();
        assert_eq!(active.version, map.version);
        assert_eq!(active.points, map.points);

        store.activate_calibration(None).unwrap();
        assert!(store.active_calibration().unwrap().is_none());
        assert!(store.activate_calibration(Some("missing")).is_err());
    }

    #[test]
    fn a_candidate_promotion_supersedes_the_previous_one() {
        let (_dir, store) = store();
        let first = candidate(&store, 0.99, None);
        let second = candidate(&store, 0.95, None);

        let promoted = store.promote_candidate(first).unwrap();
        assert!(promoted.is_active());
        assert_eq!(promoted.superseded_id, 0);
        assert_eq!(store.active_candidate().unwrap().unwrap().id, first);

        let promoted = store.promote_candidate(second).unwrap();
        assert_eq!(promoted.superseded_id, first);
        assert_eq!(promoted.block_threshold, 0.95);
        assert_eq!(
            store.candidate(first).unwrap().unwrap().status,
            "superseded"
        );
        // Promoting the one already active is not a second promotion.
        assert!(store.promote_candidate(second).is_err());
    }

    #[test]
    fn a_rollback_restores_the_previous_candidate_and_its_artifact() {
        let (_dir, store) = store();
        let first = candidate(&store, 0.99, None);
        let second = candidate(&store, 0.95, None);
        store.promote_candidate(first).unwrap();
        store.promote_candidate(second).unwrap();

        let restored = store.rollback_active_candidate().unwrap().unwrap();
        assert_eq!(restored.id, first);
        assert_eq!(restored.status, "active");
        assert_eq!(restored.block_threshold, 0.99);
        // The artifact is the actual model, not a version string.
        let bytes = store
            .model_artifact(&restored.model_sha256)
            .unwrap()
            .expect("the stored model");
        assert_eq!(bytes, b"model-bytes-0.99");
        assert_eq!(
            store.candidate(second).unwrap().unwrap().status,
            "rolled_back"
        );
        // Nothing before the first candidate to restore.
        assert!(store.rollback_active_candidate().unwrap().is_none());
    }

    #[test]
    fn a_candidate_carries_its_calibration_map_through_promotion_and_rollback() {
        let (_dir, store) = store();
        let samples: Vec<crate::calibration::Labelled> = (0..80)
            .map(|i| crate::calibration::Labelled {
                score: if i % 2 == 0 { 0.9 } else { 0.1 },
                threat: i % 2 == 0,
            })
            .collect();
        let map = crate::calibration::fit(&samples, "builtin", 9).unwrap();
        store.save_calibration(&map, None).unwrap();
        let first = candidate(&store, 0.99, None);
        let second = candidate(&store, 0.95, Some(map.clone()));
        store.promote_candidate(first).unwrap();
        assert!(store.active_calibration().unwrap().is_none());

        store.promote_candidate(second).unwrap();
        assert_eq!(
            store.active_calibration().unwrap().unwrap().version,
            map.version
        );

        let restored = store.rollback_active_candidate().unwrap().unwrap();
        assert_eq!(restored.id, first);
        assert!(
            store.active_calibration().unwrap().is_none(),
            "the previous version had no calibration"
        );
    }

    #[test]
    fn authority_records_each_source_and_a_demotion() {
        let (_dir, store) = store();
        store.set_authority_stage("model", "propose").unwrap();
        store
            .record_authority_outcome("model", "monitor", 4, 40, true)
            .unwrap();
        store.set_authority_stage("feed", "enforce").unwrap();
        let rows = store.authority().unwrap();
        assert_eq!(rows.len(), 2);
        let model = rows.iter().find(|r| r.source == "model").unwrap();
        assert_eq!(model.stage, "monitor");
        assert_eq!(model.false_positives, 4);
        assert!(model.demoted_at > 0);
        let feed = rows.iter().find(|r| r.source == "feed").unwrap();
        assert_eq!(feed.stage, "enforce");
    }
}
