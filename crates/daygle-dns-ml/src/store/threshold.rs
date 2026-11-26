//! Threshold trials: the record of every candidate the operator ran, so a
//! threshold that turned out too eager can be put back to the one recorded
//! beside the model it was tuned with.
//!
//! Each row holds the model version and the threshold as one candidate: the
//! number means nothing away from the model it was measured against. Rolling
//! back restores `base_threshold` and leaves the model alone (see
//! `POST /api/ai/threshold/rollback`).

use rusqlite::{params, OptionalExtension};

use daygle_dns_core::error::Result;

use super::AiStore;

pub(super) const TABLES: &str = "
CREATE TABLE IF NOT EXISTS ai_threshold_trials (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    model              TEXT NOT NULL,
    base_threshold     REAL NOT NULL,
    candidate          REAL NOT NULL,
    fpr_target         REAL NOT NULL,
    passed             INTEGER NOT NULL,
    report             TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    applied_at         INTEGER NOT NULL DEFAULT 0,
    rolled_back_at     INTEGER NOT NULL DEFAULT 0,
    restored_threshold REAL NOT NULL DEFAULT 0
);
";

/// One threshold trial as it was recorded.
#[derive(Debug, Clone)]
pub struct ThresholdTrial {
    pub id: i64,
    /// The live model's identity when the trial ran: `builtin`, or the model
    /// path with its stamp.
    pub model: String,
    /// The threshold in force when the trial ran, and what a rollback of this
    /// trial restores.
    pub base_threshold: f32,
    /// The threshold the trial chose by false-positive rate.
    pub candidate: f32,
    pub fpr_target: f32,
    /// Whether the candidate met the target on the tuning half *and* kept it
    /// on the held-out half. Only a passed trial can be applied.
    pub passed: bool,
    /// The full report: the four group rows and both halves' rates.
    pub report: serde_json::Value,
    pub created_at: i64,
    pub applied_at: i64,
    pub rolled_back_at: i64,
    /// The threshold the rollback put back (0 until one happened).
    pub restored_threshold: f32,
}

impl ThresholdTrial {
    /// Applied and not since rolled back: the threshold in the config is this
    /// trial's candidate.
    pub fn in_force(&self) -> bool {
        self.applied_at > 0 && self.rolled_back_at == 0
    }
}

/// A trial about to be recorded.
pub struct NewThresholdTrial {
    pub model: String,
    pub base_threshold: f32,
    pub candidate: f32,
    pub fpr_target: f32,
    pub passed: bool,
    pub report: String,
}

const COLUMNS: &str = "id, model, base_threshold, candidate, fpr_target, passed, report, \
                       created_at, applied_at, rolled_back_at, restored_threshold";

fn row(r: &rusqlite::Row) -> rusqlite::Result<ThresholdTrial> {
    let report: String = r.get(6)?;
    Ok(ThresholdTrial {
        id: r.get(0)?,
        model: r.get(1)?,
        base_threshold: r.get(2)?,
        candidate: r.get(3)?,
        fpr_target: r.get(4)?,
        passed: r.get(5)?,
        report: serde_json::from_str(&report).unwrap_or(serde_json::Value::Null),
        created_at: r.get(7)?,
        applied_at: r.get(8)?,
        rolled_back_at: r.get(9)?,
        restored_threshold: r.get(10)?,
    })
}

impl AiStore {
    /// Record a trial. Nothing is applied: the threshold stays as it was until
    /// the operator applies this trial.
    pub fn save_threshold_trial(&self, trial: &NewThresholdTrial) -> Result<ThresholdTrial> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_threshold_trials
                (model, base_threshold, candidate, fpr_target, passed, report, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                trial.model,
                trial.base_threshold,
                trial.candidate,
                trial.fpr_target,
                trial.passed,
                trial.report,
                super::now_epoch(),
            ],
        )?;
        let id = conn.last_insert_rowid();
        let found = conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM ai_threshold_trials WHERE id = ?1"),
                params![id],
                row,
            )
            .optional()?;
        found.ok_or_else(|| {
            daygle_dns_core::error::DaygleError::Database(
                "the threshold trial disappeared after it was recorded".to_string(),
            )
        })
    }

    /// Every trial, newest first.
    pub fn threshold_trials(&self, limit: u32) -> Result<Vec<ThresholdTrial>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM ai_threshold_trials ORDER BY id DESC LIMIT ?1"
        ))?;
        let collected = stmt
            .query_map(params![limit.clamp(1, 100)], row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }

    pub fn threshold_trial(&self, id: i64) -> Result<Option<ThresholdTrial>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM ai_threshold_trials WHERE id = ?1"),
                params![id],
                row,
            )
            .optional()?)
    }

    /// The trial whose candidate is in force, if one is.
    pub fn applied_threshold_trial(&self) -> Result<Option<ThresholdTrial>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM ai_threshold_trials
                     WHERE applied_at > 0 AND rolled_back_at = 0
                     ORDER BY applied_at DESC LIMIT 1"
                ),
                [],
                row,
            )
            .optional()?)
    }

    /// Mark a trial applied. A threshold can only be in force once, so any
    /// other trial still marked applied is rolled back onto its own base.
    pub fn mark_threshold_applied(&self, id: i64) -> Result<bool> {
        let conn = self.lock()?;
        let now = super::now_epoch();
        conn.execute(
            "UPDATE ai_threshold_trials
             SET rolled_back_at = ?1, restored_threshold = base_threshold
             WHERE applied_at > 0 AND rolled_back_at = 0 AND id <> ?2",
            params![now, id],
        )?;
        let changed = conn.execute(
            "UPDATE ai_threshold_trials SET applied_at = ?1, rolled_back_at = 0
             WHERE id = ?2 AND applied_at = 0",
            params![now, id],
        )?;
        Ok(changed > 0)
    }

    /// Roll a trial back: the threshold returns to the trial's own base, not
    /// to some later number, and the model is untouched. Returns the
    /// threshold to restore, or `None` when the trial was not in force.
    pub fn mark_threshold_rolled_back(&self, id: i64) -> Result<Option<f32>> {
        let conn = self.lock()?;
        let base: Option<f32> = conn
            .query_row(
                "SELECT base_threshold FROM ai_threshold_trials
                 WHERE id = ?1 AND applied_at > 0 AND rolled_back_at = 0",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(base) = base else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE ai_threshold_trials
             SET rolled_back_at = ?1, restored_threshold = ?2
             WHERE id = ?3",
            params![super::now_epoch(), base, id],
        )?;
        Ok(Some(base))
    }

    /// The threat verdicts that carry a model score, for a threshold trial:
    /// `(domain, threat_score)`, highest score first.
    pub fn scored_threats(&self, limit: u32) -> Result<Vec<(String, f32)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, threat_score FROM ai_verdicts
             WHERE channel = 'threat' AND status = 'classified' AND threat_score > 0
             ORDER BY threat_score DESC, domain LIMIT ?1",
        )?;
        let collected = stmt
            .query_map(params![limit.clamp(1, 200_000)], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, f32>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }
}
