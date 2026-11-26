//! Threshold trials: the record of every candidate the operator ran, so a
//! threshold that turned out too eager can be put back to the one recorded
//! beside the model it was tuned with.
//!
//! Each row holds the model version and the threshold as one candidate: the
//! number means nothing away from the model it was measured against. Applying
//! also records the model that was live at that moment, because a retrain can
//! promote a different one between the trial and its application. Rolling
//! back restores `base_threshold` and leaves the model alone (see
//! `POST /api/ai/threshold/rollback`).

use rusqlite::{params, Connection, OptionalExtension};

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
    restored_threshold REAL NOT NULL DEFAULT 0,
    applied_model      TEXT NOT NULL DEFAULT ''
);
";

/// Add the columns a database from before this feature lacks.
pub(super) fn upgrade(conn: &Connection) -> rusqlite::Result<()> {
    let has: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_threshold_trials') \
         WHERE name = 'applied_model')",
        [],
        |r| r.get(0),
    )?;
    if !has {
        conn.execute(
            "ALTER TABLE ai_threshold_trials ADD COLUMN applied_model TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

/// One threshold trial as it was recorded.
#[derive(Debug, Clone)]
pub struct ThresholdTrial {
    pub id: i64,
    /// The live model's identity when the trial ran: `builtin`, or the model
    /// path with its stamp.
    pub model: String,
    /// The threshold in force when the trial was last applied, and what a
    /// rollback of this trial restores. A trial run against one threshold can
    /// be applied later, after the threshold moved, so this is the one it
    /// replaced rather than the one it was measured at.
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
    /// The model that was live when this trial was applied. A model promoted
    /// after the trial ran is a different candidate, so this is recorded at
    /// apply time rather than assumed from [`Self::model`]. Empty for a trial
    /// applied before the column existed.
    pub applied_model: String,
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
                       created_at, applied_at, rolled_back_at, restored_threshold, \
                       applied_model";

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
        applied_model: r.get(11)?,
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

    /// Mark a trial applied in place of `base`, the threshold it replaces,
    /// recording `model` as the model actually live at that moment. Only one
    /// threshold can be in force, so any other trial still marked applied is
    /// rolled back onto its own base. A trial that was rolled back can be
    /// applied again: the console offers that, and refusing it would leave a
    /// candidate that passed unreachable.
    pub fn mark_threshold_applied(&self, id: i64, base: f32, model: &str) -> Result<bool> {
        let conn = self.lock()?;
        let now = super::now_epoch();
        conn.execute(
            "UPDATE ai_threshold_trials
             SET rolled_back_at = ?1, restored_threshold = base_threshold
             WHERE applied_at > 0 AND rolled_back_at = 0 AND id <> ?2",
            params![now, id],
        )?;
        let changed = conn.execute(
            "UPDATE ai_threshold_trials
             SET applied_at = ?1, base_threshold = ?3, applied_model = ?4,
                 rolled_back_at = 0, restored_threshold = 0
             WHERE id = ?2 AND (applied_at = 0 OR rolled_back_at > 0)",
            params![now, id, base, model],
        )?;
        Ok(changed > 0)
    }

    /// Roll a trial back: the threshold returns to the trial's own base, not
    /// to some later number, and the model is untouched. Returns the
    /// threshold to restore and the model the trial was applied under, or
    /// `None` when the trial was not in force.
    pub fn mark_threshold_rolled_back(&self, id: i64) -> Result<Option<(f32, String)>> {
        let conn = self.lock()?;
        let base: Option<(f32, String)> = conn
            .query_row(
                "SELECT base_threshold, applied_model FROM ai_threshold_trials
                 WHERE id = ?1 AND applied_at > 0 AND rolled_back_at = 0",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((base, model)) = base else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE ai_threshold_trials
             SET rolled_back_at = ?1, restored_threshold = ?2
             WHERE id = ?3",
            params![super::now_epoch(), base, id],
        )?;
        Ok(Some((base, model)))
    }

    /// The scores a threshold trial is fitted on: `(domain, score)`,
    /// highest first. `score` is exactly the number `fresh_blocked` compares
    /// with `ai.block_threshold` (see [`Self::GATE_SCORE`]); reading
    /// `threat_score` here measured the model's raw opinion while enforcement
    /// ignored what the evidence stages added.
    pub fn gate_scores(&self, limit: u32) -> Result<Vec<(String, f32)>> {
        Ok(self
            .gate_samples(limit)?
            .into_iter()
            .map(|(domain, score, _)| (domain, score))
            .collect())
    }

    /// [`Self::gate_scores`] with the verdict's classification time, for the
    /// time-based evaluation and the label-provenance report.
    pub fn gate_samples(&self, limit: u32) -> Result<Vec<(String, f32, i64)>> {
        let conn = self.lock()?;
        // The same expression `fresh_blocked` compares: the calibrated score
        // when a map was in force for the verdict, else the confidence.
        let mut stmt = conn.prepare(
            "SELECT domain, COALESCE(NULLIF(calibrated_score, 0), confidence), classified_at
             FROM ai_verdicts
             WHERE channel = 'threat' AND status = 'classified'
               AND COALESCE(NULLIF(calibrated_score, 0), confidence) > 0
             ORDER BY COALESCE(NULLIF(calibrated_score, 0), confidence) DESC, domain LIMIT ?1",
        )?;
        let collected = stmt
            .query_map(params![limit.clamp(1, 200_000)], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, f32>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, AiStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = AiStore::open(&dir.path().join("ai.db")).unwrap();
        (dir, store)
    }

    fn trial(store: &AiStore, base: f32, candidate: f32) -> ThresholdTrial {
        store
            .save_threshold_trial(&NewThresholdTrial {
                model: "builtin".to_string(),
                base_threshold: base,
                candidate,
                fpr_target: 0.01,
                passed: true,
                report: "{}".to_string(),
            })
            .unwrap()
    }

    #[test]
    fn a_rolled_back_trial_can_be_applied_again() {
        let (_dir, store) = store();
        let first = trial(&store, 0.99, 0.96);

        assert!(store
            .mark_threshold_applied(first.id, 0.99, "builtin")
            .unwrap());
        assert!(store.threshold_trial(first.id).unwrap().unwrap().in_force());
        // Applying the one already in force is not a second application.
        assert!(!store
            .mark_threshold_applied(first.id, 0.99, "builtin")
            .unwrap());

        // Undo puts back the threshold the application replaced.
        assert_eq!(
            store
                .mark_threshold_rolled_back(first.id)
                .unwrap()
                .map(|(base, _)| base),
            Some(0.99)
        );
        assert!(!store.threshold_trial(first.id).unwrap().unwrap().in_force());

        // And it can go back in force, now replacing the 0.97 an operator set
        // in between, so undoing it again returns there and not to 0.99.
        assert!(store
            .mark_threshold_applied(first.id, 0.97, "builtin")
            .unwrap());
        let in_force = store.threshold_trial(first.id).unwrap().unwrap();
        assert!(in_force.in_force());
        assert!((in_force.base_threshold - 0.97).abs() < 1e-6);
        assert!((in_force.restored_threshold - 0.0).abs() < 1e-6);
        assert_eq!(
            store
                .mark_threshold_rolled_back(first.id)
                .unwrap()
                .map(|(base, _)| base),
            Some(0.97)
        );
    }

    /// The model live at apply time is what makes a candidate readable as one
    /// thing: the trial's own `model` is the one it was measured with, which a
    /// retrain may have replaced before the operator applied it.
    #[test]
    fn applying_records_the_model_that_was_live() {
        let (_dir, store) = store();
        let first = trial(&store, 0.99, 0.96);

        assert!(store
            .mark_threshold_applied(first.id, 0.99, "model-v14@1700000000:4096")
            .unwrap());
        let applied = store.threshold_trial(first.id).unwrap().unwrap();
        assert_eq!(applied.applied_model, "model-v14@1700000000:4096");
        // The model it was measured with is kept apart from the one applied.
        assert_eq!(applied.model, "builtin");

        // Rolling back returns the threshold and the model that went with it.
        assert_eq!(
            store.mark_threshold_rolled_back(first.id).unwrap(),
            Some((0.99, "model-v14@1700000000:4096".to_string()))
        );
        let undone = store.threshold_trial(first.id).unwrap().unwrap();
        assert_eq!(undone.applied_model, "model-v14@1700000000:4096");

        // A second application records the model live then, not the first.
        assert!(store
            .mark_threshold_applied(first.id, 0.99, "model-v15")
            .unwrap());
        assert_eq!(
            store
                .threshold_trial(first.id)
                .unwrap()
                .unwrap()
                .applied_model,
            "model-v15"
        );
    }

    /// The trial must read the number the gate compares. A row whose evidence
    /// raised its confidence above the model's own score is exactly where the
    /// two used to diverge.
    #[test]
    fn the_trial_reads_the_confidence_the_gate_compares() {
        let (_dir, store) = store();
        store.observe("age-raised.example").unwrap();
        store
            .save_verdicts(&[crate::store::NewVerdict {
                domain: "age-raised.example".to_string(),
                channel: crate::store::Channel::Threat,
                category: "phishing".to_string(),
                severity: "threat".to_string(),
                status: "classified".to_string(),
                confidence: 0.97,
                backend: "fasttext".to_string(),
                evidence: "raised because the domain is newly registered".to_string(),
                threat_score: 0.80,
                expires_after_secs: 3_600,
            }])
            .unwrap();

        assert_eq!(
            store.gate_scores(10).unwrap(),
            vec![("age-raised.example".to_string(), 0.97)]
        );
    }

    #[test]
    fn applying_one_trial_rolls_back_the_other() {
        let (_dir, store) = store();
        let first = trial(&store, 0.99, 0.96);
        let second = trial(&store, 0.99, 0.93);

        assert!(store
            .mark_threshold_applied(first.id, 0.99, "builtin")
            .unwrap());
        assert!(store
            .mark_threshold_applied(second.id, 0.96, "builtin")
            .unwrap());

        assert!(store.applied_threshold_trial().unwrap().unwrap().id == second.id);
        let undone = store.threshold_trial(first.id).unwrap().unwrap();
        assert!(!undone.in_force());
        assert!((undone.restored_threshold - 0.99).abs() < 1e-6);
        assert!(store
            .mark_threshold_rolled_back(first.id)
            .unwrap()
            .is_none());
    }
}
