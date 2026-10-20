//! Verdict storage: a small SQLite database dedicated to the AI subsystem.
//!
//! Keeping AI verdicts in a separate database file (rather than a table in
//! the authoritative zone store) has two reasons: the scanner writes in
//! bursts that should never contend with the DNS query log writer, and the
//! whole subsystem can be deleted/trained/rebuilt without touching serving
//! data. The layout:
//!
//! - `ai_verdicts` – one row per observed domain (UNIQUE), with category,
//!   severity, confidence, TTL metadata and observation counters.
//! - `ai_overrides` – operator vetoes: `allow` rows that the policy plugin
//!   honours over its own block snapshot (manual operator blocks go through
//!   the normal policy blocklist instead of this table).
//!
//! All timestamps are Unix epoch seconds so snapshot building compares plain
//! integers. The connection is mutex-guarded (rusqlite `Connection` is
//! `Send` but not `Sync`), matching `ZoneStore`'s pattern, so the store can
//! be shared between the scanner thread and the API handlers.

use std::sync::{Arc, Mutex};

use daygle_dns_core::error::{DaygleError, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// One stored verdict row.
#[derive(Debug, Clone)]
pub struct VerdictRow {
    pub domain: String,
    /// Category label; empty when no verdict yet (`status` explains).
    pub category: String,
    /// `info` or `threat` (empty when no verdict yet).
    pub severity: String,
    /// `pending`, `classified`, `skipped` (below confidence floor / no
    /// signal), or `stale` (verdict expired and is awaiting re-scan).
    pub status: String,
    pub confidence: f32,
    /// Backend that produced the verdict (`fasttext`, `heuristic`).
    pub backend: String,
    pub evidence: String,
    /// In how many scan cycles the domain showed up in the query log.
    pub observations: u32,
    /// Unix epoch seconds of the latest classification (0 when pending).
    pub classified_at: i64,
    /// Unix epoch seconds at which the verdict expires (0 when pending).
    pub expires_at: i64,
    /// The domain itself has an operator `allow` override (it is exempt).
    pub overridden: bool,
}

/// One operator override.
#[derive(Debug, Clone)]
pub struct OverrideRow {
    pub domain: String,
    pub action: String,
    pub reason: String,
    pub created_at: i64,
}

fn now_epoch() -> i64 {
    chrono::Utc::now().timestamp()
}

/// SQLite-backed verdict + override store for the AI subsystem.
pub struct AiStore {
    conn: Arc<Mutex<Connection>>,
}

impl AiStore {
    /// Open (creating tables if needed) the AI verdicts database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        // Parent directories: the default layout puts `ai.db` next to the
        // authoritative database, which may live in a fresh data dir.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(DaygleError::Io)?;
            }
        }
        let conn = Connection::open(path).map_err(|e| {
            DaygleError::Database(format!("cannot open AI store {}: {e}", path.display()))
        })?;
        // Scanner bursts are small and infrequent; WAL keeps readers (API)
        // unblocked while a verdict batch commits.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ai_verdicts (
                domain        TEXT PRIMARY KEY,
                category      TEXT NOT NULL DEFAULT '',
                severity      TEXT NOT NULL DEFAULT '',
                status        TEXT NOT NULL DEFAULT 'pending',
                confidence    REAL NOT NULL DEFAULT 0,
                backend       TEXT NOT NULL DEFAULT '',
                evidence      TEXT NOT NULL DEFAULT '',
                observations  INTEGER NOT NULL DEFAULT 0,
                classified_at INTEGER NOT NULL DEFAULT 0,
                expires_at    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ai_verdicts_status
                ON ai_verdicts (status);
            CREATE INDEX IF NOT EXISTS idx_ai_verdicts_expires
                ON ai_verdicts (expires_at);

            CREATE TABLE IF NOT EXISTS ai_overrides (
                domain     TEXT PRIMARY KEY,
                action     TEXT NOT NULL,
                reason     TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| DaygleError::Internal(format!("AI store lock poisoned: {e}")))
    }

    /// Record that `domain` was observed (bumping the observation counter)
    /// and create a pending row on first sight. Returns whether a *new*
    /// candidate appeared (an upsert touching an existing row is `false`).
    pub fn observe(&self, domain: &str) -> Result<bool> {
        let conn = self.lock()?;
        let existed = conn
            .query_row(
                "SELECT 1 FROM ai_verdicts WHERE domain = ?1",
                params![domain],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if existed {
            conn.execute(
                "UPDATE ai_verdicts SET observations = observations + 1 WHERE domain = ?1",
                params![domain],
            )?;
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO ai_verdicts (domain, observations) VALUES (?1, 1)",
            params![domain],
        )?;
        Ok(true)
    }

    /// Domains waiting for classification (new, re-queued after expiry, or
    /// left pending by an interrupted cycle), most-seen first.
    pub fn pending_domains(&self, limit: u32) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain FROM ai_verdicts WHERE status = 'pending'
             ORDER BY observations DESC, domain LIMIT ?1",
        )?;
        let collected = stmt
            .query_map(params![limit as i64], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }

    /// Persist a classification. `expires_after_secs = 0` records a verdict
    /// without an expiry (scanner verdicts always pass a TTL; only operator
    /// pins use 0).
    #[allow(clippy::too_many_arguments)]
    pub fn save_verdict(
        &self,
        domain: &str,
        category: &str,
        severity: &str,
        status: &str,
        confidence: f32,
        backend: &str,
        evidence: &str,
        expires_after_secs: i64,
    ) -> Result<()> {
        let now = now_epoch();
        let expires_at = if expires_after_secs > 0 {
            now + expires_after_secs
        } else {
            0
        };
        let conn = self.lock()?;
        conn.execute(
            "UPDATE ai_verdicts
             SET category = ?2, severity = ?3, status = ?4, confidence = ?5,
                 backend = ?6, evidence = ?7, classified_at = ?8, expires_at = ?9
             WHERE domain = ?1 AND status = 'pending'",
            params![
                domain, category, severity, status, confidence, backend, evidence, now, expires_at
            ],
        )?;
        Ok(())
    }

    /// Verdicts older than `until_epoch` are re-queued to `pending` so the
    /// next scan cycle re-classifies them (bounded by `limit` per call).
    /// Categories are cleared - a changed site must never inherit the old
    /// verdict; freshness is decided by a new classification, not a memory.
    pub fn expire_old(&self, until_epoch: i64, limit: u32) -> Result<usize> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain FROM ai_verdicts
             WHERE status IN ('classified', 'skipped')
               AND expires_at > 0 AND expires_at <= ?1
             LIMIT ?2",
        )?;
        let collected = stmt
            .query_map(params![until_epoch, limit as i64], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        drop(stmt);
        let mut requeued = 0usize;
        for domain in &collected {
            let changed = conn.execute(
                "UPDATE ai_verdicts SET status = 'pending', category = '', severity = '',
                     confidence = 0, evidence = ''
                 WHERE domain = ?1 AND status IN ('classified', 'skipped')",
                params![domain],
            )?;
            requeued += changed;
        }
        Ok(requeued)
    }

    /// Fresh (non-expired) classified verdicts at or above `threshold`, minus
    /// exact operator `allow` vetoes. The block snapshot narrows these to the
    /// auto-block categories and to domains no parent override exempts.
    pub fn fresh_blocked(
        &self,
        now_epoch: i64,
        threshold: f32,
    ) -> Result<Vec<(String, String, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, category, expires_at FROM ai_verdicts
             WHERE status = 'classified'
               AND confidence >= ?1 AND expires_at > ?2
               AND NOT EXISTS (
                   SELECT 1 FROM ai_overrides o
                   WHERE o.domain = ai_verdicts.domain AND o.action = 'allow'
               )
             ORDER BY expires_at",
        )?;
        let collected = stmt
            .query_map(params![threshold, now_epoch], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }

    /// Apply an operator override row (insert or replace).
    pub fn set_override(&self, domain: &str, action: &str, reason: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_overrides (domain, action, reason, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(domain) DO UPDATE
             SET action = ?2, reason = ?3, created_at = ?4",
            params![domain, action, reason, now_epoch()],
        )?;
        Ok(())
    }

    /// Clear an operator override; the AI verdict (if any) applies normally
    /// again. Returns whether one existed.
    pub fn clear_override(&self, domain: &str) -> Result<bool> {
        let conn = self.lock()?;
        Ok(conn.execute(
            "DELETE FROM ai_overrides WHERE domain = ?1",
            params![domain],
        )? > 0)
    }

    /// Every override, newest first.
    pub fn list_overrides(&self) -> Result<Vec<OverrideRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, action, reason, created_at FROM ai_overrides
             ORDER BY created_at DESC, domain",
        )?;
        let collected = stmt
            .query_map([], |r| {
                Ok(OverrideRow {
                    domain: r.get(0)?,
                    action: r.get(1)?,
                    reason: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }

    /// The domains with an `allow` override.
    pub fn allow_overrides(&self) -> Result<std::collections::HashSet<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT domain FROM ai_overrides WHERE action = 'allow'")?;
        let collected = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(collected)
    }

    /// Whether the domain has an `allow` override.
    pub fn is_overridden_allow(&self, domain: &str) -> Result<bool> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT 1 FROM ai_overrides WHERE domain = ?1 AND action = 'allow'",
                params![domain],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Paginated verdict list, most recently classified first (pending rows
    /// last), with an optional status filter and a domain substring search.
    /// Returns the page plus the total row count under the same filter.
    pub fn list_verdicts(
        &self,
        status: Option<&str>,
        search: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VerdictRow>, u64)> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 500);
        let offset = offset.min(u32::MAX - limit);
        let status = status.unwrap_or("").trim().to_string();
        // LIKE pattern with the wildcard characters escaped.
        let search = search
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{search}%");
        let filter = "(?1 = '' OR v.status = ?1) AND v.domain LIKE ?2 ESCAPE '\\'";
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM ai_verdicts v WHERE {filter}"),
            params![status, pattern],
            |r| r.get(0),
        )?;
        let mut stmt = conn.prepare(&format!(
            "SELECT v.domain, v.category, v.severity, v.status, v.confidence, v.backend,
                    v.evidence, v.observations, v.classified_at, v.expires_at,
                    EXISTS (SELECT 1 FROM ai_overrides o
                            WHERE o.domain = v.domain AND o.action = 'allow')
             FROM ai_verdicts v WHERE {filter}
             ORDER BY v.classified_at DESC, v.domain
             LIMIT {limit} OFFSET {offset}"
        ))?;
        let collected = stmt
            .query_map(params![status, pattern], |r| {
                Ok(VerdictRow {
                    domain: r.get(0)?,
                    category: r.get(1)?,
                    severity: r.get(2)?,
                    status: r.get(3)?,
                    confidence: r.get::<_, f64>(4)? as f32,
                    backend: r.get(5)?,
                    evidence: r.get(6)?,
                    observations: r.get::<_, i64>(7)? as u32,
                    classified_at: r.get(8)?,
                    expires_at: r.get(9)?,
                    overridden: r.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((collected, total as u64))
    }

    /// Per-status counts, for the status endpoint (missing statuses are absent).
    pub fn status_counts(&self) -> Result<Vec<(String, usize)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT status, COUNT(*) FROM ai_verdicts GROUP BY status")?;
        let collected = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }
}
