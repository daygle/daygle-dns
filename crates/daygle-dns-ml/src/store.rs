//! Verdict storage: a small SQLite database dedicated to the AI subsystem.
//!
//! Keeping AI verdicts in a separate database file (rather than a table in
//! the authoritative zone store) has two reasons: the scanner writes in
//! bursts that should never contend with the DNS query log writer, and the
//! whole subsystem can be deleted/trained/rebuilt without touching serving
//! data. The layout:
//!
//! - `ai_verdicts` - one row per observed domain *per channel* (PRIMARY KEY
//!   `(domain, channel)`), with category, severity, confidence, TTL metadata
//!   and observation counters. The categorizer and the threat detector are
//!   separate passes, so each keeps its own verdict, status, confidence and
//!   expiry for the same domain. A row not queried again since its verdict
//!   was made is dropped when the verdict expires (and comes back as new if
//!   it is queried later), so the table tracks the domains in use rather
//!   than every domain ever seen.
//! - `ai_overrides` - operator vetoes: `allow` rows that the policy plugin
//!   honours over its own block snapshot (manual operator blocks go through
//!   the normal policy blocklist instead of this table).
//! - `ai_category_overrides` - operator relabels: a domain's category as the
//!   operator set it. The scanner keeps its own verdict (and re-checks it),
//!   but the console shows this label and category blocking matches it.
//!
//! All timestamps are Unix epoch seconds so snapshot building compares plain
//! integers. The connection is mutex-guarded (rusqlite `Connection` is
//! `Send` but not `Sync`), matching `ZoneStore`'s pattern, so the store can
//! be shared between the scanner thread and the API handlers.

use std::sync::{Arc, Mutex};

use daygle_dns_core::error::{DaygleError, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::backend::Channel;

/// Filters shared by the paginated verdict and threat lists.
#[derive(Debug, Default)]
pub struct VerdictFilter<'a> {
    pub status: Option<&'a str>,
    pub category: Option<&'a str>,
    pub severity: Option<&'a str>,
    /// `exempt` or `not_exempt`.
    pub exemption: Option<&'a str>,
    pub search: Option<&'a str>,
    /// `content` or `threat`. `None` keeps the list's own default: the
    /// verdict list shows the categorization channel, the threat list the
    /// threat channel.
    pub channel: Option<&'a str>,
}

/// Page bounds for a paginated verdict or threat list.
#[derive(Debug, Clone, Copy)]
pub struct VerdictPage {
    pub limit: u32,
    pub offset: u32,
}

/// One stored verdict row.
#[derive(Debug, Clone)]
pub struct VerdictRow {
    pub domain: String,
    /// Which pass produced the row: `content` (categorization) or `threat`.
    pub channel: String,
    /// Category label; empty when no verdict yet (`status` explains).
    pub category: String,
    /// `info`, `threat`, or `disputed` (a threat the verifier disagreed
    /// with, never auto-blocked); empty when no verdict yet.
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
    /// The operator relabelled this domain: `category` is their label, not
    /// the model's.
    pub category_overridden: bool,
}

/// One classification to store (see [`AiStore::save_verdicts`]).
#[derive(Debug, Clone)]
pub struct NewVerdict {
    pub domain: String,
    /// The pass that produced it ([`Channel`]).
    pub channel: Channel,
    pub category: String,
    pub severity: String,
    /// `classified` or `skipped`.
    pub status: String,
    pub confidence: f32,
    pub backend: String,
    pub evidence: String,
    /// Seconds until the verdict expires (0: never).
    pub expires_after_secs: i64,
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

/// The verdict table: one row per domain per channel. Both channels classify
/// the same domain independently, each keeping its own category, status,
/// confidence and expiry.
const VERDICTS_TABLE: &str = "CREATE TABLE IF NOT EXISTS ai_verdicts (
    domain        TEXT NOT NULL,
    channel       TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    confidence    REAL NOT NULL DEFAULT 0,
    backend       TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    observations  INTEGER NOT NULL DEFAULT 0,
    classified_at INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER NOT NULL DEFAULT 0,
    last_seen     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain, channel)
)";

const OVERRIDES_TABLE: &str = "CREATE TABLE IF NOT EXISTS ai_overrides (
    domain     TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
)";

/// Operator category relabels: the model keeps classifying (and re-checking)
/// the domain; the console and category blocking use this label instead.
const CATEGORY_OVERRIDES_TABLE: &str = "CREATE TABLE IF NOT EXISTS ai_category_overrides (
    domain     TEXT PRIMARY KEY,
    category   TEXT NOT NULL,
    created_at INTEGER NOT NULL
)";

/// The columns every verdict query returns, in [`VerdictRow`] order.
const VERDICT_COLUMNS: &str = concat!(
    "v.domain, v.channel, ",
    // The operator's relabel wins over the model's label for display and
    // filtering; the model's own verdict is still stored and re-checked.
    // A relabel is a categorization decision: the threat channel's rows keep
    // the model's own label.
    "COALESCE((SELECT c.category FROM ai_category_overrides c ",
    "WHERE c.domain = v.domain AND v.channel = 'content'), v.category), ",
    "v.severity, v.status, v.confidence, ",
    "v.backend, v.evidence, v.observations, v.classified_at, v.expires_at, ",
    "EXISTS (SELECT 1 FROM ai_overrides o ",
    "WHERE o.domain = v.domain AND o.action = 'allow'), ",
    "EXISTS (SELECT 1 FROM ai_category_overrides c WHERE c.domain = v.domain)"
);

/// Map a row selected with [`VERDICT_COLUMNS`].
fn verdict_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<VerdictRow> {
    Ok(VerdictRow {
        domain: r.get(0)?,
        channel: r.get(1)?,
        category: r.get(2)?,
        severity: r.get(3)?,
        status: r.get(4)?,
        confidence: r.get::<_, f64>(5)? as f32,
        backend: r.get(6)?,
        evidence: r.get(7)?,
        observations: r.get::<_, i64>(8)? as u32,
        classified_at: r.get(9)?,
        expires_at: r.get(10)?,
        overridden: r.get(11)?,
        category_overridden: r.get(12)?,
    })
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
        let mut conn = Connection::open(path).map_err(|e| {
            DaygleError::Database(format!("cannot open AI store {}: {e}", path.display()))
        })?;
        // Scanner bursts are small and infrequent; WAL keeps readers (API)
        // unblocked while a verdict batch commits.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(&format!(
            "{VERDICTS_TABLE};\n{OVERRIDES_TABLE};\n{CATEGORY_OVERRIDES_TABLE};"
        ))?;
        let has_column = |name: &str| -> Result<bool> {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_verdicts') WHERE name = ?1)",
                params![name],
                |r| r.get(0),
            )?)
        };
        // When the domain was last seen in the query log. Rows from before
        // the column get the upgrade time, so each is checked once more.
        if !has_column("last_seen")? {
            conn.execute(
                "ALTER TABLE ai_verdicts ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
            conn.execute(
                "UPDATE ai_verdicts SET last_seen = ?1",
                params![now_epoch()],
            )?;
        }
        // Threats the verifier disputed used to be stored as plain `info`
        // verdicts, which the block snapshot did not tell apart.
        conn.execute(
            "UPDATE ai_verdicts SET severity = 'disputed'
             WHERE severity = 'info' AND evidence LIKE '%disagrees%: downgraded'",
            [],
        )?;
        // Upgrade from one row per domain to one row per domain and channel:
        // an existing verdict becomes the channel its severity implies, and
        // the other channel gets a pending row so the next cycle fills it in.
        // Nothing that was blocking stops blocking on upgrade.
        if !has_column("channel")? {
            // One transaction: SQLite DDL is transactional, so an interrupted
            // upgrade leaves the old table untouched instead of orphaning
            // verdicts in a half-renamed database.
            let tx = conn.transaction()?;
            tx.execute_batch(&format!(
                "ALTER TABLE ai_verdicts RENAME TO ai_verdicts_pre_channel;
                 {VERDICTS_TABLE};
                 INSERT INTO ai_verdicts
                     (domain, channel, category, severity, status, confidence,
                      backend, evidence, observations, classified_at, expires_at,
                      last_seen)
                 SELECT domain,
                        CASE WHEN severity IN ('threat', 'disputed') THEN 'threat'
                             ELSE 'content' END,
                        category, severity, status, confidence, backend, evidence,
                        observations, classified_at, expires_at, last_seen
                 FROM ai_verdicts_pre_channel;
                 INSERT OR IGNORE INTO ai_verdicts
                     (domain, channel, observations, last_seen)
                 SELECT domain,
                        CASE WHEN severity IN ('threat', 'disputed') THEN 'content'
                             ELSE 'threat' END,
                        observations, last_seen
                 FROM ai_verdicts_pre_channel;
                 DROP TABLE ai_verdicts_pre_channel;"
            ))?;
            tx.commit()?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_ai_verdicts_status
                ON ai_verdicts (status);
             CREATE INDEX IF NOT EXISTS idx_ai_verdicts_expires
                ON ai_verdicts (expires_at);",
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
        Ok(self.observe_all(&[domain.to_string()])? == 1)
    }

    /// [`Self::observe`] for many domains in one transaction (a cycle's
    /// harvest can be tens of thousands of names; one commit each made the
    /// harvest the slowest part of a cycle). Returns how many were new.
    pub fn observe_all(&self, domains: &[String]) -> Result<usize> {
        let mut conn = self.lock()?;
        let now = now_epoch();
        let tx = conn.transaction()?;
        let mut new = 0;
        {
            let mut insert = tx.prepare(
                "INSERT INTO ai_verdicts (domain, channel, observations, last_seen)
                 VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(domain, channel) DO NOTHING",
            )?;
            let mut bump = tx.prepare(
                "UPDATE ai_verdicts SET observations = observations + 1, last_seen = ?2
                 WHERE domain = ?1",
            )?;
            for domain in domains {
                // A new domain starts a pending row in *both* channels: the
                // categorizer and the threat detector classify it
                // independently, each on its own schedule.
                let mut inserted = false;
                for channel in Channel::all() {
                    if insert.execute(params![domain, channel.as_str(), now])? == 1 {
                        inserted = true;
                    }
                }
                if inserted {
                    new += 1;
                } else {
                    bump.execute(params![domain, now])?;
                }
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// Classifications waiting to run: a domain and the channel that still
    /// owes it a verdict (new, re-queued after expiry, or left pending by an
    /// interrupted cycle), most-seen first. `limit` bounds verdicts, not
    /// domains, because each domain has one pending row per channel.
    pub fn pending_domains(&self, limit: u32) -> Result<Vec<(String, Channel)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, channel FROM ai_verdicts WHERE status = 'pending'
             ORDER BY observations DESC, domain LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            // An unreadable channel cannot auto-block (the content channel
            // never does), so that is the safe fallback.
            .map(|(domain, channel)| {
                (
                    domain,
                    Channel::from_stored(&channel).unwrap_or(Channel::Content),
                )
            })
            .collect())
    }

    /// Persist a classification. `expires_after_secs = 0` records a verdict
    /// without an expiry (scanner verdicts always pass a TTL; only operator
    /// pins use 0).
    #[allow(clippy::too_many_arguments)]
    pub fn save_verdict(
        &self,
        channel: Channel,
        domain: &str,
        category: &str,
        severity: &str,
        status: &str,
        confidence: f32,
        backend: &str,
        evidence: &str,
        expires_after_secs: i64,
    ) -> Result<()> {
        self.save_verdicts(&[NewVerdict {
            domain: domain.to_string(),
            channel,
            category: category.to_string(),
            severity: severity.to_string(),
            status: status.to_string(),
            confidence,
            backend: backend.to_string(),
            evidence: evidence.to_string(),
            expires_after_secs,
        }])
    }

    /// [`Self::save_verdict`] for a whole cycle's results, in one
    /// transaction.
    pub fn save_verdicts(&self, verdicts: &[NewVerdict]) -> Result<()> {
        let now = now_epoch();
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        {
            let mut update = tx.prepare(
                "UPDATE ai_verdicts
                 SET category = ?3, severity = ?4, status = ?5, confidence = ?6,
                     backend = ?7, evidence = ?8, classified_at = ?9, expires_at = ?10
                 WHERE domain = ?1 AND channel = ?2 AND status = 'pending'",
            )?;
            for v in verdicts {
                let expires_at = if v.expires_after_secs > 0 {
                    now + v.expires_after_secs
                } else {
                    0
                };
                update.execute(params![
                    v.domain,
                    v.channel.as_str(),
                    v.category,
                    v.severity,
                    v.status,
                    v.confidence,
                    v.backend,
                    v.evidence,
                    now,
                    expires_at
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Verdicts expired by `until_epoch` (bounded by `limit` per call): those
    /// of domains queried since they were classified are re-queued to
    /// `pending` so the next scan cycle re-classifies them; the rest are
    /// dropped (a domain queried again later starts over as new). Returns
    /// the number re-queued. Categories are cleared - a changed site must
    /// never inherit the old verdict; freshness is decided by a new
    /// classification, not a memory.
    pub fn expire_old(&self, until_epoch: i64, limit: u32) -> Result<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let expired: Vec<(String, String, bool)> = {
            let mut stmt = tx.prepare(
                "SELECT domain, channel, last_seen > classified_at FROM ai_verdicts
                 WHERE status IN ('classified', 'skipped')
                   AND expires_at > 0 AND expires_at <= ?1
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![until_epoch, limit as i64], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut requeued = 0usize;
        // Expiry is per channel: a threat verdict and a content verdict for
        // the same domain age out on their own TTLs.
        for (domain, channel, seen_since) in &expired {
            if *seen_since {
                requeued += tx.execute(
                    "UPDATE ai_verdicts SET status = 'pending', category = '', severity = '',
                         confidence = 0, evidence = ''
                     WHERE domain = ?1 AND channel = ?2 AND status IN ('classified', 'skipped')",
                    params![domain, channel],
                )?;
            } else {
                tx.execute(
                    "DELETE FROM ai_verdicts WHERE domain = ?1 AND channel = ?2",
                    params![domain, channel],
                )?;
            }
        }
        tx.commit()?;
        Ok(requeued)
    }

    /// Fresh (non-expired) classified *threat-channel* verdicts at or above
    /// `threshold`, minus exact operator `allow` vetoes and threats the
    /// verifier disputed. The block snapshot narrows these to the auto-block
    /// categories and to domains no parent override exempts. Content-channel
    /// rows are categorizations: they never reach the snapshot.
    pub fn fresh_blocked(
        &self,
        now_epoch: i64,
        threshold: f32,
    ) -> Result<Vec<(String, String, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, category, expires_at FROM ai_verdicts
             WHERE channel = 'threat' AND status = 'classified'
               AND severity != 'disputed'
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

    /// Relabel `domain` as `category`, overriding the model's label until
    /// cleared. The model keeps classifying the domain; this only changes
    /// what the console shows and what category blocking matches.
    pub fn set_category_override(&self, domain: &str, category: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_category_overrides (domain, category, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(domain) DO UPDATE SET category = ?2, created_at = ?3",
            params![domain, category.to_ascii_lowercase(), now_epoch()],
        )?;
        Ok(())
    }

    /// Drop a category relabel, so the model's own label applies again.
    /// Returns whether one existed.
    pub fn clear_category_override(&self, domain: &str) -> Result<bool> {
        let conn = self.lock()?;
        Ok(conn.execute(
            "DELETE FROM ai_category_overrides WHERE domain = ?1",
            params![domain],
        )? > 0)
    }

    /// Every category relabel, as `domain -> category`.
    pub fn category_overrides(&self) -> Result<std::collections::HashMap<String, String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT domain, category FROM ai_category_overrides")?;
        let collected = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(collected)
    }

    /// Fresh, classified *content-channel* verdicts: the domains that carry a
    /// category the console can show and a group can block. The scanner
    /// narrows these to non-exempt domains and applies operator relabels.
    pub fn fresh_categories(&self, now_epoch: i64) -> Result<Vec<(String, String, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, category, expires_at FROM ai_verdicts
             WHERE channel = 'content' AND status = 'classified'
               AND category != '' AND expires_at > ?1",
        )?;
        let collected = stmt
            .query_map(params![now_epoch], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
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
            "SELECT {VERDICT_COLUMNS}
             FROM ai_verdicts v WHERE {filter}
             ORDER BY v.classified_at DESC, v.domain, v.channel
             LIMIT {limit} OFFSET {offset}"
        ))?;
        let collected = stmt
            .query_map(params![status, pattern], verdict_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((collected, total as u64))
    }

    /// Paginated threat list: classified verdicts with `threat` or
    /// `disputed` (verifier-overruled, never auto-blocked) severity, highest
    /// confidence first. Same shape as [`Self::list_verdicts`], restricted
    /// to the rows the AI page's Threats tab shows.
    pub fn list_threats(
        &self,
        search: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VerdictRow>, u64)> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 500);
        let offset = offset.min(u32::MAX - limit);
        // LIKE pattern with the wildcard characters escaped.
        let search = search
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{search}%");
        let filter = "v.channel = 'threat' AND v.status = 'classified'
                 AND v.severity IN ('threat', 'disputed')
                 AND v.domain LIKE ?1 ESCAPE '\\'";
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM ai_verdicts v WHERE {filter}"),
            params![pattern],
            |r| r.get(0),
        )?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {VERDICT_COLUMNS}
             FROM ai_verdicts v WHERE {filter}
             ORDER BY v.confidence DESC, v.classified_at DESC, v.domain
             LIMIT {limit} OFFSET {offset}"
        ))?;
        let collected = stmt
            .query_map(params![pattern], verdict_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((collected, total as u64))
    }

    /// Paginated verdict list with optional status, category, severity,
    /// exemption and domain filters.
    pub fn list_verdicts_filtered(
        &self,
        filter: &VerdictFilter<'_>,
        page: VerdictPage,
    ) -> Result<(Vec<VerdictRow>, u64)> {
        self.list_filtered(false, filter, page)
    }

    /// Paginated threat list with optional category, severity and exemption
    /// filters, plus a domain search.
    pub fn list_threats_filtered(
        &self,
        filter: &VerdictFilter<'_>,
        page: VerdictPage,
    ) -> Result<(Vec<VerdictRow>, u64)> {
        self.list_filtered(true, filter, page)
    }

    fn list_filtered(
        &self,
        threats_only: bool,
        filter: &VerdictFilter<'_>,
        page: VerdictPage,
    ) -> Result<(Vec<VerdictRow>, u64)> {
        let conn = self.lock()?;
        let limit = page.limit.clamp(1, 500);
        let offset = page.offset.min(u32::MAX - limit);
        let status = filter.status.unwrap_or("").trim().to_ascii_lowercase();
        let category = filter
            .category
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let category = format!("%{category}%");
        let severity = filter.severity.unwrap_or("").trim().to_ascii_lowercase();
        let exemption = filter.exemption.unwrap_or("").trim().to_ascii_lowercase();
        let search = filter
            .search
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let search = format!("%{search}%");
        // Each list shows its own channel: the verdict list the
        // categorizer's labels, the threat list the threat detector's.
        let channel = filter
            .channel
            .unwrap_or(if threats_only { "threat" } else { "content" })
            .trim()
            .to_ascii_lowercase();
        let filter =
            "(?1 = 0 OR (v.status = 'classified' AND v.severity IN ('threat', 'disputed')))
            AND (?2 = '' OR v.status = ?2)
            AND (?3 = '%%' OR lower(COALESCE((SELECT c.category FROM ai_category_overrides c
                WHERE c.domain = v.domain AND v.channel = 'content'), v.category))
                LIKE ?3 ESCAPE '\\')
            AND (?4 = '' OR v.severity = ?4)
            AND (?5 = '' OR (?5 = 'exempt' AND EXISTS (
                SELECT 1 FROM ai_overrides o WHERE o.domain = v.domain AND o.action = 'allow'))
                OR (?5 = 'not_exempt' AND NOT EXISTS (
                SELECT 1 FROM ai_overrides o WHERE o.domain = v.domain AND o.action = 'allow')))
            AND v.domain LIKE ?6 ESCAPE '\\'
            AND v.channel = ?7";
        let params = params![
            threats_only,
            status,
            category,
            severity,
            exemption,
            search,
            channel
        ];
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM ai_verdicts v WHERE {filter}"),
            params,
            |r| r.get(0),
        )?;
        let order = if threats_only {
            "v.confidence DESC, v.classified_at DESC, v.domain"
        } else {
            "v.classified_at DESC, v.domain"
        };
        let mut stmt = conn.prepare(&format!(
            "SELECT {VERDICT_COLUMNS}
             FROM ai_verdicts v WHERE {filter}
             ORDER BY {order} LIMIT {limit} OFFSET {offset}"
        ))?;
        let collected = stmt
            .query_map(params, verdict_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((collected, total as u64))
    }

    /// Per-status domain counts, for the status endpoint (missing statuses are
    /// absent). Counted by domain, not by row: a domain has one row per
    /// channel, and the console talks about domains.
    pub fn status_counts(&self) -> Result<Vec<(String, usize)>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT status, COUNT(DISTINCT domain) FROM ai_verdicts GROUP BY status")?;
        let collected = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(collected)
    }
}
