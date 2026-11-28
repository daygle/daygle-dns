//! The store's evidence tables: what the AI knows about a domain from
//! somewhere other than its own classifiers.
//!
//! * `ai_intel` - names published by the maintained threat feeds
//!   ([`crate::intel`]), with each feed's download state in `ai_intel_feeds`.
//!   Kept here rather than only in memory so a server that cannot reach the
//!   feeds for a while still has the last good lists after a restart.
//! * `ai_seen` - how long and how widely this network has used a domain:
//!   the days it was looked up on and (hashed) clients that looked it up. A
//!   name many clients have used for weeks is "established" - the automatic
//!   counterpart to an operator's "not a threat".
//! * `ai_page_texts` - the title and opening text of pages the page stage
//!   read, so a page-text model can be trained on them ([`crate::page_model`]).

use std::collections::{BTreeSet, HashMap};

use daygle_dns_core::{config::FusionMode, error::Result};
use rusqlite::{named_params, params, Connection, OptionalExtension};

use super::{now_epoch, AiStore};

pub(super) const TABLES: &str = "
CREATE TABLE IF NOT EXISTS ai_intel (
    domain   TEXT NOT NULL,
    wildcard INTEGER NOT NULL,
    feed     TEXT NOT NULL,
    PRIMARY KEY (domain, wildcard, feed)
);
CREATE INDEX IF NOT EXISTS idx_ai_intel_feed ON ai_intel (feed);
CREATE TABLE IF NOT EXISTS ai_intel_feeds (
    feed         TEXT PRIMARY KEY,
    entries      INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0,
    attempted_at INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    failing_since INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_seen (
    domain     TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    days       INTEGER NOT NULL DEFAULT 1,
    clients    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_seen_last ON ai_seen (last_seen);
CREATE TABLE IF NOT EXISTS ai_page_texts (
    domain  TEXT PRIMARY KEY,
    title   TEXT NOT NULL DEFAULT '',
    text    TEXT NOT NULL DEFAULT '',
    read_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_page_texts_read ON ai_page_texts (read_at);
CREATE TABLE IF NOT EXISTS ai_page_discovery (
    domain TEXT PRIMARY KEY,
    final_host TEXT,
    category TEXT,
    confidence REAL,
    evidence TEXT NOT NULL,
    inspected_at INTEGER NOT NULL,
    retry_at INTEGER NOT NULL,
    scoring_version TEXT NOT NULL DEFAULT '',
    enforcement_eligible INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ai_page_discovery_retry ON ai_page_discovery (retry_at);
CREATE TABLE IF NOT EXISTS ai_age_attempts (
    domain       TEXT PRIMARY KEY,
    attempted_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_threat_rate (
    at         INTEGER NOT NULL,
    classified INTEGER NOT NULL,
    threats    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_threat_rate_at ON ai_threat_rate (at);
CREATE TABLE IF NOT EXISTS ai_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// How long a domain whose registration date could not be found waits
/// before it is looked up again: the RDAP cache's own retry time, so the
/// next try is a real lookup, and other candidates get their turn meanwhile.
pub const AGE_RETRY_SECS: i64 = 6 * 3600;

/// How long the per-scan threat counts are kept: the watch on a new model
/// compares against the week before it went live.
const RATE_RETENTION_SECS: i64 = 30 * 86_400;

/// Distinct clients remembered per domain. Enough to tell "one device" from
/// "the whole network" without keeping a growing list.
pub const MAX_CLIENTS_KEPT: usize = 16;
/// Days a domain must have been looked up on to count as established.
pub const ESTABLISHED_DAYS: i64 = 14;
/// Distinct clients that must have looked it up.
pub const ESTABLISHED_CLIENTS: usize = 3;
/// A sighting history unused for this long is forgotten.
const SEEN_RETENTION_SECS: i64 = 90 * 86_400;
/// Page texts kept for the page-text model, newest first.
const PAGE_TEXTS_KEPT: i64 = 5_000;
/// Characters of page text kept per page.
pub const PAGE_TEXT_CHARS: usize = 4_000;

/// One maintained feed's download state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedState {
    pub entries: u64,
    /// Unix time of the last successful download (0: never).
    pub updated_at: i64,
    /// Unix time of the last attempt, successful or not.
    pub attempted_at: i64,
    /// Why the last attempt failed; empty when it succeeded.
    pub error: String,
    /// When the current run of failed attempts began (0: not failing).
    pub failing_since: i64,
}

/// How long and how widely this network has used one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub first_seen: i64,
    pub last_seen: i64,
    /// Distinct UTC days it was looked up on.
    pub days: i64,
    /// Distinct clients that looked it up (capped at [`MAX_CLIENTS_KEPT`]).
    pub clients: usize,
}

impl Sighting {
    /// Used for weeks by several clients: not something the name alone
    /// should be allowed to block.
    pub fn established(&self) -> bool {
        self.days >= ESTABLISHED_DAYS && self.clients >= ESTABLISHED_CLIENTS
    }
}

/// A short, stable stand-in for a client address: the history only needs to
/// tell clients apart, not to say who they are.
pub fn client_tag(client: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in client.trim().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", hash as u32)
}

fn day(epoch: i64) -> i64 {
    epoch.div_euclid(86_400)
}

fn sighting(r: &rusqlite::Row<'_>) -> rusqlite::Result<Sighting> {
    let clients: String = r.get(3)?;
    Ok(Sighting {
        first_seen: r.get(0)?,
        last_seen: r.get(1)?,
        days: r.get(2)?,
        clients: clients.split(',').filter(|c| !c.is_empty()).count(),
    })
}

/// Bring evidence tables from older releases up to date.
pub(super) fn upgrade(conn: &Connection) -> rusqlite::Result<()> {
    let has: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_intel_feeds') WHERE name = 'failing_since')",
        [],
        |r| r.get(0),
    )?;
    if !has {
        conn.execute(
            "ALTER TABLE ai_intel_feeds ADD COLUMN failing_since INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    // A page finding made by an older scoring version is not evidence for the
    // version now in force: the review joins on this column.
    let has_scoring: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_page_discovery') WHERE name = 'scoring_version')",
        [],
        |r| r.get(0),
    )?;
    if !has_scoring {
        conn.execute(
            "ALTER TABLE ai_page_discovery ADD COLUMN scoring_version TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    let has_eligibility: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ai_page_discovery') WHERE name = 'enforcement_eligible')",
        [],
        |row| row.get(0),
    )?;
    if !has_eligibility {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE ai_page_discovery ADD COLUMN enforcement_eligible INTEGER NOT NULL DEFAULT 0;
             UPDATE ai_page_discovery SET retry_at = 0 WHERE confidence >= 0.95;
             COMMIT;",
        )?;
    }
    Ok(())
}

pub(super) fn prune(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM ai_page_discovery WHERE retry_at <= ?1",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM ai_seen WHERE last_seen < ?1",
        params![now - SEEN_RETENTION_SECS],
    )?;
    conn.execute(
        "DELETE FROM ai_threat_rate WHERE at < ?1",
        params![now - RATE_RETENTION_SECS],
    )?;
    conn.execute(
        "DELETE FROM ai_age_attempts WHERE attempted_at < ?1",
        params![now - 30 * 86_400],
    )?;
    conn.execute(
        "DELETE FROM ai_page_texts WHERE domain NOT IN
             (SELECT domain FROM ai_page_texts ORDER BY read_at DESC LIMIT ?1)",
        params![PAGE_TEXTS_KEPT],
    )?;
    Ok(())
}

impl AiStore {
    pub(crate) fn page_discovery_candidates(
        &self,
        now: i64,
        floor: f32,
        limit: usize,
        fusion: FusionMode,
    ) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT v.domain FROM ai_verdicts v
             WHERE v.channel = 'threat' AND v.expires_at > :now
               AND v.severity != 'disputed'
               AND (v.status = 'skipped' OR (v.status = 'classified'
                    AND (v.confidence < :floor OR ({gate}) < :floor)))
               AND NOT EXISTS (SELECT 1 FROM ai_page_discovery p
                               WHERE p.domain = v.domain AND p.retry_at > :now)
               AND NOT EXISTS (SELECT 1 FROM ai_overrides o WHERE o.domain = v.domain)
               AND NOT EXISTS (SELECT 1 FROM ai_category_overrides o WHERE o.domain = v.domain)
             ORDER BY v.classified_at, v.domain LIMIT :limit",
            gate = super::threshold::GATE_SCORE,
        ))?;
        let rows = stmt
            .query_map(named_params! {
                ":now": now, ":floor": floor, ":limit": limit as i64, ":fusion": fusion.as_str(),
            }, |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Recently first-seen DNS names, independent of classifier confidence.
    pub(crate) fn new_dns_discovery_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<String>> {
        const NEW_NAME_WINDOW: i64 = 7 * 86_400;
        let since = now.saturating_sub(NEW_NAME_WINDOW);
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT s.domain FROM ai_seen s JOIN ai_verdicts v
               ON v.domain = s.domain AND v.channel = 'threat'
             WHERE s.last_seen BETWEEN ?1 AND ?2 AND s.first_seen BETWEEN ?1 AND ?2
               AND v.severity != 'disputed'
               AND NOT EXISTS (SELECT 1 FROM ai_page_discovery p
                               WHERE p.domain = s.domain AND p.retry_at > ?2)
               AND NOT EXISTS (SELECT 1 FROM ai_overrides o WHERE o.domain = s.domain)
               AND NOT EXISTS (SELECT 1 FROM ai_category_overrides o WHERE o.domain = s.domain)
             ORDER BY s.first_seen, s.domain LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![since, now, limit as i64], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub(crate) fn save_page_discovery(
        &self,
        domain: &str,
        reading: &crate::page::DiscoveryReading,
        now: i64,
        scoring_version: &str,
    ) -> Result<()> {
        let retry_at = now
            + if reading.final_host.is_some() {
                86_400
            } else {
                3_600
            };
        self.lock()?.execute(
            "INSERT INTO ai_page_discovery
                 (domain, final_host, category, confidence, evidence, inspected_at, retry_at, scoring_version, enforcement_eligible)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(domain) DO UPDATE SET final_host = excluded.final_host,
                 category = excluded.category, confidence = excluded.confidence,
                 evidence = excluded.evidence, inspected_at = excluded.inspected_at,
                 retry_at = excluded.retry_at, scoring_version = excluded.scoring_version,
                 enforcement_eligible = excluded.enforcement_eligible",
            params![
                domain,
                reading.final_host,
                reading.category,
                reading.confidence,
                reading.evidence,
                now,
                retry_at,
                scoring_version,
                reading.enforcement_eligible
            ],
        )?;
        Ok(())
    }

    /// Only current, undisputed findings on the original hostname can block.
    pub(crate) fn page_discovery_blocks(
        &self,
        now: i64,
        threshold: f32,
    ) -> Result<Vec<(String, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT p.domain, min(p.retry_at, v.expires_at)
             FROM ai_page_discovery p JOIN ai_verdicts v
               ON v.domain = p.domain AND v.channel = 'threat'
             WHERE p.enforcement_eligible = 1 AND p.confidence >= ?2
               AND p.final_host = p.domain AND p.retry_at > ?1
               AND v.expires_at > ?1 AND v.status IN ('classified', 'skipped')
               AND v.severity != 'disputed'
               AND NOT EXISTS (SELECT 1 FROM ai_overrides o WHERE o.domain = p.domain)
               AND NOT EXISTS (SELECT 1 FROM ai_category_overrides o WHERE o.domain = p.domain)",
        )?;
        let rows = stmt
            .query_map(
                params![now, threshold.max(crate::page::DISCOVERY_ENFORCEMENT_FLOOR)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Counts for [`Self::page_discovery_review_rows`]: every current finding,
    /// and how many were explicitly corrected or confirmed. Deriving the
    /// counts from the same rows the status reports keeps the two from
    /// disagreeing, and counts each finding once even when it has several
    /// overrides. A policy `allow` exemption is neither.
    pub(crate) fn page_discovery_reviews(
        &self,
        now: i64,
        scoring_version: Option<&str>,
    ) -> Result<(i64, i64, i64)> {
        let rows = self.page_discovery_review_rows(now, scoring_version)?;
        let mut findings = 0;
        let mut corrected = 0;
        let mut confirmed = 0;
        for row in &rows {
            findings += 1;
            match row.get("review").and_then(serde_json::Value::as_str) {
                Some("corrected") => corrected += 1,
                Some("confirmed") => confirmed += 1,
                _ => {}
            }
        }
        Ok((findings, corrected, confirmed))
    }

    /// Every current page finding under `scoring_version` with the explicit
    /// review that attaches to it: the domain, evidence source (`page`),
    /// scoring version, and review time. A policy `allow` exemption is not a
    /// review outcome: it is listed as `exempted`, never as a confirmation.
    /// One row per finding, whatever the number of overrides.
    pub(crate) fn page_discovery_review_rows(
        &self,
        now: i64,
        scoring_version: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT p.domain, p.category, p.confidence, p.inspected_at,
                    p.scoring_version,
                    CASE WHEN EXISTS (SELECT 1 FROM ai_overrides a
                                      WHERE a.domain = p.domain AND a.action = 'allow'
                                        AND a.created_at >= p.inspected_at) THEN 'exempted'
                         WHEN EXISTS (SELECT 1 FROM ai_overrides o
                                      WHERE o.domain = p.domain AND o.action = 'not_threat'
                                        AND o.created_at >= p.inspected_at) THEN 'corrected'
                         WHEN EXISTS (SELECT 1 FROM ai_category_overrides c
                                      WHERE c.domain = p.domain AND c.category = p.category
                                        AND c.created_at >= p.inspected_at) THEN 'confirmed'
                         ELSE 'unreviewed' END AS review,
                    COALESCE((SELECT MAX(o.created_at) FROM ai_overrides o
                              WHERE o.domain = p.domain
                                AND o.action IN ('allow', 'not_threat')
                                AND o.created_at >= p.inspected_at),
                             (SELECT MAX(c.created_at) FROM ai_category_overrides c
                              WHERE c.domain = p.domain AND c.category = p.category
                                AND c.created_at >= p.inspected_at), 0) AS reviewed_at
             FROM ai_page_discovery p
             WHERE p.category IS NOT NULL AND p.retry_at > ?1
               AND (?2 IS NULL OR p.scoring_version = ?2)
             ORDER BY p.inspected_at DESC, p.domain",
        )?;
        let rows = stmt
            .query_map(params![now, scoring_version], |r| {
                Ok(serde_json::json!({
                    "domain": r.get::<_, String>(0)?,
                    "source": "page",
                    "category": r.get::<_, Option<String>>(1)?,
                    "confidence": r.get::<_, Option<f64>>(2)?,
                    "finding_at": r.get::<_, i64>(3)?,
                    "scoring_version": r.get::<_, String>(4)?,
                    "review": r.get::<_, String>(5)?,
                    "reviewed_at": r.get::<_, i64>(6)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Page findings an operator explicitly confirmed: the category override
    /// matches the finding and no allow/not_threat override covers it. These
    /// are the only page discoveries a retrain or a holdout may use as labels;
    /// an unreviewed finding and a policy exemption supply nothing.
    pub(crate) fn reviewed_page_discovery_labels(
        &self,
        now: i64,
    ) -> Result<std::collections::HashMap<String, String>> {
        let mut labels = std::collections::HashMap::new();
        for row in self.page_discovery_review_rows(now, None)? {
            if row.get("review").and_then(serde_json::Value::as_str) != Some("confirmed") {
                continue;
            }
            let (Some(domain), Some(category)) = (
                row.get("domain").and_then(serde_json::Value::as_str),
                row.get("category").and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            labels.insert(domain.to_string(), category.to_string());
        }
        Ok(labels)
    }

    /// Direct exact-host observations from the independent page rules.
    /// Reinspection replaces the row, so a weaker or redirected result
    /// immediately removes the previous observation from automatic learning.
    pub(crate) fn directly_corroborated_discoveries(
        &self,
        before: i64,
    ) -> Result<Vec<(String, Option<String>)>> {
        const EVIDENCE_WINDOW_SECS: i64 = 7 * 86_400;
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT p.domain, p.category FROM ai_page_discovery p
             WHERE p.enforcement_eligible = 1 AND p.final_host = p.domain
               AND p.confidence >= ?1 AND p.inspected_at BETWEEN ?2 AND ?3
               AND NOT EXISTS (SELECT 1 FROM ai_verdicts v WHERE v.domain = p.domain
                               AND v.channel = 'threat' AND v.severity = 'disputed')
               AND NOT EXISTS (SELECT 1 FROM ai_overrides o WHERE o.domain = p.domain)
               AND NOT EXISTS (SELECT 1 FROM ai_category_overrides o WHERE o.domain = p.domain)
             ORDER BY p.inspected_at DESC, p.domain LIMIT 2048",
        )?;
        let rows = stmt
            .query_map(
                params![
                    crate::page::DISCOVERY_ENFORCEMENT_FLOOR,
                    before.saturating_sub(EVIDENCE_WINDOW_SECS),
                    before
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub(crate) fn page_discovery(
        &self,
        domain: &str,
        now: i64,
    ) -> Result<Option<crate::PageDiscoveryReport>> {
        let result = self
            .lock()?
            .query_row(
                "SELECT final_host, category, confidence, evidence, inspected_at, retry_at,
                        scoring_version, enforcement_eligible
             FROM ai_page_discovery WHERE domain = ?1 AND retry_at > ?2",
                params![domain, now],
                |r| {
                    Ok(crate::PageDiscoveryReport {
                        reading: crate::page::DiscoveryReading {
                            final_host: r.get(0)?,
                            category: r.get(1)?,
                            confidence: r.get(2)?,
                            evidence: r.get(3)?,
                            enforcement_eligible: r.get(7)?,
                        },
                        inspected_at: r.get(4)?,
                        retry_at: r.get(5)?,
                        scoring_version: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }
    // ── Threat feeds ────────────────────────────────────────────────────

    /// Replace feed `feed`'s names with `entries` (blocklist syntax: a name,
    /// or `*.suffix` for every name under it) and record the download.
    pub fn replace_intel(&self, feed: &str, entries: &BTreeSet<String>) -> Result<usize> {
        let mut conn = self.lock()?;
        let now = now_epoch();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM ai_intel WHERE feed = ?1", params![feed])?;
        let mut stored = 0usize;
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO ai_intel (domain, wildcard, feed) VALUES (?1, ?2, ?3)",
            )?;
            for entry in entries {
                // Exceptions (`@@`) belong to blocking, not to labels.
                if entry.starts_with('@') {
                    continue;
                }
                let (domain, wildcard) = match entry.strip_prefix("*.") {
                    Some(suffix) => (suffix, true),
                    None => (entry.as_str(), false),
                };
                if domain.is_empty() || !domain.contains('.') {
                    // A bare TLD says nothing about one site.
                    continue;
                }
                stored += insert.execute(params![domain, wildcard, feed])?;
            }
        }
        tx.execute(
            "INSERT INTO ai_intel_feeds (feed, entries, updated_at, attempted_at, error)
             VALUES (?1, ?2, ?3, ?3, '')
             ON CONFLICT(feed) DO UPDATE SET entries = ?2, updated_at = ?3,
                 attempted_at = ?3, error = '', failing_since = 0",
            params![feed, stored as i64, now],
        )?;
        tx.commit()?;
        Ok(stored)
    }

    /// Record a failed download of `feed`; its last good names stay.
    pub fn intel_failed(&self, feed: &str, error: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_intel_feeds (feed, attempted_at, error, failing_since)
             VALUES (?1, ?2, ?3, ?2)
             ON CONFLICT(feed) DO UPDATE SET attempted_at = ?2, error = ?3,
                 failing_since = CASE WHEN failing_since = 0 THEN ?2 ELSE failing_since END",
            params![feed, now_epoch(), error],
        )?;
        Ok(())
    }

    /// Every feed's download state, by feed id.
    pub fn intel_feeds(&self) -> Result<HashMap<String, FeedState>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT feed, entries, updated_at, attempted_at, error, failing_since FROM ai_intel_feeds")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    FeedState {
                        entries: r.get::<_, i64>(1)?.max(0) as u64,
                        updated_at: r.get(2)?,
                        attempted_at: r.get(3)?,
                        error: r.get(4)?,
                        failing_since: r.get(5)?,
                    },
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    /// Every stored feed name: `(domain, wildcard, feed)`.
    pub fn intel_entries(&self) -> Result<Vec<(String, bool, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT domain, wildcard, feed FROM ai_intel")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    /// Threat verdicts already decided (classified or skipped), with their
    /// evidence: what a change in the outside evidence may have to revisit.
    pub fn decided_threats(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, evidence FROM ai_verdicts
             WHERE channel = 'threat' AND status IN ('classified', 'skipped')",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    /// Send these domains' threat verdicts back to the scan queue, so the
    /// next cycle classifies them again with the evidence as it is now. The
    /// verdict's fields stay until then.
    pub fn requeue_threat_domains(&self, domains: &[String]) -> Result<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut queued = 0usize;
        {
            let mut update = tx.prepare(
                "UPDATE ai_verdicts SET status = 'pending'
                 WHERE channel = 'threat' AND domain = ?1
                   AND status IN ('classified', 'skipped')",
            )?;
            for domain in domains {
                queued += update.execute(params![domain])?;
            }
        }
        tx.commit()?;
        Ok(queued)
    }

    /// Send back to the scan queue the threats that now block a domain this
    /// network has come to rely on: established since the verdict was made,
    /// so the next cycle disputes them (see [`crate::evidence`]). A feed
    /// listing outranks being established, so listed verdicts stay. Returns
    /// how many were re-queued.
    pub fn requeue_newly_established(&self) -> Result<usize> {
        let established: std::collections::HashSet<String> =
            self.established_domains(u32::MAX)?.into_iter().collect();
        if established.is_empty() {
            return Ok(0);
        }
        let threats: Vec<String> = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare(
                "SELECT domain FROM ai_verdicts
                 WHERE channel = 'threat' AND status = 'classified' AND severity = 'threat'
                   AND instr(evidence, ?1) = 0",
            )?;
            let rows = stmt
                .query_map(params![crate::evidence::LISTED_NOTE], |r| r.get(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?;
            rows
        };
        let now_established: Vec<String> = threats
            .into_iter()
            .filter(|domain| established.contains(domain))
            .collect();
        self.requeue_threat_domains(&now_established)
    }

    /// A value the engine keeps between restarts (e.g. which model file was
    /// live), or `None`.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT value FROM ai_meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    /// After the model changes, bring forward the re-check of every verdict
    /// on a domain still in use, spread over `window_secs` (starting an
    /// hour from `now`) so the new model reaches old verdicts in days, not
    /// at the end of a 90-day lifetime, without a backlog that would leave
    /// threats waiting unblocked. A verdict due sooner keeps its time, and
    /// one on a domain nobody looked up again is left to its lifetime.
    /// Returns how many verdicts were brought forward.
    pub fn stagger_rechecks(&self, now: i64, window_secs: i64) -> Result<usize> {
        let hours = (window_secs / 3600).max(1);
        let conn = self.lock()?;
        Ok(conn.execute(
            "UPDATE ai_verdicts
             SET expires_at = ?1 + 3600 + (rowid % ?2) * 3600
             WHERE status IN ('classified', 'skipped')
               AND last_seen > classified_at
               AND expires_at > ?1 + 3600 + (rowid % ?2) * 3600",
            params![now, hours],
        )?)
    }

    // ── Domain age ──────────────────────────────────────────────────────

    /// Threat verdicts whose domain age has not been looked up yet, newest
    /// first: `(domain, confidence, evidence)`.
    pub fn age_candidates(&self, limit: u32) -> Result<Vec<(String, f32, String)>> {
        self.age_candidates_at(limit, now_epoch())
    }

    /// [`Self::age_candidates`] at a given time (tests). A domain whose date
    /// could not be found is skipped for [`AGE_RETRY_SECS`], so domains that
    /// never resolve (a TLD without RDAP) cannot hold the queue.
    pub fn age_candidates_at(&self, limit: u32, now: i64) -> Result<Vec<(String, f32, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT v.domain, v.confidence, v.evidence FROM ai_verdicts v
             LEFT JOIN ai_age_attempts a ON a.domain = v.domain
             WHERE v.channel = 'threat' AND v.status = 'classified' AND v.severity = 'threat'
               AND instr(v.evidence, ', registered ') = 0
               AND (a.attempted_at IS NULL OR a.attempted_at <= ?2)
               AND NOT EXISTS (SELECT 1 FROM ai_overrides o WHERE o.domain = v.domain)
             ORDER BY COALESCE(a.attempted_at, 0), v.classified_at DESC, v.domain
             LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64, now - AGE_RETRY_SECS], |r| {
                Ok((r.get(0)?, r.get::<_, f64>(1)? as f32, r.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }

    /// Record that `domain`'s registration date could not be found now.
    pub fn age_lookup_failed(&self, domain: &str) -> Result<()> {
        self.age_lookup_failed_at(domain, now_epoch())
    }

    /// [`Self::age_lookup_failed`] at a given time (tests).
    pub fn age_lookup_failed_at(&self, domain: &str, at: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_age_attempts (domain, attempted_at) VALUES (?1, ?2)
             ON CONFLICT(domain) DO UPDATE SET attempted_at = ?2",
            params![domain, at],
        )?;
        Ok(())
    }

    /// Record a domain-age decision on a threat verdict: its new confidence
    /// and the note that says why. Whether a row was updated.
    pub fn apply_age(&self, domain: &str, confidence: f32, note: &str) -> Result<bool> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE ai_verdicts SET confidence = ?2, evidence = evidence || ?3
             WHERE domain = ?1 AND channel = 'threat' AND instr(evidence, ', registered ') = 0",
            params![domain, f64::from(confidence), note],
        )?;
        Ok(updated > 0)
    }

    // ── How the live model behaves ──────────────────────────────────────

    /// Record one scan's threat-channel output: how many domains it
    /// classified and how many of them qualified to block.
    pub fn record_threat_rate(&self, classified: usize, threats: usize) -> Result<()> {
        self.record_threat_rate_at(classified, threats, now_epoch())
    }

    /// [`Self::record_threat_rate`] at a given time (tests).
    pub fn record_threat_rate_at(&self, classified: usize, threats: usize, at: i64) -> Result<()> {
        if classified == 0 {
            return Ok(());
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_threat_rate (at, classified, threats) VALUES (?1, ?2, ?3)",
            params![at, classified as i64, threats as i64],
        )?;
        Ok(())
    }

    /// Domains classified and threats qualifying to block in `[from, to)`.
    pub fn threat_rate(&self, from: i64, to: i64) -> Result<(u64, u64)> {
        let conn = self.lock()?;
        let (classified, threats): (i64, i64) = conn.query_row(
            "SELECT COALESCE(SUM(classified), 0), COALESCE(SUM(threats), 0)
             FROM ai_threat_rate WHERE at >= ?1 AND at < ?2",
            params![from, to],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((classified.max(0) as u64, threats.max(0) as u64))
    }

    /// "Not a threat" marks filed since `since` on threat detections made
    /// since then: the operator correcting what a new model flagged.
    pub fn not_threat_marks_since(&self, since: i64) -> Result<u64> {
        let conn = self.lock()?;
        let marks: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ai_overrides o
             JOIN ai_verdicts v ON v.domain = o.domain AND v.channel = 'threat'
             WHERE o.action = 'not_threat' AND o.created_at >= ?1 AND v.classified_at >= ?1",
            params![since],
            |r| r.get(0),
        )?;
        Ok(marks.max(0) as u64)
    }

    // ── How this network uses a domain ──────────────────────────────────

    /// Record one harvest: each domain with the clients that looked it up.
    pub fn record_sightings(&self, sightings: &[(String, Vec<String>)]) -> Result<()> {
        self.record_sightings_at(sightings, now_epoch())
    }

    /// [`Self::record_sightings`] at a given time (tests age the history).
    pub fn record_sightings_at(&self, sightings: &[(String, Vec<String>)], now: i64) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        {
            let mut read =
                tx.prepare("SELECT last_seen, days, clients FROM ai_seen WHERE domain = ?1")?;
            let mut write = tx.prepare(
                "INSERT INTO ai_seen (domain, first_seen, last_seen, days, clients)
                 VALUES (?1, ?2, ?2, 1, ?3)
                 ON CONFLICT(domain) DO UPDATE SET last_seen = ?2, days = ?4, clients = ?3",
            )?;
            for (domain, clients) in sightings {
                let existing: Option<(i64, i64, String)> = read
                    .query_row(params![domain], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .optional()?;
                let (days, mut known) = match &existing {
                    Some((last, days, known)) => (
                        if day(*last) < day(now) {
                            days + 1
                        } else {
                            *days
                        },
                        known
                            .split(',')
                            .filter(|c| !c.is_empty())
                            .map(str::to_string)
                            .collect::<BTreeSet<String>>(),
                    ),
                    None => (1, BTreeSet::new()),
                };
                for client in clients {
                    if known.len() >= MAX_CLIENTS_KEPT {
                        break;
                    }
                    known.insert(client_tag(client));
                }
                let joined = known.into_iter().collect::<Vec<_>>().join(",");
                write.execute(params![domain, now, joined, days])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// How this network has used `domain`, if it has been seen.
    pub fn sighting(&self, domain: &str) -> Result<Option<Sighting>> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                "SELECT first_seen, last_seen, days, clients FROM ai_seen WHERE domain = ?1",
                params![domain],
                sighting,
            )
            .optional()?)
    }

    /// Established domains (see [`Sighting::established`]), most widely used
    /// first, at most `limit`.
    pub fn established_domains(&self, limit: u32) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, first_seen, last_seen, days, clients FROM ai_seen
             WHERE days >= ?1
             ORDER BY days DESC, domain",
        )?;
        let mut out = Vec::new();
        let mut rows = stmt.query(params![ESTABLISHED_DAYS])?;
        while let Some(row) = rows.next()? {
            let clients: String = row.get(4)?;
            if clients.split(',').filter(|c| !c.is_empty()).count() >= ESTABLISHED_CLIENTS {
                out.push(row.get::<_, String>(0)?);
                if out.len() >= limit as usize {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Forget sighting histories and page texts past their retention.
    pub fn prune_evidence(&self) -> Result<()> {
        let conn = self.lock()?;
        prune(&conn, now_epoch())?;
        Ok(())
    }

    // ── Page texts ──────────────────────────────────────────────────────

    /// Keep the opening text of a page the page stage read.
    pub fn save_page_text(&self, domain: &str, title: &str, text: &str) -> Result<()> {
        let conn = self.lock()?;
        let text: String = text.chars().take(PAGE_TEXT_CHARS).collect();
        let title: String = title.chars().take(300).collect();
        conn.execute(
            "INSERT INTO ai_page_texts (domain, title, text, read_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(domain) DO UPDATE SET title = ?2, text = ?3, read_at = ?4",
            params![domain, title, text, now_epoch()],
        )?;
        Ok(())
    }

    /// Every kept page text: `(domain, title, text)`, newest first.
    pub fn page_texts(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT domain, title, text FROM ai_page_texts ORDER BY read_at DESC, domain",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
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

    #[test]
    fn discovery_considers_the_live_assessment_and_keeps_reviews_explicit() {
        let (_dir, store) = store();
        let domain = "uncertain.example";
        store.observe(domain).unwrap();
        store
            .save_verdict(
                crate::backend::Channel::Threat,
                domain,
                "phishing",
                "threat",
                "classified",
                0.9,
                "fasttext",
                "model",
                3600,
            )
            .unwrap();
        store.lock().unwrap().execute(
            "UPDATE ai_verdicts SET assessment_mode = 'decide', assessment_score = 0.25 WHERE domain = ?1",
            [domain],
        ).unwrap();
        let now = now_epoch();
        assert_eq!(
            store
                .page_discovery_candidates(now, 0.5, 4, FusionMode::Decide)
                .unwrap(),
            [domain]
        );
        assert!(store
            .page_discovery_candidates(now, 0.5, 4, FusionMode::Monitor)
            .unwrap()
            .is_empty());

        store
            .save_page_discovery(
                domain,
                &crate::page::DiscoveryReading {
                    final_host: Some(domain.to_string()),
                    category: Some("phishing".to_string()),
                    confidence: Some(0.9),
                    enforcement_eligible: false,
                    evidence: "two page cues".to_string(),
                },
                now,
                "test-version",
            )
            .unwrap();
        store
            .set_override(domain, "allow", "policy exemption")
            .unwrap();
        assert_eq!(
            store
                .page_discovery_reviews(now, Some("test-version"))
                .unwrap(),
            (1, 0, 0),
            "an allow exemption earns no review credit"
        );
        store
            .set_override(domain, "not_threat", "reviewed")
            .unwrap();
        assert_eq!(
            store
                .page_discovery_reviews(now, Some("test-version"))
                .unwrap(),
            (1, 1, 0)
        );
        assert!(
            store
                .page_discovery_reviews(now, Some("another-version"))
                .unwrap()
                == (0, 0, 0),
            "a review only counts under the scoring version that made the finding"
        );
    }

    #[test]
    fn direct_discovery_eligibility_does_not_depend_on_the_display_category() {
        let (_dir, store) = store();
        let domain = "uncategorized.example";
        let now = now_epoch();
        store.observe(domain).unwrap();
        store
            .save_verdict(
                crate::backend::Channel::Threat,
                domain,
                "",
                "",
                "skipped",
                0.0,
                "model",
                "",
                3600,
            )
            .unwrap();
        let mut reading = crate::page::DiscoveryReading {
            final_host: Some(domain.to_string()),
            category: None,
            confidence: Some(0.96),
            enforcement_eligible: false,
            evidence: String::new(),
        };
        store
            .save_page_discovery(domain, &reading, now, "page")
            .unwrap();
        assert!(store.page_discovery_blocks(now, 0.95).unwrap().is_empty());
        assert!(store
            .directly_corroborated_discoveries(now)
            .unwrap()
            .is_empty());
        reading.enforcement_eligible = true;
        store
            .save_page_discovery(domain, &reading, now, "page")
            .unwrap();
        assert_eq!(store.page_discovery_blocks(now, 0.95).unwrap()[0].0, domain);
        assert_eq!(
            store.directly_corroborated_discoveries(now).unwrap(),
            [(domain.to_string(), None)]
        );
        assert!(store
            .directly_corroborated_discoveries(now + 8 * 86_400)
            .unwrap()
            .is_empty());
        reading.final_host = Some("different.example".to_owned());
        store
            .save_page_discovery(domain, &reading, now, "page")
            .unwrap();
        assert!(store
            .directly_corroborated_discoveries(now)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn discovery_cache_delays_retry_and_leaves_the_threat_verdict_unchanged() {
        let (_dir, store) = store();
        let domain = "ordinary.example";
        store.observe(domain).unwrap();
        store
            .save_verdict(
                crate::backend::Channel::Threat,
                domain,
                "",
                "",
                "skipped",
                0.0,
                "fasttext",
                "no signal",
                86_400,
            )
            .unwrap();
        let now = now_epoch();
        assert_eq!(
            store
                .page_discovery_candidates(now, 0.5, 4, FusionMode::Monitor)
                .unwrap(),
            [domain]
        );
        let unknown = crate::page::DiscoveryReading {
            final_host: None,
            category: None,
            confidence: None,
            enforcement_eligible: false,
            evidence: "unavailable".to_owned(),
        };
        store
            .save_page_discovery(domain, &unknown, now, "test-version")
            .unwrap();
        assert!(store
            .page_discovery_candidates(now, 0.5, 4, FusionMode::Monitor)
            .unwrap()
            .is_empty());
        let report = store.page_discovery(domain, now).unwrap().unwrap();
        assert!(report.reading.confidence.is_none());
        assert_eq!(report.retry_at, now + 3_600);
        assert_eq!(
            store
                .page_discovery_candidates(report.retry_at, 0.5, 4, FusionMode::Monitor)
                .unwrap(),
            [domain]
        );
        let finding = crate::page::DiscoveryReading {
            final_host: Some(domain.to_owned()),
            category: Some("phishing".to_owned()),
            confidence: Some(0.9),
            enforcement_eligible: false,
            evidence: "two page cues".to_owned(),
        };
        store
            .save_page_discovery(domain, &finding, now, "test-version")
            .unwrap();
        assert_eq!(
            store.page_discovery(domain, now).unwrap().unwrap().retry_at,
            now + 86_400
        );
        assert_eq!(status(&store, domain), "skipped");
        assert!(store
            .fresh_blocked(now, 0.5, daygle_dns_core::config::FusionMode::Decide)
            .unwrap()
            .is_empty());
    }

    fn threat(store: &AiStore, domain: &str, evidence: &str) {
        store.observe(domain).unwrap();
        store
            .save_verdict(
                crate::backend::Channel::Threat,
                domain,
                "phishing",
                "threat",
                "classified",
                0.995,
                "fasttext",
                evidence,
                86_400,
            )
            .unwrap();
    }

    fn status(store: &AiStore, domain: &str) -> String {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT status FROM ai_verdicts WHERE domain = ?1 AND channel = 'threat'",
                params![domain],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// A threat on a domain that has since become established goes back to
    /// the queue (to be disputed); a listed one stays, a feed outranks it.
    #[test]
    fn threats_on_newly_established_domains_are_rechecked() {
        let (_dir, store) = store();
        let now = now_epoch();
        let clients: Vec<String> = (0..4).map(|i| format!("10.0.0.{i}")).collect();
        for domain in ["relied-on.example", "listed.example", "rare.example"] {
            let days = if domain == "rare.example" {
                2
            } else {
                ESTABLISHED_DAYS
            };
            for d in 0..days {
                store
                    .record_sightings_at(
                        &[(domain.to_string(), clients.clone())],
                        now - (days - d) * 86_400,
                    )
                    .unwrap();
            }
        }
        threat(&store, "relied-on.example", "model");
        threat(
            &store,
            "listed.example",
            "model, listed by Phishing Army as phishing",
        );
        threat(&store, "rare.example", "model");
        assert_eq!(store.requeue_newly_established().unwrap(), 1);
        assert_eq!(status(&store, "relied-on.example"), "pending");
        assert_eq!(status(&store, "listed.example"), "classified");
        assert_eq!(status(&store, "rare.example"), "classified");
    }

    /// After a model change, verdicts on domains still in use are re-checked
    /// within the window; one nobody looked up again keeps its lifetime.
    #[test]
    fn a_model_change_brings_rechecks_forward_for_domains_in_use() {
        let (_dir, store) = store();
        let now = now_epoch();
        threat(&store, "in-use.example", "model");
        threat(&store, "forgotten.example", "model");
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "UPDATE ai_verdicts SET classified_at = ?1 - 100, expires_at = ?1 + 90 * 86400",
                params![now],
            )
            .unwrap();
            conn.execute(
                "UPDATE ai_verdicts SET last_seen = ?1 WHERE domain = 'in-use.example'",
                params![now],
            )
            .unwrap();
            conn.execute(
                "UPDATE ai_verdicts SET last_seen = ?1 - 200 WHERE domain = 'forgotten.example'",
                params![now],
            )
            .unwrap();
        }
        let window = 3 * 86_400;
        assert_eq!(store.stagger_rechecks(now, window).unwrap(), 1);
        let expiry = |domain: &str| -> i64 {
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT expires_at FROM ai_verdicts WHERE domain = ?1 AND channel = 'threat'",
                    params![domain],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let brought = expiry("in-use.example");
        assert!(brought > now && brought <= now + window + 3600, "{brought}");
        assert_eq!(expiry("forgotten.example"), now + 90 * 86_400);
        // Running it again does not push a verdict later.
        store.stagger_rechecks(now, window).unwrap();
        assert_eq!(expiry("in-use.example"), brought);
    }

    #[test]
    fn a_domain_becomes_established_over_days_and_clients() {
        let (_dir, store) = store();
        let start = 1_700_000_000;
        let clients = |n: usize| (0..n).map(|i| format!("10.0.0.{i}")).collect::<Vec<_>>();
        for d in 0..ESTABLISHED_DAYS - 1 {
            store
                .record_sightings_at(&[("mail.example".into(), clients(4))], start + d * 86_400)
                .unwrap();
            // A second sighting the same day is not another day.
            store
                .record_sightings_at(
                    &[("mail.example".into(), clients(1))],
                    start + d * 86_400 + 60,
                )
                .unwrap();
        }
        let seen = store.sighting("mail.example").unwrap().unwrap();
        assert_eq!(seen.days, ESTABLISHED_DAYS - 1);
        assert_eq!(seen.clients, 4);
        assert!(!seen.established());
        store
            .record_sightings_at(
                &[("mail.example".into(), clients(1))],
                start + ESTABLISHED_DAYS * 86_400,
            )
            .unwrap();
        assert!(store
            .sighting("mail.example")
            .unwrap()
            .unwrap()
            .established());
        assert_eq!(store.established_domains(10).unwrap(), vec!["mail.example"]);

        // One client, however long, is not the network.
        for d in 0..ESTABLISHED_DAYS + 2 {
            store
                .record_sightings_at(&[("beacon.example".into(), clients(1))], start + d * 86_400)
                .unwrap();
        }
        assert!(!store
            .sighting("beacon.example")
            .unwrap()
            .unwrap()
            .established());
    }

    #[test]
    fn clients_are_capped_and_hashed() {
        let (_dir, store) = store();
        let many: Vec<String> = (0..40).map(|i| format!("192.0.2.{i}")).collect();
        store
            .record_sightings(&[("cdn.example".into(), many)])
            .unwrap();
        assert_eq!(
            store.sighting("cdn.example").unwrap().unwrap().clients,
            MAX_CLIENTS_KEPT
        );
        let conn = store.lock().unwrap();
        let raw: String = conn
            .query_row("SELECT clients FROM ai_seen", [], |r| r.get(0))
            .unwrap();
        assert!(!raw.contains("192.0.2"), "addresses are not stored");
    }

    #[test]
    fn feeds_replace_their_own_names_only() {
        let (_dir, store) = store();
        let set = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>();
        store
            .replace_intel(
                "phish",
                &set(&["bad.example", "*.worse.example", "com", "@@ok.example"]),
            )
            .unwrap();
        store
            .replace_intel("scam", &set(&["fake.example"]))
            .unwrap();
        let mut entries = store.intel_entries().unwrap();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                ("bad.example".into(), false, "phish".into()),
                ("fake.example".into(), false, "scam".into()),
                ("worse.example".into(), true, "phish".into()),
            ]
        );
        store
            .replace_intel("phish", &set(&["new.example"]))
            .unwrap();
        assert_eq!(store.intel_entries().unwrap().len(), 2);
        store.intel_failed("phish", "timed out").unwrap();
        let feeds = store.intel_feeds().unwrap();
        assert_eq!(feeds["phish"].entries, 1);
        assert_eq!(feeds["phish"].error, "timed out");
        assert!(feeds["phish"].updated_at > 0);
    }

    #[test]
    fn page_texts_are_truncated() {
        let (_dir, store) = store();
        store
            .save_page_text("a.example", "Title", &"x".repeat(PAGE_TEXT_CHARS * 2))
            .unwrap();
        let texts = store.page_texts().unwrap();
        assert_eq!(texts[0].2.len(), PAGE_TEXT_CHARS);
    }
}
