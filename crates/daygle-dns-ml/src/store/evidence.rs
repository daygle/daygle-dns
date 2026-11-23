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

use daygle_dns_core::error::Result;
use rusqlite::{params, Connection, OptionalExtension};

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
    error        TEXT NOT NULL DEFAULT ''
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
";

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

pub(super) fn prune(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM ai_seen WHERE last_seen < ?1",
        params![now - SEEN_RETENTION_SECS],
    )?;
    conn.execute(
        "DELETE FROM ai_page_texts WHERE domain NOT IN
             (SELECT domain FROM ai_page_texts ORDER BY read_at DESC LIMIT ?1)",
        params![PAGE_TEXTS_KEPT],
    )?;
    Ok(())
}

impl AiStore {
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
                 attempted_at = ?3, error = ''",
            params![feed, stored as i64, now],
        )?;
        tx.commit()?;
        Ok(stored)
    }

    /// Record a failed download of `feed`; its last good names stay.
    pub fn intel_failed(&self, feed: &str, error: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ai_intel_feeds (feed, attempted_at, error) VALUES (?1, ?2, ?3)
             ON CONFLICT(feed) DO UPDATE SET attempted_at = ?2, error = ?3",
            params![feed, now_epoch(), error],
        )?;
        Ok(())
    }

    /// Every feed's download state, by feed id.
    pub fn intel_feeds(&self) -> Result<HashMap<String, FeedState>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT feed, entries, updated_at, attempted_at, error FROM ai_intel_feeds")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    FeedState {
                        entries: r.get::<_, i64>(1)?.max(0) as u64,
                        updated_at: r.get(2)?,
                        attempted_at: r.get(3)?,
                        error: r.get(4)?,
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
