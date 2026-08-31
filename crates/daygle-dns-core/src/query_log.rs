//! Persistent query logging: daily JSON-lines files with rotation.
//!
//! [`QueryLogger`] appends one JSON object per served query to
//! `queries-YYYY-MM-DD.log` inside the configured directory (Technitium-style
//! query logs). Files rotate automatically at UTC midnight; files older than
//! `retention_days` are deleted during rotation (0 keeps every file).
//!
//! Logging is best-effort: a write or open failure logs once via `tracing`
//! and disables the logger for the process lifetime so a broken log directory
//! can never take DNS down with it.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{Datelike, Utc};
use serde::Serialize;
use tracing::{info, warn};

/// Cap on how large a single log line may be (long TXT payloads are
/// truncated defensively; query names never exceed 255 bytes anyway).
const MAX_LINE_BYTES: usize = 8 * 1024;

/// One persisted query-log entry (JSON per line).
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Client IP.
    pub client: String,
    /// Query name (lowercased, no trailing dot).
    pub qname: String,
    /// Query type string (`A`, `AAAA`, ...).
    pub qtype: String,
    /// Outcome classification (`authoritative`, `recursive`, `blocked`, ...).
    pub outcome: String,
    /// Response code (`NOERROR`, `NXDOMAIN`, ...) when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    /// Server-side handling time in milliseconds.
    pub elapsed_ms: u64,
}

struct Inner {
    dir: PathBuf,
    retention_days: u32,
    /// `None` once a write/open has failed (logger disabled).
    writer: Option<(String, BufWriter<File>)>,
}

impl Drop for Inner {
    /// Flush the current file so buffered lines never sit in memory when the
    /// logger is dropped (tests and graceful shutdown rely on this).
    fn drop(&mut self) {
        if let Some((_, w)) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }
}

/// Persistent per-query logger with daily file rotation.
pub struct QueryLogger {
    inner: Mutex<Inner>,
}

impl QueryLogger {
    /// Create a logger writing into `dir`, deleting files older than
    /// `retention_days` at rotation (0 = keep forever).
    pub fn new(dir: &Path, retention_days: u32) -> Self {
        Self {
            inner: Mutex::new(Inner {
                dir: dir.to_path_buf(),
                retention_days,
                writer: None,
            }),
        }
    }

    /// Append one query. Never panics; on I/O failure the logger disables
    /// itself after a single warning.
    pub fn log(&self, entry: &QueryLogEntry) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if inner.writer.is_none() {
            // First log or the logger was disabled by a previous failure:
            // (re)open today's file below.
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let needs_rotation = inner
            .writer
            .as_ref()
            .map(|(day, _)| day.as_str() != today)
            .unwrap_or(true);
        if needs_rotation {
            match open_log_file(&inner.dir, &today) {
                Ok(file) => {
                    if let Some((_, w)) = inner.writer.as_mut() {
                        let _ = w.flush();
                    }
                    inner.writer = Some((today.clone(), BufWriter::new(file)));
                    info!(dir = %inner.dir.display(), file = %today, "query log opened");
                    sweep_old_logs(&inner.dir, inner.retention_days);
                }
                Err(e) => {
                    warn!(
                        dir = %inner.dir.display(),
                        error = %e,
                        "query log open failed; persistent query logging disabled"
                    );
                    inner.writer = None;
                    return;
                }
            }
        }

        let Some((_, writer)) = inner.writer.as_mut() else {
            return;
        };
        if let Err(e) = write_line(writer, entry) {
            warn!(error = %e, "query log write failed; persistent query logging disabled");
            inner.writer = None;
        }
    }

    /// Whether the logger is still able to write (used by tests).
    pub fn is_active(&self) -> bool {
        self.inner.lock().map(|i| i.writer.is_some()).unwrap_or(false)
    }
}

fn open_log_file(dir: &Path, day: &str) -> std::io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(format!("queries-{day}.log")))
}

/// Serialize `entry` as a single JSON line.
fn write_line(w: &mut BufWriter<File>, entry: &QueryLogEntry) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if line.len() > MAX_LINE_BYTES {
        line.truncate(MAX_LINE_BYTES);
    }
    line.push(b'\n');
    w.write_all(&line)?;
    // Flush eagerly: a crash must not lose the log tail (queries are low-rate
    // compared to disk throughput, and BufWriter already coalesces bursts).
    w.flush()
}

/// Delete `queries-*.log` files older than `retention_days` (0 = keep all).
fn sweep_old_logs(dir: &Path, retention_days: u32) {
    if retention_days == 0 {
        return;
    }
    let cutoff = Utc::now().num_days_from_ce() - i32::try_from(retention_days).unwrap_or(i32::MAX);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(day) = name
            .strip_prefix("queries-")
            .and_then(|s| s.strip_suffix(".log"))
        else {
            continue;
        };
        // Parse YYYY-MM-DD into a day count.
        let parts: Vec<&str> = day.split('-').collect();
        if parts.len() != 3 {
            continue;
        }
        let (Ok(y), Ok(m), Ok(d)) = (
            parts[0].parse::<i32>(),
            parts[1].parse::<u32>(),
            parts[2].parse::<u32>(),
        ) else {
            continue;
        };
        #[allow(clippy::type_complexity)]
        let _ = (&y, &m, &d);
        let days = chrono::NaiveDate::from_ymd_opt(y, m, d)
            .map(|date| date.num_days_from_ce())
            .unwrap_or(i32::MAX);
        if days < cutoff {
            if let Err(e) = std::fs::remove_file(entry.path()) {
                warn!(file = %name, error = %e, "failed to delete old query log");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(qname: &str) -> QueryLogEntry {
        QueryLogEntry {
            ts: Utc::now().to_rfc3339(),
            client: "127.0.0.1".to_string(),
            qname: qname.to_string(),
            qtype: "A".to_string(),
            outcome: "recursive".to_string(),
            rcode: Some("NOERROR".to_string()),
            elapsed_ms: 3,
        }
    }

    #[test]
    fn writes_daily_file_with_lines() {
        let dir = tempfile::tempdir().unwrap();
        let logger = QueryLogger::new(dir.path(), 30);
        for _ in 0..3 {
            logger.log(&entry("a.example"));
        }
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("queries-{today}.log"));
        assert!(path.exists(), "today's log file must exist");

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["qname"], "a.example");
        assert_eq!(first["outcome"], "recursive");
    }

    #[test]
    fn disabled_after_io_failure() {
        // A path *inside a file* makes create_dir_all fail deterministically.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let logger = QueryLogger::new(&blocker.join("logs"), 30);
        logger.log(&entry("a.example"));
        assert!(!logger.is_active(), "logger must disable itself on failure");
        // Further logs are silently ignored (no panic).
        logger.log(&entry("b.example"));
    }

    #[test]
    fn retention_sweep_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        // Fabricate a 40-day-old log file.
        let old_date = Utc::now() - chrono::Duration::days(40);
        let old_name = format!(
            "queries-{:04}-{:02}-{:02}.log",
            old_date.year(),
            old_date.month(),
            old_date.day()
        );
        std::fs::write(dir.path().join(&old_name), b"{}\n").unwrap();
        sweep_old_logs(dir.path(), 30);
        assert!(!dir.path().join(old_name).exists(), "old file must be swept");
    }

    #[test]
    fn retention_zero_keeps_files() {
        let dir = tempfile::tempdir().unwrap();
        let old_date = Utc::now() - chrono::Duration::days(400);
        let old_name = format!(
            "queries-{:04}-{:02}-{:02}.log",
            old_date.year(),
            old_date.month(),
            old_date.day()
        );
        std::fs::write(dir.path().join(&old_name), b"{}\n").unwrap();
        sweep_old_logs(dir.path(), 0);
        assert!(dir.path().join(old_name).exists(), "retention 0 keeps files");
    }
}
