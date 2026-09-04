//! In-memory log ring buffer exposed through the REST API and GUI.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

/// Severity of a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// One log line.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    /// Wall-clock timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    /// Free-form component/subsystem tag, e.g. `recursive`.
    pub component: String,
    pub message: String,
}

/// Bounded in-memory log buffer. Newest entries are appended; once full the
/// oldest entries are dropped.
#[derive(Debug)]
pub struct LogStore {
    inner: Mutex<VecDeque<LogEntry>>,
    capacity: usize,
}

impl LogStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity: capacity.max(1),
        }
    }

    /// Append an entry, dropping the oldest entry if the buffer is full.
    ///
    /// Messages are stored sentence-cased (first letter capitalized) so the
    /// Logs page reads consistently no matter how a subsystem phrased its
    /// message; everything after the first character is left untouched.
    pub fn push(&self, level: LogLevel, component: &str, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            component: component.to_string(),
            message: sentence_case(&message.into()),
        };
        let mut inner = self.inner.lock();
        if inner.len() >= self.capacity {
            inner.pop_front();
        }
        inner.push_back(entry);
    }

    /// Convenience helpers.
    pub fn info(&self, component: &str, message: impl Into<String>) {
        self.push(LogLevel::Info, component, message);
    }
    pub fn warn(&self, component: &str, message: impl Into<String>) {
        self.push(LogLevel::Warn, component, message);
    }
    pub fn error(&self, component: &str, message: impl Into<String>) {
        self.push(LogLevel::Error, component, message);
    }

    /// All entries, oldest first.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.inner.lock().iter().cloned().collect()
    }

    /// Most recent `n` entries, oldest first.
    pub fn tail(&self, n: usize) -> Vec<LogEntry> {
        let inner = self.inner.lock();
        let skip = inner.len().saturating_sub(n);
        inner.iter().skip(skip).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.lock().clear();
    }
}

/// Uppercase the first alphabetic character of `message`, leaving the rest
/// untouched (messages often start with an IP, a path or a quote).
fn sentence_case(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) if first.is_alphabetic() => {
            first.to_uppercase().collect::<String>() + chars.as_str()
        }
        _ => message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_entries_in_order() {
        let store = LogStore::new(10);
        store.info("a", "first");
        store.warn("b", "second");
        let entries = store.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "First");
        assert_eq!(entries[1].component, "b");
    }

    #[test]
    fn bounds_the_buffer() {
        let store = LogStore::new(3);
        for i in 0..5 {
            store.info("x", format!("m{i}"));
        }
        let entries = store.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "M2");
        assert_eq!(entries[2].message, "M4");
    }

    #[test]
    fn sentence_cases_messages_on_push() {
        let store = LogStore::new(10);
        store.info("api", "settings updated via the console");
        store.warn("reload", "DNS listeners rebound");
        store.error("api", "'quoted' message keeps its punctuation");
        store.info("api", "127.0.0.1:53 does not get capitalized");
        let entries = store.entries();
        assert_eq!(entries[0].message, "Settings updated via the console");
        assert_eq!(entries[1].message, "DNS listeners rebound");
        assert_eq!(entries[2].message, "'quoted' message keeps its punctuation");
        assert_eq!(entries[3].message, "127.0.0.1:53 does not get capitalized");
    }

    #[test]
    fn tail_returns_recent_only() {
        let store = LogStore::new(10);
        for i in 0..10 {
            store.info("x", format!("m{i}"));
        }
        let tail = store.tail(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].message, "M7");
    }
}
