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
    pub fn push(&self, level: LogLevel, component: &str, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            component: component.to_string(),
            message: message.into(),
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
        assert_eq!(entries[0].message, "first");
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
        assert_eq!(entries[0].message, "m2");
        assert_eq!(entries[2].message, "m4");
    }

    #[test]
    fn tail_returns_recent_only() {
        let store = LogStore::new(10);
        for i in 0..10 {
            store.info("x", format!("m{i}"));
        }
        let tail = store.tail(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].message, "m7");
    }
}
