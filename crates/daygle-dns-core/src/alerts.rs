//! Alerts: events that need the operator's attention, raised from anywhere
//! in the server and delivered by email and/or webhook.
//!
//! The parts of the server that notice an event call [`raise`]; delivery is
//! installed once at startup with [`set_sender`] (the API crate does the
//! sending, reading the live `[alerts]` settings). Repeats of the same alert
//! are held back for a while so a failure that persists does not flood the
//! inbox, and [`resolve`] re-arms an alert once its cause has cleared.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

/// What an alert is about; each kind can be switched off on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    BlocklistFailure,
    ZoneTransferFailure,
    CertificateExpiry,
    Dnssec,
    UpdateAvailable,
    AiBlocks,
    /// Sent from the console to check the settings.
    Test,
    /// A scheduled report (Settings -> Alerts), not an alert.
    Report,
}

impl AlertKind {
    /// How long a repeat of the same alert is held back.
    fn repeat_after(self) -> Duration {
        const HOUR: u64 = 3600;
        Duration::from_secs(match self {
            Self::BlocklistFailure | Self::ZoneTransferFailure | Self::Dnssec => 6 * HOUR,
            Self::CertificateExpiry => 24 * HOUR,
            // Keyed by version: one alert per release.
            Self::UpdateAvailable => u64::MAX / 4,
            Self::AiBlocks | Self::Test | Self::Report => 0,
        })
    }
}

/// One alert.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    /// Identifies "the same alert" for holding back repeats (e.g. the zone
    /// name for a transfer failure).
    #[serde(skip)]
    pub key: String,
    /// One line, used as the email subject.
    pub title: String,
    /// The details.
    pub message: String,
}

/// Delivers an alert; returns whether it was accepted (alerts on and the
/// kind wanted), so a dropped alert is not counted as sent.
pub type Sender = Box<dyn Fn(&Alert) -> bool + Send + Sync>;

static SENDER: RwLock<Option<Sender>> = RwLock::new(None);
static SENT: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Install the delivery function (once, at startup).
pub fn set_sender(sender: Sender) {
    if let Ok(mut slot) = SENDER.write() {
        *slot = Some(sender);
    }
}

/// Raise an alert. Repeats of `key` are held back for a while after one
/// was delivered.
pub fn raise(
    kind: AlertKind,
    key: impl Into<String>,
    title: impl Into<String>,
    message: impl Into<String>,
) {
    let alert = Alert {
        kind,
        key: key.into(),
        title: title.into(),
        message: message.into(),
    };
    let mut sent = SENT.lock().unwrap_or_else(|e| e.into_inner());
    let sent = sent.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if sent
        .get(&alert.key)
        .is_some_and(|at| now.duration_since(*at) < kind.repeat_after())
    {
        return;
    }
    let delivered = SENDER
        .read()
        .ok()
        .and_then(|slot| slot.as_ref().map(|send| send(&alert)))
        .unwrap_or(false);
    if delivered {
        sent.insert(alert.key, now);
    }
}

/// The cause of `key` has cleared: the next occurrence alerts right away.
pub fn resolve(key: &str) {
    let mut sent = SENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(sent) = sent.as_mut() {
        sent.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn repeats_are_held_back_until_resolved() {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        set_sender(Box::new(move |alert| {
            if alert.key.starts_with("unit-test") {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            true
        }));
        raise(AlertKind::ZoneTransferFailure, "unit-test:zone", "t", "m");
        raise(AlertKind::ZoneTransferFailure, "unit-test:zone", "t", "m");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        resolve("unit-test:zone");
        raise(AlertKind::ZoneTransferFailure, "unit-test:zone", "t", "m");
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // A different key is a different alert.
        raise(AlertKind::ZoneTransferFailure, "unit-test:other", "t", "m");
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
