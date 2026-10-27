//! Query export: every answered query, as a JSON object, POSTed in batches
//! to an HTTP(S) endpoint (a log collector such as Vector, Fluent Bit,
//! Logstash or Splunk HEC). The `[log_export]` settings are read for every
//! batch, so a change in Settings applies at once.
//!
//! Queries go through a bounded queue to one background task, so exporting
//! never slows a query down. A batch that cannot be delivered is retried a
//! few times and then dropped; drops (a full queue or a failed batch) are
//! counted and reported in the server log once the endpoint answers again.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_dns_core::config::{DaygleConfig, LogExportSettings};
use daygle_dns_core::LogStore;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Queued queries before new ones are dropped.
const QUEUE: usize = 16_384;
/// How long one POST may take.
const TIMEOUT: Duration = Duration::from_secs(15);
/// Delivery attempts per batch.
const ATTEMPTS: u32 = 3;
/// Wait before the first retry (doubled for each further one).
const RETRY_AFTER: Duration = Duration::from_secs(2);

/// One answered query, as exported.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QueryEvent {
    /// RFC 3339, milliseconds, UTC.
    pub time: String,
    /// This server's host name.
    pub server: String,
    pub client: String,
    pub qname: String,
    pub qtype: String,
    /// `udp`, `tcp`, `tls`, `https`, `quic` or `h3`.
    pub protocol: String,
    /// `recursive`, `authoritative`, `blocked`, `cached`, ...
    pub outcome: String,
    /// `NOERROR`, `NXDOMAIN`, ... when known.
    pub rcode: Option<String>,
    pub elapsed_ms: u64,
}

/// Counters for the console.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ExportStatus {
    /// Queries delivered since start.
    pub sent: u64,
    /// Queries dropped since start (queue full or endpoint unreachable).
    pub dropped: u64,
    /// Why the last batch failed, while the endpoint keeps failing.
    pub last_error: Option<String>,
}

pub struct LogExporter {
    tx: mpsc::Sender<QueryEvent>,
    config: Arc<ArcSwap<DaygleConfig>>,
    server: String,
    sent: AtomicU64,
    dropped: AtomicU64,
    /// Drops not yet reported in the server log.
    unreported: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl LogExporter {
    /// Start the exporter. It does nothing until `[log_export]` is enabled.
    pub fn start(
        config: Arc<ArcSwap<DaygleConfig>>,
        logs: Arc<LogStore>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE);
        let exporter = Arc::new(Self {
            tx,
            config,
            server: daygle_dns_core::config::detect_server_name().unwrap_or_default(),
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            unreported: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        tokio::spawn(run(exporter.clone(), rx, logs, shutdown));
        exporter
    }

    /// Whether queries are being exported (checked before building one).
    pub fn enabled(&self) -> bool {
        self.config.load().log_export.enabled
    }

    /// Queue one answered query. Never blocks; drops (counted) when the
    /// queue is full.
    #[allow(clippy::too_many_arguments)]
    pub fn query(
        &self,
        client: std::net::IpAddr,
        qname: &str,
        qtype: &str,
        protocol: &str,
        outcome: &str,
        rcode: Option<&str>,
        elapsed_ms: u64,
    ) {
        if !self.enabled() {
            return;
        }
        let event = QueryEvent {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            server: self.server.clone(),
            client: client.to_string(),
            qname: if qname.is_empty() { "." } else { qname }.to_string(),
            qtype: qtype.to_string(),
            protocol: protocol.to_string(),
            outcome: outcome.to_string(),
            rcode: rcode.map(str::to_string),
            elapsed_ms,
        };
        if self.tx.try_send(event).is_err() {
            self.drop_events(1);
        }
    }

    pub fn status(&self) -> ExportStatus {
        ExportStatus {
            sent: self.sent.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }

    fn drop_events(&self, count: u64) {
        self.dropped.fetch_add(count, Ordering::Relaxed);
        self.unreported.fetch_add(count, Ordering::Relaxed);
    }
}

/// The request body for `events` in the configured format.
pub fn body(settings: &LogExportSettings, events: &[QueryEvent]) -> Vec<u8> {
    if settings.json_array() {
        return serde_json::to_vec(events).unwrap_or_default();
    }
    let mut out = Vec::with_capacity(events.len() * 192);
    for event in events {
        if serde_json::to_writer(&mut out, event).is_ok() {
            out.push(b'\n');
        }
    }
    out
}

/// POST one batch; the error says why it was not accepted.
pub async fn post(
    client: &reqwest::Client,
    settings: &LogExportSettings,
    events: &[QueryEvent],
) -> Result<(), String> {
    let content_type = if settings.json_array() {
        "application/json"
    } else {
        "application/x-ndjson"
    };
    let mut request = client
        .post(settings.url.trim())
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(body(settings, events));
    let authorization = settings.authorization.trim();
    if !authorization.is_empty() {
        request = request.header(reqwest::header::AUTHORIZATION, authorization);
    }
    let response = request
        .send()
        .await
        .map_err(|e| crate::alerts::describe(&e))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("the endpoint answered {}", response.status()))
    }
}

/// An HTTP client for exporting.
pub fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

/// A sample query, for the console's test button.
pub fn test_event() -> QueryEvent {
    QueryEvent {
        time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        server: daygle_dns_core::config::detect_server_name().unwrap_or_default(),
        client: "192.0.2.1".to_string(),
        qname: "test.daygle-dns.invalid".to_string(),
        qtype: "A".to_string(),
        protocol: "udp".to_string(),
        outcome: "test".to_string(),
        rcode: Some("NOERROR".to_string()),
        elapsed_ms: 0,
    }
}

async fn run(
    exporter: Arc<LogExporter>,
    mut rx: mpsc::Receiver<QueryEvent>,
    logs: Arc<LogStore>,
    shutdown: CancellationToken,
) {
    let client = match client() {
        Ok(client) => client,
        Err(e) => {
            logs.error(
                "log_export",
                format!("cannot start the query exporter: {e}"),
            );
            return;
        }
    };
    let mut failing = false;
    loop {
        let first = tokio::select! {
            _ = shutdown.cancelled() => return,
            event = rx.recv() => match event {
                Some(event) => event,
                None => return,
            },
        };
        let settings = exporter.config.load().log_export.clone();
        let mut batch = vec![first];
        let deadline = Instant::now() + Duration::from_secs(u64::from(settings.flush_secs.max(1)));
        let mut stopping = false;
        while batch.len() < settings.batch_size.max(1) as usize {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    stopping = true;
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => break,
                event = rx.recv() => match event {
                    Some(event) => batch.push(event),
                    None => {
                        stopping = true;
                        break;
                    }
                },
            }
        }
        // Switched off (or misconfigured) since these were queued.
        if !settings.enabled || settings.check().is_err() {
            if stopping {
                return;
            }
            continue;
        }
        // One attempt only when stopping, so shutdown is not held up.
        let attempts = if stopping { 1 } else { ATTEMPTS };
        let mut result = Err(String::new());
        for attempt in 0..attempts {
            if attempt > 0 {
                let wait = RETRY_AFTER * 2u32.pow(attempt - 1);
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(wait) => {}
                }
            }
            result = post(&client, &settings, &batch).await;
            if result.is_ok() {
                break;
            }
        }
        let count = batch.len() as u64;
        match result {
            Ok(()) => {
                exporter.sent.fetch_add(count, Ordering::Relaxed);
                *exporter
                    .last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                let lost = exporter.unreported.swap(0, Ordering::Relaxed);
                if failing || lost > 0 {
                    logs.info(
                        "log_export",
                        format!(
                            "queries reach {} again; {lost} were dropped meanwhile",
                            settings.url.trim()
                        ),
                    );
                }
                failing = false;
            }
            Err(e) => {
                exporter.drop_events(count);
                if !failing {
                    logs.warn(
                        "log_export",
                        format!("cannot export queries to {}: {e}", settings.url.trim()),
                    );
                }
                failing = true;
                *exporter
                    .last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(e);
            }
        }
        if stopping {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_ndjson_or_an_array() {
        let event = test_event();
        let mut settings = LogExportSettings::default();
        let ndjson = String::from_utf8(body(&settings, &[event.clone(), event.clone()])).unwrap();
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["qname"], "test.daygle-dns.invalid");
        assert_eq!(parsed["rcode"], "NOERROR");
        settings.format = "json".into();
        let array: Vec<serde_json::Value> =
            serde_json::from_slice(&body(&settings, &[event])).unwrap();
        assert_eq!(array.len(), 1);
        assert_eq!(array[0]["outcome"], "test");
    }
}
