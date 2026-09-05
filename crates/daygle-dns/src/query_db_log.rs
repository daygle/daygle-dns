//! Asynchronous database query-log sink.
//!
//! [`QueryDbLogger`] accepts entries on the DNS query path via [`Self::log`],
//! which only pushes into a bounded channel (never touching SQLite), and a
//! background task drains that channel in batches through
//! `ZoneStore::insert_query_logs`. When the channel is full the entry is
//! dropped and a counter is bumped — a logging backlog can never slow queries
//! down. Retention (`logging.query_db_max_rows`) is enforced opportunistically
//! by the same writer task.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::debug;

/// Channel capacity. At the default batch interval this absorbs bursts of a
/// few thousand queries per second; beyond that, entries are dropped (see
/// [`Self::dropped`]).
const CHANNEL_CAPACITY: usize = 8192;

/// Rows buffered before an early flush (latency bound for quiet servers).
const BATCH_MAX_ROWS: usize = 512;

/// One queued query-log entry (pre-insert shape; the id is assigned by SQLite).
pub struct QueryDbEntry {
    pub ts: String,
    pub client: String,
    pub qname: String,
    pub qtype: String,
    pub protocol: String,
    pub outcome: String,
    pub rcode: Option<String>,
    pub elapsed_ms: u64,
}

/// Async query-log writer. Cloneable handle for the dispatcher.
#[derive(Clone)]
pub struct QueryDbLogger {
    tx: mpsc::Sender<QueryDbEntry>,
    dropped: Arc<AtomicU64>,
}

impl QueryDbLogger {
    /// Create the logger and spawn its background writer against `store`.
    /// The writer stops when every handle is dropped or `shutdown` fires.
    pub fn spawn(
        store: daygle_dns_authoritative::ZoneStore,
        max_rows: usize,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<QueryDbEntry>(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_dropped = Arc::clone(&dropped);
        let handle = Self { tx, dropped };
        tokio::spawn(async move {
            run_writer(store, max_rows, rx, shutdown, writer_dropped).await;
        });
        handle
    }

    /// Queue one entry. Never blocks; drops (counted) under pressure.
    pub fn log(&self, entry: QueryDbEntry) {
        if self.tx.try_send(entry).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Entries dropped because the channel was full since startup.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn run_writer(
    store: daygle_dns_authoritative::ZoneStore,
    max_rows: usize,
    mut rx: mpsc::Receiver<QueryDbEntry>,
    shutdown: tokio_util::sync::CancellationToken,
    dropped: Arc<AtomicU64>,
) {
    // Wake at most twice a second, or sooner when a full batch is queued.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending: Vec<daygle_dns_authoritative::QueryLogRow> = Vec::with_capacity(BATCH_MAX_ROWS);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                // Final flush, best-effort.
                flush(&store, &mut pending);
                break;
            }
            _ = tick.tick() => {
                flush(&store, &mut pending);
                trim(&store, max_rows);
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(entry) => {
                        pending.push(daygle_dns_authoritative::QueryLogRow {
                            id: 0,
                            ts: entry.ts,
                            client: entry.client,
                            qname: entry.qname,
                            qtype: entry.qtype,
                            protocol: entry.protocol,
                            outcome: entry.outcome,
                            rcode: entry.rcode,
                            elapsed_ms: entry.elapsed_ms as i64,
                        });
                        if pending.len() >= BATCH_MAX_ROWS {
                            flush(&store, &mut pending);
                        }
                    }
                    // All handles dropped: final flush and exit.
                    None => {
                        flush(&store, &mut pending);
                        break;
                    }
                }
            }
        }
    }
    let lost = dropped.load(Ordering::Relaxed);
    if lost > 0 {
        debug!(dropped = lost, "query db logger dropped entries under load");
    }
}

fn flush(store: &daygle_dns_authoritative::ZoneStore, pending: &mut Vec<daygle_dns_authoritative::QueryLogRow>) {
    if pending.is_empty() {
        return;
    }
    if let Err(e) = store.insert_query_logs(pending) {
        debug!(error = %e, "query db log write failed; batch dropped");
    }
    pending.clear();
}

fn trim(store: &daygle_dns_authoritative::ZoneStore, max_rows: usize) {
    if max_rows == 0 {
        return;
    }
    // Cheap enough at a 2 Hz cadence and keeps the table bounded forever.
    if let Err(e) = store.trim_query_logs(max_rows) {
        debug!(error = %e, "query db log trim failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(qname: &str) -> QueryDbEntry {
        QueryDbEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            client: "127.0.0.1".to_string(),
            qname: qname.to_string(),
            qtype: "A".to_string(),
            protocol: "udp".to_string(),
            outcome: "authoritative".to_string(),
            rcode: Some("NOERROR".to_string()),
            elapsed_ms: 1,
        }
    }

    #[tokio::test]
    async fn writes_and_trims_through_the_channel() {
        let store = daygle_dns_authoritative::ZoneStore::open(":memory:").unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let logger = QueryDbLogger::spawn(store.clone(), 10, shutdown.clone());
        for i in 0..25 {
            logger.log(entry(&format!("name{i}.example")));
        }
        // Wait for the writer to drain and trim (flush ticks every 500 ms).
        let mut count = 0u64;
        for _ in 0..40 {
            let (_, c) = store.search_query_logs(&Default::default()).unwrap();
            count = c;
            if count == 10 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(count, 10, "retention cap keeps only the newest rows");
        shutdown.cancel();
    }
}
