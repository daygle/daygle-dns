//! Asynchronous database query-log sink.
//!
//! [`QueryDbLogger`] accepts entries on the DNS query path via [`Self::log`],
//! which only pushes into a bounded channel (never touching SQLite), and a
//! background task drains that channel in batches through
//! `ZoneStore::insert_query_logs`. When the channel is full the entry is
//! dropped and a counter is bumped - a logging backlog can never slow queries
//! down. Retention (`logging.query_db_max_rows` and
//! `logging.query_db_retention_days`) is enforced by the same writer task.
//!
//! The `[logging]` settings are read from the live configuration, so turning
//! the database log on or off and changing its retention in the console
//! apply at once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::DaygleConfig;
use tokio::sync::mpsc;
use tracing::debug;

/// Channel capacity. At the default batch interval this absorbs bursts of a
/// few thousand queries per second; beyond that, entries are dropped (see
/// [`Self::dropped`]).
const CHANNEL_CAPACITY: usize = 8192;

/// Rows buffered before an early flush (latency bound for quiet servers).
const BATCH_MAX_ROWS: usize = 512;

/// Writer ticks (500 ms each) between age-based trims: once a minute.
const AGE_TRIM_TICKS: u32 = 120;

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
    /// Why it was blocked, for blocked queries.
    pub block: Option<daygle_dns_core::block_log::BlockReason>,
}

/// Async query-log writer. Cloneable handle for the dispatcher.
#[derive(Clone)]
pub struct QueryDbLogger {
    tx: mpsc::Sender<QueryDbEntry>,
    dropped: Arc<AtomicU64>,
    config: Arc<ArcSwap<DaygleConfig>>,
}

impl QueryDbLogger {
    /// Create the logger and spawn its background writer against `store`.
    /// The writer stops when every handle is dropped or `shutdown` fires.
    pub fn spawn(
        store: daygle_dns_authoritative::ZoneStore,
        config: Arc<ArcSwap<DaygleConfig>>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<QueryDbEntry>(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_dropped = Arc::clone(&dropped);
        let handle = Self {
            tx,
            dropped,
            config: Arc::clone(&config),
        };
        tokio::spawn(async move {
            run_writer(store, config, rx, shutdown, writer_dropped).await;
        });
        handle
    }

    /// Queue one entry, when the database log is on. Never blocks; drops
    /// (counted) under pressure.
    pub fn log(&self, entry: QueryDbEntry) {
        if !self.config.load().logging.query_db_enabled {
            return;
        }
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
    config: Arc<ArcSwap<DaygleConfig>>,
    mut rx: mpsc::Receiver<QueryDbEntry>,
    shutdown: tokio_util::sync::CancellationToken,
    dropped: Arc<AtomicU64>,
) {
    // Wake at most twice a second, or sooner when a full batch is queued.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending: Vec<daygle_dns_authoritative::QueryLogRow> =
        Vec::with_capacity(BATCH_MAX_ROWS);
    // Trim by age on the first tick, then once a minute.
    let mut ticks_to_age_trim = 0u32;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                // Final flush, best-effort.
                flush(&store, &mut pending).await;
                break;
            }
            _ = tick.tick() => {
                flush(&store, &mut pending).await;
                let logging = config.load().logging.clone();
                trim(&store, logging.query_db_max_rows).await;
                if ticks_to_age_trim == 0 {
                    trim_by_age(&store, logging.query_db_retention_days).await;
                    ticks_to_age_trim = AGE_TRIM_TICKS;
                }
                ticks_to_age_trim -= 1;
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
                            block: entry.block,
                        });
                        if pending.len() >= BATCH_MAX_ROWS {
                            flush(&store, &mut pending).await;
                        }
                    }
                    // All handles dropped: final flush and exit.
                    None => {
                        flush(&store, &mut pending).await;
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

/// Write one batch of rows. The SQLite INSERT txn is synchronous work on a
/// shared connection, so it runs on a blocking thread to keep async workers
/// free for query serving.
async fn flush(
    store: &daygle_dns_authoritative::ZoneStore,
    pending: &mut Vec<daygle_dns_authoritative::QueryLogRow>,
) {
    if pending.is_empty() {
        return;
    }
    let batch = std::mem::take(pending);
    let res = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.insert_query_logs(&batch)
    })
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => debug!(error = %e, "query db log write failed; batch dropped"),
        Err(e) => debug!(error = %e, "query db log write join failed; batch dropped"),
    }
}

/// Opportunistically keep the query-log table bounded (`query_db_max_rows`).
/// Cheap enough at the 2 Hz cadence, and like `flush` runs off the async
/// runtime. 0 keeps everything.
async fn trim(store: &daygle_dns_authoritative::ZoneStore, max_rows: usize) {
    if max_rows == 0 {
        return;
    }
    let res = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.trim_query_logs(max_rows)
    })
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => debug!(error = %e, "query db log trim failed"),
        Err(e) => debug!(error = %e, "query db log trim join failed"),
    }
}

/// Delete rows older than `days` (0 keeps them). Runs off the async runtime.
async fn trim_by_age(store: &daygle_dns_authoritative::ZoneStore, days: u32) {
    if days == 0 {
        return;
    }
    let before = (chrono::Utc::now() - chrono::Duration::days(i64::from(days))).to_rfc3339();
    let res = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.delete_query_logs_before(&before)
    })
    .await;
    match res {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => debug!(error = %e, "query db log age trim failed"),
        Err(e) => debug!(error = %e, "query db log age trim join failed"),
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
            block: None,
        }
    }

    fn config(max_rows: usize, days: u32, enabled: bool) -> Arc<ArcSwap<DaygleConfig>> {
        let mut config = DaygleConfig::default();
        config.logging.query_db_enabled = enabled;
        config.logging.query_db_max_rows = max_rows;
        config.logging.query_db_retention_days = days;
        Arc::new(ArcSwap::from_pointee(config))
    }

    async fn count_settles_at(store: &daygle_dns_authoritative::ZoneStore, want: u64) -> u64 {
        let mut count = 0u64;
        for _ in 0..40 {
            let (_, c) = store.search_query_logs(&Default::default()).unwrap();
            count = c;
            if count == want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        count
    }

    #[tokio::test]
    async fn age_limit_and_switch_follow_the_live_config() {
        let store = daygle_dns_authoritative::ZoneStore::open(":memory:").unwrap();
        let old = daygle_dns_authoritative::QueryLogRow {
            id: 0,
            ts: (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339(),
            client: "127.0.0.1".to_string(),
            qname: "old.example".to_string(),
            qtype: "A".to_string(),
            protocol: "udp".to_string(),
            outcome: "recursive".to_string(),
            rcode: None,
            elapsed_ms: 1,
            block: None,
        };
        store.insert_query_logs(&[old]).unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let live = config(0, 7, false);
        let logger = QueryDbLogger::spawn(store.clone(), live.clone(), shutdown.clone());
        // Off: nothing is written. The 10-day-old row goes on the first tick.
        logger.log(entry("skipped.example"));
        assert_eq!(
            count_settles_at(&store, 0).await,
            0,
            "old row trimmed, off logs nothing"
        );
        // Switched on in the console: logged from then on.
        live.store(config(0, 7, true).load_full());
        logger.log(entry("kept.example"));
        assert_eq!(count_settles_at(&store, 1).await, 1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn writes_and_trims_through_the_channel() {
        let store = daygle_dns_authoritative::ZoneStore::open(":memory:").unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let logger = QueryDbLogger::spawn(store.clone(), config(10, 0, true), shutdown.clone());
        for i in 0..25 {
            logger.log(entry(&format!("name{i}.example")));
        }
        // Wait for the writer to drain and trim (flush ticks every 500 ms).
        let count = count_settles_at(&store, 10).await;
        assert_eq!(count, 10, "retention cap keeps only the newest rows");
        shutdown.cancel();
    }
}
