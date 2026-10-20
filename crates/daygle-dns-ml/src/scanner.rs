//! The background scanner: harvests unseen domains from the query log,
//! classifies them off the DNS hot path, persists verdicts with TTLs, and
//! publishes the block snapshot the policy plugin consults.
//!
//! Everything here runs at scan-cycle cadence (default every 5 min) on a
//! bounded thread; DNS latency is never touched. Expiry follows the
//! "verdicts age out" design: expired classified/skipped rows re-enter
//! `pending` and are re-classified on a later cycle; expired threat rows
//! simply drop out of the block snapshot until a fresh verdict exists.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_core::error::Result;
use daygle_dns_core::LogStore;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::backend::{ClassificationInput, DomainClassifier};
use crate::store::AiStore;

/// A domain currently auto-blocked in `enforce` mode.
#[derive(Debug, Clone)]
pub struct ActiveBlock {
    pub category: String,
    pub expires_at: i64,
}

/// Domain → active block; swapped atomically after each scan cycle and on
/// every override change, so the policy plugin's hot path is one map lookup.
pub type BlockSnapshot = HashMap<String, ActiveBlock>;

/// Shared scanner handles (also handed to the policy plugin and API).
pub struct Scanner {
    store: Arc<AiStore>,
    classifier: Box<dyn DomainClassifier + Send + Sync>,
    settings: Arc<ArcSwap<AiSettings>>,
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    logs: Arc<LogStore>,
    /// Queried by the plugin/rescans to confirm mode without another shared
    /// cell.
    pub rescan_notify: Arc<Notify>,
}

impl Scanner {
    pub fn new(
        store: Arc<AiStore>,
        classifier: Box<dyn DomainClassifier + Send + Sync>,
        settings: Arc<ArcSwap<AiSettings>>,
        snapshot: Arc<ArcSwap<BlockSnapshot>>,
        logs: Arc<LogStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            classifier,
            settings,
            snapshot,
            logs,
            rescan_notify: Arc::new(Notify::new()),
        })
    }

    fn log_info(&self, msg: String) {
        self.logs.push(daygle_dns_core::LogLevel::Info, "ai", msg);
    }

    fn log_warn(&self, msg: String) {
        self.logs.push(daygle_dns_core::LogLevel::Warn, "ai", msg);
    }

    /// One scan cycle: expire stale verdicts, classify new observations,
    /// refresh the block snapshot. Exposed publicly so tests drive cycles
    /// without the forever-loop.
    pub fn run_cycle(
        &self,
        since_epoch: i64,
        source: &daygle_dns_authoritative::ZoneStore,
    ) -> Result<usize> {
        let cfg = self.settings.load().clone();
        let now = Utc::now().timestamp();

        // 1. Expiry: stale verdicts re-enter pending.
        let expired = self.store.expire_old(now, cfg.max_domains_per_scan)?;
        if expired > 0 {
            self.log_info(format!("AI expired {expired} verdict(s), re-queued"));
        }

        // 2. Harvest candidate domains since `since_epoch`. `observe`
        //    bumps the counter and reports first sight; return trips are
        //    cheap no-ops for already-classified domains.
        let mut classified_new = 0usize;
        let mut skipped_new = 0usize;
        let mut candidates = 0usize;
        {
            let names =
                source.distinct_recent_query_names(since_epoch, cfg.max_domains_per_scan)?;
            for name in names {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                if !looks_like_domain(&name) {
                    continue;
                }
                if !self.store.observe(&name)? {
                    continue; // already known: verdict pending expiry only
                }
                candidates += 1;
                let input = ClassificationInput::domain_only(name.clone());
                let verdict = self.classifier.classify(&input);
                match verdict {
                    None => {
                        self.store.save_verdict(
                            &name,
                            "",
                            "",
                            "skipped",
                            0.0,
                            self.classifier.name(),
                            "no signal",
                            cfg.category_ttl_secs as i64,
                        )?;
                        skipped_new += 1;
                    }
                    Some(v) if v.confidence < cfg.confidence_floor => {
                        self.store.save_verdict(
                            &name,
                            &v.category,
                            severity_name(v.severity),
                            "skipped",
                            v.confidence,
                            self.classifier.name(),
                            &v.evidence,
                            cfg.category_ttl_secs as i64,
                        )?;
                        skipped_new += 1;
                    }
                    Some(v) => {
                        let ttl = if v.severity == crate::backend::Severity::Threat {
                            cfg.threat_ttl_secs
                        } else {
                            cfg.category_ttl_secs
                        } as i64;
                        self.store.save_verdict(
                            &name,
                            &v.category,
                            severity_name(v.severity),
                            "classified",
                            v.confidence,
                            self.classifier.name(),
                            &v.evidence,
                            ttl,
                        )?;
                        classified_new += 1;
                    }
                }
            }
        }

        if classified_new == 0 && skipped_new == 0 {
            self.refresh_snapshot(&cfg, now);
            return Ok(0);
        }

        self.log_info(format!(
            "AI scanned {candidates} new domain(s): {classified_new} classified, {skipped_new} skipped"
        ));

        // 4. Refresh the block snapshot.
        self.refresh_snapshot(&cfg, Utc::now().timestamp());
        Ok(classified_new)
    }

    /// Categories the loaded backend can emit, for console pickers.
    pub fn categories(&self) -> Vec<String> {
        self.classifier.categories()
    }

    /// Force-swap the block snapshot from the current store contents. Used
    /// by the scanner after each cycle and by operators after an override
    /// change; enforce mode ⇒ populated, train mode ⇒ empty.
    pub fn refresh_snapshot(&self, cfg: &AiSettings, now: i64) {
        let mut snapshot = BlockSnapshot::new();
        if cfg.mode == AiMode::Enforce {
            match self.store.fresh_blocked(now, cfg.block_threshold) {
                Ok(rows) => {
                    for (domain, category, expires_at) in rows {
                        // Filter again against the category allowlist for
                        // auto-block eligibility (only threats the config
                        // names may enforce).
                        if cfg.is_auto_block_category(&category) {
                            snapshot.insert(
                                domain,
                                ActiveBlock {
                                    category,
                                    expires_at,
                                },
                            );
                        }
                    }
                }
                Err(e) => self.log_warn(format!("AI snapshot refresh failed: {e}")),
            }
        }
        self.snapshot.store(Arc::new(snapshot));
    }

    /// The scanner loop. Returns when `shutdown` fires.
    pub async fn run_forever(
        self: Arc<Self>,
        source: Arc<daygle_dns_authoritative::ZoneStore>,
        shutdown: CancellationToken,
    ) {
        loop {
            let cfg = self.settings.load().clone();
            let since = std::time::Duration::from_secs(cfg.scan_interval_secs);
            // One cycle per interval (plus the first one promptly).
            tokio::select! {
                _ = tokio::time::sleep(since) => {}
                _ = self.rescan_notify.notified() => {}
                _ = shutdown.cancelled() => return,
            }
            if shutdown.is_cancelled() {
                return;
            }
            // The query-log cutoff: only new rows since the previous cycle.
            // Epoch math keeps this trivial; the last cycle's timestamp is
            // "now - scan_interval" so slow clocks and gaps self-heal.
            let now = Utc::now().timestamp();
            let since_epoch = now - (cfg.scan_interval_secs.max(client_catchup_secs(&cfg)) as i64);
            let result = tokio::task::spawn_blocking({
                let scanner = self.clone();
                let source = source.clone();
                move || scanner.run_cycle(since_epoch, &source)
            })
            .await;
            match result {
                Ok(Ok(classified)) => {
                    if classified > 0 {
                        self.log_info(format!("AI cycle classified {classified} domain(s)"));
                    }
                }
                Ok(Err(e)) => self.log_warn(format!("AI cycle failed: {e}")),
                Err(join_err) => self.log_warn(format!("AI cycle panicked: {join_err}")),
            }
        }
    }
}

/// Extra lookback so the first cycle after boot does not miss rows logged
/// while restarting: at most 8 intervals, capped at 8 hours.
fn client_catchup_secs(cfg: &AiSettings) -> u64 {
    cfg.scan_interval_secs.min(3600) * 8
}

/// Lowercase `info`/`threat`, shared by store writes.
fn severity_name(s: crate::backend::Severity) -> &'static str {
    match s {
        crate::backend::Severity::Info => "info",
        crate::backend::Severity::Threat => "threat",
    }
}

/// Basic sanity: a candidate is a DNS-ish name with valid labels (letters,
/// digits, `-`, `_`) of in-range length. IP literals are never classified.
pub fn looks_like_domain(name: &str) -> bool {
    if name.len() > 253 || name.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}
