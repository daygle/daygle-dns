//! The background scanner: harvests unseen domains from the query log,
//! classifies them off the DNS hot path, persists verdicts with TTLs, and
//! publishes the block snapshot the policy plugin consults.
//!
//! Everything here runs at scan-cycle cadence (default every 5 min) on
//! `workers` blocking threads; DNS latency is never touched. Expiry follows
//! the "verdicts age out" design: every `expire_check_secs`, expired
//! classified/skipped rows re-enter `pending` and are re-classified by the
//! next cycle (which classifies every pending row, new or re-queued);
//! expired verdicts drop out of the block snapshot until a fresh one exists.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
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
    /// Wakes the scan loop for an immediate cycle (rescan API, settings
    /// changes).
    pub rescan_notify: Arc<Notify>,
    /// When expired verdicts were last re-queued (UNIX seconds; 0 = never).
    last_expiry: AtomicI64,
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
            last_expiry: AtomicI64::new(0),
        })
    }

    fn log_info(&self, msg: String) {
        self.logs.push(daygle_dns_core::LogLevel::Info, "ai", msg);
    }

    fn log_warn(&self, msg: String) {
        self.logs.push(daygle_dns_core::LogLevel::Warn, "ai", msg);
    }

    /// One scan cycle: re-queue expired verdicts (every
    /// `expire_check_secs`), record the domains queried since `since_epoch`,
    /// classify every pending domain (new, re-queued or left over), and
    /// refresh the block snapshot. Returns the number of domains classified
    /// (above the confidence floor). Public so tests drive cycles directly.
    pub fn run_cycle(
        &self,
        since_epoch: i64,
        source: &daygle_dns_authoritative::ZoneStore,
    ) -> Result<usize> {
        let cfg = self.settings.load().clone();
        let now = Utc::now().timestamp();

        // 1. Expiry: stale verdicts re-enter pending.
        let last_expiry = self.last_expiry.load(Ordering::Relaxed);
        if now - last_expiry >= cfg.expire_check_secs as i64 {
            self.last_expiry.store(now, Ordering::Relaxed);
            let expired = self.store.expire_old(now, cfg.max_domains_per_scan)?;
            if expired > 0 {
                self.log_info(format!("AI re-queued {expired} expired verdict(s)"));
            }
        }

        // 2. Harvest: record every domain queried since the last cycle
        //    (new ones become pending; known ones count another sighting).
        // Recording a sighting is cheap, so the harvest cap is generous;
        // `max_domains_per_scan` bounds the expensive part, classification.
        let names = source.distinct_recent_query_names(since_epoch, HARVEST_LIMIT)?;
        for name in names {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if looks_like_domain(&name) {
                self.store.observe(&name)?;
            }
        }

        // 3. Classify everything pending, `workers` at a time.
        let pending = self.store.pending_domains(cfg.max_domains_per_scan)?;
        let verdicts = self.classify_all(&pending, cfg.workers);
        let mut classified = 0usize;
        let mut skipped = 0usize;
        for (name, verdict) in pending.iter().zip(verdicts) {
            match verdict {
                None => {
                    self.store.save_verdict(
                        name,
                        "",
                        "",
                        "skipped",
                        0.0,
                        self.classifier.name(),
                        "no signal",
                        cfg.category_ttl_secs as i64,
                    )?;
                    skipped += 1;
                }
                Some(v) if v.confidence < cfg.confidence_floor => {
                    self.store.save_verdict(
                        name,
                        &v.category,
                        severity_name(v.severity),
                        "skipped",
                        v.confidence,
                        self.classifier.name(),
                        &v.evidence,
                        cfg.category_ttl_secs as i64,
                    )?;
                    skipped += 1;
                }
                Some(v) => {
                    let ttl = if v.severity == crate::backend::Severity::Threat {
                        cfg.threat_ttl_secs
                    } else {
                        cfg.category_ttl_secs
                    } as i64;
                    self.store.save_verdict(
                        name,
                        &v.category,
                        severity_name(v.severity),
                        "classified",
                        v.confidence,
                        self.classifier.name(),
                        &v.evidence,
                        ttl,
                    )?;
                    classified += 1;
                }
            }
        }
        if !pending.is_empty() {
            self.log_info(format!(
                "AI scanned {} domain(s): {classified} classified, {skipped} skipped",
                pending.len()
            ));
        }

        // 4. Refresh the block snapshot.
        self.refresh_snapshot(&cfg, Utc::now().timestamp());
        Ok(classified)
    }

    /// Classify `domains` on up to `workers` threads, keeping their order.
    fn classify_all(
        &self,
        domains: &[String],
        workers: u32,
    ) -> Vec<Option<crate::backend::Verdict>> {
        let workers = (workers.clamp(1, 32) as usize).min(domains.len().max(1));
        if workers == 1 {
            return domains
                .iter()
                .map(|d| {
                    self.classifier
                        .classify(&ClassificationInput::domain_only(d.clone()))
                })
                .collect();
        }
        let chunk = domains.len().div_ceil(workers);
        std::thread::scope(|scope| {
            let handles: Vec<_> = domains
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        part.iter()
                            .map(|d| {
                                self.classifier
                                    .classify(&ClassificationInput::domain_only(d.clone()))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }

    /// The backend recorded on verdicts (e.g. `heuristic`, `fasttext`,
    /// `fasttext+minilm-onnx`).
    pub fn backend_name(&self) -> &str {
        self.classifier.name()
    }

    /// Categories the loaded backend can emit, for console pickers.
    pub fn categories(&self) -> Vec<String> {
        self.classifier.categories()
    }

    /// The domains that qualify for auto-blocking right now: fresh verdicts
    /// at or above the block threshold, in an auto-block category, and not
    /// exempted by an allow override on the domain or any parent domain.
    /// In enforce mode these are blocked; in train mode they are what would
    /// be.
    pub fn eligible_blocks(&self, cfg: &AiSettings, now: i64) -> Result<BlockSnapshot> {
        let overrides = self.store.allow_overrides()?;
        let mut eligible = BlockSnapshot::new();
        for (domain, category, expires_at) in self.store.fresh_blocked(now, cfg.block_threshold)? {
            if cfg.is_auto_block_category(&category) && !exempt(&domain, &overrides) {
                eligible.insert(
                    domain,
                    ActiveBlock {
                        category,
                        expires_at,
                    },
                );
            }
        }
        Ok(eligible)
    }

    /// Force-swap the block snapshot from the current store contents. Used
    /// by the scanner after each cycle and by operators after an override
    /// or settings change; enforce mode => populated, train mode => empty.
    pub fn refresh_snapshot(&self, cfg: &AiSettings, now: i64) {
        let snapshot = if cfg.mode == AiMode::Enforce {
            match self.eligible_blocks(cfg, now) {
                Ok(eligible) => eligible,
                Err(e) => {
                    // Keep the previous snapshot rather than dropping every
                    // block over a transient store error.
                    self.log_warn(format!("AI snapshot refresh failed: {e}"));
                    return;
                }
            }
        } else {
            BlockSnapshot::new()
        };
        self.snapshot.store(Arc::new(snapshot));
    }

    /// The scanner loop: one cycle right away, then one per
    /// `scan_interval_secs` (or sooner on a rescan request). Returns when
    /// `shutdown` fires.
    pub async fn run_forever(
        self: Arc<Self>,
        source: Arc<daygle_dns_authoritative::ZoneStore>,
        shutdown: CancellationToken,
    ) {
        // The first cycle looks back further so domains queried while the
        // server was restarting are not missed; later cycles read the query
        // log from where the previous one started.
        let mut since_epoch = Utc::now().timestamp() - catchup_secs(&self.settings.load()) as i64;
        loop {
            if shutdown.is_cancelled() {
                return;
            }
            let started = Utc::now().timestamp();
            let result = tokio::task::spawn_blocking({
                let scanner = self.clone();
                let source = source.clone();
                move || scanner.run_cycle(since_epoch, &source)
            })
            .await;
            match result {
                Ok(Ok(_)) => since_epoch = started,
                // A failed cycle reads the same window again next time.
                Ok(Err(e)) => self.log_warn(format!("AI cycle failed: {e}")),
                Err(join_err) => self.log_warn(format!("AI cycle panicked: {join_err}")),
            }
            let interval = std::time::Duration::from_secs(self.settings.load().scan_interval_secs);
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.rescan_notify.notified() => {}
                _ = shutdown.cancelled() => return,
            }
        }
    }
}

/// Most distinct domains recorded from the query log per cycle.
const HARVEST_LIMIT: u32 = 100_000;

/// How far back the first cycle after startup reads the query log: eight
/// intervals, at most eight hours.
fn catchup_secs(cfg: &AiSettings) -> u64 {
    cfg.scan_interval_secs.min(3600) * 8
}

/// Whether an allow override exempts `domain`: on the domain itself or on
/// any parent domain (an exemption covers subdomains).
fn exempt(domain: &str, overrides: &HashSet<String>) -> bool {
    let mut candidate = domain;
    loop {
        if overrides.contains(candidate) {
            return true;
        }
        match candidate.split_once('.') {
            Some((_, parent)) => candidate = parent,
            None => return false,
        }
    }
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
