//! The background scanner: harvests unseen domains from the query log,
//! classifies them off the DNS hot path, persists verdicts with TTLs, and
//! publishes the block snapshot the policy plugin consults.
//!
//! Every domain is classified **twice, independently**: once by the content
//! categorizer and once by the threat detector ([`Channel`]). Each channel has
//! its own backend, confidence floor and verdict TTL, and only the threat
//! channel can auto-block - a categorization is information, not a decision.
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

use crate::backend::{Channel, ClassificationInput, DomainClassifier, Severity, Verdict};
use crate::store::{AiStore, NewVerdict};

/// A domain currently auto-blocked in `enforce` mode.
#[derive(Debug, Clone)]
pub struct ActiveBlock {
    pub category: String,
    pub expires_at: i64,
}

/// Domain → active block; swapped atomically after each scan cycle and on
/// every override change, so the policy plugin's hot path is one map lookup.
pub type BlockSnapshot = HashMap<String, ActiveBlock>;

/// A domain's current content category, with the expiry of the verdict it
/// came from (or `i64::MAX` for an operator relabel, which has no TTL).
#[derive(Debug, Clone)]
pub struct ActiveCategory {
    pub category: String,
    pub expires_at: i64,
}

/// Domain → content category. This is what "block category X" matches
/// against: the scanner only labels, the operator's policy decides.
pub type CategorySnapshot = HashMap<String, ActiveCategory>;

/// Shared scanner handles (also handed to the policy plugin and API).
pub struct Scanner {
    store: Arc<AiStore>,
    /// Content categorization: labels sites, never blocks.
    content: Box<dyn DomainClassifier + Send + Sync>,
    /// Threat detection: the only channel that feeds the block snapshot.
    threat: Box<dyn DomainClassifier + Send + Sync>,
    settings: Arc<ArcSwap<AiSettings>>,
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    /// Domain → content category, for per-group category blocking.
    categories: Arc<ArcSwap<CategorySnapshot>>,
    logs: Arc<LogStore>,
    /// Wakes the scan loop for an immediate cycle (rescan API, settings
    /// changes).
    pub rescan_notify: Arc<Notify>,
    /// When expired verdicts were last re-queued (UNIX seconds; 0 = never).
    last_expiry: AtomicI64,
    /// Held while a block snapshot is computed and published, so a scan
    /// cycle cannot publish one computed before an override landed.
    publishing: std::sync::Mutex<()>,
    /// Set after the first snapshot is published: the blocks already in
    /// force at startup are not news.
    primed: std::sync::atomic::AtomicBool,
}

impl Scanner {
    /// Build a scanner over the two channel backends (seen
    /// [`crate::channel::ChannelBackend`]).
    pub fn new(
        store: Arc<AiStore>,
        content: Box<dyn DomainClassifier + Send + Sync>,
        threat: Box<dyn DomainClassifier + Send + Sync>,
        settings: Arc<ArcSwap<AiSettings>>,
        snapshot: Arc<ArcSwap<BlockSnapshot>>,
        categories: Arc<ArcSwap<CategorySnapshot>>,
        logs: Arc<LogStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            content,
            threat,
            settings,
            snapshot,
            categories,
            logs,
            rescan_notify: Arc::new(Notify::new()),
            last_expiry: AtomicI64::new(0),
            publishing: std::sync::Mutex::new(()),
            primed: std::sync::atomic::AtomicBool::new(false),
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
    /// classify every pending `(domain, channel)` pair (new, re-queued or left
    /// over), and refresh the block snapshot. Returns the number of verdicts
    /// recorded above the confidence floor - one per channel per domain, so
    /// up to twice the number of domains. Public so tests drive cycles
    /// directly.
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
        // Names inside the zones this server hosts are its own: never
        // candidates for blocking.
        let hosted: Vec<String> = source
            .list_zones()?
            .into_iter()
            .map(|z| z.name.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        let names: Vec<String> = source
            .distinct_recent_query_names(since_epoch, HARVEST_LIMIT)?
            .into_iter()
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| is_candidate(name, &hosted))
            .collect();
        self.store.observe_all(&names)?;

        // 3. Classify everything pending, `workers` at a time.
        let pending = self.store.pending_domains(cfg.max_domains_per_scan)?;
        let verdicts = self.classify_all(&pending, cfg.workers);
        let mut classified = 0usize;
        let mut skipped = 0usize;
        let rows: Vec<NewVerdict> = pending
            .iter()
            .zip(verdicts)
            .map(|((name, channel), verdict)| {
                // Each channel carries its own floor and TTL: a floor
                // tightened for threat precision must not blank out ordinary
                // categorizations, and a threat is re-checked on a shorter
                // schedule than a content label.
                let (floor, ttl, backend) = match channel {
                    Channel::Content => (
                        cfg.category_confidence_floor,
                        cfg.category_ttl_secs,
                        self.content.name(),
                    ),
                    Channel::Threat => (
                        cfg.confidence_floor,
                        cfg.threat_ttl_secs,
                        self.threat.name(),
                    ),
                };
                let (verdict, status) = match verdict {
                    None => (None, "skipped"),
                    Some(v) if v.confidence < floor => (Some(v), "skipped"),
                    Some(v) => (Some(v), "classified"),
                };
                if status == "classified" {
                    classified += 1;
                } else {
                    skipped += 1;
                }
                NewVerdict {
                    domain: name.clone(),
                    channel: *channel,
                    category: verdict
                        .as_ref()
                        .map(|v| v.category.clone())
                        .unwrap_or_default(),
                    severity: verdict
                        .as_ref()
                        .map(|v| severity_name(v.severity).to_string())
                        .unwrap_or_default(),
                    status: status.to_string(),
                    confidence: verdict.as_ref().map_or(0.0, |v| v.confidence),
                    backend: backend.to_string(),
                    evidence: verdict
                        .map(|v| v.evidence)
                        .unwrap_or_else(|| "no signal".to_string()),
                    expires_after_secs: ttl as i64,
                }
            })
            .collect();
        self.store.save_verdicts(&rows)?;
        if !pending.is_empty() {
            let domains: HashSet<&str> = pending.iter().map(|(d, _)| d.as_str()).collect();
            self.log_info(format!(
                "AI scanned {} domain(s) on both channels: {classified} classified, {skipped} skipped",
                domains.len()
            ));
        }

        // 4. Refresh the block snapshot.
        self.refresh_snapshot(&cfg, Utc::now().timestamp());
        Ok(classified)
    }

    /// Classify every pending `(domain, channel)` pair on up to `workers`
    /// threads, keeping their order: result `i` is always pair `i`'s, so a
    /// chunked worker can never shift one domain's verdict onto another. Each
    /// pair goes to its own channel's backend.
    fn classify_all(&self, pending: &[(String, Channel)], workers: u32) -> Vec<Option<Verdict>> {
        let classify_part = |part: &[(String, Channel)]| -> Vec<Option<Verdict>> {
            part.iter()
                .map(|(domain, channel)| {
                    let backend: &dyn DomainClassifier = match channel {
                        Channel::Content => self.content.as_ref(),
                        Channel::Threat => self.threat.as_ref(),
                    };
                    backend.classify(&ClassificationInput::domain_only(domain.clone()))
                })
                .collect()
        };
        let workers = (workers.clamp(1, 32) as usize).min(pending.len().max(1));
        if workers == 1 {
            return classify_part(pending);
        }
        let chunk = pending.len().div_ceil(workers);
        std::thread::scope(|scope| {
            let handles: Vec<_> = pending
                .chunks(chunk)
                .map(|part| (part.len(), scope.spawn(move || classify_part(part))))
                .collect();
            handles
                .into_iter()
                .flat_map(|(len, h)| {
                    // A worker that panicked yields "no verdict" for each of
                    // its domains. Dropping its results instead shifted every
                    // later verdict onto the wrong domain.
                    h.join().unwrap_or_else(|_| {
                        self.log_warn(format!(
                            "AI classifier panicked; {len} domain(s) left without a verdict"
                        ));
                        vec![None; len]
                    })
                })
                .collect()
        })
    }

    /// Both channels' pipelines, for the status endpoint: the bare name when
    /// they run the same pipeline, else one per channel (e.g. `fasttext
    /// (categories) / fasttext+minilm-onnx (threats)`).
    pub fn backend_name(&self) -> String {
        let (content, threat) = (self.content.name(), self.threat.name());
        if content == threat {
            content.to_string()
        } else {
            format!("{content} (categories) / {threat} (threats)")
        }
    }

    /// The content-categorization pipeline actually running.
    pub fn content_backend_name(&self) -> &str {
        self.content.name()
    }

    /// The threat-detection pipeline actually running (verifier included).
    pub fn threat_backend_name(&self) -> &str {
        self.threat.name()
    }

    /// Every label either channel can emit, for console pickers (the verdict
    /// page filters content labels, the auto-block list offers threat ones).
    pub fn categories(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .content
            .categories()
            .into_iter()
            .chain(self.threat.categories())
            .collect();
        all.sort();
        all.dedup();
        all
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

    /// The domain → category map published for category blocking: fresh
    /// content verdicts, relabelled by any operator override, minus domains
    /// an allow override exempts. A relabel also stands on its own, so an
    /// operator can categorize a domain the model has not got to yet.
    pub fn eligible_categories(&self, now: i64) -> Result<CategorySnapshot> {
        let overrides = self.store.allow_overrides()?;
        let relabels = self.store.category_overrides()?;
        let mut snapshot = CategorySnapshot::new();
        for (domain, category, expires_at) in self.store.fresh_categories(now)? {
            if exempt(&domain, &overrides) {
                continue;
            }
            let category = relabels.get(&domain).cloned().unwrap_or(category);
            snapshot.insert(
                domain,
                ActiveCategory {
                    category,
                    expires_at,
                },
            );
        }
        for (domain, category) in &relabels {
            if exempt(domain, &overrides) {
                continue;
            }
            snapshot
                .entry(domain.clone())
                .or_insert_with(|| ActiveCategory {
                    category: category.clone(),
                    expires_at: i64::MAX,
                });
        }
        Ok(snapshot)
    }

    /// Force-swap the block snapshot from the current store contents. Used
    /// by the scanner after each cycle and by operators after an override
    /// or settings change; enforce mode => populated, train mode => empty.
    /// The category snapshot is published in both modes: blocking a category
    /// is the operator's rule, not a verdict the AI acted on.
    pub fn refresh_snapshot(&self, cfg: &AiSettings, now: i64) {
        let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
        match self.eligible_categories(now) {
            Ok(categories) => self.categories.store(Arc::new(categories)),
            Err(e) => self.log_warn(format!("AI category snapshot refresh failed: {e}")),
        }
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
        let previous = self.snapshot.load();
        let mut added: Vec<(&String, &ActiveBlock)> = snapshot
            .iter()
            .filter(|(domain, _)| !previous.contains_key(*domain))
            .collect();
        if self.primed.swap(true, std::sync::atomic::Ordering::Relaxed) && !added.is_empty() {
            added.sort_by_key(|(domain, _)| *domain);
            let list: Vec<String> = added
                .iter()
                .take(10)
                .map(|(domain, block)| format!("{domain} ({})", block.category))
                .collect();
            let more = added.len().saturating_sub(list.len());
            daygle_dns_core::alerts::raise(
                daygle_dns_core::alerts::AlertKind::AiBlocks,
                format!("ai-blocks:{now}"),
                format!(
                    "The AI blocked {} new domain{}",
                    added.len(),
                    if added.len() == 1 { "" } else { "s" }
                ),
                format!(
                    "The AI scanner started blocking: {}{}. Review them under AI -> Threats, \
                     and exempt any that should stay reachable.",
                    list.join(", "),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    }
                ),
            );
        }
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
            // Turned off in the console: the plugin stops blocking at once;
            // the scanner idles until it is turned back on.
            if !self.settings.load().enabled {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                    _ = self.rescan_notify.notified() => {}
                    _ = shutdown.cancelled() => return,
                }
                continue;
            }
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
        Severity::Info => "info",
        Severity::Threat => "threat",
        Severity::Disputed => "disputed",
    }
}

/// Special-use and local-only suffixes (RFC 6761/6762/8375, `.internal`,
/// and common LAN suffixes): names under them are not on the internet, so
/// there is nothing to classify and nothing that should be auto-blocked.
const LOCAL_SUFFIXES: &[&str] = &[
    "arpa",
    "local",
    "localhost",
    "internal",
    "test",
    "invalid",
    "lan",
    "home",
    "corp",
    "localdomain",
];

/// Whether a query-log name should be classified: a valid domain of at
/// least two labels, not under a special-use or local suffix, and not in
/// a zone this server hosts. Single-label names (`wpad`, `printer`) and
/// reverse lookups were classified before, and a verdict on a hosted name
/// could auto-block the operator's own records.
fn is_candidate(name: &str, hosted: &[String]) -> bool {
    let in_zone = |zone: &str| {
        name == zone
            || (name.len() > zone.len()
                && name.ends_with(zone)
                && name.as_bytes()[name.len() - zone.len() - 1] == b'.')
    };
    looks_like_domain(name)
        && name.contains('.')
        && !LOCAL_SUFFIXES.iter().any(|s| in_zone(s))
        && !hosted.iter().any(|z| in_zone(z))
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
