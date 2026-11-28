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
use daygle_dns_core::config::{AiMode, AiSettings, FusionMode};
use daygle_dns_core::error::Result;
use daygle_dns_core::LogStore;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::assessment;
use crate::backend::{Channel, ClassificationInput, DomainClassifier, Verdict};
use crate::calibration::CalibrationMap;
use crate::fusion::{self, SignalWeights};
use crate::store::{AiStore, NewVerdict};

/// A domain currently auto-blocked in `enforce` mode.
#[derive(Debug, Clone)]
pub struct ActiveBlock {
    pub category: String,
    pub expires_at: i64,
    /// Page findings apply only to the inspected hostname.
    pub exact_host: bool,
}

/// Longest the language-model stage may run in one scan cycle.
const LLM_STAGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(180);
/// A question is only started with at least this long (or the answer limit,
/// if shorter) left in the stage: a page takes 30-60 s on a slow CPU.
const LLM_MIN_START: std::time::Duration = std::time::Duration::from_secs(60);

/// The confidence a threat verdict takes when the language model reads its
/// page as a threat too, or `None` to leave it: two independent readings
/// (the name and the page) agreeing strongly reach blocking confidence; a
/// weaker agreement adds a little, never to blocking. Never lowers, and
/// `ai.page_rule = "evidence"` only records.
pub(crate) fn llm_raise(
    cfg: &AiSettings,
    base: f32,
    reading: &crate::llm::LlmReading,
) -> Option<f32> {
    if cfg.page_rule == daygle_dns_core::config::PageRule::Evidence
        || !reading.threat
        || reading.confidence < 0.7
    {
        return None;
    }
    let raised = if base >= 0.5 && reading.confidence >= 0.85 {
        base.max(crate::evidence::LISTED_CONFIDENCE)
    } else {
        base.max((base + 0.1).min(0.95))
    };
    (raised > base + 0.001).then_some(raised)
}

/// A content verdict below this confidence has its page read (with
/// `ai.fetch_pages`): the name alone left the categorizer unsure.
pub const CATEGORY_PAGE_BELOW: f32 = 0.5;

/// How many *new* blocks one snapshot refresh may publish. A model that
/// suddenly flags a large share of the network is far more likely to be
/// broken than to have found a mass infection, so the surplus waits for the
/// next refresh while the alert says how much was held back. Domains already
/// blocked are never released by this rail.
pub const MAX_NEW_BLOCKS_PER_REFRESH: usize = 500;
/// Longest the page stages may run in one scan cycle, together.
const PAGE_STAGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

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

/// Domains with an operator `allow` override, published with the snapshots.
/// An exemption covers the domain and its subdomains, so the policy plugin
/// checks the *queried* name against it too: an exemption on
/// `www.bad.example` must hold even though the verdict that matches the
/// query is on the parent `bad.example`.
pub type ExemptionSnapshot = HashSet<String>;

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
    /// The operator's AI exemptions, for the plugin's query-time check.
    exemptions: Arc<ArcSwap<ExemptionSnapshot>>,
    logs: Arc<LogStore>,
    /// Wakes the scan loop for an immediate cycle (rescan API, settings
    /// changes).
    pub rescan_notify: Arc<Notify>,
    /// When expired verdicts were last re-queued (UNIX seconds; 0 = never).
    last_expiry: AtomicI64,
    /// Held while a block snapshot is computed and published, so a scan
    /// cycle cannot publish one computed before an override landed.
    publishing: std::sync::Mutex<()>,
    scoring_staged: std::sync::atomic::AtomicBool,
    /// Set after the first snapshot is published: the blocks already in
    /// force at startup are not news.
    primed: std::sync::atomic::AtomicBool,
    /// Model maintenance, set once by the engine: the scan loop runs it
    /// after each successful cycle.
    maintenance: std::sync::OnceLock<std::sync::Weak<crate::maintain::Maintenance>>,
    /// Page reader override, set once: tests supply readings without a
    /// network. `None` fetches the live page with the settings' limits.
    page_reader: std::sync::OnceLock<Box<dyn crate::page::PageReader>>,
    /// The page-text model, set once by the engine.
    page_model: std::sync::OnceLock<Arc<crate::page_model::PageModel>>,
    /// Registration-date lookups, set once by the engine.
    domain_age: std::sync::OnceLock<Arc<crate::age::DomainAge>>,
    /// The calibration map in force. `None` (the default, and what a
    /// rollback to no calibration restores) leaves the confidence as the
    /// score the gate compares.
    calibration: Arc<ArcSwap<Option<CalibrationMap>>>,
    /// The signal weights in force: the active candidate's, or the defaults.
    weights: Arc<ArcSwap<SignalWeights>>,
    classifier_digest: std::sync::OnceLock<Arc<ArcSwap<String>>>,
    /// Threat feeds and popularity, for the structured observations.
    intel: std::sync::OnceLock<Arc<crate::intel::Intel>>,
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
            exemptions: Arc::new(ArcSwap::from_pointee(ExemptionSnapshot::new())),
            logs,
            rescan_notify: Arc::new(Notify::new()),
            last_expiry: AtomicI64::new(0),
            publishing: std::sync::Mutex::new(()),
            scoring_staged: std::sync::atomic::AtomicBool::new(false),
            primed: std::sync::atomic::AtomicBool::new(false),
            maintenance: std::sync::OnceLock::new(),
            page_reader: std::sync::OnceLock::new(),
            page_model: std::sync::OnceLock::new(),
            domain_age: std::sync::OnceLock::new(),
            calibration: Arc::new(ArcSwap::from_pointee(None)),
            weights: Arc::new(ArcSwap::from_pointee(SignalWeights::default())),
            classifier_digest: std::sync::OnceLock::new(),
            intel: std::sync::OnceLock::new(),
        })
    }

    /// Hand the scanner the threat-feed index the observations read.
    pub fn set_intel(&self, intel: Arc<crate::intel::Intel>) {
        let _ = self.intel.set(intel);
    }

    /// Publish the calibration map the gate's score is mapped through.
    /// `None` restores the uncalibrated score (identity), which is the
    /// default and what every rollback to "no map" does.
    pub fn set_calibration(&self, calibration: Option<CalibrationMap>) {
        self.calibration.store(Arc::new(calibration));
    }

    /// Publish the signal weights the fusion uses.
    pub fn set_signal_weights(&self, weights: SignalWeights) {
        self.weights.store(Arc::new(weights));
    }

    /// The calibration map the scanner is applying.
    pub fn calibration_map(&self) -> Option<CalibrationMap> {
        self.calibration.load_full().as_ref().clone()
    }

    /// The signal weights the scanner is applying.
    pub fn signal_weights(&self) -> SignalWeights {
        self.weights.load_full().as_ref().clone()
    }

    /// The scoring identity a page finding was produced under: the page
    /// reader, the calibration map and the fusion mode. A review of a page
    /// finding counts for advancement only against the identity that made it.
    pub fn scoring_version(&self) -> String {
        let settings = self.settings.load_full();
        self.page_scoring_version(&settings)
    }

    fn page_scoring_version(&self, settings: &AiSettings) -> String {
        let reader = self
            .page_model
            .get()
            .map_or_else(|| "phrases".to_string(), |model| model.version());
        format!("page:{reader}|{}", self.verdict_scoring_version(settings))
    }

    pub(crate) fn set_classifier_digest(&self, digest: Arc<ArcSwap<String>>) {
        let _ = self.classifier_digest.set(digest);
    }

    pub(crate) fn verdict_scoring_version(&self, settings: &AiSettings) -> String {
        use sha2::{Digest, Sha256};
        let model = self
            .classifier_digest
            .get()
            .map(|digest| digest.load_full());
        let calibration = self.calibration.load();
        let payload = serde_json::json!({
            "model": model.as_deref().map(String::as_str).unwrap_or("builtin"),
            "fusion": settings.fusion,
            "weights": self.signal_weights(),
            "calibration": calibration.as_ref().as_ref().map(|map| &map.version),
            "threshold": settings.block_threshold,
            "confidence_floor": settings.confidence_floor,
            "threat_labels": settings.threat_labels(),
            "page_rule": settings.page_rule,
        });
        crate::candidate::hex(&Sha256::digest(payload.to_string()))
    }

    pub(crate) fn authority_decisions(
        &self,
        settings: &AiSettings,
    ) -> Result<Vec<crate::authority::AuthorityDecision>> {
        let calibration = self.calibration.load();
        let identity = self.verdict_scoring_version(settings);
        let page = (settings.authority.advancement && settings.monitor_page_discovery)
            .then(|| self.page_scoring_version(settings));
        crate::authority::evaluate_for_identity(
            &self.store,
            &settings.authority,
            calibration
                .as_ref()
                .as_ref()
                .map(|map| map.version.as_str())
                .unwrap_or(""),
            settings.fusion.as_str(),
            Some(&identity),
            page.as_deref(),
        )
    }

    /// Replace the reader the page stage uses, e.g. with readings a test
    /// already knows. Returns false if one was already installed.
    pub fn set_page_reader(&self, reader: Box<dyn crate::page::PageReader>) -> bool {
        self.page_reader.set(reader).is_ok()
    }

    /// Hand the scanner the model-maintenance step it runs after each cycle
    /// (see [`crate::maintain`]).
    pub fn set_maintenance(&self, maintenance: &Arc<crate::maintain::Maintenance>) {
        let _ = self.maintenance.set(Arc::downgrade(maintenance));
    }

    /// Hand the scanner the page-text model the page stage refines readings
    /// with (see [`crate::page_model`]).
    pub fn set_page_model(&self, model: Arc<crate::page_model::PageModel>) {
        let _ = self.page_model.set(model);
    }

    /// Hand the scanner the registration-date lookups for new threats (see
    /// [`crate::age`]).
    pub fn set_domain_age(&self, age: Arc<crate::age::DomainAge>) {
        let _ = self.domain_age.set(age);
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
        if self.scoring_staged.load(Ordering::Acquire) {
            return Ok(0);
        }
        let cfg = self.settings.load().clone();
        let now = Utc::now().timestamp();

        // 1. Expiry: stale verdicts re-enter pending.
        let last_expiry = self.last_expiry.load(Ordering::Relaxed);
        if now - last_expiry >= cfg.expire_check_secs as i64 {
            let expired = self.store.expire_old(now, cfg.max_domains_per_scan)?;
            // Sighting histories and page texts past their retention go on
            // the same schedule.
            if let Err(e) = self.store.prune_evidence() {
                self.log_warn(format!("AI could not prune its evidence tables: {e}"));
            }
            if expired > 0 {
                self.log_info(format!("AI re-queued {expired} expired verdict(s)"));
            }
            // A threat on a domain the network has since come to rely on is
            // re-checked now, not at expiry: the evidence disputes it.
            if cfg.network_evidence {
                match self.store.requeue_newly_established() {
                    Ok(0) => {}
                    Ok(n) => self.log_info(format!(
                        "AI re-checks {n} threat verdict(s) on domains now established on this network"
                    )),
                    Err(e) => self.log_warn(format!(
                        "AI could not re-check threats on established domains: {e}"
                    )),
                }
            }
            // A backlog larger than one batch carries on next cycle rather
            // than an `expire_check_secs` later: an expired verdict blocks
            // nothing until it is re-checked.
            if !self.store.has_expired(now)? {
                self.last_expiry.store(now, Ordering::Relaxed);
            }
        }

        // Autonomy off: the AI does no work of its own. Expiry above still
        // ran (a stale block must not outlive its verdict) and the snapshot
        // is refreshed so blocks already in force stay correct, but nothing
        // new is harvested, classified, read or retrained. Enforcement stays
        // as the operator set it: `mode` is a separate setting.
        if !cfg.autonomy {
            self.refresh_snapshot(&cfg, now);
            return Ok(0);
        }

        // 2. Harvest: record every domain queried since the last cycle
        //    (new ones become pending; known ones count another sighting).
        // Recording a sighting is cheap, so the harvest cap is generous;
        // `max_domains_per_scan` bounds the expensive part, classification.
        // Names inside the zones this server hosts are its own: never
        // candidates for blocking.
        let hosted: HashSet<String> = source
            .list_zones()?
            .into_iter()
            .map(|z| z.name.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        // Each name comes with the clients that looked it up: how widely and
        // for how long the network uses a domain is evidence the name alone
        // does not carry (see `crate::evidence`).
        let sightings: Vec<(String, Vec<String>)> = source
            .recent_query_name_clients(since_epoch, HARVEST_LIMIT)?
            .into_iter()
            .map(|(name, clients)| (name.trim_end_matches('.').to_ascii_lowercase(), clients))
            .filter(|(name, _)| is_candidate(name, &hosted))
            .collect();
        let names: Vec<String> = sightings.iter().map(|(name, _)| name.clone()).collect();
        self.store.observe_all(&names)?;
        if let Err(e) = self.store.record_sightings(&sightings) {
            self.log_warn(format!("AI could not record domain sightings: {e}"));
        }

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
                        .map(|v| v.severity.as_str().to_string())
                        .unwrap_or_default(),
                    status: status.to_string(),
                    confidence: verdict.as_ref().map_or(0.0, |v| v.confidence),
                    backend: backend.to_string(),
                    threat_score: verdict.as_ref().and_then(|v| v.threat_score).unwrap_or(0.0),
                    evidence: verdict
                        .map(|v| v.evidence)
                        .unwrap_or_else(|| "no signal".to_string()),
                    expires_after_secs: ttl as i64,
                }
            })
            .collect();
        self.store.save_verdicts(&rows)?;
        // The evidence behind every threat verdict, recorded as structured
        // observations, with the fused view and the calibrated score beside
        // them. This never fails the cycle: a verdict keeps its confidence
        // if the assessment cannot be stored.
        let assessed = self.assess_verdicts(&cfg, &rows, now);
        // What the threat channel produced this scan: the watch on a newly
        // promoted model compares it with the week before (see
        // `crate::maintain`). "Blocking" is the score of record the gate
        // compares, not the model's confidence.
        let threat_classified = rows.iter().filter(|r| r.channel == Channel::Threat).count();
        let threat_blocking = Self::blocking_count(&rows, &assessed, cfg.block_threshold);
        if let Err(e) = self
            .store
            .record_threat_rate(threat_classified, threat_blocking)
        {
            self.log_warn(format!("AI could not record its threat rate: {e}"));
        }
        if !pending.is_empty() {
            let domains: HashSet<&str> = pending.iter().map(|(d, _)| d.as_str()).collect();
            self.log_info(format!(
                "AI scanned {} domain(s) on both channels: {classified} classified, {skipped} skipped",
                domains.len()
            ));
        }

        // 3b. Domain age: when the new threats' domains were registered,
        //     before the snapshot so a freshly registered threat blocks in
        //     this cycle. A failure never fails the cycle.
        if let Some(age) = self.domain_age.get() {
            match age.stage(&cfg, Utc::now().timestamp()) {
                Ok(0) => {}
                Ok(n) => self.log_info(format!(
                    "AI adjusted {n} threat verdict(s) by when their domain was registered"
                )),
                Err(e) => self.log_warn(format!("AI domain-age stage failed: {e}")),
            }
        }

        // 4. Refresh the block snapshot.
        self.refresh_snapshot(&cfg, Utc::now().timestamp());

        // 5. Page content: evidence for the domains just flagged. Only the
        //    threat channel's candidates are read, and only when the operator
        //    turned it on; a failure here never fails the cycle.
        // Both page stages share one wall-clock budget per cycle.
        let deadline = std::time::Instant::now() + PAGE_STAGE_BUDGET;
        match self.page_stage(&cfg, Utc::now().timestamp(), deadline) {
            Ok(0) => {}
            Ok(read) => self.log_info(format!("AI read {read} page(s) behind threat candidates")),
            Err(e) => self.log_warn(format!("AI page stage failed: {e}")),
        }

        // 6. Page content for categories: the pages of domains the
        //    categorizer is unsure of, in whatever budget the threat stage
        //    left.
        match self.category_page_stage(&cfg, Utc::now().timestamp(), deadline) {
            Ok((0, _)) => {}
            Ok((read, set)) => self.log_info(format!(
                "AI read {read} page(s) of domains it was unsure how to categorize; {set} categorized from their page"
            )),
            Err(e) => self.log_warn(format!("AI category page stage failed: {e}")),
        }

        if let Err(e) = self.page_discovery_stage(&cfg, deadline) {
            self.log_warn(format!("AI page discovery failed: {e}"));
        }

        // 7. The language model, when one is configured: it reads pages the
        //    stages above kept, for the verdicts the AI is least sure of.
        match self.llm_stage(&cfg, Utc::now().timestamp()) {
            Ok((0, _)) => {}
            Ok((read, changed)) => self.log_info(format!(
                "AI asked the language model about {read} page(s); {changed} verdict(s) changed"
            )),
            Err(e) => self.log_warn(format!("AI language-model stage failed: {e}")),
        }
        Ok(classified)
    }

    /// How many of this scan's threat verdicts the gate would compare at or
    /// above `threshold`: the stored score of record where the verdict was
    /// assessed, else its confidence (what a verdict with no stored assessment
    /// is read by). The blocking-rate metric has to move with the gate, not with
    /// the model's own confidence.
    fn blocking_count(
        rows: &[NewVerdict],
        assessed: &std::collections::HashMap<String, f32>,
        threshold: f32,
    ) -> usize {
        rows.iter()
            .filter(|row| row.channel == Channel::Threat && row.status == "classified")
            .filter(|row| row.severity == "threat")
            .filter(|row| assessed.get(&row.domain).copied().unwrap_or(row.confidence) >= threshold)
            .count()
    }

    /// Record every threat verdict's signal observations and its score of
    /// record. Returns the score the gate now compares for each verdict it
    /// assessed, so the scan's blocking rate is measured on that number rather
    /// than on the confidence.
    fn assess_verdicts(
        &self,
        cfg: &AiSettings,
        rows: &[NewVerdict],
        now: i64,
    ) -> std::collections::HashMap<String, f32> {
        let mut scores = std::collections::HashMap::new();
        let identity = self.verdict_scoring_version(cfg);
        for row in rows
            .iter()
            .filter(|r| r.channel == Channel::Threat && r.status == "classified")
        {
            if let Some(score) = self.assess_row(
                cfg,
                &row.domain,
                row.threat_score,
                row.confidence,
                &row.severity,
                &row.evidence,
                now,
                Some(&identity),
            ) {
                scores.insert(row.domain.clone(), score);
            }
        }
        scores
    }

    /// Re-score every stored threat verdict under `cfg`'s fusion mode, from the
    /// observations kept beside it. The score of record is a function of the
    /// mode, so a verdict stored under another one must be rewritten before the
    /// new mode affects enforcement - otherwise the gate would compare (or the
    /// trial fit on) a score the previous configuration produced. Called when
    /// the mode changes; returns how many verdicts were rewritten.
    pub fn rescore_assessments(&self, cfg: &AiSettings) -> Result<usize> {
        let calibration = self.calibration.load_full();
        let weights = self.weights.load_full();
        self.store
            .rescore_assessments(cfg.fusion, &weights, calibration.as_ref().as_ref())
    }

    /// Recompute one stored verdict's observations and calibrated score after
    /// a later stage (the page rule or the language model) moved its
    /// confidence. Without this the gate would keep comparing a calibration
    /// of the confidence the verdict had before the evidence arrived.
    fn reassess_domain(&self, cfg: &AiSettings, domain: &str, now: i64) {
        let Ok(Some(row)) = self.store.verdict(domain, "threat") else {
            return;
        };
        let _ = self.assess_row(
            cfg,
            domain,
            row.threat_score,
            row.confidence,
            &row.severity,
            &row.evidence,
            now,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_row(
        &self,
        cfg: &AiSettings,
        domain: &str,
        threat_score: f32,
        confidence: f32,
        severity: &str,
        evidence: &str,
        now: i64,
        identity: Option<&str>,
    ) -> Option<f32> {
        let intel = self.intel.get()?;
        let index = intel.index();
        let calibration = self.calibration.load_full();
        let weights = self.weights.load_full();
        let page = self
            .store
            .page_reading(domain)
            .ok()
            .flatten()
            .map(|reading| assessment::PageNote {
                category: reading.category,
                confidence: reading.confidence,
                cues: reading.cues,
                read_at: reading.read_at,
                adjusted: self
                    .store
                    .page_adjustment(domain)
                    .ok()
                    .flatten()
                    .map(|adjustment| (adjustment.prior, adjustment.confidence)),
            });
        let observations = assessment::observe(
            &assessment::Context {
                store: &self.store,
                intel: &index,
            },
            &assessment::AssessmentInput {
                domain,
                threat_score,
                confidence,
                severity,
                evidence,
                page,
                now,
            },
        );
        let fused = (cfg.fusion != FusionMode::Off).then(|| fusion::fuse(&observations, &weights));
        // One score of record, shared with the re-scoring pass and the gate:
        // fusion decides it in `decide`, calibration maps it when a map is in
        // force.
        let score = assessment::score_of_record(
            cfg.fusion,
            confidence,
            fused.as_ref(),
            calibration.as_ref().as_ref(),
        );
        if let Err(e) = self
            .store
            .save_observations(domain, "threat", now, &observations)
        {
            self.log_warn(format!(
                "AI could not store the signals behind {domain}: {e}"
            ));
        }
        if let Err(e) = self
            .store
            .save_assessment_for_identity(domain, "threat", cfg.fusion, &score, identity)
        {
            self.log_warn(format!(
                "AI could not store the assessment of {domain}: {e}"
            ));
        }
        Some(score.gate())
    }

    /// Ask the configured language model (see [`crate::llm`]) to read kept
    /// pages: threats below the block threshold first, then content
    /// verdicts below [`CATEGORY_PAGE_BELOW`]. A threat it agrees with is
    /// raised (with `ai.page_rule` other than `evidence`); an unsure
    /// domain takes the category it names. It never lowers or clears a
    /// threat. Returns `(read, changed)`.
    fn llm_stage(&self, cfg: &AiSettings, now: i64) -> Result<(usize, usize)> {
        if !cfg.llm_enabled {
            return Ok((0, 0));
        }
        let candidates = self.store.llm_candidates(
            now,
            cfg.block_threshold,
            CATEGORY_PAGE_BELOW,
            cfg.llm_candidates_per_scan.clamp(1, 32),
        )?;
        if candidates.is_empty() {
            return Ok((0, 0));
        }
        let content_labels: Vec<String> = self
            .content
            .categories()
            .into_iter()
            .filter(|label| label != crate::learn::BENIGN_LABEL)
            .collect();
        let mut labels = content_labels.clone();
        // The effective threat labels, so a family the operator removed is
        // not offered to the model as an answer.
        for label in cfg.threat_labels() {
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
        if labels.is_empty() {
            return Ok((0, 0));
        }
        let deadline = std::time::Instant::now() + LLM_STAGE_BUDGET;
        let timeout = std::time::Duration::from_secs(cfg.llm_timeout_secs.clamp(5, 600));
        let (mut read, mut changed) = (0usize, 0usize);
        for candidate in candidates {
            // Each answer gets the configured limit, but never more than the
            // stage has left: a slow server cannot hold the scan past it.
            // A question started with less than a typical answer's time
            // left would only be cut off: leave it for the next cycle.
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left < timeout.min(LLM_MIN_START) {
                break;
            }
            let budget_cut = left < timeout;
            let reading = match crate::llm::ask(
                &cfg.llm_url,
                &cfg.llm_model,
                timeout.min(left),
                &candidate.domain,
                &candidate.title,
                &candidate.text,
                &labels,
            ) {
                Ok(reading) => reading,
                // The scan's budget, not the answer limit, ran out: the page
                // is read next cycle. Not a fault.
                Err(e) if budget_cut && e.starts_with("no answer within") => {
                    self.log_info(format!(
                        "AI language model stopped for this scan (its time budget ran out); {} is read next scan",
                        candidate.domain
                    ));
                    break;
                }
                Err(e) => {
                    // An unreachable server would fail every candidate the
                    // same way: stop for this cycle, the rows stay queued.
                    self.log_warn(format!(
                        "AI language model ({}) could not read {}: {e}",
                        cfg.llm_model, candidate.domain
                    ));
                    break;
                }
            };
            read += 1;
            let said = format!(
                "language model {} reads {}{} ({:.0}%){}",
                cfg.llm_model,
                reading.category.as_deref().unwrap_or("no listed category"),
                if reading.threat { ", a threat" } else { "" },
                reading.confidence * 100.0,
                if reading.reason.is_empty() {
                    String::new()
                } else {
                    format!(": {}", reading.reason)
                }
            );
            let (note, confidence, category) = if candidate.channel == "threat" {
                match llm_raise(cfg, candidate.confidence, &reading) {
                    Some(raised) => (
                        format!("{said} - confidence now {:.0}%", raised * 100.0),
                        Some(raised),
                        None,
                    ),
                    None => (said, None, None),
                }
            } else {
                match reading.category.as_deref().filter(|label| {
                    !reading.threat
                        && reading.confidence >= cfg.page_confidence_floor
                        && reading.confidence > candidate.confidence
                        && !cfg.is_auto_block_category(label)
                        && content_labels.iter().any(|known| known == label)
                }) {
                    Some(label) => (
                        format!(
                            "{said}; the name alone was {:.0}%",
                            candidate.confidence * 100.0
                        ),
                        Some(reading.confidence.min(0.9)),
                        Some(label.to_string()),
                    ),
                    None => (said, None, None),
                }
            };
            let moved = confidence.is_some();
            self.store.record_llm_reading(
                &candidate.domain,
                &candidate.channel,
                &note,
                confidence,
                category.as_deref(),
                &reading,
            )?;
            // A raised threat confidence has to be calibrated again before the
            // snapshot is rebuilt, or the gate would compare a stale map.
            if moved && candidate.channel == "threat" {
                self.reassess_domain(cfg, &candidate.domain, now);
                changed += 1;
            }
        }
        if changed > 0 {
            self.refresh_snapshot(cfg, now);
        }
        Ok((read, changed))
    }

    /// Read the pages of domains the categorizer is unsure of (below
    /// [`CATEGORY_PAGE_BELOW`], or no category) and categorize them from
    /// what their page says when it says so more surely. Only ordinary
    /// categories the categorizer knows are taken (see
    /// [`crate::page::classify_category`]); a page reading never makes or
    /// clears a threat, and it is never trained on. Returns `(read, set)`.
    fn category_page_stage(
        &self,
        cfg: &AiSettings,
        now: i64,
        deadline: std::time::Instant,
    ) -> Result<(usize, usize)> {
        if !cfg.fetch_pages || std::time::Instant::now() >= deadline {
            return Ok((0, 0));
        }
        let candidates = self.store.category_page_candidates(
            now,
            CATEGORY_PAGE_BELOW,
            cfg.page_candidates_per_scan.clamp(1, 64),
        )?;
        if candidates.is_empty() {
            return Ok((0, 0));
        }
        let live;
        let reader: &dyn crate::page::PageReader = match self.page_reader.get() {
            Some(reader) => reader.as_ref(),
            None => {
                live = crate::page::PageFetcher::new(
                    std::time::Duration::from_secs(cfg.page_fetch_timeout_secs.clamp(1, 30)),
                    cfg.page_fetch_max_bytes.clamp(16 * 1024, 2 * 1024 * 1024) as usize,
                );
                &live
            }
        };
        let known: HashSet<String> = self.content.categories().into_iter().collect();
        let workers = crate::page::workers().min(candidates.len());
        let chunk = candidates.len().div_ceil(workers);
        let readings: Vec<(String, f32, crate::page::Inspection)> = std::thread::scope(|scope| {
            let handles: Vec<_> = candidates
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        part.iter()
                            .take_while(|_| std::time::Instant::now() < deadline)
                            .map(|(domain, confidence)| {
                                (domain.clone(), *confidence, reader.inspect(domain))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap_or_default())
                .collect()
        });
        let mut set = 0usize;
        for (domain, confidence, inspection) in &readings {
            let Some((title, text)) = &inspection.page else {
                self.store
                    .record_category_page(domain, &inspection.note, None)?;
                continue;
            };
            if let Err(e) = self.store.save_page_text(domain, title, text) {
                self.log_warn(format!("AI could not keep the text of {domain}: {e}"));
            }
            let reading = crate::page::classify_category(title, text).filter(|r| {
                r.confidence >= cfg.page_confidence_floor
                    && r.confidence > *confidence
                    && !cfg.is_auto_block_category(r.category)
                    && (known.is_empty() || known.contains(r.category))
            });
            let short: String = title.chars().take(80).collect();
            match reading {
                Some(r) => {
                    let note = format!(
                        "page \"{short}\" reads {} ({:.0}%: {}); the name alone was {:.0}%",
                        r.category,
                        r.confidence * 100.0,
                        r.cues
                            .iter()
                            .take(3)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", "),
                        confidence * 100.0
                    );
                    if self.store.record_category_page(
                        domain,
                        &note,
                        Some((r.category, r.confidence)),
                    )? {
                        set += 1;
                    }
                }
                None => {
                    let note = format!("page \"{short}\" read, no clearer category");
                    self.store.record_category_page(domain, &note, None)?;
                }
            }
        }
        if set > 0 {
            // Category blocking follows the new labels at once.
            self.refresh_snapshot(cfg, now);
        }
        Ok((readings.len(), set))
    }

    fn page_discovery_stage(&self, cfg: &AiSettings, deadline: std::time::Instant) -> Result<()> {
        if !cfg.fetch_pages || !cfg.monitor_page_discovery || std::time::Instant::now() >= deadline
        {
            return Ok(());
        }
        let limit = crate::page::workers().min(cfg.page_candidates_per_scan as usize);
        let now = Utc::now().timestamp();
        let exemptions = self.store.allow_overrides()?;
        let candidates = self.store.page_discovery_candidates(
            now,
            cfg.confidence_floor,
            cfg.max_domains_per_scan as usize,
            cfg.fusion,
        )?;
        let live = crate::page::PageFetcher::new(
            std::time::Duration::from_secs(cfg.page_fetch_timeout_secs.clamp(1, 30)),
            cfg.page_fetch_max_bytes.clamp(16 * 1024, 2 * 1024 * 1024) as usize,
        );
        let reader: &dyn crate::page::PageReader = self
            .page_reader
            .get()
            .map_or(&live as &dyn crate::page::PageReader, |reader| {
                reader.as_ref()
            });
        let readings = std::thread::scope(|scope| {
            let handles: Vec<_> = candidates
                .into_iter()
                .filter(|domain| !exempt(domain, &exemptions))
                .take(limit)
                .take_while(|_| std::time::Instant::now() < deadline)
                .map(|domain| {
                    scope.spawn(move || {
                        let reading =
                            reader.inspect_for_discovery(&domain, cfg.page_confidence_floor);
                        (domain, reading)
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .collect::<Vec<_>>()
        });
        let scoring_version = self.scoring_version();
        for (domain, reading) in readings {
            self.store.save_page_discovery(
                &domain,
                &reading,
                Utc::now().timestamp(),
                &scoring_version,
            )?;
        }
        Ok(())
    }

    /// Fetch and read the page behind each new threat candidate, recording
    /// what it says. `ai.page_rule` decides whether the reading may move the
    /// verdict's confidence; with the default `evidence` it never does.
    fn page_stage(
        &self,
        cfg: &AiSettings,
        now: i64,
        deadline: std::time::Instant,
    ) -> Result<usize> {
        if !cfg.fetch_pages {
            return Ok(0);
        }
        let candidates = self.store.page_fetch_candidates(
            now,
            cfg.confidence_floor,
            cfg.page_candidates_per_scan.clamp(1, 64),
        )?;
        if candidates.is_empty() {
            return Ok(0);
        }
        let live;
        let reader: &dyn crate::page::PageReader = match self.page_reader.get() {
            Some(reader) => reader.as_ref(),
            None => {
                live = crate::page::PageFetcher::new(
                    std::time::Duration::from_secs(cfg.page_fetch_timeout_secs.clamp(1, 30)),
                    cfg.page_fetch_max_bytes.clamp(16 * 1024, 2 * 1024 * 1024) as usize,
                );
                &live
            }
        };
        // The stage shares the scan cycle, so it gets a wall-clock budget: a
        // batch of slow sites (each trying HTTPS, HTTP and redirects) must
        // not hold up classification. A candidate not reached stays unread
        // and is picked up next cycle.
        let workers = crate::page::workers().min(candidates.len());
        let chunk = candidates.len().div_ceil(workers);
        let readings: Vec<(String, f32, crate::page::Inspection)> = std::thread::scope(|scope| {
            let handles: Vec<_> = candidates
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        part.iter()
                            .take_while(|_| std::time::Instant::now() < deadline)
                            .map(|(domain, confidence)| {
                                (domain.clone(), *confidence, reader.inspect(domain))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap_or_default())
                .collect()
        });
        let mut recorded = 0usize;
        let mut adjusted = 0usize;
        for (domain, confidence, inspection) in &readings {
            // Keep what the page said for the page-text model, and let the
            // model refine the phrase table's reading (it can only add or
            // strengthen a threat reading).
            let mut reading = inspection.reading.clone();
            let mut model_note = None;
            if let Some((title, text)) = &inspection.page {
                if let Err(e) = self.store.save_page_text(domain, title, text) {
                    self.log_warn(format!("AI could not keep the text of {domain}: {e}"));
                }
                if let Some(model) = self.page_model.get() {
                    (reading, model_note) = model.refine(reading, title, text);
                }
            }
            let inspection = &crate::page::Inspection {
                note: match model_note {
                    Some(note) => format!("{} ({note})", inspection.note),
                    None => inspection.note.clone(),
                },
                reading,
                page: None,
            };
            let changed = crate::page::adjust_confidence(
                cfg.page_rule,
                *confidence,
                inspection.reading.as_ref(),
                // Only the block list marks agreement.
                |label| cfg.is_auto_block_category(label),
                cfg.page_confidence_floor,
            );
            let note = match changed {
                Some(new) => format!(
                    "{} - confidence now {:.0}% by ai.page_rule",
                    inspection.note,
                    new * 100.0
                ),
                None => inspection.note.clone(),
            };
            if let Some(new) = changed {
                self.store
                    .record_page_adjustment(domain, cfg.page_rule, *confidence, new)?;
            }
            self.store
                .record_page_reading(domain, &note, changed, inspection.reading.as_ref())?;
            // The reading changed the confidence: recompute the calibrated
            // score so the gate compares the confidence that is stored now.
            if changed.is_some() {
                self.reassess_domain(cfg, domain, now);
            }
            if changed.is_some() {
                adjusted += 1;
            }
            recorded += 1;
        }
        if adjusted > 0 {
            // A page decision moves what blocks and what the exports list.
            self.refresh_snapshot(cfg, now);
            self.log_info(format!(
                "AI adjusted {adjusted} threat verdict(s) from their page content"
            ));
        }
        Ok(recorded)
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
    pub fn content_backend_name(&self) -> String {
        self.content.name()
    }

    /// The threat-detection pipeline actually running (verifier included).
    pub fn threat_backend_name(&self) -> String {
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
    /// at or above the block threshold, and not exempted by an allow override
    /// on the domain or any parent domain, carrying an auto-block label.
    /// In enforce mode these are blocked; in train mode they are what would
    /// be.
    pub fn eligible_blocks(&self, cfg: &AiSettings, now: i64) -> Result<BlockSnapshot> {
        self.blocks_with(cfg, now, &self.store.allow_overrides()?)
    }

    fn blocks_with(
        &self,
        cfg: &AiSettings,
        now: i64,
        overrides: &ExemptionSnapshot,
    ) -> Result<BlockSnapshot> {
        let mut eligible = BlockSnapshot::new();
        // Graduated authority (off by default): with it on, a finding from a
        // source at `monitor` or `propose` is recorded and listed but never
        // reaches the block snapshot. A source is demoted here automatically
        // when its measured false-positive share passes the configured limit.
        let decisions = if cfg.authority.enabled {
            match self.authority_decisions(cfg) {
                Ok(decisions) => decisions,
                Err(e) => {
                    // Fail closed: a broken measurement must not grant
                    // authority nobody measured.
                    self.log_warn(format!(
                        "AI could not measure enforcement authority ({e}); holding findings to monitor"
                    ));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        // The label list is what separates a threat from an ordinary
        // category, so it gates blocking too.
        for candidate in self
            .store
            .fresh_blocked(now, cfg.block_threshold, cfg.fusion)?
        {
            if cfg.authority.enabled {
                let source = crate::authority::Source::of(&candidate.source);
                let may_block = crate::authority::decision_for(&decisions, source)
                    .is_some_and(|decision| decision.may_block());
                if !may_block {
                    continue;
                }
            }
            if cfg.is_auto_block_category(&candidate.category)
                && !exempt(&candidate.domain, overrides)
            {
                eligible.insert(
                    candidate.domain,
                    ActiveBlock {
                        category: candidate.category,
                        expires_at: candidate.expires_at,
                        exact_host: false,
                    },
                );
            }
        }
        // The operator's own threat labels: they block whatever the model's
        // confidence, and never expire. Exemptions still win, and unticking
        // the label stops them too.
        for (domain, category) in self.store.operator_threats()? {
            if cfg.is_auto_block_category(&category) && !exempt(&domain, overrides) {
                eligible.insert(
                    domain,
                    ActiveBlock {
                        category,
                        expires_at: i64::MAX,
                        exact_host: false,
                    },
                );
            }
        }
        // Page findings go through the same snapshot, cap and exemptions as
        // model findings. Graduated authority treats them as automated findings.
        // A page finding is independent of the model's enabled threat families:
        // the page itself is the evidence, so it may enforce while no family is
        // listed. The operator's explicit switches (fetch, monitor, enforce),
        // per-domain exemptions and the authority stage still bound it, and a
        // family they suppressed globally is skipped below.
        let page_source = if cfg.authority.advancement {
            crate::authority::Source::Page
        } else {
            crate::authority::Source::Model
        };
        let automated_may_block = !cfg.authority.enabled
            || crate::authority::decision_for(&decisions, page_source)
                .is_some_and(|decision| decision.may_block());
        if let Some(intel) = self.intel.get().filter(|_| {
            cfg.mode == AiMode::Enforce
                && cfg.fetch_pages
                && cfg.monitor_page_discovery
                && cfg.enforce_page_discovery
                && cfg.page_rule != daygle_dns_core::config::PageRule::Evidence
                && automated_may_block
                && self.settings.load().enforce_page_discovery
        }) {
            let intel = intel.index();
            let calibration = self.calibration.load_full();
            let weights = self.weights.load_full();
            for (domain, expires_at) in
                self.store.page_discovery_blocks(now, cfg.block_threshold)?
            {
                if eligible.contains_key(&domain)
                    || exempt(&domain, overrides)
                    || intel.is_popular(&domain)
                    || self
                        .store
                        .sighting(&domain)?
                        .is_some_and(|s| s.established())
                {
                    continue;
                }
                let Some(report) = self.store.page_discovery(&domain, now)? else {
                    continue;
                };
                if cfg.label_role(report.reading.category.as_deref().unwrap_or("phishing"))
                    == daygle_dns_core::config::LabelRole::Suppressed
                {
                    // An explicit global suppression outranks a page finding.
                    continue;
                }
                let block_category = report
                    .reading
                    .category
                    .clone()
                    .unwrap_or_else(|| "phishing".to_string());
                let Some(page) = report.observation() else {
                    continue;
                };
                let confidence = page.value.unwrap_or_default();
                let observations = self
                    .store
                    .observations(&domain, "threat")?
                    .map_or_else(Vec::new, |(_, observations)| observations);
                let fused = fusion::fuse_page_discovery(&observations, &weights, page);
                let gate = assessment::score_of_record(
                    cfg.fusion,
                    confidence,
                    Some(&fused),
                    calibration.as_ref().as_ref(),
                );
                if gate.gate().min(confidence)
                    < cfg
                        .block_threshold
                        .max(crate::page::DISCOVERY_ENFORCEMENT_FLOOR)
                {
                    continue;
                }
                eligible.insert(
                    domain,
                    ActiveBlock {
                        category: block_category,
                        expires_at,
                        exact_host: true,
                    },
                );
            }
        }
        Ok(eligible)
    }

    /// Domain -> category, for per-group category blocking.
    ///
    /// A threat label (the built-in families, unless removed, plus the ones
    /// the operator listed)
    /// gets here only on the threat channel's terms - a verdict at or above
    /// `block_threshold` that the verifier did not dispute - whatever the
    /// mode: blocking a category is the operator's rule. The categorizer's
    /// own guess at such a label is left out: it has only the low
    /// categorization floor to clear, and a group blocking "malware" then
    /// blocked Windows Update on a 77% guess. A label the operator set by
    /// hand stands.
    fn categories_with(
        &self,
        cfg: &AiSettings,
        now: i64,
        overrides: &ExemptionSnapshot,
        blocks: &BlockSnapshot,
    ) -> Result<CategorySnapshot> {
        let relabels = self.store.category_overrides()?;
        let mut snapshot = CategorySnapshot::new();
        for (domain, category, expires_at) in self.store.fresh_categories(now)? {
            if exempt(&domain, overrides) {
                continue;
            }
            let category = match relabels.get(&domain) {
                Some(relabel) => relabel.clone(),
                None if cfg.is_auto_block_category(&category) => continue,
                None => category,
            };
            snapshot.insert(
                domain,
                ActiveCategory {
                    category,
                    expires_at,
                },
            );
        }
        for (domain, block) in blocks {
            if block.exact_host || relabels.contains_key(domain) {
                continue;
            }
            snapshot.insert(
                domain.clone(),
                ActiveCategory {
                    category: block.category.clone(),
                    expires_at: block.expires_at,
                },
            );
        }
        for (domain, category) in &relabels {
            if exempt(domain, overrides) {
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
        // One read of the exemptions serves both snapshots and the plugin.
        let overrides = match self.store.allow_overrides() {
            Ok(overrides) => overrides,
            Err(e) => {
                // Keep everything previously published rather than drop
                // exemptions (or blocks) over a transient store error.
                self.log_warn(format!("AI snapshot refresh failed: {e}"));
                return;
            }
        };
        // Exemptions go out before either snapshot: a newly exempted domain
        // must never meet a block or category snapshot that still matches it
        // without the exemption that clears it, and a failed block query
        // below must not keep the new exemptions from the plugin.
        let overrides = Arc::new(overrides);
        self.exemptions.store(overrides.clone());
        if self.scoring_staged.load(Ordering::Acquire) {
            return;
        }
        // The eligible threats, read once: both snapshots are built from them.
        let eligible = match self.blocks_with(cfg, now, &overrides) {
            Ok(eligible) => eligible,
            Err(e) => {
                // Keep the previous snapshots rather than dropping every
                // block over a transient store error.
                self.log_warn(format!("AI snapshot refresh failed: {e}"));
                return;
            }
        };
        match self.categories_with(cfg, now, &overrides, &eligible) {
            Ok(categories) => self.categories.store(Arc::new(categories)),
            Err(e) => self.log_warn(format!("AI category snapshot refresh failed: {e}")),
        }
        let snapshot = if cfg.mode == AiMode::Enforce {
            eligible
        } else {
            BlockSnapshot::new()
        };
        let previous = self.snapshot.load();
        // Safety rail: a broken model (or a tagger change) that suddenly
        // calls half the network a threat must not black it out in one
        // refresh. Domains already blocked stay blocked; only the new ones
        // are held back, oldest name first, and the next refresh admits the
        // rest once the operator has had a chance to look.
        let mut snapshot = snapshot;
        let fresh: Vec<String> = snapshot
            .keys()
            .filter(|domain| !previous.contains_key(*domain))
            .cloned()
            .collect();
        let mut withheld = 0usize;
        let limit = effective_new_block_limit(cfg);
        if fresh.len() > limit {
            let mut overflow = fresh;
            overflow.sort();
            withheld = overflow.len() - limit;
            for domain in overflow.iter().skip(limit) {
                snapshot.remove(domain);
            }
        }
        let snapshot = snapshot;
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
                if withheld > 0 {
                    format!(
                        "The AI blocked {} new domain{} ({} more held back)",
                        added.len(),
                        if added.len() == 1 { "" } else { "s" },
                        withheld
                    )
                } else {
                    format!(
                        "The AI blocked {} new domain{}",
                        added.len(),
                        if added.len() == 1 { "" } else { "s" }
                    )
                },
                format!(
                    "The AI scanner started blocking: {}{}. Review them under AI -> Threats, \
                     and exempt any that should stay reachable.{}",
                    list.join(", "),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    },
                    if withheld > 0 {
                        format!(
                            " {withheld} more new domains were held back by the per-cycle limit \
                             and will be reconsidered on the next scan."
                        )
                    } else {
                        String::new()
                    }
                ),
            );
        }
        self.snapshot.store(Arc::new(snapshot));
    }

    pub(crate) fn stage_scoring(&self, staged: bool) {
        let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
        self.scoring_staged.store(staged, Ordering::Release);
    }

    /// The published exemptions, for the policy plugin.
    pub fn exemptions(&self) -> Arc<ArcSwap<ExemptionSnapshot>> {
        self.exemptions.clone()
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
                Ok(Ok(_)) => {
                    since_epoch = started;
                    // Model maintenance runs after a successful cycle, on a
                    // blocking thread. A due retrain delays the next cycle by
                    // its duration; one that is not due costs nothing.
                    if let Some(maintenance) =
                        self.maintenance.get().and_then(std::sync::Weak::upgrade)
                    {
                        let _ = tokio::task::spawn_blocking(move || maintenance.run()).await;
                    }
                }
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

/// The number of new blocks one refresh may publish. [`MAX_NEW_BLOCKS_PER_REFRESH`]
/// is a ceiling: a configured authority limit can only tighten it, never
/// bypass it.
fn effective_new_block_limit(cfg: &AiSettings) -> usize {
    if cfg.authority.enabled {
        (cfg.authority.max_new_blocks_per_refresh as usize).clamp(1, MAX_NEW_BLOCKS_PER_REFRESH)
    } else {
        MAX_NEW_BLOCKS_PER_REFRESH
    }
}

/// How far back the first cycle after startup reads the query log: eight
/// intervals, at most eight hours.
fn catchup_secs(cfg: &AiSettings) -> u64 {
    cfg.scan_interval_secs.min(3600) * 8
}

/// Whether `domain` or one of its parent names (label-aligned suffixes, so
/// `notbad.example.com` never matches `bad.example.com`) satisfies `matches`.
/// One walk over the name's own suffixes, so the caller pays for the labels it
/// has rather than for the size of the set it is checked against.
pub(crate) fn any_suffix(name: &str, mut matches: impl FnMut(&str) -> bool) -> bool {
    let mut candidate = name;
    loop {
        if matches(candidate) {
            return true;
        }
        match candidate.split_once('.') {
            Some((_, parent)) => candidate = parent,
            None => return false,
        }
    }
}

/// Whether an allow override exempts `domain`: on the domain itself or on
/// any parent domain (an exemption covers subdomains).
pub fn exempt(domain: &str, overrides: &HashSet<String>) -> bool {
    any_suffix(domain, |candidate| overrides.contains(candidate))
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
///
/// Both suffix sets are tested by walking the name's own parents: a harvest
/// of tens of thousands of names costs one lookup per label instead of one
/// comparison per hosted zone.
fn is_candidate(name: &str, hosted: &HashSet<String>) -> bool {
    looks_like_domain(name)
        && name.contains('.')
        && !any_suffix(name, |suffix| LOCAL_SUFFIXES.contains(&suffix))
        && !any_suffix(name, |suffix| hosted.contains(suffix))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(domain: &str, severity: &str, status: &str, confidence: f32) -> NewVerdict {
        NewVerdict {
            domain: domain.to_string(),
            channel: Channel::Threat,
            category: "phishing".to_string(),
            severity: severity.to_string(),
            status: status.to_string(),
            confidence,
            backend: "fasttext".to_string(),
            evidence: "model, phishing".to_string(),
            threat_score: confidence,
            expires_after_secs: 3_600,
        }
    }

    /// The blocking-rate metric counts the number the gate compares: a verdict
    /// whose fused assessment sits below the threshold is not a block even when
    /// its confidence clears it, and a verdict with no stored assessment is read
    /// by its confidence, as the gate reads it.
    #[test]
    fn the_blocking_rate_counts_the_score_of_record() {
        let rows = vec![
            verdict("fused-down.example", "threat", "classified", 0.97),
            verdict("unassessed.example", "threat", "classified", 0.97),
            verdict("quiet.example", "info", "classified", 0.97),
            verdict("skipped.example", "threat", "skipped", 0.97),
        ];
        let mut assessed = std::collections::HashMap::new();
        assessed.insert("fused-down.example".to_string(), 0.42);

        assert_eq!(
            Scanner::blocking_count(&rows, &assessed, 0.9),
            1,
            "only the unassessed confidence clears the threshold"
        );
        assert_eq!(
            Scanner::blocking_count(&rows, &assessed, 0.4),
            2,
            "the fused assessment counts at its own value"
        );
    }
}
