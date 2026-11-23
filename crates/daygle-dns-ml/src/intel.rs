//! Threat intelligence: maintained public threat feeds the AI uses as labels
//! it did not produce itself.
//!
//! A classifier that only checks itself against a copy of itself cannot tell
//! when it is wrong. These feeds are independent, curated and refreshed by
//! their maintainers, and cost nothing to consult once downloaded, so they
//! give a CPU-only install (no ONNX verifier) the outside opinion it lacked:
//!
//! * **confirmation** - a verdict of the scanner's own trains only when
//!   something independent agrees; a feed listing the domain under a threat
//!   label is such an agreement ([`crate::learn::Sources::intel`]);
//! * **held-out threats** - a sample of feed names is kept out of training and
//!   every candidate model must still detect at least as many of them as the
//!   live model does, before and during its trial;
//! * **trial truths** - a domain looked up during a trial and listed by a feed
//!   is a label the trial can score both models on, so a trial on a quiet
//!   install no longer passes for lack of evidence;
//! * **training material** - the rest of the sample trains the threat labels,
//!   so the model keeps up with new threat names without an operator;
//! * **corroboration** - a threat verdict on a listed domain is corroborated
//!   at blocking confidence ([`crate::evidence`]).
//!
//! The feeds name domains, never this network's traffic: downloading them
//! reveals nothing about what clients look up. Downloads honour
//! `policy.feed_mirror` and are on unless `ai.threat_feeds` is turned off.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_dns_core::config::{AiSettings, BlocklistFormat};
use daygle_dns_core::{LogLevel, LogStore};
use tokio_util::sync::CancellationToken;

use crate::learn::{hash_selected, Role};
use crate::scanner::looks_like_domain;
use crate::store::{AiStore, FeedState};

/// One maintained threat feed and the label its names carry.
#[derive(Debug, Clone, Copy)]
pub struct IntelFeed {
    /// Stable id stored with each name.
    pub id: &'static str,
    /// The threat label every name on the feed carries.
    pub label: &'static str,
    /// Who maintains it, for the console.
    pub source: &'static str,
    pub url: &'static str,
    pub format: BlocklistFormat,
}

/// The feeds, one per default threat label.
pub const INTEL_FEEDS: &[IntelFeed] = &[
    IntelFeed {
        id: "urlhaus",
        label: "malware",
        source: "URLhaus (abuse.ch), via malware-filter",
        url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
        format: BlocklistFormat::Domains,
    },
    IntelFeed {
        id: "phishing_army",
        label: "phishing",
        source: "Phishing Army",
        url: "https://phishing.army/download/phishing_army_blocklist.txt",
        format: BlocklistFormat::Domains,
    },
    IntelFeed {
        id: "hagezi_fake",
        label: "scam",
        source: "HaGeZi Fake",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
        format: BlocklistFormat::Wildcard,
    },
];

/// What the evidence stage writes into a verdict's evidence
/// ([`crate::evidence`]): a verdict carrying one depends on the evidence
/// settings.
const EVIDENCE_NOTES: &[&str] = &[
    ", listed by ",
    "established on this network",
    "machine-generated-looking name",
];

/// How often a downloaded feed is refreshed.
const REFRESH_SECS: i64 = 12 * 3600;
/// How long a failed download waits before it is tried again.
const RETRY_SECS: i64 = 3600;
/// How often the loop looks for feeds that are due.
const TICK: Duration = Duration::from_secs(60);
/// Largest feed body accepted.
const MAX_BYTES: usize = 32 * 1024 * 1024;

/// Feed names that train each threat label per retrain, at most.
pub const MAX_TRAINING_PER_LABEL: usize = 1_000;
/// Feed names held out per label to check every candidate, at most.
pub const MAX_PROBE_PER_LABEL: usize = 150;

/// `(label, domain)` pairs.
pub type Labelled = Vec<(String, String)>;

/// The downloaded feeds, in memory, for lookups on the scan and retrain paths.
#[derive(Debug, Default)]
pub struct IntelIndex {
    exact: HashMap<String, u8>,
    wildcard: HashMap<String, u8>,
    /// Each feed's names (wildcard suffixes as plain names), sorted, so
    /// samples are the same from run to run.
    by_feed: Vec<Vec<String>>,
}

impl IntelIndex {
    /// Build from stored `(domain, wildcard, feed)` rows; rows of unknown
    /// feeds are ignored.
    pub fn from_entries(entries: impl IntoIterator<Item = (String, bool, String)>) -> Self {
        let mut index = IntelIndex {
            by_feed: vec![Vec::new(); INTEL_FEEDS.len()],
            ..Default::default()
        };
        for (domain, wildcard, feed_id) in entries {
            let Some(at) = INTEL_FEEDS.iter().position(|f| f.id == feed_id) else {
                continue;
            };
            let at = at as u8;
            if wildcard {
                index.wildcard.entry(domain.clone()).or_insert(at);
            } else {
                index.exact.entry(domain.clone()).or_insert(at);
            }
            index.by_feed[at as usize].push(domain);
        }
        for names in &mut index.by_feed {
            names.sort_unstable();
            names.dedup();
        }
        index
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// The feed that lists `domain`: the name itself, or a parent a wildcard
    /// entry covers (`*.example` lists `a.example` and `example`).
    pub fn feed_for(&self, domain: &str) -> Option<&'static IntelFeed> {
        let domain = domain.trim().trim_end_matches('.');
        if let Some(at) = self.exact.get(domain).or_else(|| self.wildcard.get(domain)) {
            return INTEL_FEEDS.get(*at as usize);
        }
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            rest = parent;
            if let Some(at) = self.wildcard.get(rest) {
                return INTEL_FEEDS.get(*at as usize);
            }
        }
        None
    }

    /// The threat label a feed gives `domain`.
    pub fn label_for(&self, domain: &str) -> Option<&'static str> {
        self.feed_for(domain).map(|f| f.label)
    }

    /// Feed names for the labels `wanted` accepts, split into training names
    /// and a held-out probe (a stable one-in-five, by name), each spread
    /// evenly over the feed and capped per label.
    pub fn sample(&self, wanted: impl Fn(&str) -> bool) -> (Labelled, Labelled) {
        let mut training = Vec::new();
        let mut probe = Vec::new();
        for (at, names) in self.by_feed.iter().enumerate() {
            let label = INTEL_FEEDS[at].label;
            if names.is_empty() || !wanted(label) {
                continue;
            }
            let usable: Vec<&String> = names.iter().filter(|n| looks_like_domain(n)).collect();
            let (held, kept): (Vec<&String>, Vec<&String>) =
                usable.into_iter().partition(|n| hash_selected(n));
            for name in spread(&kept, MAX_TRAINING_PER_LABEL) {
                training.push((label.to_string(), name.clone()));
            }
            for name in spread(&held, MAX_PROBE_PER_LABEL) {
                probe.push((label.to_string(), name.clone()));
            }
        }
        (training, probe)
    }
}

/// At most `n` of `items`, evenly spaced, in order.
fn spread<'a, T>(items: &[&'a T], n: usize) -> Vec<&'a T> {
    if items.len() <= n {
        return items.to_vec();
    }
    (0..n).map(|i| items[i * items.len() / n]).collect()
}

/// Whether `label` is a threat for `role` and the model knows it.
pub fn wanted_label(
    role: Role,
    settings: &AiSettings,
    known: Option<&std::collections::HashSet<String>>,
    label: &str,
) -> bool {
    role.is_threat_label(settings, label) && known.is_none_or(|k| k.contains(label))
}

/// The feeds, their download state and the in-memory index.
pub struct Intel {
    store: Arc<AiStore>,
    settings: Arc<ArcSwap<AiSettings>>,
    index: ArcSwap<IntelIndex>,
    logs: Arc<LogStore>,
}

impl Intel {
    /// Load the stored feeds.
    pub fn new(
        store: Arc<AiStore>,
        settings: Arc<ArcSwap<AiSettings>>,
        logs: Arc<LogStore>,
    ) -> Arc<Self> {
        let intel = Arc::new(Self {
            store,
            settings,
            index: ArcSwap::from_pointee(IntelIndex::default()),
            logs,
        });
        intel.reload();
        intel
    }

    /// Rebuild the in-memory index from the store.
    pub fn reload(&self) {
        match self.store.intel_entries() {
            Ok(entries) => self
                .index
                .store(Arc::new(IntelIndex::from_entries(entries))),
            Err(e) => tracing::warn!(error = %e, "could not load the stored threat feeds"),
        }
    }

    /// Reload after a download and re-check every threat verdict whose
    /// listing changed: a name a feed added gets its corroboration now, and
    /// one a feed dropped loses it, instead of both waiting for the verdict
    /// to expire.
    pub fn refresh(&self) {
        let before = self.index.load_full();
        self.reload();
        let after = self.index.load_full();
        let listing = |index: &IntelIndex, domain: &str| index.feed_for(domain).map(|f| f.id);
        let changed: Vec<String> = match self.store.decided_threats() {
            Ok(rows) => rows
                .into_iter()
                .map(|(domain, _)| domain)
                .filter(|domain| listing(&before, domain) != listing(&after, domain))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "could not read threat verdicts after a feed update");
                return;
            }
        };
        self.requeue(&changed, "the threat feeds changed");
    }

    /// Re-check the threat verdicts the outside evidence touches now or
    /// touched before: after `ai.threat_feeds` or `ai.network_evidence` is
    /// switched, so the change applies within a scan instead of at expiry.
    pub fn recheck_evidence(&self) {
        let index = self.index.load_full();
        let established: std::collections::HashSet<String> = self
            .store
            .established_domains(u32::MAX)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let affected: Vec<String> = match self.store.decided_threats() {
            Ok(rows) => rows
                .into_iter()
                .filter(|(domain, evidence)| {
                    index.feed_for(domain).is_some()
                        || established.contains(domain)
                        || EVIDENCE_NOTES.iter().any(|note| evidence.contains(note))
                })
                .map(|(domain, _)| domain)
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "could not read threat verdicts after a settings change");
                return;
            }
        };
        self.requeue(&affected, "the evidence settings changed");
    }

    fn requeue(&self, domains: &[String], why: &str) {
        if domains.is_empty() {
            return;
        }
        match self.store.requeue_threat_domains(domains) {
            Ok(0) => {}
            Ok(queued) => self.logs.push(
                LogLevel::Info,
                "ai",
                format!("AI re-checks {queued} threat verdict(s) because {why}"),
            ),
            Err(e) => tracing::warn!(error = %e, "could not re-queue threat verdicts"),
        }
    }

    /// The feeds as the AI should use them now: empty while `ai.threat_feeds`
    /// is off, so turning it off stops their use at once.
    pub fn index(&self) -> Arc<IntelIndex> {
        if self.settings.load().threat_feeds {
            self.index.load_full()
        } else {
            Arc::new(IntelIndex::default())
        }
    }

    /// Each feed with its download state, for the console.
    pub fn status(&self) -> Vec<serde_json::Value> {
        let states = self.store.intel_feeds().unwrap_or_default();
        INTEL_FEEDS
            .iter()
            .map(|f| {
                let state = states.get(f.id).cloned().unwrap_or_default();
                serde_json::json!({
                    "id": f.id,
                    "label": f.label,
                    "source": f.source,
                    "entries": state.entries,
                    "updated_at": (state.updated_at > 0).then_some(state.updated_at),
                    "error": (!state.error.is_empty()).then_some(state.error),
                })
            })
            .collect()
    }

    /// Keep the feeds downloaded and fresh until `shutdown`. `mirror` gives
    /// `policy.feed_mirror` (a base URL, or empty).
    pub async fn run(
        self: Arc<Self>,
        mirror: impl Fn() -> String + Send + 'static,
        shutdown: CancellationToken,
    ) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        loop {
            if self.settings.load().threat_feeds {
                let states = self.store.intel_feeds().unwrap_or_default();
                let now = chrono::Utc::now().timestamp();
                let mut changed = false;
                for feed in INTEL_FEEDS {
                    if !due(states.get(feed.id), now) {
                        continue;
                    }
                    let url = daygle_dns_policy::feeds::mirrored(feed.url, &mirror());
                    let outcome = fetch(&client, &url).await.and_then(|body| {
                        let entries = daygle_dns_policy::parse_blocklist(&body, feed.format);
                        if entries.is_empty() {
                            Err(format!("{url} held no names"))
                        } else {
                            Ok(entries)
                        }
                    });
                    changed |= self.store_outcome(feed, outcome).await;
                }
                if changed {
                    let intel = self.clone();
                    let _ = tokio::task::spawn_blocking(move || intel.refresh()).await;
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    }

    async fn store_outcome(
        self: &Arc<Self>,
        feed: &'static IntelFeed,
        outcome: std::result::Result<BTreeSet<String>, String>,
    ) -> bool {
        let intel = self.clone();
        tokio::task::spawn_blocking(move || match outcome {
            Ok(entries) => match intel.store.replace_intel(feed.id, &entries) {
                Ok(stored) => {
                    intel.logs.push(
                        LogLevel::Info,
                        "ai",
                        format!(
                            "AI threat feed {} updated: {stored} {} names",
                            feed.source, feed.label
                        ),
                    );
                    true
                }
                Err(e) => {
                    let e = format!("could not store the names: {e}");
                    intel.logs.push(
                        LogLevel::Warn,
                        "ai",
                        format!("AI threat feed {}: {e}", feed.source),
                    );
                    let _ = intel.store.intel_failed(feed.id, &e);
                    false
                }
            },
            Err(e) => {
                tracing::warn!(feed = feed.id, error = %e, "AI threat feed download failed");
                intel.logs.push(
                    LogLevel::Warn,
                    "ai",
                    format!(
                        "AI threat feed {} could not be downloaded: {e}",
                        feed.source
                    ),
                );
                let _ = intel.store.intel_failed(feed.id, &e);
                false
            }
        })
        .await
        .unwrap_or(false)
    }
}

/// Whether a feed in `state` should be downloaded at `now`.
fn due(state: Option<&FeedState>, now: i64) -> bool {
    let Some(state) = state else { return true };
    if !state.error.is_empty() && state.attempted_at > state.updated_at {
        return now - state.attempted_at >= RETRY_SECS;
    }
    now - state.updated_at >= REFRESH_SECS
}

async fn fetch(client: &reqwest::Client, url: &str) -> std::result::Result<String, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {}", describe(&e)))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    let too_large = || format!("{url} is larger than {MAX_BYTES} bytes");
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("{url}: {}", describe(&e)))?
    {
        if body.len() + chunk.len() > MAX_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// An error with its causes: reqwest's own text ("error sending request for
/// url") says nothing about why (DNS, TLS, refused, timed out) without them.
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> IntelIndex {
        IntelIndex::from_entries([
            (
                "bad-login.example".to_string(),
                false,
                "phishing_army".to_string(),
            ),
            (
                "fakeshop.example".to_string(),
                true,
                "hagezi_fake".to_string(),
            ),
            ("dropper.example".to_string(), false, "urlhaus".to_string()),
            (
                "ignored.example".to_string(),
                false,
                "retired_feed".to_string(),
            ),
        ])
    }

    #[test]
    fn lookups_follow_wildcards_only() {
        let index = index();
        assert_eq!(index.label_for("bad-login.example"), Some("phishing"));
        assert_eq!(
            index.label_for("www.bad-login.example"),
            None,
            "exact entry"
        );
        assert_eq!(index.label_for("fakeshop.example"), Some("scam"));
        assert_eq!(index.label_for("pay.fakeshop.example"), Some("scam"));
        assert_eq!(index.label_for("dropper.example."), Some("malware"));
        assert_eq!(index.label_for("ignored.example"), None);
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn samples_are_stable_disjoint_and_filtered() {
        let mut entries = Vec::new();
        for i in 0..2_000 {
            entries.push((
                format!("phish-{i}.example"),
                false,
                "phishing_army".to_string(),
            ));
            entries.push((format!("drop-{i}.example"), false, "urlhaus".to_string()));
        }
        let index = IntelIndex::from_entries(entries);
        let (training, probe) = index.sample(|label| label == "phishing");
        assert!(training.iter().chain(&probe).all(|(l, _)| l == "phishing"));
        assert_eq!(training.len(), MAX_TRAINING_PER_LABEL);
        assert_eq!(probe.len(), MAX_PROBE_PER_LABEL);
        let held: std::collections::HashSet<_> = probe.iter().map(|(_, d)| d).collect();
        assert!(training.iter().all(|(_, d)| !held.contains(d)));
        assert_eq!(index.sample(|label| label == "phishing"), (training, probe));
    }

    #[test]
    fn feeds_are_due_on_schedule() {
        let now = 1_000_000;
        assert!(due(None, now));
        let fresh = FeedState {
            updated_at: now - 60,
            attempted_at: now - 60,
            ..Default::default()
        };
        assert!(!due(Some(&fresh), now));
        let stale = FeedState {
            updated_at: now - REFRESH_SECS,
            ..fresh.clone()
        };
        assert!(due(Some(&stale), now));
        let failed = FeedState {
            attempted_at: now - 60,
            error: "timeout".into(),
            ..stale.clone()
        };
        assert!(!due(Some(&failed), now), "waits before retrying");
        let failed_long_ago = FeedState {
            attempted_at: now - RETRY_SECS,
            ..failed
        };
        assert!(due(Some(&failed_long_ago), now));
    }
}
