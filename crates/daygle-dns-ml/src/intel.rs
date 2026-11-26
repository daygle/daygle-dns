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
//! Beside them sits the opposite kind of list: Tranco's ranking of the most
//! popular sites ([`POPULAR`]). A popular registered domain is almost never
//! a threat on its name alone, so a name-only detection on one is disputed,
//! and popular sites are part of the "ordinary" probe every candidate model
//! is tested on. That protects a site from day one, where the established-
//! domain check needs weeks of this network's traffic.
//!
//! The lists name domains, never this network's traffic: downloading them
//! reveals nothing about what clients look up. Downloads honour
//! `policy.feed_mirror` and are on unless `ai.threat_feeds` is turned off.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_dns_core::config::{AiSettings, BlocklistFormat};
use daygle_dns_core::{LogLevel, LogStore};
use tokio_util::sync::CancellationToken;

use crate::learn::hash_selected;
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

/// The popular-sites list: Tranco's research ranking, combined from several
/// providers and hard to manipulate. Only its top [`POPULAR_SIZE`] are kept.
pub struct PopularList {
    /// Stable id stored with each name.
    pub id: &'static str,
    pub source: &'static str,
    /// Answers with the latest list's download URL (`"download"`).
    pub latest_url: &'static str,
}

/// Whether a feed lists a name itself or through a wildcard entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listed {
    /// The feed lists this exact name.
    Exact,
    /// The feed lists a wildcard entry (`*.example`) that names this domain
    /// or a parent of it.
    Wildcard,
}

impl Listed {
    pub fn as_str(self) -> &'static str {
        match self {
            Listed::Exact => "exact",
            Listed::Wildcard => "wildcard",
        }
    }
}

/// A feed hit on a name: which feed, how it was listed and the name the feed
/// actually lists (the domain, or the parent of a wildcard entry).
#[derive(Debug, Clone)]
pub struct Attribution {
    pub feed: &'static IntelFeed,
    pub listed: Listed,
    pub listed_name: String,
}

pub const POPULAR: PopularList = PopularList {
    id: "tranco",
    source: "Tranco top 100,000",
    latest_url: "https://tranco-list.eu/api/lists/date/latest",
};

/// Ranks kept from the popular list.
pub const POPULAR_SIZE: usize = 100_000;
/// Popular sites in the ordinary probe every candidate is tested on.
pub const MAX_POPULAR_PROBE: usize = 300;

/// What the evidence stage writes into a verdict's evidence
/// ([`crate::evidence`]): a verdict carrying one depends on the evidence
/// settings.
const EVIDENCE_NOTES: &[&str] = &[
    crate::evidence::LISTED_NOTE,
    "a popular site",
    "established on this network",
    "machine-generated-looking name",
    crate::age::AGE_NOTE,
];

/// How often a downloaded feed is refreshed.
const REFRESH_SECS: i64 = 12 * 3600;
/// How long a failed download waits before it is tried again.
const RETRY_SECS: i64 = 3600;
/// How long a download that never reached its server (a failed lookup, a
/// refused or timed-out connection) waits: such failures are usually brief,
/// e.g. while this server's own resolver is starting, so waiting the full
/// [`RETRY_SECS`] would leave a feed missing for an hour over a blip.
const NETWORK_RETRY_SECS: i64 = 300;
/// Starts the stored error of a download that never reached its server.
const UNREACHABLE: &str = "could not reach ";
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
    /// Popular registered domains ([`POPULAR`]), sorted.
    popular: std::collections::HashSet<String>,
    popular_sorted: Vec<String>,
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
            if feed_id == POPULAR.id {
                index.popular.insert(domain);
                continue;
            }
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
        index.popular_sorted = index.popular.iter().cloned().collect();
        index.popular_sorted.sort_unstable();
        index
    }

    /// Whether `domain`'s registered domain is a popular site. Matching the
    /// registered domain, never a parent, matters: `pages.dev` is popular,
    /// but `evil.pages.dev` is someone's own site, and the Public Suffix
    /// List makes it a registered domain of its own.
    pub fn is_popular(&self, domain: &str) -> bool {
        if self.popular.is_empty() {
            return false;
        }
        let name = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        psl::domain_str(&name).is_some_and(|registered| self.popular.contains(registered))
    }

    /// Popular sites for the ordinary probe, spread evenly over the list.
    pub fn popular_sample(&self) -> Vec<String> {
        let all: Vec<&String> = self.popular_sorted.iter().collect();
        spread(&all, MAX_POPULAR_PROBE)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.popular.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// The feed that lists `domain`: the name itself, or a parent a wildcard
    /// entry covers (`*.example` lists `a.example` and `example`).
    pub fn feed_for(&self, domain: &str) -> Option<&'static IntelFeed> {
        self.attribution(domain).map(|found| found.feed)
    }

    /// A parent of `domain` a feed lists exactly. It is never evidence
    /// against the name itself (only a wildcard entry covers subdomains), but
    /// it explains a hit the console would otherwise show as absent.
    pub fn exact_parent(&self, domain: &str) -> Option<Attribution> {
        let domain = domain.trim().trim_end_matches('.');
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            rest = parent;
            if let Some(at) = self.exact.get(rest) {
                return Some(Attribution {
                    feed: INTEL_FEEDS.get(*at as usize)?,
                    listed: Listed::Exact,
                    listed_name: rest.to_string(),
                });
            }
        }
        None
    }

    /// Whether a popular list is loaded: without one, a domain that is not
    /// popular is unknown, not clear.
    pub fn has_popular(&self) -> bool {
        !self.popular.is_empty()
    }

    /// The feed that lists `domain`, how it lists it and the name it lists.
    ///
    /// A plain (non-wildcard) listing only ever condemns its own name: a feed
    /// listing `example` says nothing about `child.example`. A wildcard entry
    /// does cover the subdomains it names, which is the feed's own choice.
    pub fn attribution(&self, domain: &str) -> Option<Attribution> {
        let domain = domain.trim().trim_end_matches('.');
        if let Some(at) = self.exact.get(domain) {
            return Some(Attribution {
                feed: INTEL_FEEDS.get(*at as usize)?,
                listed: Listed::Exact,
                listed_name: domain.to_string(),
            });
        }
        if let Some(at) = self.wildcard.get(domain) {
            return Some(Attribution {
                feed: INTEL_FEEDS.get(*at as usize)?,
                listed: Listed::Wildcard,
                listed_name: domain.to_string(),
            });
        }
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            rest = parent;
            if let Some(at) = self.wildcard.get(rest) {
                return Some(Attribution {
                    feed: INTEL_FEEDS.get(*at as usize)?,
                    listed: Listed::Wildcard,
                    listed_name: rest.to_string(),
                });
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

/// Whether `label` is a threat and the model knows it.
pub fn wanted_label(
    settings: &AiSettings,
    known: Option<&std::collections::HashSet<String>>,
    label: &str,
) -> bool {
    crate::learn::is_threat_label(settings, label) && known.is_none_or(|k| k.contains(label))
}

/// The feeds, their download state and the in-memory index.
pub struct Intel {
    store: Arc<AiStore>,
    settings: Arc<ArcSwap<AiSettings>>,
    index: ArcSwap<IntelIndex>,
    logs: Arc<LogStore>,
    /// Lists already alerted on for their current stale spell.
    stale_alerted: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Set by [`Intel::update_now`]: download every feed on the next pass,
    /// due or not.
    forced: AtomicBool,
    wake: tokio::sync::Notify,
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
            stale_alerted: std::sync::Mutex::new(std::collections::HashSet::new()),
            logs,
            forced: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
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
        let listing = |index: &IntelIndex, domain: &str| {
            (
                index.feed_for(domain).map(|f| f.id),
                index.is_popular(domain),
            )
        };
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
                        || index.is_popular(domain)
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
            .map(|f| (f.id, f.label, f.source))
            .chain(std::iter::once((POPULAR.id, "popular", POPULAR.source)))
            .map(|(id, label, source)| {
                let state = states.get(id).cloned().unwrap_or_default();
                let is_stale = stale(&state, chrono::Utc::now().timestamp());
                serde_json::json!({
                    "id": id,
                    "label": label,
                    "source": source,
                    "entries": state.entries,
                    "updated_at": (state.updated_at > 0).then_some(state.updated_at),
                    "error": (!state.error.is_empty()).then_some(state.error),
                    "stale": is_stale,
                })
            })
            .collect()
    }

    /// Download every feed now instead of waiting for its refresh or retry
    /// (the console's Update Now). Does nothing while `ai.threat_feeds` is off.
    pub fn update_now(&self) {
        self.forced.store(true, Ordering::SeqCst);
        self.wake.notify_one();
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
            let forced = self.forced.swap(false, Ordering::SeqCst);
            if self.settings.load().threat_feeds {
                let states = self.store.intel_feeds().unwrap_or_default();
                let now = chrono::Utc::now().timestamp();
                let mut changed = false;
                for feed in INTEL_FEEDS {
                    if !forced && !due(states.get(feed.id), now) {
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
                if forced || due(states.get(POPULAR.id), now) {
                    let outcome = fetch_popular(&client, &mirror()).await;
                    changed |= self.store_popular(outcome).await;
                }
                if changed {
                    let intel = self.clone();
                    let _ = tokio::task::spawn_blocking(move || intel.refresh()).await;
                }
                self.alert_stale(&self.store.intel_feeds().unwrap_or_default(), now);
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = self.wake.notified() => {}
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

impl Intel {
    async fn store_popular(
        self: &Arc<Self>,
        outcome: std::result::Result<BTreeSet<String>, String>,
    ) -> bool {
        let intel = self.clone();
        tokio::task::spawn_blocking(move || match outcome {
            Ok(entries) => match intel.store.replace_intel(POPULAR.id, &entries) {
                Ok(stored) => {
                    intel.logs.push(
                        LogLevel::Info,
                        "ai",
                        format!("AI popular-sites list updated: {stored} sites"),
                    );
                    true
                }
                Err(e) => {
                    let _ = intel.store.intel_failed(POPULAR.id, &e.to_string());
                    false
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "AI popular-sites list download failed");
                let _ = intel.store.intel_failed(POPULAR.id, &e);
                false
            }
        })
        .await
        .unwrap_or(false)
    }
}

/// Download the latest popular-sites list: ask for its URL, then fetch the
/// top [`POPULAR_SIZE`] as `rank,domain` lines.
async fn fetch_popular(
    client: &reqwest::Client,
    mirror: &str,
) -> std::result::Result<BTreeSet<String>, String> {
    let latest = fetch(
        client,
        &daygle_dns_policy::feeds::mirrored(POPULAR.latest_url, mirror),
    )
    .await?;
    let latest: serde_json::Value =
        serde_json::from_str(&latest).map_err(|e| format!("the list index was not JSON: {e}"))?;
    let download = latest
        .get("download")
        .and_then(|v| v.as_str())
        .ok_or("the list index named no download")?;
    // The index links the full million; the same path takes the size.
    let base = download.rsplit_once('/').map_or(download, |(base, _)| base);
    let url = format!("{base}/{POPULAR_SIZE}");
    let body = fetch(client, &daygle_dns_policy::feeds::mirrored(&url, mirror)).await?;
    let entries = parse_popular(&body);
    if entries.len() < 1_000 {
        return Err(format!("{url} held only {} sites", entries.len()));
    }
    Ok(entries)
}

/// `rank,domain` lines as registered domains.
pub fn parse_popular(body: &str) -> BTreeSet<String> {
    body.lines()
        .filter_map(|line| line.trim().split_once(','))
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| looks_like_domain(domain))
        .take(POPULAR_SIZE)
        .collect()
}

/// A list not updated for this long is stale: the AI is working from old
/// threat names (or old popularity) and the operator should know.
pub const STALE_SECS: i64 = 48 * 3600;

/// Whether a list in `state` is stale at `now`: its last success (or, never
/// having succeeded, its first attempts) lies more than [`STALE_SECS`] back
/// and the latest attempt failed.
fn stale(state: &FeedState, now: i64) -> bool {
    stale_since(state).is_some_and(|since| now - since >= STALE_SECS)
}

/// Since when a failing list has been without fresh data: its last success,
/// or the start of its failures when it never had one.
fn stale_since(state: &FeedState) -> Option<i64> {
    if state.error.is_empty() {
        return None;
    }
    let since = if state.updated_at > 0 {
        state.updated_at
    } else {
        state.failing_since
    };
    (since > 0).then_some(since)
}

impl Intel {
    /// Raise one alert per list per stale spell (a list that recovers and
    /// goes stale again alerts again). Held in memory: a restart alerts once
    /// more for a list still stale, which is better than never.
    fn alert_stale(&self, states: &HashMap<String, FeedState>, now: i64) {
        let mut alerted = self.stale_alerted.lock().unwrap_or_else(|e| e.into_inner());
        let lists = INTEL_FEEDS
            .iter()
            .map(|f| (f.id, f.source))
            .chain(std::iter::once((POPULAR.id, POPULAR.source)));
        for (id, source) in lists {
            let Some(state) = states.get(id) else {
                continue;
            };
            if !stale(state, now) {
                alerted.remove(id);
                continue;
            }
            if !alerted.insert(id.to_string()) {
                continue;
            }
            let days = stale_since(state).map_or(2, |since| (now - since) / 86_400);
            daygle_dns_core::alerts::raise(
                daygle_dns_core::alerts::AlertKind::AiModel,
                format!("ai-feed-stale:{id}:{now}"),
                format!("AI list {source} is not updating"),
                format!(
                    "The AI could not download {source} for {} or more ({}). It keeps using the last copy it has, so new threats it lists are missed. Check the server's internet access or policy.feed_mirror.",
                    if days >= 2 { format!("{days} days") } else { "two days".to_string() },
                    state.error
                ),
            );
        }
    }
}

/// Whether a feed in `state` should be downloaded at `now`.
fn due(state: Option<&FeedState>, now: i64) -> bool {
    let Some(state) = state else { return true };
    if !state.error.is_empty() && state.attempted_at > state.updated_at {
        let wait = if state.error.starts_with(UNREACHABLE) {
            NETWORK_RETRY_SECS
        } else {
            RETRY_SECS
        };
        return now - state.attempted_at >= wait;
    }
    now - state.updated_at >= REFRESH_SECS
}

async fn fetch(client: &reqwest::Client, url: &str) -> std::result::Result<String, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{UNREACHABLE}{url}: {}", describe(&e)))?;
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
        .map_err(|e| format!("{UNREACHABLE}{url}: {}", describe(&e)))?
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
    fn a_plain_listing_never_condemns_a_subdomain() {
        let index = index();
        // `dropper.example` is listed exactly, not as `*.dropper.example`:
        // its own name is the threat, an unrelated site under that parent is
        // not. Only a wildcard entry covers subdomains.
        assert!(index.feed_for("child.dropper.example").is_none());
        assert!(index.feed_for("a.b.bad-login.example").is_none());
        assert_eq!(
            index.feed_for("pay.fakeshop.example").map(|f| f.source),
            index.feed_for("fakeshop.example").map(|f| f.source)
        );

        let exact = index.attribution("dropper.example").expect("listed");
        assert_eq!((exact.listed, exact.listed_name.as_str()), (Listed::Exact, "dropper.example"));
        let wildcard = index.attribution("pay.fakeshop.example").expect("listed");
        assert_eq!(
            (wildcard.listed, wildcard.listed_name.as_str()),
            (Listed::Wildcard, "fakeshop.example"),
            "a wildcard hit names the parent the feed actually lists"
        );
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
    fn popular_sites_match_by_registered_domain_only() {
        let entries = parse_popular("1,google.com\n2,pages.dev\n3,Example.CO.UK.\nbad line\n");
        assert!(entries.contains("google.com") && entries.contains("example.co.uk"));
        let index = IntelIndex::from_entries(
            entries
                .into_iter()
                .map(|d| (d, false, POPULAR.id.to_string())),
        );
        assert!(index.is_popular("mail.google.com"));
        assert!(index.is_popular("shop.example.co.uk"));
        // A site on a hosting platform is someone's own registered domain.
        assert!(!index.is_popular("evil.pages.dev"));
        assert!(!index.is_popular("google.com.evil.example"));
        assert_eq!(
            index.label_for("google.com"),
            None,
            "popular is not a threat label"
        );
        assert_eq!(index.popular_sample().len(), 3);
    }

    #[test]
    fn failing_lists_go_stale_after_two_days() {
        let now = 10_000_000;
        let ok = FeedState {
            updated_at: now - STALE_SECS * 3,
            ..Default::default()
        };
        assert!(!stale(&ok, now), "an old copy with no failure is not stale");
        let failing = FeedState {
            error: "timed out".into(),
            failing_since: now - 3600,
            ..ok.clone()
        };
        assert!(stale(&failing, now), "measured from the last success");
        let never = FeedState {
            error: "timed out".into(),
            attempted_at: now - 60,
            failing_since: now - STALE_SECS,
            ..Default::default()
        };
        assert!(
            stale(&never, now),
            "never downloaded: measured from the first failure"
        );
        let fresh_failure = FeedState {
            failing_since: now - 3600,
            ..never
        };
        assert!(!stale(&fresh_failure, now));
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
        let unreachable = FeedState {
            attempted_at: now - 60,
            error: format!("{UNREACHABLE}https://feed.example/: dns error"),
            ..stale.clone()
        };
        assert!(!due(Some(&unreachable), now), "a short wait first");
        let unreachable_a_while_ago = FeedState {
            attempted_at: now - NETWORK_RETRY_SECS,
            ..unreachable
        };
        assert!(
            due(Some(&unreachable_a_while_ago), now),
            "a network failure is retried well before the hour"
        );
    }
}
