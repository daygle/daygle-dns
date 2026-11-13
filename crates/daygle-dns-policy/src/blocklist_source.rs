//! Remote blocklist sources (like Technitium's blocklist management).
//!
//! A [`BlocklistSourceManager`] fetches one or more HTTP(S) blocklist URLs,
//! parses each in its declared format (`domains`, `hosts`, `adblock`, or
//! `rpz`),
//! merges the sources that apply to everyone into a single domain set, and
//! hands it to the policy engine as the *remote* blocklist. Sources scoped to
//! client groups are compiled one by one into [`GroupBlocklists`] instead,
//! where the client groups that select them look them up. Sources are
//! refreshed on their `refresh_secs` schedule (never more often than
//! [`MIN_REFRESH`]), and a failed download is retried after
//! [`RETRY_AFTER_FAILURE`]. The refresh loop lives in the `daygle-dns` crate
//! (`reload.rs`): it calls [`BlocklistSourceManager::refresh_due`] and then
//! sleeps [`BlocklistSourceManager::next_refresh_in`]
//! ([`BlocklistSourceManager::refresh_all`] is the console's force-refresh).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use daygle_dns_core::config::{
    normalize_domains, BlocklistFormat, BlocklistScope, BlocklistSourceConfig,
};
use daygle_dns_core::error::{DaygleError, Result};

use crate::Blocklist;

/// Fetch limits: allow large hosts and adblock lists while bounding memory use.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The shortest refresh interval honoured, whatever `refresh_secs` says: a
/// list host must not be asked for its list every few seconds.
pub const MIN_REFRESH: Duration = Duration::from_secs(5 * 60);

/// After a failed download, try again this soon (or at the source's own
/// interval, if shorter) rather than a whole interval later: downloads are
/// held in memory only, so a server started before its network was up, or
/// a list host that was briefly down, would otherwise block nothing from
/// that source for up to a day.
pub const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5 * 60);

/// How many sources are downloaded at once.
const PARALLEL_FETCHES: usize = 4;

/// How long the refresh loop sleeps with no enabled source (a change wakes
/// it sooner).
const IDLE_REFRESH: Duration = Duration::from_secs(24 * 3600);

/// A source's refresh interval, with the [`MIN_REFRESH`] floor.
fn interval(source: &BlocklistSourceConfig) -> Duration {
    Duration::from_secs(source.refresh_secs).max(MIN_REFRESH)
}

/// When `source`, whose status is `st`, is next due for a download: at once
/// when never fetched, an interval after its last success, and
/// [`RETRY_AFTER_FAILURE`] after a failed attempt.
fn due_at(st: &SourceStatus, source: &BlocklistSourceConfig, now: Instant) -> Instant {
    let scheduled = st.last_fetch.map_or(now, |last| last + interval(source));
    match (&st.last_error, st.last_attempt) {
        (Some(_), Some(attempt)) => {
            scheduled.max(attempt + RETRY_AFTER_FAILURE.min(interval(source)))
        }
        _ => scheduled,
    }
}

/// The enabled sources scoped to client groups, each compiled on its own and
/// keyed by lower-cased source name. Shared between the refresh loop, which
/// fills it, and the client-group matcher, which reads it on every query; a
/// list selected by several groups is held once.
///
/// It also keeps the entries of each source that applies to everyone or to
/// the DoT listener (those are merged into one list for the policy engine),
/// so a block can be traced back to the source that listed the name.
#[derive(Debug, Default)]
pub struct GroupBlocklists {
    lists: RwLock<Arc<HashMap<String, Arc<Blocklist>>>>,
    merged_sources: RwLock<Arc<MergedSources>>,
    /// The security and privacy categories' maintained lists.
    feeds: Arc<crate::feeds::FeedLists>,
}

/// The entries of the sources merged into the engine's lists, by source
/// name (shared with the source status, so this costs no copy).
#[derive(Debug, Default)]
struct MergedSources {
    everyone: Vec<(String, Arc<BTreeSet<String>>)>,
    dot: Vec<(String, Arc<BTreeSet<String>>)>,
}

impl GroupBlocklists {
    /// The security and privacy categories' maintained lists, filled by
    /// [`crate::feeds::run`].
    pub fn feeds(&self) -> &Arc<crate::feeds::FeedLists> {
        &self.feeds
    }

    /// The current lists (cheap: one `Arc` clone).
    pub fn snapshot(&self) -> Arc<HashMap<String, Arc<Blocklist>>> {
        read_guard(&self.lists).clone()
    }

    /// The compiled list for the source called `name` (any case), if it is
    /// enabled and scoped to groups.
    pub fn get(&self, name: &str) -> Option<Arc<Blocklist>> {
        self.snapshot().get(&name.to_ascii_lowercase()).cloned()
    }

    pub(crate) fn set(&self, lists: HashMap<String, Arc<Blocklist>>) {
        *write_guard(&self.lists) = Arc::new(lists);
    }

    /// Every source merged into the everyone list (or, with `dot`, the DoT
    /// listener's list) that lists `domain`, with the entry that lists it:
    /// `(source name, entry)`, in source order.
    pub fn sources_listing(&self, domain: &str, dot: bool) -> Vec<(String, String)> {
        let merged = read_guard(&self.merged_sources).clone();
        let sources = if dot { &merged.dot } else { &merged.everyone };
        sources
            .iter()
            .filter_map(|(name, entries)| {
                crate::blocklist::entry_for(entries, domain).map(|entry| (name.clone(), entry))
            })
            .collect()
    }

    /// The first source [`Self::sources_listing`] would name. This runs for
    /// every query a remote list blocks, so it stops at the first match.
    pub fn first_source_listing(&self, domain: &str, dot: bool) -> Option<(String, String)> {
        let merged = read_guard(&self.merged_sources).clone();
        let sources = if dot { &merged.dot } else { &merged.everyone };
        sources.iter().find_map(|(name, entries)| {
            crate::blocklist::entry_for(entries, domain).map(|entry| (name.clone(), entry))
        })
    }

    fn set_merged_sources(&self, merged: MergedSources) {
        *write_guard(&self.merged_sources) = Arc::new(merged);
    }
}

/// Per-source runtime status, surfaced through the API.
#[derive(Debug, Clone)]
pub struct SourceStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub format: BlocklistFormat,
    pub refresh_secs: u64,
    pub scope: BlocklistScope,
    /// When the source was last fetched successfully.
    pub last_fetch: Option<Instant>,
    /// When a download of it was last attempted, successful or not (paces
    /// the retry after a failure).
    pub last_attempt: Option<Instant>,
    /// The same event as wall-clock time: `last_fetch` only yields a
    /// relative age (and dies with the process), so this is what lets the
    /// console show an absolute "Last Updated" date and time.
    pub last_fetch_at: Option<SystemTime>,
    /// Domains contributed by this source on its last successful fetch.
    pub domains: usize,
    /// Cached domain set from the last successful fetch. Kept so a source
    /// removal/disable can rebuild the merged remote blocklist immediately,
    /// without waiting for the next due refetch. Shared (`Arc`) so status
    /// snapshots stay cheap for lists with hundreds of thousands of entries.
    pub cached_domains: Arc<BTreeSet<String>>,
    /// Human-readable error from the last failed fetch, if any.
    pub last_error: Option<String>,
}

/// Lock a mutex, recovering from poisoning.
///
/// Every lock in this module guards a snapshot of plain data (the source list,
/// the per-source status, the compiled lists), so a poisoned lock means some
/// unrelated thread panicked while holding it, not that the data is unusable.
/// Propagating the poison would turn that one panic into a permanent one: the
/// refresh loop and the source status endpoint would panic on every later
/// call, so blocklist refreshes and `GET /api/policy/blocklist/sources` would
/// never work again until a restart. Recover the guard instead, matching the
/// rest of the codebase.
fn lock_guard<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn read_guard<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_guard<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

/// Whether the status row `st` still describes `source`. The source list can
/// be replaced while a fetch is in flight: a row is only updated with (or
/// read for) a source of the same name, URL and format, so an edited URL
/// never gets the old URL's domains cached under it.
fn describes(st: &SourceStatus, source: &BlocklistSourceConfig) -> bool {
    st.name == source.name && st.url == source.url && st.format == source.format
}

/// A group-scoped source's domain set and the list compiled from it.
type CompiledSource = (Arc<BTreeSet<String>>, Arc<Blocklist>);

/// A merged list and the per-source sets it was built from.
type MergedList = (Vec<Arc<BTreeSet<String>>>, Arc<Blocklist>);

/// The merged list of `parts`: the cached one while they are the very same
/// sets (nothing refetched or changed since), else built afresh. An
/// unchanged list is then the same `Arc`, which the policy engine compares
/// by pointer instead of entry by entry.
fn merged_list(
    cache: &mut Option<MergedList>,
    parts: Vec<Arc<BTreeSet<String>>>,
) -> Arc<Blocklist> {
    if let Some((built_from, list)) = cache.as_ref() {
        if built_from.len() == parts.len()
            && built_from
                .iter()
                .zip(&parts)
                .all(|(a, b)| Arc::ptr_eq(a, b))
        {
            return list.clone();
        }
    }
    let list = Arc::new(Blocklist::from_sets(parts.iter().map(|p| p.as_ref())));
    *cache = Some((parts, list.clone()));
    list
}

/// The merged lists last published, by audience.
#[derive(Default)]
struct MergedCache {
    everyone: Option<MergedList>,
    dot: Option<MergedList>,
}

/// Fetches and parses remote blocklist sources and merges their domains.
pub struct BlocklistSourceManager {
    /// The configured sources. Held behind a mutex so the console can add,
    /// edit and remove sources at runtime (the API layer stores the list in
    /// the database) without rebuilding the manager or restarting the
    /// refresh loop.
    sources: Mutex<Vec<BlocklistSourceConfig>>,
    client: reqwest::Client,
    status: Mutex<Vec<SourceStatus>>,
    /// Wakes the background refresh loop when [`Self::set_sources`] changes
    /// the list. Used together with `changed_flag` so a sleeping loop picks
    /// up the change after its next tick (notifications alone miss
    /// notifications issued while the future is not parked on `notified()`).
    changed: tokio::sync::Notify,
    /// Sticky "sources changed" flag inspected by the refresh loop after
    /// each tick. Set in `set_sources`; cleared by `take_change`.
    changed_flag: std::sync::atomic::AtomicBool,
    /// Group-scoped sources, published for the client-group matcher.
    group_lists: Arc<GroupBlocklists>,
    /// The compiled form of each group-scoped source and the domain set it
    /// was built from, so an unchanged source is not recompiled every cycle.
    compiled: Mutex<HashMap<String, CompiledSource>>,
    /// The merged domain list of the sources scoped to the DoT listener,
    /// published by every refresh cycle (`None` when none contribute).
    /// Read by the refresh loop to swap into the policy engine's DoT set.
    dot_list: RwLock<Option<Arc<Blocklist>>>,
    /// The merged lists last built, reused while their sources are unchanged.
    merged: Mutex<MergedCache>,
    /// Held for a whole refresh cycle: the background loop and a forced
    /// refresh from the console would otherwise download the same lists at
    /// once, and the later to finish could record the older copy.
    cycle: tokio::sync::Mutex<()>,
}

impl BlocklistSourceManager {
    /// Build a manager for `sources` that publishes group-scoped sources to
    /// `group_lists`. The client follows redirects, enforces TLS (rustls) and
    /// caps response size. A download may take a few minutes as long as data
    /// keeps arriving (big lists over a slow link), but a server that stops
    /// sending is given up on after 30 s.
    pub fn new(
        sources: Vec<BlocklistSourceConfig>,
        group_lists: Arc<GroupBlocklists>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| DaygleError::Config(format!("cannot build HTTP client: {e}")))?;
        let status = sources
            .iter()
            .map(|s| SourceStatus {
                name: s.name.clone(),
                url: s.url.clone(),
                enabled: s.enabled,
                format: s.format,
                refresh_secs: s.refresh_secs,
                scope: s.scope,
                last_fetch: None,
                last_attempt: None,
                last_fetch_at: None,
                domains: 0,
                cached_domains: Arc::default(),
                last_error: None,
            })
            .collect();
        Ok(Self {
            sources: Mutex::new(sources),
            client,
            status: Mutex::new(status),
            changed: tokio::sync::Notify::new(),
            changed_flag: std::sync::atomic::AtomicBool::new(false),
            group_lists,
            compiled: Mutex::default(),
            dot_list: RwLock::new(None),
            merged: Mutex::default(),
            cycle: tokio::sync::Mutex::new(()),
        })
    }

    /// The group-scoped sources this manager publishes.
    pub fn group_lists(&self) -> Arc<GroupBlocklists> {
        Arc::clone(&self.group_lists)
    }

    /// The merged domain set of the sources scoped to the DoT listener
    /// (`None` when no `dot`-scoped source contributes domains).
    pub fn dot_blocklist(&self) -> Option<Arc<Blocklist>> {
        read_guard(&self.dot_list).clone()
    }

    pub fn is_empty(&self) -> bool {
        lock_guard(&self.sources).is_empty()
    }

    /// The currently configured sources (a clone). Callers that run a refresh
    /// in the background compare this before and after the fetch so a stale
    /// result never overwrites a newer source list.
    pub fn sources(&self) -> Vec<BlocklistSourceConfig> {
        lock_guard(&self.sources).clone()
    }

    /// Replace the configured sources at runtime. The per-source status is
    /// rebuilt so a removed source disappears and an added or changed one
    /// starts from "not fetched yet". An identical list is a no-op that keeps
    /// the current status and already-fetched domains.
    ///
    /// A source whose name, URL and format are unchanged keeps what it
    /// downloaded and when (its domains depend on nothing else): editing its
    /// interval, scope or enabled flag neither discards the list nor forces
    /// a download. Only new or re-pointed sources start from "not fetched".
    pub fn set_sources(&self, sources: Vec<BlocklistSourceConfig>) {
        let mut guard = lock_guard(&self.sources);
        if *guard == sources {
            return;
        }
        let prev_status = lock_guard(&self.status);
        let prev_index: std::collections::HashMap<(String, String), SourceStatus> = prev_status
            .iter()
            .map(|s| ((s.name.clone(), s.url.clone()), s.clone()))
            .collect();
        drop(prev_status);

        let status: Vec<SourceStatus> = sources
            .iter()
            .map(|s| {
                let carried = prev_index.get(&(s.name.clone(), s.url.clone()));
                let mut new = SourceStatus {
                    name: s.name.clone(),
                    url: s.url.clone(),
                    enabled: s.enabled,
                    format: s.format,
                    refresh_secs: s.refresh_secs,
                    scope: s.scope,
                    last_fetch: None,
                    last_attempt: None,
                    last_fetch_at: None,
                    domains: 0,
                    cached_domains: Arc::default(),
                    last_error: None,
                };
                if let Some(prev) = carried.filter(|prev| prev.format == new.format) {
                    new.last_fetch = prev.last_fetch;
                    new.last_attempt = prev.last_attempt;
                    new.last_fetch_at = prev.last_fetch_at;
                    new.domains = prev.domains;
                    new.cached_domains = prev.cached_domains.clone();
                    new.last_error = prev.last_error.clone();
                }
                new
            })
            .collect();
        *guard = sources;
        *lock_guard(&self.status) = status;
        // Wake the refresh loop. `notify_waiters` only wakes tasks currently
        // parked on `notified()`; to wake one that may be mid-sleep we use
        // `notify_one` (which is sufficient because there's a single refresh
        // loop) AND arm a flag the loop inspects after each tick.
        self.changed.notify_one();
        self.changed_flag
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether the source list has changed since the last `take_change`.
    pub fn take_change(&self) -> bool {
        self.changed_flag
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    /// Notify handle fired when the source list changes (see `changed`).
    pub fn changed_notify(&self) -> &tokio::sync::Notify {
        &self.changed
    }

    /// How long the refresh loop may sleep: until the next enabled source
    /// is due (see [`due_at`]), at least a second, and [`IDLE_REFRESH`] with
    /// none.
    pub fn next_refresh_in(&self) -> Duration {
        let sources = lock_guard(&self.sources).clone();
        let status = lock_guard(&self.status);
        let now = Instant::now();
        sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.enabled)
            .filter_map(|(i, source)| {
                let st = status.get(i).filter(|st| describes(st, source))?;
                Some(due_at(st, source, now).saturating_duration_since(now))
            })
            .min()
            .map_or(IDLE_REFRESH, |wait| wait.max(Duration::from_secs(1)))
    }

    /// The list of configured sources (for the API status endpoint).
    pub fn status(&self) -> Vec<SourceStatus> {
        lock_guard(&self.status).clone()
    }

    /// Fetch every enabled source that is due (see [`due_at`]), publish the
    /// group-scoped sources and return the merged remote blocklist of the
    /// sources that apply to everyone.
    ///
    /// Due sources are downloaded [`PARALLEL_FETCHES`] at a time. A source
    /// that fails is logged, raises an alert and is retried after
    /// [`RETRY_AFTER_FAILURE`]; its previously downloaded domains are kept,
    /// so a transient error never blanks the list.
    ///
    /// The returned list always reflects the *current* enabled sources:
    /// fetched results are merged with the per-source caches, so removing or
    /// disabling a source is reflected immediately even when no source was
    /// due. While nothing changed it is the very list returned last time.
    pub async fn refresh_due(&self) -> Result<Arc<Blocklist>> {
        let _cycle = self.cycle.lock().await;
        // Snapshot the list so the fetch cycle never holds the source lock
        // across network I/O, and so a concurrent `set_sources` cannot make
        // the loop read a half-replaced list.
        let sources = lock_guard(&self.sources).clone();
        let now = Instant::now();

        // The list may have been replaced (and shortened) since the snapshot
        // was taken, so never index the status table blindly.
        let due: Vec<(usize, BlocklistSourceConfig)> = {
            let status = lock_guard(&self.status);
            sources
                .iter()
                .enumerate()
                .filter(|(_, source)| source.enabled)
                .filter(|(i, source)| {
                    status
                        .get(*i)
                        .is_some_and(|st| describes(st, source) && due_at(st, source, now) <= now)
                })
                .map(|(i, source)| (i, source.clone()))
                .collect()
        };

        let permits = Arc::new(tokio::sync::Semaphore::new(PARALLEL_FETCHES));
        let mut downloads = tokio::task::JoinSet::new();
        let mut by_task = HashMap::new();
        for (i, source) in due {
            let client = self.client.clone();
            let permits = permits.clone();
            let task_source = source.clone();
            let handle = downloads.spawn(async move {
                let _permit = permits.acquire_owned().await;
                fetch_source(&client, &task_source).await
            });
            by_task.insert(handle.id(), (i, source));
        }
        while let Some(joined) = downloads.join_next_with_id().await {
            let (id, result) = match joined {
                Ok((id, result)) => (id, result),
                Err(e) => (
                    e.id(),
                    Err(DaygleError::Proto(format!("the download task failed: {e}"))),
                ),
            };
            if let Some((i, source)) = by_task.remove(&id) {
                self.record(i, &source, now, result);
            }
        }

        // Merge the per-source caches so the effective set follows the
        // current source list, not the last fetch cycle. A source removed or
        // disabled on the latest edit stops contributing here immediately.
        // Group-scoped sources are compiled one by one instead, and
        // DoT-scoped sources are merged into their own listener-scoped set.
        let mut group_sets: Vec<(String, Arc<BTreeSet<String>>)> = Vec::new();
        let mut everyone_parts = Vec::new();
        let mut dot_parts = Vec::new();
        let mut merged_sources = MergedSources::default();
        {
            let status = lock_guard(&self.status);
            for (i, source) in sources.iter().enumerate() {
                if !source.enabled {
                    continue;
                }
                let Some(st) = status.get(i).filter(|st| describes(st, source)) else {
                    continue;
                };
                let domains = st.cached_domains.clone();
                match source.scope {
                    BlocklistScope::Everyone => {
                        everyone_parts.push(domains.clone());
                        merged_sources.everyone.push((source.name.clone(), domains));
                    }
                    BlocklistScope::Groups => {
                        group_sets.push((source.name.to_ascii_lowercase(), domains))
                    }
                    BlocklistScope::Dot => {
                        dot_parts.push(domains.clone());
                        merged_sources.dot.push((source.name.clone(), domains));
                    }
                }
            }
        }
        self.publish_group_lists(group_sets);
        self.group_lists.set_merged_sources(merged_sources);

        let (everyone, dot) = {
            let mut cache = lock_guard(&self.merged);
            let dot = (!dot_parts.iter().all(|p| p.is_empty()))
                .then(|| merged_list(&mut cache.dot, dot_parts));
            (merged_list(&mut cache.everyone, everyone_parts), dot)
        };
        // An emptied or disabled DoT-scoped source stops blocking on the
        // listener immediately.
        *write_guard(&self.dot_list) = dot;

        // Always hand back the current effective list (possibly empty): a
        // source removed, disabled, or emptied on its last fetch must stop
        // blocking immediately.
        Ok(everyone)
    }

    /// Record one download's outcome against its status row, if the row
    /// still describes the source (the list may have been replaced while the
    /// download was in flight).
    fn record(
        &self,
        i: usize,
        source: &BlocklistSourceConfig,
        started: Instant,
        result: Result<BTreeSet<String>>,
    ) {
        match &result {
            Ok(domains) => {
                tracing::info!(
                    source = %source.name,
                    domains = domains.len(),
                    "blocklist source refreshed"
                );
                daygle_dns_core::alerts::resolve(&format!("blocklist:{}", source.name));
            }
            Err(e) => {
                tracing::warn!(source = %source.name, error = %e, "blocklist source fetch failed");
                daygle_dns_core::alerts::raise(
                    daygle_dns_core::alerts::AlertKind::BlocklistFailure,
                    format!("blocklist:{}", source.name),
                    format!("Blocklist '{}' cannot be downloaded", source.name),
                    format!(
                        "Downloading the blocklist '{}' from {} failed: {e}. The last \
                         downloaded copy (if any) stays in use; it is tried again in a few \
                         minutes.",
                        source.name, source.url
                    ),
                );
            }
        }
        let mut status = lock_guard(&self.status);
        let Some(st) = status.get_mut(i).filter(|st| describes(st, source)) else {
            return;
        };
        st.last_attempt = Some(Instant::now());
        match result {
            Ok(domains) => {
                st.last_fetch = Some(started);
                st.last_fetch_at = Some(SystemTime::now());
                st.domains = domain_count(&domains, source.format);
                st.cached_domains = Arc::new(domains);
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(e.to_string()),
        }
    }

    /// Compile the group-scoped sources (reusing the compiled form of any
    /// whose domain set is unchanged) and publish them.
    fn publish_group_lists(&self, sets: Vec<(String, Arc<BTreeSet<String>>)>) {
        let mut compiled = lock_guard(&self.compiled);
        let mut next = HashMap::with_capacity(sets.len());
        for (name, domains) in sets {
            let list = match compiled.get(&name) {
                Some((built_from, list)) if Arc::ptr_eq(built_from, &domains) => list.clone(),
                _ => Arc::new(Blocklist::from_sets([domains.as_ref()])),
            };
            next.insert(name, (domains, list));
        }
        self.group_lists.set(
            next.iter()
                .map(|(name, (_, list))| (name.clone(), list.clone()))
                .collect(),
        );
        *compiled = next;
    }

    /// Force a refresh of every enabled source now (used by `POST
    /// /api/policy/blocklist/sources`).
    pub async fn refresh_all(&self) -> Result<Arc<Blocklist>> {
        // Wait out a cycle already running, so its downloads are not
        // repeated by this one only to race it.
        let cycle = self.cycle.lock().await;
        // Reset the per-source due-tracking (the retry pause after a failure
        // included) so everything is due. `last_fetch_at` keeps the
        // wall-clock time of the last success until a refresh replaces it.
        {
            let mut status = lock_guard(&self.status);
            for st in status.iter_mut() {
                st.last_fetch = None;
                st.last_attempt = None;
            }
        }
        drop(cycle);
        self.refresh_due().await
    }

    /// Fetch the body at `url` over HTTP(S), enforcing the redirect limit,
    /// the timeout and the size cap. Exposed so the API can validate a
    /// candidate source (probe + parse) without saving it first.
    pub async fn fetch_text(&self, url: &str) -> Result<String> {
        fetch_text(&self.client, url).await
    }
}

/// Fetch and parse one source into its normalized domain set.
async fn fetch_source(
    client: &reqwest::Client,
    source: &BlocklistSourceConfig,
) -> Result<BTreeSet<String>> {
    let text = fetch_text(client, &source.url).await?;
    Ok(parse_blocklist(&text, source.format))
}

/// Fetch the body at `url` with `client`, aborting past [`MAX_BODY_BYTES`].
async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| DaygleError::Proto(format!("GET {url}: {e}")))?;
    if !response.status().is_success() {
        return Err(DaygleError::Proto(format!(
            "GET {url} returned {}",
            response.status()
        )));
    }
    // Reject over-large bodies up front when the server advertises a length.
    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(DaygleError::Proto(format!(
                "blocklist {url} advertises {len} bytes, over the {MAX_BODY_BYTES} limit"
            )));
        }
    }
    // Stream the body chunk by chunk, aborting as soon as the cap is
    // exceeded so a server that lies about (or omits) Content-Length cannot
    // force us to buffer an unbounded amount into memory.
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DaygleError::Proto(format!("read {url}: {e}")))?
    {
        if bytes.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(DaygleError::Proto(format!(
                "blocklist {url} exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Guess the wire format of a blocklist body from its content, for the
/// console's "validate / auto-detect" flow.
///
/// The heuristic scores line shapes that are characteristic of each format:
/// AdGuard/uBlock markers (`||`, `##`, `@@`) for `adblock`, hosts-file IP
/// prefixes for `hosts`, and single-token dotted names for `domains`.
/// Zone-file records (`CNAME`, `SOA`, `$ORIGIN`) mark an `rpz` zone.
/// Returns `None` for content that looks like none of these.
///
/// This is deliberately conservative: it is used to catch a source whose
/// declared format does not match its content (e.g. an adblock filter saved
/// as `hosts`), not as a substitute for parsing.
pub fn detect_blocklist_format(text: &str) -> Option<BlocklistFormat> {
    detect_blocklist_format_at("", text)
}

/// [`detect_blocklist_format`] with the source's URL as a hint: a plain
/// domains list whose URL or header comments say it is a wildcard list
/// (oisd's `domainswild2`), and which has no `*.` entries of its own, is
/// [`BlocklistFormat::Wildcard`].
pub fn detect_blocklist_format_at(url: &str, text: &str) -> Option<BlocklistFormat> {
    let mut adblock = 0usize;
    let mut hosts = 0usize;
    let mut domains = 0usize;
    let mut rpz = 0usize;
    let mut starred = 0usize;
    let mut wild_hint = url.to_ascii_lowercase().contains("wild");

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with('!') {
            wild_hint |= line.to_ascii_lowercase().contains("wild");
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with("*.") {
            starred += 1;
        }
        // Zone-file records and directives (RPZ).
        if line.starts_with("$ORIGIN") || line.starts_with("$TTL") {
            rpz += 1;
            continue;
        }
        if line
            .split_whitespace()
            .any(|t| t.eq_ignore_ascii_case("CNAME") || t.eq_ignore_ascii_case("SOA"))
        {
            rpz += 1;
            continue;
        }
        // AdGuard/uBlock network rules and cosmetic filters.
        if line.starts_with("||") || line.contains("##") || line.contains("#?#") {
            adblock += 1;
            continue;
        }
        // Hosts-file entries: a loopback/placeholder IP followed by a name.
        let hosts_ip = ["0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255"]
            .iter()
            .find(|p| line.starts_with(**p))
            .and_then(|p| line.get(p.len()..))
            .is_some_and(|rest| rest.chars().next().is_some_and(|c| c.is_whitespace()));
        if hosts_ip {
            hosts += 1;
            continue;
        }
        // Plain-domain entries: a single token that contains a dot and carries
        // no other blocklist syntax. Pure IPs/prefixes don't count.
        let single_token = !line.chars().any(|c| c.is_whitespace());
        if single_token
            && line.contains('.')
            && !line.contains('|')
            && !line.contains('/')
            && !line
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
        {
            domains += 1;
        }
    }

    if rpz > 0 && rpz >= adblock.max(hosts).max(domains) {
        Some(BlocklistFormat::Rpz)
    } else if adblock > 0 && adblock >= hosts {
        Some(BlocklistFormat::Adblock)
    } else if hosts > 0 {
        Some(BlocklistFormat::Hosts)
    } else if domains > 0 {
        Some(if wild_hint && starred == 0 {
            BlocklistFormat::Wildcard
        } else {
            BlocklistFormat::Domains
        })
    } else if adblock > 0 {
        Some(BlocklistFormat::Adblock)
    } else {
        None
    }
}

/// How many domains a parsed list blocks: a wildcard list holds two entries
/// (`x` and `*.x`) per listed name, as do adblock `||x^` rules, and adblock
/// exceptions block nothing.
pub fn domain_count(domains: &BTreeSet<String>, format: BlocklistFormat) -> usize {
    match format {
        BlocklistFormat::Wildcard => domains.iter().filter(|d| !d.starts_with("*.")).count(),
        BlocklistFormat::Adblock => domains
            .iter()
            .filter(|d| {
                !(d.starts_with(crate::blocklist::EXCEPTION_PREFIX)
                    || d.starts_with("*.") && domains.contains(&d[2..]))
            })
            .count(),
        _ => domains.len(),
    }
}

/// Parse a blocklist body in the given format into normalized domain patterns
/// (lowercase, no trailing dot, `*.` prefixes preserved for wildcards).
///
/// Whatever the format, only entries that can match a query name are kept
/// (see [`plausible_entry`]).
pub fn parse_blocklist(text: &str, format: BlocklistFormat) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    match format {
        BlocklistFormat::Domains => {
            out.extend(normalize_domains(list_names(text).map(str::to_string)));
        }
        BlocklistFormat::Wildcard => {
            // Each name stands for itself and every subdomain.
            for domain in normalize_domains(
                list_names(text).map(|name| name.trim_start_matches("*.").to_string()),
            ) {
                out.insert(format!("*.{domain}"));
                out.insert(domain);
            }
        }
        BlocklistFormat::Hosts => {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // `0.0.0.0 example.com [alias ...]` - every hostname column
                // after the address, up to an inline comment.
                let hosts = line
                    .split_whitespace()
                    .skip(1)
                    .take_while(|field| !field.starts_with('#'))
                    // Skip bare labels (localhost, broadcasthost): real
                    // entries are FQDNs, with or without the root dot.
                    // Addresses (`0.0.0.0 0.0.0.0`) are dropped below.
                    .filter(|host| host.trim_end_matches('.').contains('.'))
                    .map(str::to_string);
                out.extend(normalize_domains(hosts));
            }
        }
        BlocklistFormat::Adblock => {
            for line in text.lines() {
                if let Some(entries) = parse_adblock_rule(line) {
                    out.extend(entries);
                }
            }
        }
        BlocklistFormat::Rpz => out = parse_rpz(text),
    }
    out.retain(|entry| plausible_entry(entry));
    out
}

/// The name on each line of a plain list: the first word, without an
/// inline comment (`tracker.example # added 2024`, `ads.example#note`).
/// Comment and blank lines yield nothing.
fn list_names(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let name = line.split_whitespace().next()?.split('#').next()?;
        (!name.is_empty() && !name.starts_with('!')).then_some(name)
    })
}

/// Whether a parsed entry can ever match a query name: a host name (letters,
/// digits, hyphens, underscores; labels of 1 to 63 characters; 253 at
/// most), optionally `*.`-wildcarded or `@@`-excepted, and not an IP
/// address. Anything else - an address from a hosts line, a line the
/// format's parser could not make sense of, text IDNA could not convert -
/// would sit in memory, inflate the count and block nothing.
pub(crate) fn plausible_entry(entry: &str) -> bool {
    let entry = entry
        .strip_prefix(crate::blocklist::EXCEPTION_PREFIX)
        .unwrap_or(entry);
    let name = entry.strip_prefix("*.").unwrap_or(entry);
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Modifiers that change what a DNS adblock rule means in ways a blocklist
/// cannot express (per client, per record type, rewrites, disabling another
/// rule): a rule carrying one is skipped rather than turned into a blanket
/// block. Other modifiers (`important`, browser-only ones such as
/// `third-party`) leave the rule a plain block.
const UNSUPPORTED_ADBLOCK_MODIFIERS: [&str; 6] = [
    "badfilter",
    "client",
    "ctag",
    "denyallow",
    "dnsrewrite",
    "dnstype",
];

/// One adblock-syntax line as blocklist entries (AdGuard DNS filtering
/// syntax):
///
/// - `||example.com^` blocks the name and every subdomain;
/// - `|example.com^` and a bare `example.com` block the name only;
/// - `@@` makes the rule an exception ([`crate::blocklist::EXCEPTION_PREFIX`])
///   that unblocks what other rules block.
///
/// `None` for comments, cosmetic rules, patterns with wildcards, paths or
/// regular expressions, and rules with modifiers that cannot be honoured.
fn parse_adblock_rule(line: &str) -> Option<Vec<String>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') || line.starts_with('#') {
        return None;
    }
    // Cosmetic and HTML filters are for browsers.
    if line.contains("##") || line.contains("#?#") || line.contains("#@#") || line.contains("#$#") {
        return None;
    }
    let (exception, rule) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern, modifiers) = match rule.split_once('$') {
        Some((pattern, modifiers)) => (pattern, modifiers),
        None => (rule, ""),
    };
    let unsupported = modifiers.split(',').any(|m| {
        let name = m.trim().trim_start_matches('~');
        let name = name.split('=').next().unwrap_or(name);
        UNSUPPORTED_ADBLOCK_MODIFIERS.contains(&name.to_ascii_lowercase().as_str())
    });
    if unsupported {
        return None;
    }
    let (subdomains, name) = if let Some(rest) = pattern.strip_prefix("||") {
        (true, rest)
    } else {
        (false, pattern.strip_prefix('|').unwrap_or(pattern))
    };
    let name = name.trim_end_matches('|').trim_end_matches('^');
    if !name.contains('.') || name.contains(['*', '/', '|', '^', '$', ':']) {
        return None;
    }
    let domain = normalize_domains([name.to_string()]).into_iter().next()?;
    let prefix = if exception {
        crate::blocklist::EXCEPTION_PREFIX
    } else {
        ""
    };
    let mut entries = vec![format!("{prefix}{domain}")];
    if subdomains {
        entries.push(format!("{prefix}*.{domain}"));
    }
    Some(entries)
}

/// The records of a zone file as `(owner, fields)`, with comments removed,
/// parenthesised records joined, and blank owners filled in from the record
/// before. Directives come back with the directive as the owner.
fn zone_records(text: &str) -> Vec<(String, Vec<String>)> {
    let mut records = Vec::new();
    let mut owner = String::new();
    let mut pending: Option<(bool, Vec<String>)> = None;
    let mut depth = 0i32;
    for raw in text.lines() {
        let line = raw.split(';').next().unwrap_or("");
        let starts_blank = line.starts_with([' ', '\t']);
        let tokens: Vec<String> = line
            .replace(['(', ')'], " ")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        depth += line.matches('(').count() as i32 - line.matches(')').count() as i32;
        match pending.as_mut() {
            Some((_, fields)) => fields.extend(tokens),
            None if tokens.is_empty() => continue,
            None => pending = Some((starts_blank, tokens)),
        }
        if depth > 0 {
            continue;
        }
        depth = 0;
        let Some((blank, mut fields)) = pending.take() else {
            continue;
        };
        if !blank && !fields.is_empty() {
            let first = fields.remove(0);
            if !first.starts_with('$') {
                owner = first.clone();
            }
            if first.starts_with('$') {
                records.push((first.to_ascii_uppercase(), fields));
                continue;
            }
        }
        records.push((owner.clone(), fields));
    }
    records
}

/// The QNAME triggers of a Response Policy Zone. Every trigger is blocked
/// whatever its action (NXDOMAIN, NODATA, DROP, a walled-garden CNAME or
/// local data all keep the client off the name), except `rpz-passthru.`
/// exceptions, which are left out. IP, NSDNAME, NSIP and client-IP triggers
/// have no domain to block and are skipped.
fn parse_rpz(text: &str) -> BTreeSet<String> {
    const SPECIAL: [&str; 5] = [
        "rpz-ip",
        "rpz-nsdname",
        "rpz-nsip",
        "rpz-client-ip",
        "rpz-ip6",
    ];
    let mut origin: Option<String> = None;
    let mut blocked = BTreeSet::new();
    let mut passthru = BTreeSet::new();
    for (owner, fields) in zone_records(text) {
        if owner == "$ORIGIN" {
            if let Some(o) = fields.first() {
                let o = o.to_ascii_lowercase();
                origin = Some(match (o.ends_with('.'), &origin) {
                    (true, _) => o,
                    (false, Some(cur)) => format!("{o}.{cur}"),
                    (false, None) => format!("{o}."),
                });
            }
            continue;
        }
        if owner.starts_with('$') {
            continue;
        }
        // Skip the TTL and class, which may come in either order.
        let mut rest = fields.iter().skip_while(|f| {
            f.chars().next().is_some_and(|c| c.is_ascii_digit())
                || ["IN", "CH", "HS", "CS"].contains(&f.to_ascii_uppercase().as_str())
        });
        let Some(rtype) = rest.next().map(|t| t.to_ascii_uppercase()) else {
            continue;
        };
        let owner = owner.to_ascii_lowercase();
        if rtype == "SOA" {
            // A zone without `$ORIGIN` is named by its SOA.
            if origin.is_none() && owner.ends_with('.') {
                origin = Some(owner);
            }
            continue;
        }
        if rtype == "NS" || owner == "@" {
            continue;
        }
        // The trigger: the owner relative to the zone's origin.
        let name = if let Some(absolute) = owner.strip_suffix('.') {
            let Some(origin) = &origin else {
                continue;
            };
            if absolute == origin.trim_end_matches('.') {
                continue;
            }
            match absolute.strip_suffix(&format!(".{}", origin.trim_end_matches('.'))) {
                Some(relative) => relative.to_string(),
                None => continue,
            }
        } else {
            owner
        };
        if name == "*"
            || !name.contains('.') && !name.starts_with("*.")
            || name
                .rsplit('.')
                .next()
                .is_some_and(|tld| SPECIAL.contains(&tld))
        {
            continue;
        }
        let target = rest.next().map(|t| t.to_ascii_lowercase());
        match (rtype.as_str(), target.as_deref()) {
            ("CNAME", Some("rpz-passthru.")) => {
                passthru.insert(name);
            }
            ("CNAME", Some("rpz-tcp-only.")) => {}
            _ => {
                blocked.insert(name);
            }
        }
    }
    normalize_domains(blocked.difference(&passthru).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic in an unrelated thread that happened to hold one of these
    /// locks must not make the manager (and its status endpoint) panic for
    /// the rest of the process's life.
    #[test]
    fn poisoned_locks_are_recovered() {
        let lists = Arc::new(GroupBlocklists::default());
        let manager =
            Arc::new(BlocklistSourceManager::new(Vec::new(), Arc::clone(&lists)).unwrap());
        {
            let lists = Arc::clone(&lists);
            let manager = Arc::clone(&manager);
            let _ = std::thread::spawn(move || {
                let _lists = lists.lists.write().unwrap();
                let _status = manager.status.lock().unwrap();
                panic!("simulated panic while holding the locks");
            })
            .join();
        }

        // Every accessor still works after the poisoning.
        assert!(lists.snapshot().is_empty());
        lists.set(HashMap::new());
        assert!(lists.get("anything").is_none());
        assert!(manager.status().is_empty());
        assert!(manager.sources().is_empty());
        assert_eq!(manager.next_refresh_in(), IDLE_REFRESH);
    }

    #[test]
    fn parses_domain_format() {
        let text = "# comment\n! also a comment\nexample.com\nAds.Example.NET.\n*.tracker.test\n\n";
        let set = parse_blocklist(text, BlocklistFormat::Domains);
        assert!(set.contains("example.com"));
        assert!(set.contains("ads.example.net"));
        assert!(set.contains("*.tracker.test"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn parses_hosts_format() {
        let text = "\
# StevenBlack hosts file
127.0.0.1 localhost
0.0.0.0 example.com
0.0.0.0 ads.example.net # inline comment
0.0.0.0 one.example.org two.example.org
::1 localhost
255.255.255.255 broadcasthost
";
        let set = parse_blocklist(text, BlocklistFormat::Hosts);
        assert!(set.contains("example.com"));
        assert!(set.contains("ads.example.net"));
        assert!(set.contains("one.example.org"));
        assert!(set.contains("two.example.org"));
        assert!(!set.contains("comment"));
        assert!(!set.contains("localhost"));
        assert!(!set.contains("broadcasthost"));
    }

    #[test]
    fn parses_adblock_format() {
        let text = "\
! Title: Example filter
||ads.example.com^
||tracker.example.net^$third-party
@@||allow.example.com^
example.com##.banner
";
        let set = parse_blocklist(text, BlocklistFormat::Adblock);
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracker.example.net"));
        assert!(!set.contains("allow.example.com"));
        assert!(!set.contains("example.com"));
        assert_eq!(domain_count(&set, BlocklistFormat::Adblock), 2);
    }

    #[test]
    fn adblock_rules_follow_dns_filtering_syntax() {
        let text = "\
||ads.example.com^
|exact.example.com^
plain.example.com
@@||cdn.ads.example.com^
||rewritten.example.com^$dnsrewrite=1.2.3.4
||only-a.example.com^$dnstype=A
||important.example.com^$important
||*.wild.example.com^
/regex\\.example/
";
        let list = crate::Blocklist::from_set(parse_blocklist(text, BlocklistFormat::Adblock));
        // `||` covers the name and its subdomains.
        assert!(list.contains("ads.example.com"));
        assert!(list.contains("x.ads.example.com"));
        // Exceptions unblock their name (and, with `||`, its subdomains).
        assert!(!list.contains("cdn.ads.example.com"));
        assert!(!list.contains("img.cdn.ads.example.com"));
        // `|name^` and a bare name are that name only.
        assert!(list.contains("exact.example.com"));
        assert!(!list.contains("x.exact.example.com"));
        assert!(list.contains("plain.example.com"));
        assert!(!list.contains("x.plain.example.com"));
        // Modifiers a blocklist cannot honour skip the rule.
        assert!(!list.contains("rewritten.example.com"));
        assert!(!list.contains("only-a.example.com"));
        assert!(list.contains("important.example.com"));
        // Wildcard patterns and regular expressions are not domains.
        assert!(!list.contains("a.wild.example.com"));
    }

    #[test]
    fn parses_rpz_format() {
        let text = "$TTL 300
@ IN SOA localhost. hostmaster.localhost. (
        1 ; serial
        3600 600 86400 300 )
    IN NS localhost.
bad.example        CNAME .            ; NXDOMAIN
*.bad.example      CNAME .
nodata.example 60 IN CNAME *.
dropped.example    CNAME rpz-drop.
garden.example     CNAME walled.garden.example.
local.example      A     192.0.2.1
                   AAAA  2001:db8::1
ok.bad.example     CNAME rpz-passthru.
tcp.example        CNAME rpz-tcp-only.
32.1.2.0.192.rpz-ip CNAME .
ns.evil.rpz-nsdname CNAME .
Mixed.Example.     CNAME .
";
        let set = parse_blocklist(text, BlocklistFormat::Rpz);
        let got: Vec<&str> = set.iter().map(String::as_str).collect();
        // No origin is known, so the absolute name is skipped.
        assert_eq!(
            got,
            [
                "*.bad.example",
                "bad.example",
                "dropped.example",
                "garden.example",
                "local.example",
                "nodata.example",
            ]
        );

        // Absolute names under the origin (from `$ORIGIN` or the SOA).
        let text = "$ORIGIN rpz.example.org.
@ SOA ns. admin. 1 2 3 4 5
ads.tracker.com.rpz.example.org. CNAME .
elsewhere.com. CNAME .
Sub CNAME .
x.sub CNAME .
";
        let set = parse_blocklist(text, BlocklistFormat::Rpz);
        let got: Vec<&str> = set.iter().map(String::as_str).collect();
        assert_eq!(got, ["ads.tracker.com", "x.sub"]);
        let text = "rpz.local. 300 IN SOA ns. admin. 1 2 3 4 5
ads.tracker.com.rpz.local. 300 IN CNAME .
";
        let set = parse_blocklist(text, BlocklistFormat::Rpz);
        assert!(set.contains("ads.tracker.com"));
        assert_eq!(detect_blocklist_format(text), Some(BlocklistFormat::Rpz));
    }

    #[test]
    fn manager_is_empty_with_no_sources() {
        let m = BlocklistSourceManager::new(vec![], Arc::default()).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn detects_hosts_format() {
        let text = "# StevenBlack hosts\n127.0.0.1 localhost\n0.0.0.0 example.com\n::1 localhost\n";
        assert_eq!(detect_blocklist_format(text), Some(BlocklistFormat::Hosts));
        // A mismatched declaration is caught even when the adblock parser
        // would have extracted junk from the same text.
        assert_ne!(
            detect_blocklist_format(text),
            Some(BlocklistFormat::Adblock)
        );
    }

    #[test]
    fn detects_adblock_format() {
        let text = "! Title: Example\n||ads.example.com^\n||tracker.example.net^$third-party\nexample.com##.banner\n";
        assert_eq!(
            detect_blocklist_format(text),
            Some(BlocklistFormat::Adblock)
        );
    }

    #[test]
    fn detects_domains_format() {
        let text = "# a plain list\nexample.com\nads.example.net\n*.tracker.test\n";
        assert_eq!(
            detect_blocklist_format(text),
            Some(BlocklistFormat::Domains)
        );
    }

    #[test]
    fn detect_returns_none_for_unknown_content() {
        assert_eq!(detect_blocklist_format("hello world\n"), None);
        assert_eq!(detect_blocklist_format(""), None);
    }

    #[test]
    fn wildcard_format_covers_subdomains() {
        let set = parse_blocklist(
            "# comment\nAds.Test\n*.track.test\n",
            BlocklistFormat::Wildcard,
        );
        let list = Blocklist::from_set(set.clone());
        assert!(list.contains("ads.test"));
        assert!(list.contains("a.b.ads.test"));
        assert!(list.contains("track.test"));
        assert!(list.contains("x.track.test"));
        assert!(!list.contains("notads.test"));
        assert_eq!(domain_count(&set, BlocklistFormat::Wildcard), 2);
    }

    #[test]
    fn wildcard_lists_are_detected_from_hints() {
        let plain = "example.com\nads.example.net\n";
        assert_eq!(
            detect_blocklist_format(plain),
            Some(BlocklistFormat::Domains)
        );
        assert_eq!(
            detect_blocklist_format_at("https://big.oisd.nl/domainswild2", plain),
            Some(BlocklistFormat::Wildcard)
        );
        assert_eq!(
            detect_blocklist_format(&format!("# Syntax: wildcard domains\n{plain}")),
            Some(BlocklistFormat::Wildcard)
        );
        // Explicit `*.` entries mean the list spells out its wildcards.
        assert_eq!(
            detect_blocklist_format_at("https://big.oisd.nl/domainswild", "*.example.com\n"),
            Some(BlocklistFormat::Domains)
        );
    }

    /// A local HTTP server answering every request with `status` and
    /// `body`; the counter is the number of requests it got.
    async fn list_server(
        status: u16,
        body: &'static str,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (url, hits)
    }

    fn source(url: &str, refresh_secs: u64) -> BlocklistSourceConfig {
        BlocklistSourceConfig {
            name: "list".to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            refresh_secs,
            enabled: true,
            scope: BlocklistScope::Everyone,
        }
    }

    fn hits(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A cycle with nothing due returns the very list it published last, so
    /// publishing it costs a pointer comparison, not a rebuild and an
    /// entry-by-entry one.
    #[tokio::test]
    async fn unchanged_cycles_reuse_the_published_list() {
        let (url, counter) = list_server(200, "a.test\nb.test\n").await;
        let m = BlocklistSourceManager::new(vec![source(&url, 3600)], Arc::default()).unwrap();
        let first = m.refresh_due().await.unwrap();
        assert_eq!(first.len(), 2);
        let second = m.refresh_due().await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(hits(&counter), 1, "nothing was due the second time");
        // The next download is an interval away.
        let wait = m.next_refresh_in();
        assert!(wait > Duration::from_secs(3590) && wait <= Duration::from_secs(3600));
    }

    /// A failed download is tried again within minutes, not a whole
    /// (here daily) interval later, and not on every cycle before then.
    #[tokio::test]
    async fn a_failed_download_is_retried_within_minutes() {
        let (url, counter) = list_server(503, "").await;
        let m = BlocklistSourceManager::new(vec![source(&url, 86_400)], Arc::default()).unwrap();
        assert!(m.refresh_due().await.unwrap().is_empty());
        assert!(m.status()[0].last_error.is_some());
        let wait = m.next_refresh_in();
        assert!(
            wait <= RETRY_AFTER_FAILURE && wait > RETRY_AFTER_FAILURE - Duration::from_secs(10),
            "{wait:?}"
        );
        m.refresh_due().await.unwrap();
        assert_eq!(hits(&counter), 1, "not retried before the pause is over");
    }

    /// A list host is never asked more often than every few minutes.
    #[tokio::test]
    async fn refreshes_are_never_more_frequent_than_the_floor() {
        let (url, _) = list_server(200, "a.test\n").await;
        let m = BlocklistSourceManager::new(vec![source(&url, 1)], Arc::default()).unwrap();
        m.refresh_due().await.unwrap();
        assert!(m.next_refresh_in() > MIN_REFRESH - Duration::from_secs(10));
    }

    /// Two cycles at once (the background loop and a console action)
    /// download a due source once: the second waits for the first.
    #[tokio::test]
    async fn concurrent_cycles_download_once() {
        let (url, counter) = list_server(200, "a.test\n").await;
        let m = BlocklistSourceManager::new(vec![source(&url, 3600)], Arc::default()).unwrap();
        let (a, b) = tokio::join!(m.refresh_due(), m.refresh_due());
        assert_eq!((a.unwrap().len(), b.unwrap().len()), (1, 1));
        assert_eq!(hits(&counter), 1);
    }

    /// Editing a source's interval or toggling it keeps what it downloaded:
    /// its domains depend only on its URL and format.
    #[tokio::test]
    async fn editing_a_source_keeps_its_download() {
        let (url, counter) = list_server(200, "a.test\nb.test\n").await;
        let m = BlocklistSourceManager::new(vec![source(&url, 3600)], Arc::default()).unwrap();
        m.refresh_due().await.unwrap();
        m.set_sources(vec![source(&url, 7200)]);
        assert_eq!(m.status()[0].domains, 2);
        assert_eq!(m.refresh_due().await.unwrap().len(), 2);
        let mut off = source(&url, 7200);
        off.enabled = false;
        m.set_sources(vec![off]);
        assert!(
            m.refresh_due().await.unwrap().is_empty(),
            "a disabled source blocks nothing"
        );
        m.set_sources(vec![source(&url, 7200)]);
        assert_eq!(m.refresh_due().await.unwrap().len(), 2);
        assert_eq!(hits(&counter), 1, "no edit forced a download");
        // A new URL is a new list.
        m.set_sources(vec![source(&format!("{url}?v=2"), 7200)]);
        assert_eq!(m.status()[0].domains, 0);
    }

    #[test]
    fn plain_lists_drop_inline_comments_and_junk() {
        let set = parse_blocklist(
            "# header\n\
             tracker.example # added 2024\n\
             ads.example#note\n\
             *.wild.example\n\
             \tspaced.example   \n\
             192.0.2.1\n\
             bad name with spaces\n\
             not_a|domain\n\
             ! adblock-style comment\n",
            BlocklistFormat::Domains,
        );
        let expected: BTreeSet<String> = [
            "tracker.example",
            "ads.example",
            "*.wild.example",
            "spaced.example",
            "bad",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(set, expected);
        let wild = parse_blocklist("ads.test # note\n", BlocklistFormat::Wildcard);
        assert_eq!(wild.len(), 2);
        assert!(wild.contains("*.ads.test"));
    }

    #[test]
    fn hosts_files_keep_rooted_names_and_drop_addresses() {
        let set = parse_blocklist(
            "0.0.0.0 0.0.0.0\n\
             0.0.0.0 rooted.example.\n\
             127.0.0.1 localhost\n\
             ::1 ip6-localhost ip6-loopback\n\
             0.0.0.0 ads.example # tracker\n",
            BlocklistFormat::Hosts,
        );
        let expected: BTreeSet<String> = ["rooted.example", "ads.example"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn only_plausible_names_are_kept() {
        for ok in [
            "example.com",
            "*.example.com",
            "@@cdn.example.com",
            "@@*.example.com",
            "_dmarc.example.com",
            "xn--bcher-kva.de",
            "zip",
        ] {
            assert!(plausible_entry(ok), "{ok}");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        for bad in [
            "",
            "*.",
            "192.0.2.1",
            "a..b",
            ".example.com",
            "has space.com",
            "bücher.de",
            "a|b.com",
            long_label.as_str(),
        ] {
            assert!(!plausible_entry(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_first_listing_source_is_named() {
        let lists = GroupBlocklists::default();
        let set = |items: &[&str]| Arc::new(items.iter().map(|s| s.to_string()).collect());
        lists.set_merged_sources(MergedSources {
            everyone: vec![
                ("One".into(), set(&["other.test"])),
                ("Two".into(), set(&["*.ads.test"])),
                ("Three".into(), set(&["x.ads.test"])),
            ],
            dot: vec![],
        });
        assert_eq!(
            lists.first_source_listing("x.ads.test", false),
            Some(("Two".to_string(), "*.ads.test".to_string()))
        );
        assert_eq!(lists.sources_listing("x.ads.test", false).len(), 2);
        assert_eq!(lists.first_source_listing("x.ads.test", true), None);
        assert_eq!(lists.first_source_listing("nothing.test", false), None);
    }

    #[test]
    fn set_sources_replaces_runtime_list() {
        let m = BlocklistSourceManager::new(vec![], Arc::default()).unwrap();
        assert!(m.is_empty());
        m.set_sources(vec![BlocklistSourceConfig {
            name: "a".to_string(),
            url: "https://example.com/list.txt".to_string(),
            format: BlocklistFormat::Domains,
            refresh_secs: 3600,
            enabled: true,
            scope: BlocklistScope::Everyone,
        }]);
        assert_eq!(m.sources().len(), 1);
        assert!(!m.is_empty());
        // An identical replacement is a no-op; a different one replaces.
        m.set_sources(m.sources());
        assert_eq!(m.status().len(), 1);
        m.set_sources(vec![]);
        assert!(m.is_empty());
        assert!(m.status().is_empty());
    }
}
