//! Remote blocklist sources (like Technitium's blocklist management).
//!
//! A [`BlocklistSourceManager`] fetches one or more HTTP(S) blocklist URLs,
//! parses each in its declared format (`domains`, `hosts`, `adblock`, or
//! `rpz`),
//! merges the sources that apply to everyone into a single domain set, and
//! hands it to the policy engine as the *remote* blocklist. Sources scoped to
//! client groups are compiled one by one into [`GroupBlocklists`] instead,
//! where the client groups that select them look them up. Sources are
//! refreshed on their
//! `refresh_secs` schedule; the refresh loop lives in `daygle` and calls
//! [`BlocklistSourceManager::refresh_all`].

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

/// The enabled sources scoped to client groups, each compiled on its own and
/// keyed by lower-cased source name. Shared between the refresh loop, which
/// fills it, and the client-group matcher, which reads it on every query; a
/// list selected by several groups is held once.
#[derive(Debug, Default)]
pub struct GroupBlocklists {
    lists: RwLock<Arc<HashMap<String, Arc<Blocklist>>>>,
}

impl GroupBlocklists {
    /// The current lists (cheap: one `Arc` clone).
    pub fn snapshot(&self) -> Arc<HashMap<String, Arc<Blocklist>>> {
        self.lists.read().unwrap().clone()
    }

    /// The compiled list for the source called `name` (any case), if it is
    /// enabled and scoped to groups.
    pub fn get(&self, name: &str) -> Option<Arc<Blocklist>> {
        self.snapshot().get(&name.to_ascii_lowercase()).cloned()
    }

    pub(crate) fn set(&self, lists: HashMap<String, Arc<Blocklist>>) {
        *self.lists.write().unwrap() = Arc::new(lists);
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

/// A group-scoped source's domain set and the list compiled from it.
type CompiledSource = (Arc<BTreeSet<String>>, Arc<Blocklist>);

/// Fetches and parses remote blocklist sources and merges their domains.
pub struct BlocklistSourceManager {
    /// The configured sources. Held behind a mutex so the console can add,
    /// edit and remove sources at runtime (the list is persisted to the
    /// config file by the API layer) without rebuilding the manager or
    /// restarting the refresh loop.
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
}

impl BlocklistSourceManager {
    /// Build a manager for `sources` that publishes group-scoped sources to
    /// `group_lists`. The client follows redirects, enforces TLS (rustls) and
    /// caps response size.
    pub fn new(
        sources: Vec<BlocklistSourceConfig>,
        group_lists: Arc<GroupBlocklists>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
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
        })
    }

    /// The group-scoped sources this manager publishes.
    pub fn group_lists(&self) -> Arc<GroupBlocklists> {
        Arc::clone(&self.group_lists)
    }

    /// The merged domain set of the sources scoped to the DoT listener
    /// (`None` when no `dot`-scoped source contributes domains).
    pub fn dot_blocklist(&self) -> Option<Arc<Blocklist>> {
        self.dot_list.read().unwrap().clone()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.lock().unwrap().is_empty()
    }

    /// The currently configured sources (a clone). Callers that run a refresh
    /// in the background compare this before and after the fetch so a stale
    /// result never overwrites a newer source list.
    pub fn sources(&self) -> Vec<BlocklistSourceConfig> {
        self.sources.lock().unwrap().clone()
    }

    /// Replace the configured sources at runtime. The per-source status is
    /// rebuilt so a removed source disappears and an added or changed one
    /// starts from "not fetched yet". An identical list is a no-op that keeps
    /// the current status and already-fetched domains.
    ///
    /// Sources that already had a successful fetch keep their `last_fetch`
    /// and `last_fetch_at` timestamps; only newly-added or changed entries
    /// are marked stale. This
    /// avoids a thundering-herd refetch on every source edit.
    pub fn set_sources(&self, sources: Vec<BlocklistSourceConfig>) {
        let mut guard = self.sources.lock().unwrap();
        if *guard == sources {
            return;
        }
        // Carry forward `last_fetch`, `last_fetch_at`, `domains`, and
        // `last_error` for sources
        // whose identity is unchanged. The (name, url) tuple is the identity.
        let prev_status = self.status.lock().unwrap();
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
                    last_fetch_at: None,
                    domains: 0,
                    cached_domains: Arc::default(),
                    last_error: None,
                };
                if let Some(prev) = carried {
                    // Only carry forward state if the entry is otherwise
                    // identical (format, refresh interval, enabled flag).
                    if prev.format == new.format
                        && prev.refresh_secs == new.refresh_secs
                        && prev.enabled == new.enabled
                    {
                        new.last_fetch = prev.last_fetch;
                        new.last_fetch_at = prev.last_fetch_at;
                        new.domains = prev.domains;
                        new.cached_domains = prev.cached_domains.clone();
                        new.last_error = prev.last_error.clone();
                    }
                }
                new
            })
            .collect();
        *guard = sources;
        *self.status.lock().unwrap() = status;
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

    /// The smallest refresh interval among enabled sources (used to pace the
    /// refresh loop); 24 h when there are no sources.
    pub fn min_refresh(&self) -> Duration {
        self.sources
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.enabled)
            .map(|s| Duration::from_secs(s.refresh_secs))
            .min()
            .unwrap_or(Duration::from_secs(86400))
    }

    /// The list of configured sources (for the API status endpoint).
    pub fn status(&self) -> Vec<SourceStatus> {
        self.status.lock().unwrap().clone()
    }

    /// Fetch every enabled source whose refresh interval has elapsed since
    /// its last successful fetch, publish the group-scoped sources and return
    /// the merged remote blocklist of the sources that apply to everyone.
    ///
    /// A source that fails is logged and skipped; its previously cached
    /// domains are kept so a transient error never blanks the list.
    ///
    /// The returned set always reflects the *current* enabled sources: fetched
    /// results are merged with the per-source caches, so removing or disabling
    /// a source is reflected immediately even when no source was due for a
    /// refetch. Empty when no source contributes domains.
    pub async fn refresh_due(&self) -> Result<Blocklist> {
        // Snapshot the list so the fetch cycle never holds the source lock
        // across network I/O, and so a concurrent `set_sources` cannot make
        // the loop read a half-replaced list.
        let sources = self.sources.lock().unwrap().clone();
        let now = Instant::now();
        let mut merged: BTreeSet<String> = BTreeSet::new();

        for (i, source) in sources.iter().enumerate() {
            if !source.enabled {
                continue;
            }
            // The list may have been replaced (and shortened) since the
            // snapshot was taken, so never index the status table blindly.
            let last_fetch = {
                let status = self.status.lock().unwrap();
                match status.get(i) {
                    Some(st) if st.name == source.name => st.last_fetch,
                    _ => continue,
                }
            };
            let due = match last_fetch {
                Some(last) => now.duration_since(last) >= Duration::from_secs(source.refresh_secs),
                None => true, // never fetched: fetch on startup
            };
            if !due {
                continue;
            }

            match self.fetch(source).await {
                Ok(domains) => {
                    tracing::info!(
                        source = %source.name,
                        domains = domains.len(),
                        "blocklist source refreshed"
                    );
                    {
                        // The source list may have been replaced while this
                        // fetch was in flight; only record results against a
                        // status row that still describes this source.
                        let mut status = self.status.lock().unwrap();
                        if let Some(st) = status.get_mut(i) {
                            if st.name == source.name {
                                st.last_fetch = Some(now);
                                st.last_fetch_at = Some(SystemTime::now());
                                st.domains = domain_count(&domains, source.format);
                                st.cached_domains = Arc::new(domains);
                                st.last_error = None;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(source = %source.name, error = %e, "blocklist source fetch failed");
                    let mut status = self.status.lock().unwrap();
                    if let Some(st) = status.get_mut(i) {
                        if st.name == source.name {
                            st.last_error = Some(e.to_string());
                        }
                    }
                }
            }
        }

        // Merge the per-source caches so the effective set follows the
        // current source list, not the last fetch cycle. A source removed or
        // disabled on the latest edit stops contributing here immediately.
        // Group-scoped sources are compiled one by one instead, and
        // DoT-scoped sources are merged into their own listener-scoped set.
        let mut group_sets: Vec<(String, Arc<BTreeSet<String>>)> = Vec::new();
        let mut dot_merged: BTreeSet<String> = BTreeSet::new();
        {
            let status = self.status.lock().unwrap();
            for (i, source) in sources.iter().enumerate() {
                if !source.enabled {
                    continue;
                }
                if let Some(st) = status.get(i) {
                    if st.name == source.name {
                        match source.scope {
                            BlocklistScope::Everyone => {
                                merged.extend(st.cached_domains.iter().cloned())
                            }
                            BlocklistScope::Groups => group_sets.push((
                                source.name.to_ascii_lowercase(),
                                st.cached_domains.clone(),
                            )),
                            BlocklistScope::Dot => {
                                dot_merged.extend(st.cached_domains.iter().cloned())
                            }
                        }
                    }
                }
            }
        }
        self.publish_group_lists(group_sets);

        // Publish the DoT-scoped merge the same way: an emptied or disabled
        // source stops blocking on the listener immediately.
        *self.dot_list.write().unwrap() =
            (!dot_merged.is_empty()).then(|| Arc::new(Blocklist::from_set(dot_merged)));

        // Always hand back the current effective set (possibly empty): a
        // source removed, disabled, or emptied on its last fetch must stop
        // blocking immediately. Callers persist the engine only when the set
        // actually differs, so an unchanged result is a no-op.
        Ok(Blocklist::from_set(merged))
    }

    /// Compile the group-scoped sources (reusing the compiled form of any
    /// whose domain set is unchanged) and publish them.
    fn publish_group_lists(&self, sets: Vec<(String, Arc<BTreeSet<String>>)>) {
        let mut compiled = self.compiled.lock().unwrap();
        let mut next = HashMap::with_capacity(sets.len());
        for (name, domains) in sets {
            let list = match compiled.get(&name) {
                Some((built_from, list)) if Arc::ptr_eq(built_from, &domains) => list.clone(),
                _ => Arc::new(Blocklist::from_set(domains.as_ref().clone())),
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
    /// /api/policy/blocklist/refresh`).
    pub async fn refresh_all(&self) -> Result<Blocklist> {
        // Reset the per-source due-tracking so everything is considered due.
        // Only the schedule marker is cleared: `last_fetch_at` keeps the
        // wall-clock time of the last success until a refresh replaces it.
        {
            let mut status = self.status.lock().unwrap();
            for st in status.iter_mut() {
                st.last_fetch = None;
            }
        }
        self.refresh_due().await
    }

    /// Fetch and parse one source into its normalized domain set.
    async fn fetch(&self, source: &BlocklistSourceConfig) -> Result<BTreeSet<String>> {
        let text = self.fetch_text(&source.url).await?;
        Ok(parse_blocklist(&text, source.format))
    }

    /// Fetch the body at `url` over HTTP(S), enforcing the redirect limit,
    /// the 30 s timeout and the size cap. Exposed so the API can validate a
    /// candidate source (probe + parse) without saving it first.
    pub async fn fetch_text(&self, url: &str) -> Result<String> {
        let mut response = self
            .client
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
                    "blocklist {url} exceeds {} bytes",
                    MAX_BODY_BYTES
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
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

/// How many domains a parsed list names: a wildcard list holds two entries
/// (`x` and `*.x`) per listed name.
pub fn domain_count(domains: &BTreeSet<String>, format: BlocklistFormat) -> usize {
    match format {
        BlocklistFormat::Wildcard => domains.iter().filter(|d| !d.starts_with("*.")).count(),
        _ => domains.len(),
    }
}

/// Parse a blocklist body in the given format into normalized domain patterns
/// (lowercase, no trailing dot, `*.` prefixes preserved for wildcards).
pub fn parse_blocklist(text: &str, format: BlocklistFormat) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    match format {
        BlocklistFormat::Domains => {
            out.extend(normalize_domains(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
                    .map(|l| l.to_string()),
            ));
        }
        BlocklistFormat::Wildcard => {
            // Each name stands for itself and every subdomain.
            for domain in normalize_domains(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
                    .map(|l| l.trim_start_matches("*.").to_string()),
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
                    // Skip loopback/placeholder entries and bare labels
                    // (localhost, broadcasthost): real entries are FQDNs.
                    .filter(|host| host.contains('.') && !host.ends_with('.'))
                    .map(str::to_string);
                out.extend(normalize_domains(hosts));
            }
        }
        BlocklistFormat::Adblock => {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                    continue;
                }
                // Ignore exception rules (`@@`) and cosmetics (`##`, `#?#`).
                if line.starts_with("@@") || line.contains("##") || line.contains("#?#") {
                    continue;
                }
                // Drop the `$options` suffix and cosmetic/shortcut markers.
                let domain = line
                    .trim_start_matches("||")
                    .split('$')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('^')
                    .trim_end_matches('|');
                // Only keep entries that look like a domain (contain a dot)
                // and carry no other adblock syntax.
                if domain.contains('.') && !domain.contains('*') && !domain.contains('/') {
                    out.extend(normalize_domains([domain.to_string()]));
                }
            }
        }
        BlocklistFormat::Rpz => out = parse_rpz(text),
    }
    out
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
