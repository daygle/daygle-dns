//! Remote blocklist sources (like Technitium's blocklist management).
//!
//! A [`BlocklistSourceManager`] fetches one or more HTTP(S) blocklist URLs,
//! parses each in its declared format (`domains`, `hosts`, or `adblock`),
//! merges the results into a single domain set, and hands it to the policy
//! engine as the *remote* blocklist. Sources are refreshed on their
//! `refresh_secs` schedule; the refresh loop lives in `daygle` and calls
//! [`BlocklistSourceManager::refresh_all`].

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use daygle_dns_core::config::{normalize_domains, BlocklistFormat, BlocklistSourceConfig};
use daygle_dns_core::error::{DaygleError, Result};

use crate::Blocklist;

/// Fetch limits: a body larger than this is rejected (hosts files and adblock
/// lists can be large, but 32 MiB is beyond any reasonable blocklist).
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Per-source runtime status, surfaced through the API.
#[derive(Debug, Clone)]
pub struct SourceStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub format: BlocklistFormat,
    pub refresh_secs: u64,
    /// When the source was last fetched successfully.
    pub last_fetch: Option<Instant>,
    /// Domains contributed by this source on its last successful fetch.
    pub domains: usize,
    /// Human-readable error from the last failed fetch, if any.
    pub last_error: Option<String>,
}

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
    /// the list, so a source added while the loop is resting on a long
    /// interval is picked up on its own schedule without a restart.
    changed: tokio::sync::Notify,
}

impl BlocklistSourceManager {
    /// Build a manager for `sources`. The client follows redirects, enforces
    /// TLS (rustls) and caps response size.
    pub fn new(sources: Vec<BlocklistSourceConfig>) -> Result<Self> {
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
                last_fetch: None,
                domains: 0,
                last_error: None,
            })
            .collect();
        Ok(Self {
            sources: Mutex::new(sources),
            client,
            status: Mutex::new(status),
            changed: tokio::sync::Notify::new(),
        })
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
    pub fn set_sources(&self, sources: Vec<BlocklistSourceConfig>) {
        let mut guard = self.sources.lock().unwrap();
        if *guard == sources {
            return;
        }
        let status = sources
            .iter()
            .map(|s| SourceStatus {
                name: s.name.clone(),
                url: s.url.clone(),
                enabled: s.enabled,
                format: s.format,
                refresh_secs: s.refresh_secs,
                last_fetch: None,
                domains: 0,
                last_error: None,
            })
            .collect();
        *guard = sources;
        *self.status.lock().unwrap() = status;
        // Wake the refresh loop so it re-arms on the new schedule promptly.
        self.changed.notify_waiters();
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
    /// its last successful fetch, and return the merged remote blocklist.
    ///
    /// A source that fails is logged and skipped; the others still apply.
    /// Returns `Ok(None)` when no source was due (nothing changed).
    pub async fn refresh_due(&self) -> Result<Option<Blocklist>> {
        // Snapshot the list so the fetch cycle never holds the source lock
        // across network I/O, and so a concurrent `set_sources` cannot make
        // the loop read a half-replaced list.
        let sources = self.sources.lock().unwrap().clone();
        let now = Instant::now();
        let mut merged: BTreeSet<String> = BTreeSet::new();
        let mut any_due = false;

        for (i, source) in sources.iter().enumerate() {
            if !source.enabled {
                continue;
            }
            let due = match self.status.lock().unwrap()[i].last_fetch {
                Some(last) => now.duration_since(last) >= Duration::from_secs(source.refresh_secs),
                None => true, // never fetched: fetch on startup
            };
            if !due {
                continue;
            }
            any_due = true;

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
                                st.domains = domains.len();
                                st.last_error = None;
                            }
                        }
                    }
                    merged.extend(domains);
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

        if any_due {
            Ok(Some(Blocklist::from_set(merged)))
        } else {
            Ok(None)
        }
    }

    /// Force a refresh of every enabled source now (used by `POST
    /// /api/policy/blocklist/refresh`).
    pub async fn refresh_all(&self) -> Result<Option<Blocklist>> {
        // Reset the per-source due-tracking so everything is considered due.
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
/// Returns `None` for content that looks like none of the three.
///
/// This is deliberately conservative: it is used to catch a source whose
/// declared format does not match its content (e.g. an adblock filter saved
/// as `hosts`), not as a substitute for parsing.
pub fn detect_blocklist_format(text: &str) -> Option<BlocklistFormat> {
    let mut adblock = 0usize;
    let mut hosts = 0usize;
    let mut domains = 0usize;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        // AdGuard/uBlock network rules and cosmetic filters.
        if line.starts_with("||") || line.contains("##") || line.contains("#?#") {
            adblock += 1;
            continue;
        }
        // Hosts-file entries: a loopback/placeholder IP followed by a name.
        let hosts_ip = ["0.0.0.0", "127.0.0.1", "::1", "255.255.255.255"]
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

    if adblock > 0 && adblock >= hosts {
        Some(BlocklistFormat::Adblock)
    } else if hosts > 0 {
        Some(BlocklistFormat::Hosts)
    } else if domains > 0 {
        Some(BlocklistFormat::Domains)
    } else if adblock > 0 {
        Some(BlocklistFormat::Adblock)
    } else {
        None
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
        BlocklistFormat::Hosts => {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // `0.0.0.0 example.com` - take the hostname column.
                let mut fields = line.split_whitespace();
                let _ip = fields.next();
                if let Some(host) = fields.next() {
                    // Skip loopback/placeholder entries and bare labels
                    // (localhost, broadcasthost): real entries are FQDNs.
                    if !host.is_empty()
                        && !host.starts_with('#')
                        && host.contains('.')
                        && !host.ends_with('.')
                    {
                        out.extend(normalize_domains([host.to_string()]));
                    }
                }
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
    }
    out
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
::1 localhost
255.255.255.255 broadcasthost
";
        let set = parse_blocklist(text, BlocklistFormat::Hosts);
        assert!(set.contains("example.com"));
        assert!(set.contains("ads.example.net"));
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
    fn manager_is_empty_with_no_sources() {
        let m = BlocklistSourceManager::new(vec![]).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn detects_hosts_format() {
        let text = "# StevenBlack hosts\n127.0.0.1 localhost\n0.0.0.0 example.com\n::1 localhost\n";
        assert_eq!(detect_blocklist_format(text), Some(BlocklistFormat::Hosts));
        // A mismatched declaration is caught even when the adblock parser
        // would have extracted junk from the same text.
        assert_ne!(detect_blocklist_format(text), Some(BlocklistFormat::Adblock));
    }

    #[test]
    fn detects_adblock_format() {
        let text = "! Title: Example\n||ads.example.com^\n||tracker.example.net^$third-party\nexample.com##.banner\n";
        assert_eq!(detect_blocklist_format(text), Some(BlocklistFormat::Adblock));
    }

    #[test]
    fn detects_domains_format() {
        let text = "# a plain list\nexample.com\nads.example.net\n*.tracker.test\n";
        assert_eq!(detect_blocklist_format(text), Some(BlocklistFormat::Domains));
    }

    #[test]
    fn detect_returns_none_for_unknown_content() {
        assert_eq!(detect_blocklist_format("hello world\n"), None);
        assert_eq!(detect_blocklist_format(""), None);
    }

    #[test]
    fn set_sources_replaces_runtime_list() {
        let m = BlocklistSourceManager::new(vec![]).unwrap();
        assert!(m.is_empty());
        m.set_sources(vec![BlocklistSourceConfig {
            name: "a".to_string(),
            url: "https://example.com/list.txt".to_string(),
            format: BlocklistFormat::Domains,
            refresh_secs: 3600,
            enabled: true,
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
