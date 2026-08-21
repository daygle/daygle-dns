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

use daygle_core::config::{normalize_domains, BlocklistFormat, BlocklistSourceConfig};
use daygle_core::error::{DaygleError, Result};

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
    sources: Vec<BlocklistSourceConfig>,
    client: reqwest::Client,
    status: Mutex<Vec<SourceStatus>>,
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
            sources,
            client,
            status: Mutex::new(status),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// The smallest refresh interval among enabled sources (used to pace the
    /// refresh loop); 24 h when there are no sources.
    pub fn min_refresh(&self) -> Duration {
        self.sources
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
        let now = Instant::now();
        let mut merged: BTreeSet<String> = BTreeSet::new();
        let mut any_due = false;

        for (i, source) in self.sources.iter().enumerate() {
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
                        let mut status = self.status.lock().unwrap();
                        let st = &mut status[i];
                        st.last_fetch = Some(now);
                        st.domains = domains.len();
                        st.last_error = None;
                    }
                    merged.extend(domains);
                }
                Err(e) => {
                    tracing::warn!(source = %source.name, error = %e, "blocklist source fetch failed");
                    self.status.lock().unwrap()[i].last_error = Some(e.to_string());
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
        let response = self
            .client
            .get(&source.url)
            .send()
            .await
            .map_err(|e| DaygleError::Proto(format!("GET {}: {e}", source.url)))?;
        if !response.status().is_success() {
            return Err(DaygleError::Proto(format!(
                "GET {} returned {}",
                source.url,
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| DaygleError::Proto(format!("read {}: {e}", source.url)))?;
        if bytes.len() > MAX_BODY_BYTES {
            return Err(DaygleError::Proto(format!(
                "blocklist {} exceeds {} bytes",
                source.url, MAX_BODY_BYTES
            )));
        }
        let text = String::from_utf8_lossy(&bytes);
        Ok(parse_blocklist(&text, source.format))
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
}
