//! Category feeds: the maintained public lists security and privacy
//! categories are built from ([`crate::security::Feed`]), downloaded and
//! refreshed in the background, but only for categories some filtering
//! group uses.
//!
//! Lists are kept in memory in [`FeedLists`] (shared with the filtering
//! groups through [`crate::GroupBlocklists`]). A failed refresh keeps the
//! last good list; until a category's first download succeeds it matches
//! nothing, and the console says so.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use daygle_dns_core::config::{normalize_domains, BlocklistFormat};
use serde::Serialize;
use tracing::{info, warn};

use crate::blocklist::EXCEPTION_PREFIX;
use crate::blocklist_source::parse_blocklist;
use crate::security::{Feed, FeedFormat, SECURITY_CATEGORIES};
use crate::Blocklist;

/// How often a downloaded feed is refreshed.
const REFRESH: Duration = Duration::from_secs(12 * 3600);
/// How long a failed download waits before it is tried again.
const RETRY: Duration = Duration::from_secs(3600);
/// How often the loop looks for feeds that are due or newly in use.
const TICK: Duration = Duration::from_secs(5);
/// Largest feed body accepted.
const MAX_BYTES: usize = 32 * 1024 * 1024;

/// A category feed's state, for the console.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FeedStatus {
    /// Names (entries) in the current list.
    pub entries: usize,
    /// When the current list was downloaded.
    pub updated_at: Option<DateTime<Utc>>,
    /// Why the last download failed, if it did.
    pub error: Option<String>,
    #[serde(skip)]
    next_attempt: Option<Instant>,
}

/// The downloaded category lists, by category id.
#[derive(Debug, Default)]
pub struct FeedLists {
    lists: RwLock<Arc<HashMap<&'static str, Arc<Blocklist>>>>,
    status: Mutex<HashMap<&'static str, FeedStatus>>,
}

impl FeedLists {
    /// The list of category `id`, once downloaded.
    pub fn get(&self, id: &str) -> Option<Arc<Blocklist>> {
        self.lists
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Every category feed's state, by category id.
    pub fn status(&self) -> HashMap<&'static str, FeedStatus> {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install category `id`'s list (tests and the refresh loop).
    pub fn set(&self, id: &'static str, list: Blocklist) {
        let entries = list.len();
        let mut lists = self.lists.write().unwrap_or_else(|e| e.into_inner());
        let mut next = lists.as_ref().clone();
        next.insert(id, Arc::new(list));
        *lists = Arc::new(next);
        drop(lists);
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        let entry = status.entry(id).or_default();
        entry.entries = entries;
        entry.updated_at = Some(Utc::now());
        entry.error = None;
        entry.next_attempt = Some(Instant::now() + REFRESH);
    }

    fn failed(&self, id: &'static str, error: String) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        let entry = status.entry(id).or_default();
        entry.error = Some(error);
        entry.next_attempt = Some(Instant::now() + RETRY);
    }

    fn due(&self, id: &'static str) -> bool {
        let status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status
            .get(id)
            .and_then(|s| s.next_attempt)
            .is_none_or(|at| at <= Instant::now())
    }
}

/// Keep the feeds of the categories `in_use` returns downloaded and fresh,
/// forever. `in_use` is asked on every tick, so a category a group starts
/// using is downloaded within [`TICK`]. `mirror` gives a base URL to fetch
/// every feed from instead of its own host (`policy.feed_mirror`), or an
/// empty string.
pub async fn run(
    lists: Arc<FeedLists>,
    in_use: impl Fn() -> Vec<String> + Send + 'static,
    mirror: impl Fn() -> String + Send + 'static,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default();
    loop {
        let wanted = in_use();
        let mirror = mirror();
        for category in SECURITY_CATEGORIES {
            let Some(feed) = category.feed else { continue };
            if !wanted.iter().any(|id| id.eq_ignore_ascii_case(category.id))
                || !lists.due(category.id)
            {
                continue;
            }
            match download(&client, &feed, &mirror).await {
                Ok(list) => {
                    info!(
                        category = category.id,
                        source = feed.source,
                        entries = list.len(),
                        "category feed updated"
                    );
                    lists.set(category.id, list);
                }
                Err(e) => {
                    warn!(category = category.id, source = feed.source, error = %e, "category feed download failed");
                    lists.failed(category.id, e);
                }
            }
        }
        tokio::time::sleep(TICK).await;
    }
}

/// `url` fetched through `mirror` (a base URL; empty for none): the
/// mirror's URL followed by `url` without its scheme, so
/// `https://raw.githubusercontent.com/a/b` becomes
/// `<mirror>/raw.githubusercontent.com/a/b`.
pub fn mirrored(url: &str, mirror: &str) -> String {
    let mirror = mirror.trim().trim_end_matches('/');
    if mirror.is_empty() {
        return url.to_string();
    }
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    format!("{mirror}/{rest}")
}

async fn download(
    client: &reqwest::Client,
    feed: &Feed,
    mirror: &str,
) -> Result<Blocklist, String> {
    let mut entries = parse_feed(
        feed.format,
        &fetch(client, &mirrored(feed.url, mirror)).await?,
    );
    if entries.is_empty() {
        return Err("the list is empty".to_string());
    }
    if let Some(allow) = feed.allow_url {
        let allowed = parse_feed(feed.format, &fetch(client, &mirrored(allow, mirror)).await?);
        entries.extend(
            allowed
                .into_iter()
                .map(|e| format!("{EXCEPTION_PREFIX}{e}")),
        );
    }
    Ok(Blocklist::from_set(entries))
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let response = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    let body = response.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_BYTES {
        return Err(format!("{url} is larger than {MAX_BYTES} bytes"));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// A feed body as blocklist entries ([`Blocklist::from_set`] syntax).
pub fn parse_feed(format: FeedFormat, text: &str) -> BTreeSet<String> {
    match format {
        FeedFormat::Wildcard => parse_blocklist(text, BlocklistFormat::Wildcard),
        FeedFormat::Domains => parse_blocklist(text, BlocklistFormat::Domains),
        FeedFormat::AdguardCnameTrackers => {
            #[derive(serde::Deserialize)]
            struct Entry {
                #[serde(rename = "type")]
                kind: String,
                domains: Vec<String>,
            }
            let entries: Vec<Entry> = serde_json::from_str(text).unwrap_or_default();
            // AdGuard advises against blocking its clickthrough, microsite
            // and mail-tracker entries, which serve pages and links people
            // open.
            let domains = entries
                .into_iter()
                .filter(|e| e.kind == "tracker" || e.kind == "ad")
                .flat_map(|e| e.domains);
            parse_blocklist(
                &domains.collect::<Vec<_>>().join("\n"),
                BlocklistFormat::Wildcard,
            )
        }
        FeedFormat::IpfsGateways => {
            let urls: Vec<String> = serde_json::from_str(text).unwrap_or_default();
            let hosts = urls.into_iter().filter_map(|u| {
                url::Url::parse(&u)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
            });
            normalize_domains(hosts)
                .into_iter()
                .flat_map(|h| [format!("*.{h}"), h])
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_feeds_cover_subdomains_and_bare_tlds() {
        let list = Blocklist::from_set(parse_feed(
            FeedFormat::Wildcard,
            "# HaGeZi\nduckdns.org\nzip\n",
        ));
        assert!(list.contains("duckdns.org"));
        assert!(list.contains("phish.duckdns.org"));
        assert!(list.contains("update.zip"));
        assert!(!list.contains("example.com"));
    }

    #[test]
    fn allowlists_become_exceptions() {
        let mut entries = parse_feed(FeedFormat::Wildcard, "top\n");
        entries.extend(
            parse_feed(FeedFormat::Wildcard, "good.top\n")
                .into_iter()
                .map(|e| format!("{EXCEPTION_PREFIX}{e}")),
        );
        let list = Blocklist::from_set(entries);
        assert!(list.contains("bad.top"));
        assert!(!list.contains("good.top"));
        assert!(!list.contains("www.good.top"));
    }

    #[test]
    fn adguard_catalogue_keeps_trackers_and_ads_only() {
        let text = r#"[
            {"company_name": "Eulerian", "type": "tracker", "domains": ["eulerian.net"]},
            {"company_name": "Some Ad", "type": "ad", "domains": ["ad1n.net"]},
            {"company_name": "Pardot", "type": "clickthrough", "domains": ["go.pardot.com"]}
        ]"#;
        let list = Blocklist::from_set(parse_feed(FeedFormat::AdguardCnameTrackers, text));
        assert!(list.contains("shop.eulerian.net"));
        assert!(list.contains("x.ad1n.net"));
        assert!(!list.contains("go.pardot.com"));
    }

    #[test]
    fn ipfs_gateways_by_host() {
        let text = r#"["https://ipfs.io", "https://dweb.link", "not a url"]"#;
        let list = Blocklist::from_set(parse_feed(FeedFormat::IpfsGateways, text));
        assert!(list.contains("ipfs.io"));
        assert!(list.contains("bafy.ipfs.dweb.link"));
        assert!(!list.contains("example.com"));
    }

    #[test]
    fn mirrors_keep_the_host_and_path() {
        assert_eq!(
            mirrored(
                "https://raw.githubusercontent.com/a/b.txt",
                "http://10.0.0.5:8080/feeds/"
            ),
            "http://10.0.0.5:8080/feeds/raw.githubusercontent.com/a/b.txt"
        );
        assert_eq!(mirrored("https://x.test/y", " "), "https://x.test/y");
    }

    #[test]
    fn feeds_are_stored_with_status() {
        let feeds = FeedLists::default();
        assert!(feeds.get("dynamic_dns").is_none());
        assert!(feeds.due("dynamic_dns"));
        feeds.set("dynamic_dns", Blocklist::from_lines(["duckdns.org"]));
        assert!(feeds.get("dynamic_dns").unwrap().contains("duckdns.org"));
        assert!(!feeds.due("dynamic_dns"));
        assert_eq!(feeds.status()["dynamic_dns"].entries, 1);
    }
}
