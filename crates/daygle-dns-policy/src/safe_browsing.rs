//! Google Safe Browsing (Update API v4) for the Google Safe Browsing
//! security category.
//!
//! The threat lists are kept locally as SHA-256 hash prefixes and updated
//! in the background, so a lookup sends Google nothing unless one of a
//! name's hashes starts with a listed prefix; then only that prefix (4 bytes
//! of a hash, shared by many names) is sent to fetch the full hashes, which
//! are cached for as long as Google says. Google never sees the client's
//! address or the name itself.
//!
//! DNS only sees host names, so each name is checked as the expressions
//! `host/` for the host and up to four of its parent domains: entries for
//! whole sites are caught, entries for single pages on a site are not.
//!
//! The Safe Browsing APIs are for non-commercial use only; the operator
//! brings their own API key (`policy.safe_browsing_key`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// The Safe Browsing API.
pub const DEFAULT_URL: &str = "https://safebrowsing.googleapis.com";

/// The threat types checked, where Google offers them as URL lists for any
/// platform.
const THREAT_TYPES: &[&str] = &[
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
];

/// The shortest wait between list updates, whatever the server allows.
const MIN_UPDATE_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// How long a failed update waits first; it doubles with each further
/// failure, up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(15 * 60);
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);
/// How long to wait for full hashes before answering without them.
const FIND_TIMEOUT: Duration = Duration::from_secs(2);
/// Most cached full-hash answers kept before the expired ones are dropped.
const CACHE_CAP: usize = 50_000;

/// One local threat list.
#[derive(Debug, Clone, Default)]
struct List {
    threat_type: String,
    platform_type: String,
    threat_entry_type: String,
    /// The opaque client state of the last update, empty for none yet.
    state: String,
    /// Hash prefixes, sorted.
    prefixes: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Database {
    lists: Vec<List>,
    /// Every list's prefixes, by length, for lookups.
    index: HashMap<usize, HashSet<Vec<u8>>>,
}

impl Database {
    fn reindex(&mut self) {
        self.index.clear();
        for list in &self.lists {
            for prefix in &list.prefixes {
                self.index
                    .entry(prefix.len())
                    .or_default()
                    .insert(prefix.clone());
            }
        }
    }

    fn prefix_count(&self) -> usize {
        self.lists.iter().map(|l| l.prefixes.len()).sum()
    }
}

/// The settings the update loop and lookups use: API key and base URL.
pub type Settings = Arc<dyn Fn() -> (String, String) + Send + Sync>;

/// A local Safe Browsing database and full-hash cache.
pub struct SafeBrowsing {
    client: reqwest::Client,
    settings: Settings,
    started: AtomicBool,
    db: RwLock<Database>,
    /// Full hash -> (threat type, expiry).
    full: Mutex<HashMap<[u8; 32], (String, Instant)>>,
    /// Prefixes known to match no threat, until.
    negative: Mutex<HashMap<Vec<u8>, Instant>>,
}

impl std::fmt::Debug for SafeBrowsing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeBrowsing").finish_non_exhaustive()
    }
}

impl SafeBrowsing {
    /// A database whose API key and base URL are read from `settings` each
    /// time they are needed, so a key saved in the console applies without a
    /// restart. Nothing is downloaded until [`Self::check`] is first called.
    pub fn new(settings: Settings) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            client,
            settings,
            started: AtomicBool::new(false),
            db: RwLock::default(),
            full: Mutex::default(),
            negative: Mutex::default(),
        }
    }

    /// The threat type Google lists `qname` (a host name, lowercase ASCII)
    /// under, if any. Starts the background list updates on first use. Waits
    /// for full hashes only when a hash prefix matches, at most
    /// [`FIND_TIMEOUT`]; without an API key, or before the first update,
    /// nothing matches.
    pub async fn check(self: &Arc<Self>, qname: &str) -> Option<String> {
        self.start();
        let (key, base) = (self.settings)();
        if key.is_empty() {
            return None;
        }
        let hashes: Vec<[u8; 32]> = expressions(qname)
            .iter()
            .map(|e| Sha256::digest(e.as_bytes()).into())
            .collect();
        let now = Instant::now();
        {
            let full = self.full.lock().unwrap_or_else(|e| e.into_inner());
            for hash in &hashes {
                if let Some((threat, until)) = full.get(hash) {
                    if *until > now {
                        return Some(threat.clone());
                    }
                }
            }
        }
        let (prefixes, threat_types, platform_types, entry_types, states) = {
            let db = self.db.read().unwrap_or_else(|e| e.into_inner());
            let mut prefixes: Vec<Vec<u8>> = Vec::new();
            for hash in &hashes {
                for (len, set) in &db.index {
                    let prefix = &hash[..(*len).min(32)];
                    if set.contains(prefix) && !prefixes.iter().any(|p| p == prefix) {
                        prefixes.push(prefix.to_vec());
                    }
                }
            }
            let unique = |f: fn(&List) -> &String| {
                let mut v: Vec<String> = db.lists.iter().map(|l| f(l).clone()).collect();
                v.sort();
                v.dedup();
                v
            };
            (
                prefixes,
                unique(|l| &l.threat_type),
                unique(|l| &l.platform_type),
                unique(|l| &l.threat_entry_type),
                db.lists.iter().map(|l| l.state.clone()).collect::<Vec<_>>(),
            )
        };
        let prefixes: Vec<Vec<u8>> = {
            let negative = self.negative.lock().unwrap_or_else(|e| e.into_inner());
            prefixes
                .into_iter()
                .filter(|p| negative.get(p).is_none_or(|until| *until <= now))
                .collect()
        };
        if prefixes.is_empty() {
            return None;
        }
        let request = json!({
            "client": client_info(),
            "clientStates": states,
            "threatInfo": {
                "threatTypes": threat_types,
                "platformTypes": platform_types,
                "threatEntryTypes": entry_types,
                "threatEntries": prefixes
                    .iter()
                    .map(|p| json!({ "hash": BASE64.encode(p) }))
                    .collect::<Vec<_>>(),
            },
        });
        let url = format!(
            "{}/v4/fullHashes:find?key={key}",
            base.trim_end_matches('/')
        );
        let response = tokio::time::timeout(FIND_TIMEOUT, async {
            self.client
                .post(&url)
                .json(&request)
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?
                .json::<Value>()
                .await
                .ok()
        })
        .await
        .ok()
        .flatten()?;
        let now = Instant::now();
        let mut found = None;
        {
            let mut full = self.full.lock().unwrap_or_else(|e| e.into_inner());
            if full.len() >= CACHE_CAP {
                full.retain(|_, (_, until)| *until > now);
            }
            for m in response["matches"].as_array().into_iter().flatten() {
                let Some(hash) = m["threat"]["hash"]
                    .as_str()
                    .and_then(|h| BASE64.decode(h).ok())
                    .and_then(|h| <[u8; 32]>::try_from(h).ok())
                else {
                    continue;
                };
                let threat = m["threatType"].as_str().unwrap_or("MALWARE").to_string();
                let ttl = parse_duration(m["cacheDuration"].as_str()).unwrap_or_default();
                if hashes.contains(&hash) && found.is_none() {
                    found = Some(threat.clone());
                }
                full.insert(hash, (threat, now + ttl));
            }
        }
        let negative_ttl =
            parse_duration(response["negativeCacheDuration"].as_str()).unwrap_or_default();
        if found.is_none() && !negative_ttl.is_zero() {
            let mut negative = self.negative.lock().unwrap_or_else(|e| e.into_inner());
            if negative.len() >= CACHE_CAP {
                negative.retain(|_, until| *until > now);
            }
            for prefix in prefixes {
                negative.insert(prefix, now + negative_ttl);
            }
        }
        found
    }

    /// Start the background update loop, once.
    fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move { this.update_loop().await });
    }

    async fn update_loop(self: Arc<Self>) {
        let mut current = (String::new(), String::new());
        let mut failures = 0u32;
        loop {
            let settings = (self.settings)();
            if settings.0.is_empty() {
                if !current.0.is_empty() {
                    self.reset();
                    current = settings;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
            if settings != current {
                self.reset();
                current = settings.clone();
                failures = 0;
            }
            let wait = match self.update(&settings.0, &settings.1).await {
                Ok(wait) => {
                    failures = 0;
                    wait.max(MIN_UPDATE_INTERVAL)
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    let backoff = FIRST_BACKOFF
                        .saturating_mul(1 << failures.min(10).saturating_sub(1))
                        .min(MAX_BACKOFF);
                    warn!(error = %e, retry_in = ?backoff, "Safe Browsing list update failed");
                    backoff
                }
            };
            // Wake early when the key or URL changes.
            let deadline = Instant::now() + wait;
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_secs(60).min(wait)).await;
                if (self.settings)() != current {
                    break;
                }
            }
        }
    }

    fn reset(&self) {
        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Database::default();
        self.full.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.negative
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Fetch list updates and apply them; returns how long to wait before
    /// the next update.
    async fn update(&self, key: &str, base: &str) -> Result<Duration, String> {
        let base = base.trim_end_matches('/');
        let lists_empty = self
            .db
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .lists
            .is_empty();
        if lists_empty {
            let body = self
                .get_json(&format!("{base}/v4/threatLists?key={key}"))
                .await?;
            let lists = threat_lists(&body);
            if lists.is_empty() {
                return Err("the API offers none of the threat lists checked".to_string());
            }
            self.db.write().unwrap_or_else(|e| e.into_inner()).lists = lists;
        }
        let requests: Vec<Value> = self
            .db
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .lists
            .iter()
            .map(|l| {
                json!({
                    "threatType": l.threat_type,
                    "platformType": l.platform_type,
                    "threatEntryType": l.threat_entry_type,
                    "state": l.state,
                    "constraints": { "supportedCompressions": ["RAW"] },
                })
            })
            .collect();
        let body = self
            .client
            .post(format!("{base}/v4/threatListUpdates:fetch?key={key}"))
            .json(&json!({ "client": client_info(), "listUpdateRequests": requests }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = body.status();
        if !status.is_success() {
            return Err(format!("threatListUpdates:fetch answered {status}"));
        }
        let body: Value = body.json().await.map_err(|e| e.to_string())?;
        let mut db = self.db.write().unwrap_or_else(|e| e.into_inner());
        for update in body["listUpdateResponses"].as_array().into_iter().flatten() {
            let Some(list) = db.lists.iter_mut().find(|l| {
                update["threatType"].as_str() == Some(l.threat_type.as_str())
                    && update["platformType"].as_str() == Some(l.platform_type.as_str())
                    && update["threatEntryType"].as_str() == Some(l.threat_entry_type.as_str())
            }) else {
                continue;
            };
            if let Err(e) = apply_update(list, update) {
                warn!(list = %list.threat_type, error = %e, "Safe Browsing list update rejected; fetching it whole next time");
                list.state.clear();
                list.prefixes.clear();
            }
        }
        db.reindex();
        info!(
            lists = db.lists.len(),
            prefixes = db.prefix_count(),
            "Safe Browsing lists updated"
        );
        Ok(parse_duration(body["minimumWaitDuration"].as_str()).unwrap_or_default())
    }

    async fn get_json(&self, url: &str) -> Result<Value, String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "{} answered {status}",
                url.split('?').next().unwrap_or(url)
            ));
        }
        response.json().await.map_err(|e| e.to_string())
    }
}

fn client_info() -> Value {
    json!({ "clientId": "daygle-dns", "clientVersion": env!("CARGO_PKG_VERSION") })
}

/// The lists to keep, from a `threatLists` answer: URL lists of the checked
/// threat types for any platform.
fn threat_lists(body: &Value) -> Vec<List> {
    body["threatLists"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| {
            l["threatEntryType"] == "URL"
                && l["platformType"] == "ANY_PLATFORM"
                && l["threatType"]
                    .as_str()
                    .is_some_and(|t| THREAT_TYPES.contains(&t))
        })
        .map(|l| List {
            threat_type: l["threatType"].as_str().unwrap_or_default().to_string(),
            platform_type: "ANY_PLATFORM".to_string(),
            threat_entry_type: "URL".to_string(),
            ..List::default()
        })
        .collect()
}

/// Apply one list's update: a full update replaces the list, a partial one
/// removes the given indices of the sorted list and then adds. The result
/// must match the update's checksum.
fn apply_update(list: &mut List, update: &Value) -> Result<(), String> {
    let mut prefixes = if update["responseType"] == "FULL_UPDATE" {
        Vec::new()
    } else {
        std::mem::take(&mut list.prefixes)
    };
    let mut removed: HashSet<usize> = HashSet::new();
    for set in update["removals"].as_array().into_iter().flatten() {
        if set["compressionType"].as_str().is_some_and(|c| c != "RAW") {
            return Err("compressed removals".to_string());
        }
        for index in set["rawIndices"]["indices"]
            .as_array()
            .into_iter()
            .flatten()
        {
            removed.insert(index.as_u64().ok_or("bad removal index")? as usize);
        }
    }
    if removed.iter().any(|i| *i >= prefixes.len()) {
        return Err("removal index out of range".to_string());
    }
    let mut prefixes: Vec<Vec<u8>> = prefixes
        .drain(..)
        .enumerate()
        .filter(|(i, _)| !removed.contains(i))
        .map(|(_, p)| p)
        .collect();
    for set in update["additions"].as_array().into_iter().flatten() {
        if set["compressionType"].as_str().is_some_and(|c| c != "RAW") {
            return Err("compressed additions".to_string());
        }
        let size = set["rawHashes"]["prefixSize"].as_u64().unwrap_or(0) as usize;
        let raw = BASE64
            .decode(set["rawHashes"]["rawHashes"].as_str().unwrap_or(""))
            .map_err(|e| format!("bad hashes: {e}"))?;
        if !(4..=32).contains(&size) || raw.len() % size != 0 {
            return Err("bad prefix size".to_string());
        }
        prefixes.extend(raw.chunks(size).map(<[u8]>::to_vec));
    }
    prefixes.sort();
    if let Some(expected) = update["checksum"]["sha256"].as_str() {
        let expected = BASE64
            .decode(expected)
            .map_err(|e| format!("bad checksum: {e}"))?;
        let actual = Sha256::digest(prefixes.concat());
        if actual.as_slice() != expected.as_slice() {
            return Err("checksum mismatch".to_string());
        }
    }
    list.prefixes = prefixes;
    list.state = update["newClientState"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok(())
}

/// The expressions a host name is looked up as: `host/` for the host and
/// for up to four parent domains, made from its last five labels (not the
/// TLD alone). An address is looked up as itself.
pub fn expressions(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.');
    if host.parse::<IpAddr>().is_ok() {
        return vec![format!("{host}/")];
    }
    let labels: Vec<&str> = host.split('.').collect();
    let mut out = vec![format!("{host}/")];
    let start = labels.len().saturating_sub(5);
    for i in start..labels.len().saturating_sub(1) {
        let suffix = labels[i..].join(".");
        let expression = format!("{suffix}/");
        if !out.contains(&expression) {
            out.push(expression);
        }
    }
    out
}

/// A protobuf JSON duration (`"300s"`, `"1.5s"`).
fn parse_duration(value: Option<&str>) -> Option<Duration> {
    let secs: f64 = value?.strip_suffix('s')?.parse().ok()?;
    (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_expressions() {
        assert_eq!(
            expressions("a.b.c.d.e.f.g"),
            vec!["a.b.c.d.e.f.g/", "c.d.e.f.g/", "d.e.f.g/", "e.f.g/", "f.g/"]
        );
        assert_eq!(
            expressions("www.example.com"),
            vec!["www.example.com/", "example.com/"]
        );
        assert_eq!(expressions("example.com"), vec!["example.com/"]);
        assert_eq!(expressions("192.0.2.1"), vec!["192.0.2.1/"]);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration(Some("300s")), Some(Duration::from_secs(300)));
        assert_eq!(
            parse_duration(Some("1.5s")),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(parse_duration(Some("5m")), None);
        assert_eq!(parse_duration(None), None);
    }

    fn update(response_type: &str, additions: &[&[u8]], removals: &[u64], all: &[&[u8]]) -> Value {
        let mut sorted: Vec<&[u8]> = all.to_vec();
        sorted.sort();
        json!({
            "responseType": response_type,
            "additions": [{
                "compressionType": "RAW",
                "rawHashes": { "prefixSize": 4, "rawHashes": BASE64.encode(additions.concat()) }
            }],
            "removals": if removals.is_empty() { json!([]) } else {
                json!([{ "compressionType": "RAW", "rawIndices": { "indices": removals } }])
            },
            "newClientState": format!("state-{}", all.len()),
            "checksum": { "sha256": BASE64.encode(Sha256::digest(sorted.concat())) }
        })
    }

    #[test]
    fn full_and_partial_updates_apply_and_verify() {
        let mut list = List::default();
        apply_update(
            &mut list,
            &update("FULL_UPDATE", &[b"cccc", b"aaaa"], &[], &[b"aaaa", b"cccc"]),
        )
        .unwrap();
        assert_eq!(list.prefixes, vec![b"aaaa".to_vec(), b"cccc".to_vec()]);
        assert_eq!(list.state, "state-2");
        // Remove index 0 (aaaa) of the sorted list, then add bbbb.
        apply_update(
            &mut list,
            &update("PARTIAL_UPDATE", &[b"bbbb"], &[0], &[b"bbbb", b"cccc"]),
        )
        .unwrap();
        assert_eq!(list.prefixes, vec![b"bbbb".to_vec(), b"cccc".to_vec()]);
        // A wrong checksum is refused and leaves the caller to start over.
        let mut bad = update("PARTIAL_UPDATE", &[b"dddd"], &[], &[b"zzzz"]);
        bad["newClientState"] = json!("nope");
        assert!(apply_update(&mut list, &bad).is_err());
    }

    #[test]
    fn only_checked_url_lists_are_kept() {
        let lists = threat_lists(&json!({ "threatLists": [
            {"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"},
            {"threatType": "MALWARE", "platformType": "WINDOWS", "threatEntryType": "URL"},
            {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"},
            {"threatType": "CSD_WHITELIST", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"},
            {"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threatEntryType": "EXECUTABLE"}
        ]}));
        let types: Vec<&str> = lists.iter().map(|l| l.threat_type.as_str()).collect();
        assert_eq!(types, vec!["MALWARE", "SOCIAL_ENGINEERING"]);
    }
}
