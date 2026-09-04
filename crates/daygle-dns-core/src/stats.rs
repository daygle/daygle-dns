//! Time-series query statistics and top-N tables for the dashboard.
//!
//! [`QueryStats`] records every served query into:
//!
//! - **Minute buckets** - a bounded ring of per-minute counters (24 h of
//!   history) powering the dashboard's time-series chart.
//! - **Top-N tables** - bounded counters per client IP, per query domain,
//!   and per *blocked* domain, powering Technitium-style top lists.
//!
//! All structures are bounded: at most [`MAX_BUCKETS`] minute buckets and
//! [`MAX_TOP_ENTRIES`] keys per top table (excess keys are pruned by count),
//! so memory stays flat regardless of traffic.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;

/// 24 h of one-minute buckets.
pub const MAX_BUCKETS: usize = 1440;
/// Cap on keys per top table (pruned down to [`TOP_KEEP`] when exceeded).
pub const MAX_TOP_ENTRIES: usize = 5_000;
/// Keys kept after a prune.
pub const TOP_KEEP: usize = 2_000;

/// Outcome classification for one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered from an authoritative zone.
    Authoritative,
    /// Resolved recursively (cache hit or miss).
    Recursive,
    /// Synthetic split-horizon answer.
    SplitHorizon,
    /// Blocked / redirected / refused by policy.
    Blocked,
    /// Rate-limited.
    RateLimited,
    /// Negative or failed resolution.
    Error,
}

/// One per-minute bucket of counters.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Bucket {
    /// Epoch minutes (UNIX_EPOCH / 60) this bucket covers.
    pub minute: u64,
    pub queries: u64,
    pub authoritative: u64,
    pub recursive: u64,
    pub split_horizon: u64,
    pub blocked: u64,
    pub rate_limited: u64,
    pub errors: u64,
}

impl Bucket {
    fn new(minute: u64) -> Self {
        Self {
            minute,
            ..Default::default()
        }
    }
}

/// Aggregated series point returned to the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    /// ISO-ish epoch seconds for the bucket start.
    pub t: u64,
    pub queries: u64,
    pub authoritative: u64,
    pub recursive: u64,
    pub blocked: u64,
    pub errors: u64,
    pub rate_limited: u64,
}

/// One top-N row.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TopEntry {
    pub key: String,
    pub count: u64,
}

struct Inner {
    buckets: Mutex<Vec<Bucket>>,
    clients: Mutex<HashMap<String, u64>>,
    domains: Mutex<HashMap<String, u64>>,
    blocked_domains: Mutex<HashMap<String, u64>>,
}

/// Shared dashboard statistics.
pub struct QueryStats {
    inner: Inner,
}

impl Default for QueryStats {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryStats {
    pub fn new() -> Self {
        Self {
            inner: Inner {
                buckets: Mutex::new(Vec::with_capacity(64)),
                clients: Mutex::new(HashMap::new()),
                domains: Mutex::new(HashMap::new()),
                blocked_domains: Mutex::new(HashMap::new()),
            },
        }
    }

    /// Record one query. `qname` is lowercased with the trailing dot already
    /// stripped by the caller.
    pub fn record(&self, client: IpAddr, qname: &str, outcome: Outcome) {
        let now_min = epoch_minutes();
        {
            let mut buckets = self.inner.buckets.lock();
            match buckets.last_mut() {
                Some(b) if b.minute == now_min => match outcome {
                    Outcome::Authoritative => b.authoritative += 1,
                    Outcome::Recursive => b.recursive += 1,
                    Outcome::SplitHorizon => b.split_horizon += 1,
                    Outcome::Blocked => b.blocked += 1,
                    Outcome::RateLimited => b.rate_limited += 1,
                    Outcome::Error => b.errors += 1,
                },
                _ => {
                    // New minute (possibly after a gap): rotate.
                    let mut b = Bucket::new(now_min);
                    match outcome {
                        Outcome::Authoritative => b.authoritative += 1,
                        Outcome::Recursive => b.recursive += 1,
                        Outcome::SplitHorizon => b.split_horizon += 1,
                        Outcome::Blocked => b.blocked += 1,
                        Outcome::RateLimited => b.rate_limited += 1,
                        Outcome::Error => b.errors += 1,
                    }
                    buckets.push(b);
                    if buckets.len() > MAX_BUCKETS {
                        let excess = buckets.len() - MAX_BUCKETS;
                        buckets.drain(..excess);
                    }
                }
            }
            buckets.last_mut().expect("bucket just pushed").queries += 1;
        }

        bump(&self.inner.clients, &client.to_string());
        bump(&self.inner.domains, qname);
        if matches!(outcome, Outcome::Blocked) {
            bump(&self.inner.blocked_domains, qname);
        }
    }

    /// Series aggregated over the last `window_minutes` (empty buckets are
    /// materialized for gaps so the chart has a continuous x axis).
    pub fn series(&self, window_minutes: u32) -> Vec<SeriesPoint> {
        let window = window_minutes.clamp(1, MAX_BUCKETS as u32) as u64;
        let now_min = epoch_minutes();
        let first = now_min.saturating_sub(window - 1);
        let buckets = self.inner.buckets.lock();
        let by_minute: HashMap<u64, &Bucket> =
            buckets.iter().map(|b| (b.minute, b)).collect();
        (first..=now_min)
            .map(|m| {
                let b = by_minute.get(&m);
                SeriesPoint {
                    t: m * 60,
                    queries: b.map(|b| b.queries).unwrap_or(0),
                    authoritative: b.map(|b| b.authoritative).unwrap_or(0),
                    recursive: b.map(|b| b.recursive).unwrap_or(0),
                    blocked: b.map(|b| b.blocked).unwrap_or(0),
                    errors: b.map(|b| b.errors).unwrap_or(0),
                    rate_limited: b.map(|b| b.rate_limited).unwrap_or(0),
                }
            })
            .collect()
    }

    /// Top `n` clients by query count.
    pub fn top_clients(&self, n: usize) -> Vec<TopEntry> {
        top(&self.inner.clients, n)
    }

    /// Top `n` query domains.
    pub fn top_domains(&self, n: usize) -> Vec<TopEntry> {
        top(&self.inner.domains, n)
    }

    /// Top `n` blocked domains.
    pub fn top_blocked(&self, n: usize) -> Vec<TopEntry> {
        top(&self.inner.blocked_domains, n)
    }

    /// Drop all history (used by tests and future admin actions).
    pub fn clear(&self) {
        self.inner.buckets.lock().clear();
        self.inner.clients.lock().clear();
        self.inner.domains.lock().clear();
        self.inner.blocked_domains.lock().clear();
    }
}

fn epoch_minutes() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

fn bump(map: &Mutex<HashMap<String, u64>>, key: &str) {
    let mut m = map.lock();
    if m.len() >= MAX_TOP_ENTRIES && !m.contains_key(key) {
        prune(&mut m);
    }
    *m.entry(key.to_string()).or_insert(0) += 1;
}

fn top(map: &Mutex<HashMap<String, u64>>, n: usize) -> Vec<TopEntry> {
    let m = map.lock();
    let mut rows: Vec<TopEntry> = m
        .iter()
        .map(|(k, c)| TopEntry {
            key: k.clone(),
            count: *c,
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    rows.truncate(n);
    rows
}

/// Keep only the [`TOP_KEEP`] highest-count keys (deterministic tiebreak by
/// key) so the map stays bounded without losing the hot entries.
fn prune(map: &mut HashMap<String, u64>) {
    let mut rows: Vec<(String, u64)> = map
        .iter()
        .map(|(k, c)| (k.clone(), *c))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    map.clear();
    for (k, c) in rows.into_iter().take(TOP_KEEP) {
        map.insert(k, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn buckets_accumulate_within_a_minute() {
        let s = QueryStats::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..3 {
            s.record(ip, "a.example", Outcome::Recursive);
        }
        s.record(ip, "b.example", Outcome::Blocked);
        let series = s.series(1);
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].queries, 4);
        assert_eq!(series[0].recursive, 3);
        assert_eq!(series[0].blocked, 1);
    }

    #[test]
    fn series_gaps_are_zero_filled() {
        let s = QueryStats::new();
        let series = s.series(5);
        assert_eq!(series.len(), 5);
        assert!(series.iter().all(|p| p.queries == 0));
    }

    #[test]
    fn top_tables_rank_and_cap() {
        let s = QueryStats::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..5 {
            s.record(ip, "hot.example", Outcome::Recursive);
        }
        s.record(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), "cold.example", Outcome::Recursive);
        let clients = s.top_clients(10);
        assert_eq!(clients[0].key, "127.0.0.1");
        assert_eq!(clients[0].count, 5);
        let domains = s.top_domains(1);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].key, "hot.example");
    }

    #[test]
    fn blocked_domains_only_count_blocked() {
        let s = QueryStats::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        s.record(ip, "ads.example", Outcome::Blocked);
        s.record(ip, "ok.example", Outcome::Recursive);
        let blocked = s.top_blocked(10);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].key, "ads.example");
    }

    #[test]
    fn prune_keeps_hot_entries() {
        let mut map = HashMap::new();
        for i in 0..(MAX_TOP_ENTRIES + 10) {
            map.insert(format!("k{i}"), i as u64 % 7);
        }
        prune(&mut map);
        assert_eq!(map.len(), TOP_KEEP);
        // The hottest key (count 6) must survive.
        assert!(map.values().any(|&c| c == 6));
    }

    #[test]
    fn bucket_ring_is_bounded() {
        let s = QueryStats::new();
        {
            // Simulate 24h+ of minutes by back-dating the last bucket.
            let mut buckets = s.inner.buckets.lock();
            let mut b = Bucket::new(epoch_minutes() - (MAX_BUCKETS as u64) - 2);
            b.queries = 1;
            buckets.push(b);
        }
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        s.record(ip, "x.example", Outcome::Recursive);
        let buckets = s.inner.buckets.lock();
        assert!(buckets.len() <= MAX_BUCKETS + 1);
    }
}
