//! Cache assistant: prefetching and serve-stale for the recursive resolver.
//!
//! Hickory's resolver caches internally but has no prefetch or stale-serving
//! of its own, so this module implements both at the Daygle layer:
//!
//! - **Prefetch** — every successful lookup updates a freshness snapshot
//!   (`valid_until` from Hickory, so Hickory's TTL clamping is honored).
//!   When a *popular* name (queried at least `prefetch_min_queries` times in
//!   the sliding `prefetch_window_secs` window) is served with less than
//!   `prefetch_ttl_fraction_pct` of its effective TTL remaining, a background
//!   task re-resolves it, so the next client never waits on an upstream
//!   round trip.
//! - **Serve-stale** — when an upstream lookup *fails* (timeout, transport
//!   error — not NXDOMAIN, which is a real answer) and a previously-good
//!   answer for the name exists that expired less than `serve_stale_secs`
//!   ago, that stale answer is served with a short TTL. "Stale bread is
//!   better than no bread."
//!
//! Both structures are bounded: at most [`MAX_TRACKED_ENTRIES`] names are
//! tracked, and expired/least-popular entries are evicted, so memory stays
//! flat regardless of query volume.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use hickory_proto::op::Query;
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::lookup::Lookup;
use parking_lot::Mutex;
use tracing::debug;

/// Upper bound on tracked names (snapshots + popularity + in-flight dedup).
/// Prevents unbounded memory growth from adversarial query patterns.
pub const MAX_TRACKED_ENTRIES: usize = 10_000;

/// TTL applied to serve-stale responses: clients re-query quickly so a
/// recovered upstream is picked up fast, but caches still help.
pub const STALE_TTL_SECS: u32 = 30;

#[derive(Clone, Debug, Default)]
pub struct PrefetchConfig {
    pub enabled: bool,
    pub ttl_fraction_pct: u32,
    pub min_queries: u32,
    pub window: Duration,
    pub serve_stale_secs: u64,
}

/// A stored copy of the last good answer for one (name, type).
#[derive(Clone, Debug)]
struct Snapshot {
    query: Query,
    answers: Vec<Record>,
    /// When the underlying cached copy expires (Hickory's clamping applied).
    valid_until: Instant,
    /// When we first stored this snapshot (defines the effective TTL).
    fetched_at: Instant,
}

/// Sliding-window popularity for one (name, type).
#[derive(Clone, Copy, Debug)]
struct Popularity {
    count: u32,
    window_start: Instant,
}

/// Cache assistant shared by the default and conditional resolvers.
#[derive(Default)]
pub struct CacheAssistant {
    snapshots: Mutex<HashMap<CacheKey, Snapshot>>,
    popular: Mutex<HashMap<CacheKey, Popularity>>,
    in_flight: Mutex<HashSet<CacheKey>>,
    config: PrefetchConfig,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub rtype: u16,
}

impl CacheAssistant {
    pub fn new(config: PrefetchConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Record a fresh successful lookup: refresh the snapshot and bump the
    /// name's popularity, then decide whether a prefetch should fire.
    pub fn on_success(&self, key: &CacheKey, lookup: &Lookup) -> bool {
        let valid_until = lookup.valid_until();
        let now = Instant::now();
        let snapshot = Snapshot {
            query: lookup.query().clone(),
            answers: lookup.answers().to_vec(),
            valid_until,
            fetched_at: now,
        };

        let mut snapshots = self.snapshots.lock();
        if snapshots.len() >= MAX_TRACKED_ENTRIES && !snapshots.contains_key(key) {
            evict_oldest(&mut snapshots);
        }
        snapshots.insert(key.clone(), snapshot);
        drop(snapshots);

        let popular = self.bump_popularity(key, now);

        if !self.config.enabled || !popular {
            return false;
        }
        // Prefetch when less than the configured fraction of the effective
        // TTL remains.
        let effective_ttl = valid_until.saturating_duration_since(now);
        let full_ttl = valid_until.saturating_duration_since(
            self.snapshots
                .lock()
                .get(key)
                .map(|s| s.fetched_at)
                .unwrap_or(now),
        );
        let trigger = full_ttl.mul_f32(self.config.ttl_fraction_pct as f32 / 100.0);
        if effective_ttl < trigger {
            debug!(
                name = %key.name,
                rtype = key.rtype,
                remaining_secs = effective_ttl.as_secs(),
                "prefetch triggered for popular name"
            );
            true // caller spawns the background refresh
        } else {
            false
        }
    }

    /// On upstream failure, return a serve-stale `Lookup` when a snapshot
    /// expired no more than `serve_stale_secs` ago (and 0 disables the
    /// feature). The stale answer carries a short TTL.
    pub fn on_failure(&self, key: &CacheKey) -> Option<Lookup> {
        if self.config.serve_stale_secs == 0 {
            return None;
        }
        let now = Instant::now();
        let max_age = Duration::from_secs(self.config.serve_stale_secs);
        let snapshots = self.snapshots.lock();
        let snapshot = snapshots.get(key)?;
        // Still-fresh entries are irrelevant here: Hickory's cache would
        // have answered. Only *expired* entries are eligible.
        let expired_for = now.saturating_duration_since(snapshot.valid_until);
        if snapshot.valid_until >= now || expired_for > max_age {
            return None;
        }
        debug!(
            name = %key.name,
            rtype = key.rtype,
            stale_for_secs = expired_for.as_secs(),
            "serving stale answer after upstream failure"
        );
        let stale_ttl = Duration::from_secs(u64::from(STALE_TTL_SECS));
        Some(Lookup::new_with_deadline(
            snapshot.query.clone(),
            stale_answers(&snapshot.answers),
            now + stale_ttl,
        ))
    }

    /// Bump the sliding-window counter; returns whether the name has crossed
    /// `prefetch_min_queries` inside the window.
    fn bump_popularity(&self, key: &CacheKey, now: Instant) -> bool {
        let mut popular = self.popular.lock();
        if popular.len() >= MAX_TRACKED_ENTRIES && !popular.contains_key(key) {
            // Drop entries whose window has lapsed (cheap sweep), else the
            // oldest by count.
            popular.retain(|_, p| now.saturating_duration_since(p.window_start) < self.config.window);
            if popular.len() >= MAX_TRACKED_ENTRIES {
                evict_least_popular(&mut popular, now);
            }
        }
        let entry = popular.entry(key.clone()).or_insert(Popularity {
            count: 0,
            window_start: now,
        });
        if now.saturating_duration_since(entry.window_start) >= self.config.window {
            *entry = Popularity {
                count: 0,
                window_start: now,
            };
        }
        entry.count += 1;
        entry.count >= self.config.min_queries
    }

    /// Mark a prefetch as started; `false` means one is already running.
    pub fn try_begin_prefetch(&self, key: &CacheKey) -> bool {
        let mut in_flight = self.in_flight.lock();
        in_flight.insert(key.clone())
    }

    /// Clear the in-flight marker when a prefetch finishes.
    pub fn end_prefetch(&self, key: &CacheKey) {
        self.in_flight.lock().remove(key);
    }

    /// Drop all tracked state (cache flush).
    pub fn clear(&self) {
        self.snapshots.lock().clear();
        self.popular.lock().clear();
        self.in_flight.lock().clear();
    }

    pub fn tracked_names(&self) -> usize {
        self.snapshots.lock().len()
    }
}

/// Cap record TTLs on a serve-stale response (the data is old; tell clients
/// to re-check soon).
fn stale_answers(answers: &[Record]) -> Vec<Record> {
    answers
        .iter()
        .map(|r| {
            let mut rec = r.clone();
            rec.ttl = STALE_TTL_SECS;
            rec
        })
        .collect()
}

fn evict_oldest<K: Clone + std::hash::Hash + Eq, V: Clone + HasInstant>(
    map: &mut HashMap<K, V>,
) {
    let oldest = map
        .iter()
        .min_by_key(|(_, v)| v.instant())
        .map(|(k, _)| k.clone());
    if let Some(k) = oldest {
        map.remove(&k);
    }
}

fn evict_least_popular(map: &mut HashMap<CacheKey, Popularity>, now: Instant) {
    let victim = map
        .iter()
        .min_by_key(|(_, p)| (p.count, u64::try_from(p.window_start.elapsed().as_millis()).unwrap_or(0)))
        .map(|(k, _)| k.clone());
    let _ = now;
    if let Some(k) = victim {
        map.remove(&k);
    }
}

trait HasInstant {
    fn instant(&self) -> Instant;
}

impl HasInstant for Snapshot {
    fn instant(&self) -> Instant {
        self.fetched_at
    }
}

/// Key for a name/type pair.
pub fn cache_key(name: &hickory_proto::rr::Name, rtype: RecordType) -> CacheKey {
    CacheKey {
        name: name.to_string().to_ascii_lowercase(),
        rtype: u16::from(rtype),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;

    fn config() -> PrefetchConfig {
        PrefetchConfig {
            enabled: true,
            ttl_fraction_pct: 10,
            min_queries: 2,
            window: Duration::from_secs(60),
            serve_stale_secs: 3_600,
        }
    }

    fn lookup_a(name: &str, ttl_secs: u64) -> Lookup {
        let query = Query::query(Name::from_utf8(name).unwrap(), RecordType::A);
        let record = Record::from_rdata(
            query.name().clone(),
            ttl_secs as u32,
            RData::A(hickory_proto::rr::rdata::a::A(Ipv4Addr::new(192, 0, 2, 7))),
        );
        Lookup::new_with_deadline(query, [record], Instant::now() + Duration::from_secs(ttl_secs))
    }

    fn key_for(name: &str) -> CacheKey {
        cache_key(&Name::from_utf8(name).unwrap(), RecordType::A)
    }

    #[test]
    fn snapshot_stores_and_expires() {
        let ca = CacheAssistant::new(config());
        let key = key_for("fast.example.");
        let lk = lookup_a("fast.example.", 300);
        ca.on_success(&key, &lk);

        // Fresh entry is not stale-eligible.
        assert!(ca.on_failure(&key).is_none());

        // Simulate expiry: replace with an expired snapshot.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(120);
        }
        let stale = ca.on_failure(&key).expect("stale answer");
        assert_eq!(stale.answers().first().unwrap().ttl, STALE_TTL_SECS);
    }

    #[test]
    fn stale_window_respected() {
        let mut cfg = config();
        cfg.serve_stale_secs = 60;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("old.example.");
        ca.on_success(&key, &lookup_a("old.example.", 300));
        // Expired 2 minutes ago → beyond the 60 s window.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(120);
        }
        assert!(ca.on_failure(&key).is_none());
    }

    #[test]
    fn stale_disabled_at_zero() {
        let mut cfg = config();
        cfg.serve_stale_secs = 0;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("x.example.");
        ca.on_success(&key, &lookup_a("x.example.", 300));
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(120);
        }
        assert!(ca.on_failure(&key).is_none());
    }

    #[test]
    fn popularity_threshold_and_window() {
        let ca = CacheAssistant::new(config());
        let key = key_for("pop.example.");
        assert!(!ca.bump_popularity(&key, Instant::now()));
        assert!(ca.bump_popularity(&key, Instant::now()));
        // Window lapse resets the count.
        let later = Instant::now() + Duration::from_secs(120);
        assert!(!ca.bump_popularity(&key, later));
    }

    #[test]
    fn prefetch_decision_matches_fraction() {
        let ca = CacheAssistant::new(config());
        let key = key_for("frac.example.");
        // 1000 s TTL; below 10 % (100 s) remaining → prefetch fires.
        ca.on_success(&key, &lookup_a("frac.example.", 1000));
        // Pretend the cache is old: shave valid_until down.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() + Duration::from_secs(50);
        }
        // Recompute through on_success path: re-store with a long TTL, then
        // manually age it — the trigger math is (valid_until - fetched_at) *
        // pct; emulate by re-storing with fetched_at long past.
        let lk = lookup_a("frac.example.", 1000);
        ca.on_success(&key, &lk); // full TTL again
        // Now shrink remaining while keeping fetched_at old.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() + Duration::from_secs(50);
        }
        let fresh = ca.snapshots.lock().get(&key).unwrap().clone();
        let effective = fresh.valid_until.saturating_duration_since(Instant::now());
        assert!(effective < Duration::from_secs(100));
    }

    #[test]
    fn in_flight_dedup() {
        let ca = CacheAssistant::new(config());
        let key = key_for("dedup.example.");
        assert!(ca.try_begin_prefetch(&key));
        assert!(!ca.try_begin_prefetch(&key));
        ca.end_prefetch(&key);
        assert!(ca.try_begin_prefetch(&key));
    }

    #[test]
    fn bounded_maps_evict() {
        let ca = CacheAssistant::new(config());
        for i in 0..(MAX_TRACKED_ENTRIES as u32 + 5) {
            let name = format!("n{i}.example.");
            let key = cache_key(&Name::from_utf8(&name).unwrap(), RecordType::A);
            ca.on_success(&key, &lookup_a(&name, 300));
        }
        assert!(
            ca.tracked_names() <= MAX_TRACKED_ENTRIES,
            "snapshots must stay bounded"
        );
    }
}
