//! Cache assistant: prefetching and serve-stale for the recursive resolver.
//!
//! Hickory's resolver caches internally but has no prefetch or stale-serving
//! of its own, so this module implements both at the Daygle layer:
//!
//! - **Prefetch** - every successful lookup updates a freshness snapshot
//!   (`valid_until` from Hickory, so Hickory's TTL clamping is honored).
//!   When a *popular* name (queried at least `prefetch_min_queries` times in
//!   the sliding `prefetch_window_secs` window) is served with less than
//!   `prefetch_ttl_fraction_pct` of its effective TTL remaining, a background
//!   task re-resolves it, so the next client never waits on an upstream
//!   round trip.
//! - **Serve-stale** - when an upstream lookup *fails* (timeout, transport
//!   error - not NXDOMAIN, which is a real answer) and a previously-good
//!   answer for the name exists that expired less than `serve_stale_secs`
//!   ago, that stale answer is served with a short TTL. "Stale bread is
//!   better than no bread."
//!
//! Both structures are bounded: at most [`MAX_TRACKED_ENTRIES`] names are
//! tracked, and expired/least-popular entries are evicted, so memory stays
//! flat regardless of query volume.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Entries evicted at once when a bounded map is full. Evicting a batch keeps
/// the amortized cost per insert constant: evicting a single victim meant a
/// full O(n) scan for *every* new name once the map had filled up, which a
/// stream of random query names makes the steady state.
const EVICT_BATCH: usize = MAX_TRACKED_ENTRIES / 10;

#[derive(Clone, Debug, Default)]
pub struct PrefetchConfig {
    pub enabled: bool,
    pub ttl_fraction_pct: u32,
    pub min_queries: u32,
    pub window: Duration,
    pub serve_stale_secs: u64,
    /// Upper bound, in seconds, for cached *positive* TTLs. Records whose TTL
    /// exceeds this are clamped at insert time. 0 disables the cap.
    pub max_cache_ttl: u32,
    /// TTL, in seconds, for caching *failure responses*. 0 disables failure
    /// caching.
    pub failure_cache_ttl: u32,
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
    /// An optional cached failure: when set, `cached_failure_code` replays it
    /// until it expires instead of retrying upstream.
    failure_until: Option<Instant>,
    /// The DNS response code to replay the cached failure with.
    failure_code: Option<u16>,
    /// The SOA of a cached negative answer (NXDOMAIN or NODATA), replayed
    /// in the authority section so clients can cache it too (RFC 2308).
    failure_soa: Option<Record>,
    /// Whether this entry was imported from the snapshot file (rather than
    /// captured from a live answer). Only such entries are handed out by
    /// [`Self::fresh_answer`]: Hickory's own cache covers live repeats, and
    /// an early assistant hit there would skip the route/metrics
    /// bookkeeping the resolution path records.
    restored: bool,
}

/// One cache entry exported for (or restored from) the snapshot file, as
/// written by the `persist` module. Expiries are absolute Unix-epoch seconds
/// so a restore is deterministic however much time passed between the write
/// (shutdown) and the next startup.
#[derive(Clone)]
pub struct PersistedEntry {
    pub key: CacheKey,
    pub query: Query,
    pub answers: Vec<Record>,
    /// When the entry's answer validity ends (Unix seconds).
    pub valid_through_secs: u64,
    /// When the cached failure stops being replayed (Unix seconds; 0 = none).
    pub failure_through_secs: u64,
    pub failure_code: Option<u16>,
    /// The SOA of the cached negative answer (RFC 2308).
    pub failure_soa: Option<Record>,
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Upper bound for a *restored* validity window, to shed entries whose
/// expiry is absurdly far out because the wall clock moved between the
/// snapshot and the restore. Real TTLs (and the failure cache) stay well
/// under it.
const MAX_RESTORED_VALID_SECS: u64 = 7 * 24 * 60 * 60;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub rtype: u16,
    /// Which resolver the answers came from (client policies keep their
    /// own); 0 for the default one.
    pub scope: u16,
}

impl CacheKey {
    /// The same name and type under another resolver's scope.
    pub fn scoped(mut self, scope: u16) -> Self {
        self.scope = scope;
        self
    }
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
    ///
    /// If a cached failure was in effect for this key, it is cleared so the next
    /// real answer (even if short-lived) beats the failure cache.
    pub fn on_success(&self, key: &CacheKey, lookup: &Lookup) -> bool {
        let now = Instant::now();
        let original_deadline = lookup.valid_until();
        // Apply the server-wide max TTL cap to both the stored record TTLs and the
        // snapshot's validity window, so the cache assistant's view of freshness
        // matches the TTLs we actually store.
        let effective_deadline = if self.config.max_cache_ttl > 0 {
            let remaining = original_deadline.saturating_duration_since(now);
            let capped = Duration::from_secs(self.config.max_cache_ttl as u64);
            now + remaining.min(capped)
        } else {
            original_deadline
        };
        let snapshot = Snapshot {
            query: lookup.query().clone(),
            answers: clamp_answer_ttls(lookup.answers(), self.config.max_cache_ttl),
            valid_until: effective_deadline,
            fetched_at: now,
            failure_until: None,
            failure_code: None,
            failure_soa: None,
            restored: false,
        };

        let mut snapshots = self.snapshots.lock();
        if snapshots.len() >= MAX_TRACKED_ENTRIES && !snapshots.contains_key(key) {
            evict_batch(&mut snapshots, |snap| snap.fetched_at);
        }
        // Clear any in-effect cached failure; a real answer beats it.
        if let Some(prev) = snapshots.get_mut(key) {
            prev.failure_until = None;
        }
        // The epoch's full TTL is measured from when the answer was first
        // observed. A Hickory cache hit re-serves the same entry with an
        // unchanged deadline, so keep the previous snapshot's `fetched_at` in
        // that case; overwriting it on every hit would make the full TTL
        // equal the remaining TTL and the prefetch trigger below could never
        // fire for any configured fraction (validation caps it at 100).
        let full_ttl = match snapshots.get(key) {
            Some(prev) if prev.valid_until == effective_deadline && effective_deadline > now => {
                effective_deadline.saturating_duration_since(prev.fetched_at)
            }
            _ => effective_deadline.saturating_duration_since(now),
        };
        snapshots.insert(key.clone(), snapshot);
        drop(snapshots);

        let popular = self.bump_popularity(key, now);

        if !self.config.enabled || !popular {
            return false;
        }
        // Prefetch when less than the configured fraction of the effective
        // TTL remains.
        let effective_ttl = effective_deadline.saturating_duration_since(now);
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

    /// Check whether a fresh cached failure exists for `key` and, if so,
    /// return the recorded response code it should be replayed as.
    ///
    /// Cached failures cover transport/timeout failures *and* negative answers
    /// (NXDOMAIN/NODATA) that arrived as errors here, so a broken or refusing
    /// upstream is not hammered on every client query. The caller replays the
    /// failure as a `DaygleError::Resolution` carrying this code - `Lookup`
    /// cannot carry a response code, so an empty lookup would wrongly surface
    /// as NoError/NODATA.
    pub fn cached_failure_code(&self, key: &CacheKey) -> Option<u16> {
        if self.config.failure_cache_ttl == 0 {
            return None;
        }
        let now = Instant::now();
        let snapshots = self.snapshots.lock();
        let snapshot = snapshots.get(key)?;
        let until = snapshot.failure_until?;
        if until <= now {
            return None;
        }
        debug!(
            name = %key.name,
            rtype = key.rtype,
            failure_ttl_secs = until.saturating_duration_since(now).as_secs(),
            "serving cached failure response"
        );
        Some(
            snapshot
                .failure_code
                .unwrap_or(hickory_proto::op::ResponseCode::ServFail.into()),
        )
    }

    /// On upstream failure (transport/timeout only - negative answers are
    /// handled by [`Self::cached_failure_code`]), return a previously-good
    /// answer for `key` when it expired less than `serve_stale_secs` ago.
    pub fn stale_answer(&self, key: &CacheKey) -> Option<Lookup> {
        if self.config.serve_stale_secs == 0 {
            return None;
        }
        let now = Instant::now();
        let snapshots = self.snapshots.lock();
        let snapshot = snapshots.get(key)?;
        let max_age = Duration::from_secs(self.config.serve_stale_secs);
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

    /// Record a cached failure for `key`, replayed by
    /// [`Self::cached_failure_code`] until `until` expires. If no snapshot
    /// exists yet for the key, a bare failure-only snapshot is created carrying
    /// `query`, so the first failure for a name that never resolved
    /// successfully is cached too.
    pub fn record_failure(&self, key: &CacheKey, query: &Query, code: u16, until: Instant) {
        let mut snapshots = self.snapshots.lock();
        if snapshots.len() >= MAX_TRACKED_ENTRIES && !snapshots.contains_key(key) {
            evict_batch(&mut snapshots, |snap| snap.fetched_at);
        }
        let snapshot = snapshots.entry(key.clone()).or_insert_with(|| Snapshot {
            query: query.clone(),
            answers: Vec::new(),
            valid_until: now_in_the_past(),
            fetched_at: Instant::now(),
            failure_until: None,
            failure_code: None,
            failure_soa: None,
            restored: false,
        });
        snapshot.failure_until = Some(until);
        snapshot.failure_code = Some(code);
        snapshot.failure_soa = None;
    }

    /// Keep the SOA of the negative answer just recorded with
    /// [`Self::record_failure`], for [`Self::cached_failure_soa`].
    pub fn set_failure_soa(&self, key: &CacheKey, soa: Record) {
        if let Some(snapshot) = self.snapshots.lock().get_mut(key) {
            snapshot.failure_soa = Some(soa);
        }
    }

    /// The SOA of the fresh cached failure for `key`, its TTL cut to what
    /// is left of the failure, so a client caches it no longer than we do.
    pub fn cached_failure_soa(&self, key: &CacheKey) -> Option<Record> {
        let now = Instant::now();
        let snapshots = self.snapshots.lock();
        let snapshot = snapshots.get(key)?;
        let left = snapshot.failure_until?.checked_duration_since(now)?;
        let mut soa = snapshot.failure_soa.clone()?;
        soa.ttl = soa
            .ttl
            .min(u32::try_from(left.as_secs()).unwrap_or(u32::MAX));
        Some(soa)
    }

    /// Bump the sliding-window counter; returns whether the name has crossed
    /// `prefetch_min_queries` inside the window.
    fn bump_popularity(&self, key: &CacheKey, now: Instant) -> bool {
        let mut popular = self.popular.lock();
        if popular.len() >= MAX_TRACKED_ENTRIES && !popular.contains_key(key) {
            // Drop entries whose window has lapsed (cheap sweep), else the
            // oldest by count.
            popular
                .retain(|_, p| now.saturating_duration_since(p.window_start) < self.config.window);
            if popular.len() >= MAX_TRACKED_ENTRIES {
                // Least popular first; among equals, the oldest window.
                evict_batch(&mut popular, |p| (p.count, p.window_start));
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

    /// Drop the tracked state (stale snapshots, cached failures,
    /// popularity) for `name` (lowercased FQDN), for one record type or all,
    /// in every scope.
    pub fn forget(&self, name: &str, rtype: Option<u16>) {
        let matches = |key: &CacheKey| key.name == name && rtype.is_none_or(|t| key.rtype == t);
        self.snapshots.lock().retain(|key, _| !matches(key));
        self.popular.lock().retain(|key, _| !matches(key));
    }

    pub fn tracked_names(&self) -> usize {
        self.snapshots.lock().len()
    }

    /// The configured failure-cache TTL (0 disables failure caching).
    pub fn failure_cache_ttl(&self) -> u32 {
        self.config.failure_cache_ttl
    }

    /// Export every stored entry for the snapshot file (see the `persist`
    /// module). Even expired entries are exported: with their absolute
    /// expiry intact, a restore can keep using them inside the serve-stale
    /// window, which is exactly what they are for.
    pub fn export_persisted(&self) -> Vec<PersistedEntry> {
        self.export_persisted_at(Instant::now())
    }

    fn export_persisted_at(&self, now: Instant) -> Vec<PersistedEntry> {
        let unix_now = unix_secs();
        let through =
            |deadline: Instant| unix_now + deadline.saturating_duration_since(now).as_secs();
        self.snapshots
            .lock()
            .iter()
            .map(|(key, snap)| PersistedEntry {
                key: key.clone(),
                query: snap.query.clone(),
                answers: snap.answers.clone(),
                valid_through_secs: through(snap.valid_until),
                failure_through_secs: snap
                    .failure_until
                    .and_then(|until| {
                        // A failure already spent does not carry over.
                        until.checked_duration_since(now).map(|_| through(until))
                    })
                    .unwrap_or(0),
                failure_code: snap.failure_code,
                failure_soa: snap.failure_soa.clone(),
            })
            .collect()
    }

    /// Restore entries from a snapshot file (see the `persist` module) and
    /// return how many were imported.
    ///
    /// Entries are dropped when their answer TTL and their cached failure
    /// are both spent (beyond their serve-stale or failure-cache windows);
    /// restoring stale-eligible answers keeps an upstream outage that starts
    /// right after a restart covered.
    pub fn import_persisted(&self, entries: Vec<PersistedEntry>) -> usize {
        let now = Instant::now();
        let now_wall = unix_secs();
        let stale_window = self.config.serve_stale_secs;
        let failure_ttl = self.config.failure_cache_ttl;
        let max_ttl = u64::from(self.config.max_cache_ttl);
        let mut snapshots = self.snapshots.lock();
        let mut restored = 0usize;
        for entry in entries {
            let valid_left = entry.valid_through_secs.saturating_sub(now_wall);
            // How long ago the answer expired (only meaningful when both
            // wall-clock readings are on the same side; a clock that moved
            // backwards yields 0 here, and an expired entry is simply kept
            // stale-eligible rather than dropped).
            let expired_for = now_wall.saturating_sub(entry.valid_through_secs);
            let failure_left = entry.failure_through_secs.saturating_sub(now_wall);
            let has_answers = !entry.answers.is_empty();
            let failure_keep = failure_left > 0 && failure_ttl > 0;
            if !has_answers && !failure_keep {
                continue;
            }
            // An expired answer is only worth restoring while serve-stale
            // can still serve it (or a live failure needs its SOA).
            if has_answers && valid_left == 0 && expired_for > stale_window && !failure_keep {
                continue;
            }
            // A validity window this far out means the wall clock moved
            // between the snapshot and the restore, not a real TTL: shed it.
            if valid_left > MAX_RESTORED_VALID_SECS {
                continue;
            }
            // TTLs were already capped when they were captured; only a
            // clock move can make the remaining TTL exceed `max_cache_ttl`.
            let capped_valid = if max_ttl > 0 {
                valid_left.min(max_ttl)
            } else {
                valid_left
            };
            let failure_until = failure_keep
                .then(|| now + Duration::from_secs(failure_left.min(u64::from(failure_ttl))));

            if snapshots.len() >= MAX_TRACKED_ENTRIES && !snapshots.contains_key(&entry.key) {
                evict_batch(&mut snapshots, |snap| snap.fetched_at);
            }
            snapshots.insert(
                entry.key.clone(),
                Snapshot {
                    query: entry.query,
                    answers: entry.answers,
                    valid_until: if capped_valid > 0 {
                        now + Duration::from_secs(capped_valid)
                    } else {
                        now_in_the_past()
                    },
                    fetched_at: now,
                    failure_until,
                    failure_code: entry.failure_code,
                    failure_soa: entry.failure_soa,
                    restored: true,
                },
            );
            restored += 1;
        }
        restored
    }

    /// A still-valid snapshot for `key`, served without an upstream round
    /// trip.
    ///
    /// Normally Hickory's cache answers first, and the assistant only holds
    /// a parallel copy. Entries restored from a snapshot file start out in
    /// the assistant alone (Hickory's cache is empty after a restart), so a
    /// restored entry is handed out directly until it is naturally
    /// superseded. The answer's TTLs are cut to what remains of the entry's
    /// validity.
    pub fn fresh_answer(&self, key: &CacheKey) -> Option<Lookup> {
        let now = Instant::now();
        let snapshots = self.snapshots.lock();
        let snapshot = snapshots.get(key)?;
        // Failure-only snapshots are preceded by a `cached_failure_code`
        // replay; anything without answers is not repliable here.
        // Live answers are NOT handed out here: Hickory's own cache covers
        // them, and an early assistant hit would skip the route/hit/miss
        // bookkeeping recorded by the resolution path (and the prefetch
        // refresh could re-fill a just-flushed entry). Only entries restored
        // from the snapshot file are served from here.
        if !snapshot.restored {
            return None;
        }
        if snapshot.answers.is_empty() {
            return None;
        }
        let remaining = snapshot.valid_until.checked_duration_since(now)?;
        let ttl = u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX);
        debug!(
            name = %key.name,
            rtype = key.rtype,
            ttl_secs = ttl,
            "serving restored cache entry"
        );
        Some(Lookup::new_with_deadline(
            snapshot.query.clone(),
            snapshot
                .answers
                .iter()
                .map(|r| {
                    let mut rec = r.clone();
                    rec.ttl = ttl;
                    rec
                })
                .collect::<Vec<_>>(),
            snapshot.valid_until,
        ))
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

/// Remove the [`EVICT_BATCH`] entries with the smallest `rank` (at least one,
/// and never more than the map holds).
fn evict_batch<K, V, R>(map: &mut HashMap<K, V>, rank: impl Fn(&V) -> R)
where
    K: Clone + std::hash::Hash + Eq,
    R: Ord,
{
    let count = EVICT_BATCH.clamp(1, map.len().max(1));
    let mut ranked: Vec<(R, &K)> = map.iter().map(|(k, v)| (rank(v), k)).collect();
    if ranked.len() > count {
        ranked.select_nth_unstable_by(count - 1, |a, b| a.0.cmp(&b.0));
        ranked.truncate(count);
    }
    let victims: Vec<K> = ranked.into_iter().map(|(_, k)| k.clone()).collect();
    for key in victims {
        map.remove(&key);
    }
}

/// Clamp each answer record's TTL to `cap` (when `cap > 0`), so cached positive
/// answers never exceed the server-wide maximum TTL.
fn clamp_answer_ttls(answers: &[Record], cap: u32) -> Vec<Record> {
    if cap == 0 {
        return answers.to_vec();
    }
    answers
        .iter()
        .map(|r| {
            let mut rec = r.clone();
            if rec.ttl > cap {
                rec.ttl = cap;
            }
            rec
        })
        .collect()
}

/// A deadline safely in the past, for failure-only snapshots that must never
/// look fresh (so serve-stale never picks them up).
fn now_in_the_past() -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now)
}

/// Key for a name/type pair.
pub fn cache_key(name: &hickory_proto::rr::Name, rtype: RecordType) -> CacheKey {
    CacheKey {
        name: name.to_string().to_ascii_lowercase(),
        rtype: u16::from(rtype),
        scope: 0,
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
            max_cache_ttl: 0,
            failure_cache_ttl: 0,
        }
    }

    fn lookup_a(name: &str, ttl_secs: u64) -> Lookup {
        let query = Query::query(Name::from_utf8(name).unwrap(), RecordType::A);
        let record = Record::from_rdata(
            query.name().clone(),
            ttl_secs as u32,
            RData::A(hickory_proto::rr::rdata::a::A(Ipv4Addr::new(192, 0, 2, 7))),
        );
        Lookup::new_with_deadline(
            query,
            [record],
            Instant::now() + Duration::from_secs(ttl_secs),
        )
    }

    fn key_for(name: &str) -> CacheKey {
        cache_key(&Name::from_utf8(name).unwrap(), RecordType::A)
    }

    fn lookup1_query() -> hickory_proto::op::Query {
        Query::query(Name::from_utf8("fail.example.").unwrap(), RecordType::A)
    }

    #[test]
    fn snapshot_stores_and_expires() {
        let ca = CacheAssistant::new(config());
        let key = key_for("fast.example.");
        let lk = lookup_a("fast.example.", 300);
        ca.on_success(&key, &lk);

        // Fresh entry is not stale-eligible.
        assert!(ca.stale_answer(&key).is_none());

        // Simulate expiry: replace with an expired snapshot.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(120);
        }
        let stale = ca.stale_answer(&key).expect("stale answer");
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
        assert!(ca.stale_answer(&key).is_none());
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
        assert!(ca.stale_answer(&key).is_none());
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
        // manually age it - the trigger math is (valid_until - fetched_at) *
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
    fn prefetch_fires_late_in_the_same_epoch() {
        let ca = CacheAssistant::new(config()); // 10 % threshold, min 2 queries
        let key = key_for("late.example.");

        // First fetch: full 100 s TTL remaining -> no prefetch (and not yet
        // popular).
        assert!(!ca.on_success(&key, &lookup_a("late.example.", 100)));

        // Simulate 95 s having elapsed inside the 100 s epoch: the deadline a
        // Hickory cache hit would re-serve is now 5 s away, and the epoch
        // started 95 s ago. 5 s remaining is below the 10 s (10 %) trigger.
        let now = Instant::now();
        let past = now
            .checked_sub(Duration::from_secs(95))
            .expect("monotonic clock covers the 95 s test epoch");
        let aged_deadline = now + Duration::from_secs(5);
        let (aged_query, aged_answers) = {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.fetched_at = past;
            s.valid_until = aged_deadline;
            (s.query.clone(), s.answers.clone())
        };
        let aged = Lookup::new_with_deadline(aged_query, aged_answers, aged_deadline);

        // Second query: popular now, and 5 s < 10 % of the 100 s epoch -> the
        // prefetch trigger must fire.
        assert!(ca.on_success(&key, &aged));

        // A brand-new epoch with the full TTL remaining never fires, even
        // though the name is popular.
        assert!(!ca.on_success(&key, &lookup_a("late.example.", 100)));
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

    #[test]
    fn max_cache_ttl_clamps_positive_ttls() {
        let mut cfg = config();
        cfg.max_cache_ttl = 60;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("big.example.");
        // Insert a 300 s record; it should be clamped to 60.
        ca.on_success(&key, &lookup_a("big.example.", 300));
        // Scope each guard: holding the lock across the next on_success call
        // would self-deadlock (parking_lot mutexes are not reentrant).
        let (stored_ttl, remaining) = {
            let snapshots = ca.snapshots.lock();
            let stored = snapshots.get(&key).unwrap();
            let remaining = stored.valid_until.saturating_duration_since(Instant::now());
            (stored.answers.first().unwrap().ttl, remaining)
        };
        assert_eq!(stored_ttl, 60);
        // The snapshot's deadline must be capped at 60 s from insertion; allow a
        // 1 s tolerance because the assertion runs a tick after on_success.
        assert!(remaining.as_secs() <= 60 && remaining.as_secs() >= 59);

        // Insert a 30 s record; it should be unchanged (below the cap).
        let key2 = key_for("small.example.");
        ca.on_success(&key2, &lookup_a("small.example.", 30));
        let stored2_ttl = {
            let snapshots = ca.snapshots.lock();
            snapshots.get(&key2).unwrap().answers.first().unwrap().ttl
        };
        assert_eq!(stored2_ttl, 30);

        // Cap of 0 disables clamping.
        let mut cfg2 = config();
        cfg2.max_cache_ttl = 0;
        let ca2 = CacheAssistant::new(cfg2);
        let key3 = key_for("uncapped.example.");
        ca2.on_success(&key3, &lookup_a("uncapped.example.", 300));
        let stored3_ttl = {
            let snapshots = ca2.snapshots.lock();
            snapshots.get(&key3).unwrap().answers.first().unwrap().ttl
        };
        assert_eq!(stored3_ttl, 300);
    }

    #[test]
    fn failure_cache_replays_on_repeat_failure() {
        let mut cfg = config();
        cfg.failure_cache_ttl = 60;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("fail.example.");

        // First, store a successful snapshot so the key exists.
        ca.on_success(&key, &lookup_a("fail.example.", 300));
        // Simulate expiry so serve-stale is the only fallback.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(300);
        }

        // Cache a failure.
        let until = Instant::now() + Duration::from_secs(60);
        let servfail = hickory_proto::op::ResponseCode::ServFail.into();
        ca.record_failure(&key, &lookup1_query(), servfail, until);

        // First check after caching: the failure is replayed with its code.
        assert_eq!(ca.cached_failure_code(&key), Some(servfail));

        // Still fresh on the second call within the window.
        assert_eq!(ca.cached_failure_code(&key), Some(servfail));

        // After expiry, the cached failure is gone but serve-stale covers the
        // transport-failure path (snapshot is old but within window).
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.failure_until = None;
        }
        assert_eq!(ca.cached_failure_code(&key), None);
        let stale = ca.stale_answer(&key).expect("stale fallback");
        assert_eq!(stale.answers().first().unwrap().ttl, STALE_TTL_SECS);
    }

    /// A cached negative answer replays its SOA, with the TTL cut to what is
    /// left of the cached failure; a new failure forgets the old SOA.
    #[test]
    fn cached_negative_answer_keeps_its_soa() {
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name, RData};
        let ca = CacheAssistant::new(config());
        let key = key_for("v6less.example.");
        let query = lookup_a("v6less.example.", 300).query().clone();
        let nodata = hickory_proto::op::ResponseCode::NoError.into();
        let soa = Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.").unwrap(),
                Name::from_ascii("admin.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );

        ca.record_failure(
            &key,
            &query,
            nodata,
            Instant::now() + Duration::from_secs(60),
        );
        assert!(ca.cached_failure_soa(&key).is_none(), "none noted yet");
        ca.set_failure_soa(&key, soa);
        let replayed = ca.cached_failure_soa(&key).expect("SOA replayed");
        assert!(
            replayed.ttl <= 60,
            "TTL {} outlives the cached failure",
            replayed.ttl
        );

        ca.record_failure(
            &key,
            &query,
            nodata,
            Instant::now() + Duration::from_secs(60),
        );
        assert!(ca.cached_failure_soa(&key).is_none(), "stale SOA kept");
    }

    #[test]
    fn failure_cache_disabled_at_zero() {
        let mut cfg = config();
        cfg.failure_cache_ttl = 0;
        cfg.serve_stale_secs = 3_600;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("nocache.example.");
        ca.on_success(&key, &lookup_a("nocache.example.", 300));
        // Expire the snapshot.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(300);
        }
        // Even with a failure recorded, caching is disabled: no replay.
        let servfail = hickory_proto::op::ResponseCode::ServFail.into();
        ca.record_failure(
            &key,
            &lookup_a("nocache.example.", 300).query().clone(),
            servfail,
            Instant::now() + Duration::from_secs(60),
        );
        assert_eq!(ca.cached_failure_code(&key), None);
        // Serve-stale still covers the transport-failure path.
        let stale = ca.stale_answer(&key).expect("stale fallback");
        assert_eq!(stale.answers().first().unwrap().ttl, STALE_TTL_SECS);
    }

    #[test]
    fn record_failure_creates_snapshot_for_unknown_key() {
        // The first failure for a name that never resolved successfully must
        // still be cached: record_failure creates a bare failure-only snapshot.
        let mut cfg = config();
        cfg.failure_cache_ttl = 60;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("never-resolved.example.");
        let query = Query::query(
            Name::from_utf8("never-resolved.example.").unwrap(),
            RecordType::A,
        );
        let until = Instant::now() + Duration::from_secs(60);
        let nxdomain = hickory_proto::op::ResponseCode::NXDomain.into();
        ca.record_failure(&key, &query, nxdomain, until);
        assert_eq!(ca.tracked_names(), 1, "failure-only snapshot created");
        assert_eq!(ca.cached_failure_code(&key), Some(nxdomain));
    }

    #[test]
    fn negative_answers_never_stale_served() {
        let mut cfg = config();
        cfg.serve_stale_secs = 3_600;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("negative.example.");
        ca.on_success(&key, &lookup_a("negative.example.", 300));
        // Expire the snapshot.
        {
            let mut snaps = ca.snapshots.lock();
            let s = snaps.get_mut(&key).unwrap();
            s.valid_until = Instant::now() - Duration::from_secs(300);
        }
        // stale_answer is only consulted for transport failures, never for a
        // negative answer: the caller routes coded errors away from it.
        let stale = ca.stale_answer(&key).expect("stale fallback");
        assert_eq!(stale.answers().first().unwrap().ttl, STALE_TTL_SECS);
    }

    #[test]
    fn on_success_clears_cached_failure() {
        let mut cfg = config();
        cfg.failure_cache_ttl = 60;
        let ca = CacheAssistant::new(cfg);
        let key = key_for("recover.example.");
        ca.on_success(&key, &lookup_a("recover.example.", 300));
        let until = Instant::now() + Duration::from_secs(60);
        let servfail = hickory_proto::op::ResponseCode::ServFail.into();
        ca.record_failure(
            &key,
            &lookup_a("recover.example.", 300).query().clone(),
            servfail,
            until,
        );
        assert!(ca.cached_failure_code(&key).is_some());
        // A fresh successful answer clears the cached failure.
        ca.on_success(&key, &lookup_a("recover.example.", 300));
        assert!(ca.cached_failure_code(&key).is_none());
    }
}
