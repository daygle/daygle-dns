//! Fixed-window query rate limiting for the DNS dispatcher.
//!
//! Two independent counters are kept: one per client (source IP) and one per
//! queried domain. Each key gets a fixed window during which at most `limit`
//! requests are admitted; requests beyond the limit are rejected. Buckets for
//! keys that stopped querying are swept periodically so the map stays bounded
//! even under source-IP spoofing.
//!
//! The limiter reads its limits from a [`RateLimitSettings`] snapshot; callers
//! swap in a new snapshot on config reload without losing existing buckets
//! (they expire naturally at the end of their window).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RateLimitSettings;

/// How often to sweep expired buckets, and the map size that triggers a sweep
/// even when the interval has not elapsed.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const SWEEP_AT_ENTRIES: usize = 10_000;

/// A thread-safe fixed-window rate limiter.
///
/// Cheap on the hot path: one mutex-guarded hash lookup per key. The mutex is
/// held only for the duration of a single map operation.
#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    clients: HashMap<IpAddr, Bucket>,
    domains: HashMap<String, Bucket>,
    enabled: bool,
    client_limit: u32,
    client_window: Duration,
    domain_limit: u32,
    domain_window: Duration,
    exempt_loopback: bool,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    /// Build a limiter from configuration.
    pub fn new(settings: &RateLimitSettings) -> Self {
        Self {
            inner: Mutex::new(Inner {
                clients: HashMap::new(),
                domains: HashMap::new(),
                enabled: settings.enabled,
                client_limit: settings.client_max_queries,
                client_window: Duration::from_secs(settings.client_window_secs),
                domain_limit: settings.domain_max_queries,
                domain_window: Duration::from_secs(settings.domain_window_secs),
                exempt_loopback: settings.exempt_loopback,
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Swap in new limits (config reload). Existing buckets are kept; they
    /// simply reset when their current window elapses.
    pub fn set_settings(&self, settings: &RateLimitSettings) {
        let mut inner = self.inner.lock().unwrap();
        inner.enabled = settings.enabled;
        inner.client_limit = settings.client_max_queries;
        inner.client_window = Duration::from_secs(settings.client_window_secs);
        inner.domain_limit = settings.domain_max_queries;
        inner.domain_window = Duration::from_secs(settings.domain_window_secs);
        inner.exempt_loopback = settings.exempt_loopback;
    }

    /// Whether rate limiting is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.lock().unwrap().enabled
    }

    /// Admit one query from `client`. Returns `true` when the query may be
    /// processed, `false` when the client exceeded its window limit.
    pub fn check_client(&self, client: IpAddr) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if !inner.enabled {
            return true;
        }
        if inner.exempt_loopback && client.is_loopback() {
            return true;
        }
        let (window, limit) = (inner.client_window, inner.client_limit);
        let allowed = check_bucket(inner.clients.entry(client), window, limit);
        maybe_sweep(&mut inner);
        allowed
    }

    /// Admit one query for `domain`. Returns `true` when the query may be
    /// processed, `false` when the domain exceeded its window limit.
    pub fn check_domain(&self, domain: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if !inner.enabled {
            return true;
        }
        let (window, limit) = (inner.domain_window, inner.domain_limit);
        let allowed = check_bucket(inner.domains.entry(domain.to_string()), window, limit);
        maybe_sweep(&mut inner);
        allowed
    }

    /// Forget all state (used by tests).
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.clients.clear();
        inner.domains.clear();
        inner.last_sweep = Instant::now();
    }

    /// The number of tracked client buckets (used by tests).
    #[cfg(test)]
    fn client_buckets(&self) -> usize {
        self.inner.lock().unwrap().clients.len()
    }

    /// The number of tracked domain buckets (used by tests).
    #[cfg(test)]
    fn domain_buckets(&self) -> usize {
        self.inner.lock().unwrap().domains.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(&RateLimitSettings::default())
    }
}

/// Core fixed-window check for one bucket.
fn check_bucket(
    entry: std::collections::hash_map::Entry<'_, impl std::hash::Hash + Eq, Bucket>,
    window: Duration,
    limit: u32,
) -> bool {
    let now = Instant::now();
    let bucket = entry.or_insert(Bucket {
        window_start: now,
        count: 0,
    });
    if now.duration_since(bucket.window_start) >= window {
        bucket.window_start = now;
        bucket.count = 0;
    }
    if bucket.count >= limit {
        return false;
    }
    bucket.count += 1;
    true
}

/// Opportunistic cleanup: drop buckets whose window has fully elapsed so a
/// flood of spoofed keys cannot grow the map without bound.
fn maybe_sweep(inner: &mut Inner) {
    let now = Instant::now();
    let due_by_time = now.duration_since(inner.last_sweep) >= SWEEP_INTERVAL;
    let due_by_size =
        inner.clients.len() + inner.domains.len() >= SWEEP_AT_ENTRIES;
    if !due_by_time && !due_by_size {
        return;
    }
    inner.last_sweep = now;
    let (client_window, domain_window) = (inner.client_window, inner.domain_window);
    inner
        .clients
        .retain(|_, b| now.duration_since(b.window_start) < client_window);
    inner
        .domains
        .retain(|_, b| now.duration_since(b.window_start) < domain_window);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool) -> RateLimitSettings {
        RateLimitSettings {
            enabled,
            client_max_queries: 3,
            client_window_secs: 60,
            domain_max_queries: 2,
            domain_window_secs: 60,
            exempt_loopback: true,
        }
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let limiter = RateLimiter::new(&settings(false));
        assert!(limiter.check_client("10.0.0.1".parse().unwrap()));
        assert!(limiter.check_client("10.0.0.1".parse().unwrap()));
        assert!(limiter.check_domain("example.com"));
        assert_eq!(limiter.client_buckets(), 0);
        assert_eq!(limiter.domain_buckets(), 0);
    }

    #[test]
    fn enforces_per_client_limit() {
        let limiter = RateLimiter::new(&settings(true));
        let client: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check_client(client));
        assert!(limiter.check_client(client));
        assert!(limiter.check_client(client));
        assert!(!limiter.check_client(client));
        assert!(!limiter.check_client(client));
        // A different client is unaffected.
        assert!(limiter.check_client("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn enforces_per_domain_limit() {
        let limiter = RateLimiter::new(&settings(true));
        assert!(limiter.check_domain("example.com"));
        assert!(limiter.check_domain("example.com"));
        assert!(!limiter.check_domain("example.com"));
        // Other domains are unaffected.
        assert!(limiter.check_domain("other.com"));
        // Per-client limiting is separate from per-domain limiting.
        assert!(limiter.check_client("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn loopback_is_exempt_when_configured() {
        let limiter = RateLimiter::new(&settings(true));
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.check_client(loopback));
        }
        assert_eq!(limiter.client_buckets(), 0);

        // The domain counter still applies to loopback-originated queries.
        assert!(limiter.check_domain("example.com"));
        assert!(limiter.check_domain("example.com"));
        assert!(!limiter.check_domain("example.com"));
    }

    #[test]
    fn window_resets_after_elapsing() {
        let mut cfg = settings(true);
        cfg.client_max_queries = 2;
        cfg.client_window_secs = 1;
        let limiter = RateLimiter::new(&cfg);
        let client: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(limiter.check_client(client));
        assert!(limiter.check_client(client));
        assert!(!limiter.check_client(client));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.check_client(client));
    }

    #[test]
    fn settings_can_be_swapped() {
        let mut cfg = settings(true);
        cfg.client_max_queries = 10;
        let limiter = RateLimiter::new(&cfg);
        assert!(limiter.check_client("10.0.0.5".parse().unwrap()));

        let mut disabled = settings(true);
        disabled.enabled = false;
        limiter.set_settings(&disabled);
        for _ in 0..50 {
            assert!(limiter.check_client("10.0.0.5".parse().unwrap()));
        }
        assert!(!limiter.is_enabled());
    }

    #[test]
    fn sweep_bounds_the_map_size() {
        let mut cfg = settings(true);
        cfg.client_window_secs = 1;
        let limiter = RateLimiter::new(&cfg);

        // Fill past the size threshold with distinct spoofed clients.
        for i in 0..(SWEEP_AT_ENTRIES + 10) {
            limiter.check_client(format!("10.{}.{}.{}", (i >> 8) % 256, i % 256, (i >> 16) % 8).parse().unwrap());
        }
        assert!(limiter.client_buckets() > SWEEP_AT_ENTRIES);

        // Let every window elapse, then any check sweeps the whole map.
        std::thread::sleep(Duration::from_millis(1100));
        limiter.check_domain("example.com");
        assert_eq!(limiter.client_buckets(), 0);
    }
}
