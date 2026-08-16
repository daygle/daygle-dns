//! Lock-free runtime metrics shared between the dispatcher and the REST API.

use std::sync::atomic::{AtomicU64, Ordering};

/// Cheap, lock-free counters for the whole server process.
///
/// The dispatcher bumps these on the hot path (every query); the API reads
/// them without locking by loading with relaxed ordering.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total DNS requests received.
    pub total_queries: AtomicU64,
    /// Queries answered from the authoritative zone catalog.
    pub authoritative: AtomicU64,
    /// Queries answered by the recursive resolver.
    pub recursive: AtomicU64,
    /// Recursive answers served from cache.
    pub cache_hits: AtomicU64,
    /// Recursive answers that missed the cache.
    pub cache_misses: AtomicU64,
    /// Queries blocked or refused by the policy engine.
    pub blocked: AtomicU64,
    /// Queries rejected by the rate limiter.
    pub rate_limited: AtomicU64,
    /// Queries that resulted in an error.
    pub errors: AtomicU64,
    /// DNSSEC-validated answers (recursive path).
    pub dnssec_validated: AtomicU64,
    /// Total bytes of DNS requests received.
    pub bytes_in: AtomicU64,
    /// Total bytes of DNS responses sent.
    pub bytes_out: AtomicU64,
}

impl Metrics {
    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    pub fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Snapshot all counters into a JSON-friendly map.
    pub fn snapshot(&self) -> MetricSnapshot {
        MetricSnapshot {
            total_queries: self.get(&self.total_queries),
            authoritative: self.get(&self.authoritative),
            recursive: self.get(&self.recursive),
            cache_hits: self.get(&self.cache_hits),
            cache_misses: self.get(&self.cache_misses),
            blocked: self.get(&self.blocked),
            rate_limited: self.get(&self.rate_limited),
            errors: self.get(&self.errors),
            dnssec_validated: self.get(&self.dnssec_validated),
            bytes_in: self.get(&self.bytes_in),
            bytes_out: self.get(&self.bytes_out),
        }
    }
}

/// Serializable snapshot of [`Metrics`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricSnapshot {
    pub total_queries: u64,
    pub authoritative: u64,
    pub recursive: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub blocked: u64,
    pub rate_limited: u64,
    pub errors: u64,
    pub dnssec_validated: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_independent() {
        let m = Metrics::default();
        m.inc(&m.total_queries);
        m.inc(&m.total_queries);
        m.add(&m.bytes_in, 42);
        assert_eq!(m.get(&m.total_queries), 2);
        assert_eq!(m.get(&m.bytes_out), 0);
        assert_eq!(m.get(&m.bytes_in), 42);
        let snap = m.snapshot();
        assert_eq!(snap.total_queries, 2);
    }
}
