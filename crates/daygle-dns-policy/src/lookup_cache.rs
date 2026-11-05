//! A cache of slow lookups (RDAP registration dates, a network's type, an
//! address's origin network) that a query waits for.
//!
//! The first query for a key starts the lookup and waits for it, up to a
//! bound; queries for the same key meanwhile wait for that same lookup
//! instead of starting their own. The lookup runs as its own task, so one
//! that outlasts the wait still finishes and fills the cache for the next
//! query. Results are kept for the time the lookup gives.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

enum Entry<V> {
    /// A lookup is running; its sender is dropped when it finishes.
    Pending(watch::Receiver<()>),
    /// The result, until the instant given.
    Known(V, Instant),
}

/// Cached lookup results by key, at most `cap` of them.
pub struct LookupCache<K, V> {
    entries: Mutex<HashMap<K, Entry<V>>>,
    cap: usize,
}

impl<K, V> std::fmt::Debug for LookupCache<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupCache")
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl<K, V> LookupCache<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// An empty cache keeping at most `cap` keys; past it the expired ones
    /// are dropped, and all of them if none has expired.
    pub fn new(cap: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            cap,
        }
    }

    /// The cached value for `key`, or the result of `lookup` (which yields
    /// the value and how long to keep it), waited for at most `wait`.
    /// `None` only when the lookup is still running after `wait`.
    pub async fn get(
        self: &Arc<Self>,
        key: K,
        wait: Duration,
        lookup: impl Future<Output = (V, Duration)> + Send + 'static,
    ) -> Option<V> {
        let mut pending = {
            let now = Instant::now();
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            match entries.get(&key) {
                Some(Entry::Known(value, until)) if *until > now => return Some(value.clone()),
                Some(Entry::Pending(rx)) => rx.clone(),
                _ => {
                    if entries.len() >= self.cap {
                        entries.retain(|_, e| matches!(e, Entry::Known(_, until) if *until > now));
                        if entries.len() >= self.cap {
                            entries.clear();
                        }
                    }
                    let (tx, rx) = watch::channel(());
                    entries.insert(key.clone(), Entry::Pending(rx.clone()));
                    let this = Arc::clone(self);
                    let key = key.clone();
                    tokio::spawn(async move {
                        let (value, ttl) = lookup.await;
                        this.entries
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(key, Entry::Known(value, Instant::now() + ttl));
                        drop(tx);
                    });
                    rx
                }
            }
        };
        // `changed` returns an error once the sender is dropped: the lookup
        // has finished (or panicked).
        let _ = tokio::time::timeout(wait, pending.changed()).await;
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&key) {
            Some(Entry::Known(value, _)) => Some(value.clone()),
            _ => None,
        }
    }

    /// Record `value` for `key` for `ttl` (tests).
    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, Entry::Known(value, Instant::now() + ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn first_query_waits_and_concurrent_ones_share_the_lookup() {
        let cache = Arc::new(LookupCache::<&str, u32>::new(10));
        let calls = Arc::new(AtomicUsize::new(0));
        let lookup = |calls: Arc<AtomicUsize>| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            (7, Duration::from_secs(60))
        };
        let wait = Duration::from_secs(2);
        let (a, b) = tokio::join!(
            cache.get("k", wait, lookup(calls.clone())),
            cache.get("k", wait, lookup(calls.clone()))
        );
        assert_eq!((a, b), (Some(7), Some(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Cached now.
        assert_eq!(cache.get("k", wait, lookup(calls.clone())).await, Some(7));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_slow_lookup_times_out_but_still_fills_the_cache() {
        let cache = Arc::new(LookupCache::<&str, u32>::new(10));
        let slow = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            (9, Duration::from_secs(60))
        };
        assert_eq!(cache.get("k", Duration::from_millis(20), slow).await, None);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // A lookup that would never finish: the cached value answers.
        let never = std::future::pending::<(u32, Duration)>();
        assert_eq!(
            cache.get("k", Duration::from_millis(20), never).await,
            Some(9)
        );
    }
}
