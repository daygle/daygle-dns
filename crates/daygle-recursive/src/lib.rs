//! # daygle-recursive
//!
//! Recursive resolution built on [`hickory_resolver`] (the continuation of
//! trust-dns-resolver).
//!
//! [`RecursiveResolver`] wraps a `TokioResolver` and configures:
//!
//! - **Root → TLD → authoritative** iteration (performed internally by
//!   Hickory's resolver state machine, seeded from the configured upstreams or
//!   the system resolver configuration).
//! - **Positive caching** with a bounded LRU (`cache_size`).
//! - **Negative caching** of NXDOMAIN/NODATA answers, bounded by
//!   `negative_cache_ttl` (Hickory derives the per-zone value from the SOA
//!   record and clamps it to our configured bounds).
//! - **Retry logic** (`attempts` per nameserver) and **timeouts**
//!   (`timeout` per nameserver).
//! - **DNSSEC validation** via the `dnssec-ring` backend.

mod upstream;

use std::sync::Arc;
use std::time::Duration;

use daygle_core::config::RecursiveSettings;
use daygle_core::error::{DaygleError, Result};
use daygle_core::Metrics;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use tracing::{debug, info};

pub use upstream::parse_upstreams;

/// A thread-safe recursive resolver.
#[derive(Clone)]
pub struct RecursiveResolver {
    inner: TokioResolver,
    settings: RecursiveSettings,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for RecursiveResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecursiveResolver")
            .field("cache_size", &self.settings.cache_size)
            .field("attempts", &self.settings.attempts)
            .field("dnssec", &self.settings.dnssec_validate)
            .finish_non_exhaustive()
    }
}

impl RecursiveResolver {
    /// Build a resolver from settings.
    ///
    /// When `upstreams` is empty or `use_system_config` is set, the operating
    /// system's resolver configuration (`/etc/resolv.conf` on Unix) is used.
    pub fn build(settings: &RecursiveSettings, metrics: Arc<Metrics>) -> Result<Self> {
        let (config, opts) = build_config(settings)?;
        let inner = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| DaygleError::Config(format!("cannot build resolver: {e}")))?;

        info!(
            cache_size = settings.cache_size,
            attempts = settings.attempts,
            timeout_secs = settings.timeout_secs,
            dnssec = settings.dnssec_validate,
            "recursive resolver ready"
        );

        Ok(Self {
            inner,
            settings: settings.clone(),
            metrics,
        })
    }

    /// Resolve `name` for `record_type`, returning the full lookup.
    pub async fn lookup(&self, name: &str, record_type: RecordType) -> Result<Lookup> {
        let name = Name::from_utf8(name)
            .map_err(|e| DaygleError::Resolution(format!("invalid name '{name}': {e}")))?;
        match self.inner.lookup(name, record_type).await {
            Ok(lookup) => {
                self.metrics.inc(&self.metrics.recursive);
                self.metrics.inc(&self.metrics.cache_misses);
                debug!(query = %lookup.query().name(), rtype = ?record_type, "resolved recursively");
                Ok(lookup)
            }
            Err(e) => {
                self.metrics.inc(&self.metrics.errors);
                Err(DaygleError::Resolution(e.to_string()))
            }
        }
    }

    /// Flush the response cache.
    pub fn clear_cache(&self) {
        self.inner.clear_cache();
        info!("recursive resolver cache cleared");
    }

    /// The configured cache capacity.
    pub fn cache_size(&self) -> usize {
        self.settings.cache_size
    }

    pub fn dnssec_enabled(&self) -> bool {
        self.settings.dnssec_validate
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

/// Translate settings into a Hickory [`ResolverConfig`] + [`ResolverOpts`].
fn build_config(settings: &RecursiveSettings) -> Result<(ResolverConfig, ResolverOpts)> {
    let config = if settings.use_system_config || settings.upstreams.is_empty() {
        info!("using system resolver configuration (resolv.conf)");
        // `TokioResolver::builder` would load system config, but we need the
        // opts; instead read it here via hickory's system_conf helpers.
        let (cfg, _opts) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| DaygleError::Config(format!("cannot read system config: {e}")))?;
        cfg
    } else {
        let name_servers = parse_upstreams(&settings.upstreams)?;
        ResolverConfig::from_parts(None, vec![], name_servers)
    };

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(settings.timeout_secs);
    opts.attempts = settings.attempts;
    opts.cache_size = settings.cache_size as u64;
    opts.validate = settings.dnssec_validate;
    opts.positive_min_ttl = Some(Duration::from_secs(settings.min_cache_ttl as u64));
    opts.negative_max_ttl = Some(Duration::from_secs(settings.negative_cache_ttl as u64));
    opts.preserve_intermediates = true;
    opts.try_tcp_on_error = true;

    Ok((config, opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_upstreams() {
        let ns = parse_upstreams(&["8.8.8.8".to_string(), "1.1.1.1:5353".to_string()]).unwrap();
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].ip, "8.8.8.8".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(ns[1].ip, "1.1.1.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn parses_tls_upstream() {
        let ns = parse_upstreams(&["tls://1.1.1.1:853@cloudflare-dns.com".to_string()]).unwrap();
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].ip, "1.1.1.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn rejects_bad_upstream() {
        assert!(parse_upstreams(&["not an upstream".to_string()]).is_err());
    }
}
