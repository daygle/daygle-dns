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
//! - **Conditional forwarding**: queries inside a configured conditional zone
//!   are resolved by that zone's dedicated upstreams instead of the default
//!   ones (longest-suffix match wins).

mod upstream;

use std::sync::Arc;
use std::time::Duration;

use daygle_dns_core::config::{ConditionalZoneConfig, RecursiveSettings};
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::Metrics;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use tracing::{debug, info};

pub use upstream::parse_upstreams;

/// A thread-safe recursive resolver.
///
/// Queries are routed by name: the most specific configured conditional zone
/// (longest suffix match) is resolved by its dedicated upstreams, everything
/// else by the default upstreams.
pub struct RecursiveResolver {
    inner: TokioResolver,
    /// Conditional forwarding zones: `zone suffix` -> dedicated resolver.
    conditional: Vec<ConditionalResolver>,
    settings: RecursiveSettings,
    metrics: Arc<Metrics>,
}

/// One conditional forwarding zone: the zone's FQDN suffix (lowercased,
/// trailing dot stripped) and its own resolver.
struct ConditionalResolver {
    zone: String,
    resolver: TokioResolver,
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

        let mut conditional = Vec::with_capacity(settings.conditional_zones.len());
        for zone in &settings.conditional_zones {
            let zone_name = normalize_zone(&zone.name);
            let (zconfig, zopts) = build_zone_config(zone, settings)?;
            let resolver = TokioResolver::builder_with_config(
                zconfig,
                TokioRuntimeProvider::default(),
            )
            .with_options(zopts)
            .build()
            .map_err(|e| {
                DaygleError::Config(format!(
                    "cannot build conditional resolver for '{}': {e}",
                    zone.name
                ))
            })?;
            info!(
                zone = %zone_name,
                upstreams = zone.upstreams.len(),
                "conditional forwarding zone ready"
            );
            conditional.push(ConditionalResolver {
                zone: zone_name,
                resolver,
            });
        }

        info!(
            cache_size = settings.cache_size,
            attempts = settings.attempts,
            timeout_secs = settings.timeout_secs,
            dnssec = settings.dnssec_validate,
            conditional_zones = conditional.len(),
            "recursive resolver ready"
        );

        Ok(Self {
            inner,
            conditional,
            settings: settings.clone(),
            metrics,
        })
    }

    /// Resolve `name` for `record_type`, returning the full lookup.
    ///
    /// Queries inside a configured conditional zone are answered by that
    /// zone's dedicated resolver; everything else uses the default upstreams.
    pub async fn lookup(&self, name: &str, record_type: RecordType) -> Result<Lookup> {
        let name = Name::from_utf8(name).map_err(|e| DaygleError::Resolution {
            message: format!("invalid name '{name}': {e}"),
            response_code: None,
        })?;
        let matched = match_conditional_zones(&self.conditional, &name);
        let via_conditional = matched.is_some();
        let inner = matched
            .map(|idx| &self.conditional[idx].resolver)
            .unwrap_or(&self.inner);
        debug!(query = %name, rtype = ?record_type, conditional = via_conditional, "lookup routing");

        match inner.lookup(name, record_type).await {
            Ok(lookup) => {
                self.metrics.inc(&self.metrics.cache_misses);
                debug!(
                    query = %lookup.query().name(),
                    rtype = ?record_type,
                    conditional = via_conditional,
                    "resolved recursively"
                );
                Ok(lookup)
            }
            Err(e) => {
                self.metrics.inc(&self.metrics.errors);
                Err(DaygleError::Resolution {
                    message: e.to_string(),
                    // Negative answers (NXDOMAIN / no records of the type)
                    // carry their response code so the server can pass it
                    // through instead of SERVFAIL. Timeouts and transport
                    // errors have no code and stay SERVFAIL.
                    response_code: negative_response_code(&e),
                })
            }
        }
    }

    /// Flush the response cache.
    pub fn clear_cache(&self) {
        self.inner.clear_cache();
        for zone in &self.conditional {
            zone.resolver.clear_cache();
        }
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

    /// The configured conditional forwarding zones (for status/metrics).
    pub fn conditional_zones(&self) -> Vec<String> {
        self.conditional.iter().map(|c| c.zone.clone()).collect()
    }
}

/// Extract the DNS response code for a negative-answer error from Hickory's
/// resolver: NXDOMAIN/no-records become `NXDomain`, explicit upstream error
/// codes are passed through, and everything else (timeouts, transport
/// failures) has no code.
fn negative_response_code(e: &hickory_resolver::net::NetError) -> Option<u16> {
    match e {
        hickory_resolver::net::NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(
            _,
        )) => Some(hickory_proto::op::ResponseCode::NXDomain.into()),
        hickory_resolver::net::NetError::Dns(hickory_resolver::net::DnsError::ResponseCode(
            code,
        )) => Some((*code).into()),
        _ => None,
    }
}

/// Normalize a zone name for suffix matching: lowercase, trailing dot
/// stripped, no leading dot.
fn normalize_zone(name: &str) -> String {
    name.trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Pick the conditional zone whose normalized suffix matches the query name
/// (label-aligned). The most specific (deepest) match wins; returns the index
/// into `conditional`, or `None` to fall through to the default resolver.
fn match_conditional_zones(conditional: &[ConditionalResolver], name: &Name) -> Option<usize> {
    match_conditional_zones_by_name(
        conditional.iter().map(|c| c.zone.as_str()),
        name,
    )
}

/// Pure matching core: the index of the longest zone suffix that is a
/// label-aligned suffix of `name` (tested directly; see tests).
fn match_conditional_zones_by_name<'a, I>(zones: I, name: &Name) -> Option<usize>
where
    I: IntoIterator<Item = &'a str>,
{
    let qname = normalize_zone(&name.to_string());
    zones.into_iter()
        .enumerate()
        // An empty zone string is the root zone and matches every name.
        .filter(|(_, z)| z.is_empty() || qname == *z || qname.ends_with(&format!(".{}", z)))
        .max_by_key(|(_, z)| z.len())
        .map(|(idx, _)| idx)
}

/// Build a [`ResolverConfig`] + [`ResolverOpts`] for one conditional zone:
/// the zone's own upstreams with the global resolution options.
fn build_zone_config(
    zone: &ConditionalZoneConfig,
    settings: &RecursiveSettings,
) -> Result<(ResolverConfig, ResolverOpts)> {
    let name_servers = parse_upstreams(&zone.upstreams)?;
    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let opts = resolver_opts(settings);
    Ok((config, opts))
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

    Ok((config, resolver_opts(settings)))
}

/// Shared [`ResolverOpts`] for the default and conditional-zone resolvers.
fn resolver_opts(settings: &RecursiveSettings) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(settings.timeout_secs);
    opts.attempts = settings.attempts;
    opts.cache_size = settings.cache_size as u64;
    opts.validate = settings.dnssec_validate;
    opts.positive_min_ttl = Some(Duration::from_secs(settings.min_cache_ttl as u64));
    opts.negative_max_ttl = Some(Duration::from_secs(settings.negative_cache_ttl as u64));
    opts.preserve_intermediates = true;
    opts.try_tcp_on_error = true;
    opts
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

    #[test]
    fn normalize_zone_formats() {
        assert_eq!(normalize_zone("corp.internal."), "corp.internal");
        assert_eq!(normalize_zone(".CORP.Internal"), "corp.internal");
        assert_eq!(normalize_zone(" example.com "), "example.com");
    }

    #[test]
    fn matches_longest_conditional_suffix() {
        let zones = ["corp.internal", "internal", "example.com"];
        let q = |n: &str| Name::from_utf8(n).unwrap();
        let m = |name: &str| match_conditional_zones_by_name(zones.iter().copied(), &q(name));
        // Exact zone apex matches itself.
        assert_eq!(m("corp.internal."), Some(0));
        // Subdomains match the deepest enclosing zone.
        assert_eq!(m("www.corp.internal."), Some(0));
        assert_eq!(m("a.b.internal."), Some(1));
        // Case-insensitive.
        assert_eq!(m("WWW.CORP.INTERNAL."), Some(0));
        // No match falls through to the default resolver.
        assert_eq!(m("example.org."), None);
        // Label-aligned: "notcorp.internal" is not inside "corp.internal".
        assert_eq!(m("notcorp.internal."), Some(1));
        // The root zone matches everything.
        assert_eq!(
            match_conditional_zones_by_name(["".to_string()].iter().map(String::as_str), &q("anything.example.")),
            Some(0)
        );
    }
}
