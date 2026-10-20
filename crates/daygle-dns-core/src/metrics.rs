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
    /// Queries answered with a split-horizon synthetic response.
    pub split_horizon: AtomicU64,
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
    /// Resolver internals for the resolver dashboard.
    pub resolver: ResolverMetrics,
}

/// Upper bounds (milliseconds) of the resolution latency histogram buckets;
/// the last bucket is everything slower.
pub const LATENCY_BUCKETS_MS: [u64; 10] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500];

/// Counters describing how the resolver answered: which route each lookup
/// took, how it ended, how long it took, and which transports its outbound
/// connections used.
#[derive(Debug, Default)]
pub struct ResolverMetrics {
    /// Lookups resolved from the root servers (recursive mode).
    pub route_recursive: AtomicU64,
    /// Lookups sent to the default upstreams (forwarding mode).
    pub route_forwarding: AtomicU64,
    /// Lookups sent to a conditional forwarder.
    pub route_conditional: AtomicU64,
    /// Lookups sent to a stub zone's nameservers.
    pub route_stub: AtomicU64,
    /// Lookups routed by a client resolution policy.
    pub route_client_policy: AtomicU64,
    /// NXDOMAIN answered from the local root zone without a lookup.
    pub route_local_root: AtomicU64,
    pub rcode_noerror: AtomicU64,
    pub rcode_nodata: AtomicU64,
    pub rcode_nxdomain: AtomicU64,
    pub rcode_servfail: AtomicU64,
    pub rcode_refused: AtomicU64,
    pub rcode_other: AtomicU64,
    /// Lookups that failed without an answer (timeouts, unreachable servers).
    pub failures: AtomicU64,
    /// Stale answers served because the upstream failed.
    pub stale_served: AtomicU64,
    /// Negative answers replayed from the failure cache.
    pub failures_replayed: AtomicU64,
    /// Latency histogram, one counter per [`LATENCY_BUCKETS_MS`] bound plus
    /// an overflow bucket.
    pub latency: [AtomicU64; 11],
    /// Sum of all recorded latencies, in microseconds.
    pub latency_sum_us: AtomicU64,
    /// Outbound connections opened to nameservers and upstreams, by
    /// transport.
    pub conn_udp: AtomicU64,
    pub conn_tcp: AtomicU64,
    pub conn_tls: AtomicU64,
    pub conn_quic: AtomicU64,
}

impl ResolverMetrics {
    /// Record one lookup's duration.
    pub fn observe_latency(&self, elapsed: std::time::Duration) {
        let ms = elapsed.as_millis() as u64;
        let bucket = LATENCY_BUCKETS_MS
            .iter()
            .position(|&bound| ms < bound)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        self.latency[bucket].fetch_add(1, Ordering::Relaxed);
        self.latency_sum_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record how a lookup ended: its response code (`0` with `nodata` set
    /// for NODATA) or `None` for a failure without one.
    pub fn observe_outcome(&self, response_code: Option<u16>, nodata: bool) {
        let counter = match response_code {
            None => &self.failures,
            Some(0) if nodata => &self.rcode_nodata,
            Some(0) => &self.rcode_noerror,
            Some(2) => &self.rcode_servfail,
            Some(3) => &self.rcode_nxdomain,
            Some(5) => &self.rcode_refused,
            Some(_) => &self.rcode_other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ResolverSnapshot {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let latency: Vec<u64> = self.latency.iter().map(get).collect();
        let count: u64 = latency.iter().sum();
        ResolverSnapshot {
            routes: RouteCounts {
                recursive: get(&self.route_recursive),
                forwarding: get(&self.route_forwarding),
                conditional: get(&self.route_conditional),
                stub: get(&self.route_stub),
                client_policy: get(&self.route_client_policy),
                local_root: get(&self.route_local_root),
            },
            outcomes: OutcomeCounts {
                noerror: get(&self.rcode_noerror),
                nodata: get(&self.rcode_nodata),
                nxdomain: get(&self.rcode_nxdomain),
                servfail: get(&self.rcode_servfail),
                refused: get(&self.rcode_refused),
                other: get(&self.rcode_other),
                failures: get(&self.failures),
                stale_served: get(&self.stale_served),
                failures_replayed: get(&self.failures_replayed),
            },
            latency: LatencySnapshot {
                bounds_ms: LATENCY_BUCKETS_MS.to_vec(),
                p50_ms: percentile(&latency, 0.50),
                p90_ms: percentile(&latency, 0.90),
                p99_ms: percentile(&latency, 0.99),
                mean_ms: if count == 0 {
                    None
                } else {
                    Some(get(&self.latency_sum_us) as f64 / count as f64 / 1000.0)
                },
                counts: latency,
            },
            connections: ConnectionCounts {
                udp: get(&self.conn_udp),
                tcp: get(&self.conn_tcp),
                tls: get(&self.conn_tls),
                quic: get(&self.conn_quic),
            },
        }
    }
}

/// The upper bound (ms) of the bucket holding the `q` quantile, or `None`
/// with no samples (the overflow bucket reports the last bound).
fn percentile(counts: &[u64], q: f64) -> Option<u64> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (total as f64 * q).ceil().max(1.0) as u64;
    let mut seen = 0;
    for (i, count) in counts.iter().enumerate() {
        seen += count;
        if seen >= target {
            return Some(
                LATENCY_BUCKETS_MS
                    .get(i)
                    .copied()
                    .unwrap_or(LATENCY_BUCKETS_MS[LATENCY_BUCKETS_MS.len() - 1]),
            );
        }
    }
    None
}

/// Serializable snapshot of [`ResolverMetrics`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolverSnapshot {
    pub routes: RouteCounts,
    pub outcomes: OutcomeCounts,
    pub latency: LatencySnapshot,
    pub connections: ConnectionCounts,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteCounts {
    pub recursive: u64,
    pub forwarding: u64,
    pub conditional: u64,
    pub stub: u64,
    pub client_policy: u64,
    pub local_root: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OutcomeCounts {
    pub noerror: u64,
    pub nodata: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    pub refused: u64,
    pub other: u64,
    pub failures: u64,
    pub stale_served: u64,
    pub failures_replayed: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencySnapshot {
    /// Bucket upper bounds in ms; `counts` has one more (overflow) entry.
    pub bounds_ms: Vec<u64>,
    pub counts: Vec<u64>,
    pub p50_ms: Option<u64>,
    pub p90_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub mean_ms: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionCounts {
    pub udp: u64,
    pub tcp: u64,
    pub tls: u64,
    pub quic: u64,
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
            split_horizon: self.get(&self.split_horizon),
            rate_limited: self.get(&self.rate_limited),
            errors: self.get(&self.errors),
            dnssec_validated: self.get(&self.dnssec_validated),
            bytes_in: self.get(&self.bytes_in),
            bytes_out: self.get(&self.bytes_out),
        }
    }
}

/// A gauge to add to the Prometheus output (values the counters here do
/// not hold, such as uptime or the number of zones).
pub struct Gauge<'a> {
    pub name: &'a str,
    pub help: &'a str,
    pub value: f64,
}

impl Metrics {
    /// Every counter in the Prometheus text exposition format (0.0.4),
    /// followed by `gauges`. Names are prefixed `daygle_dns_`.
    pub fn render_prometheus(&self, gauges: &[Gauge<'_>]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(4096);
        let mut family = |out: &mut String, name: &str, kind: &str, help: &str| {
            let _ = writeln!(out, "# HELP daygle_dns_{name} {help}");
            let _ = writeln!(out, "# TYPE daygle_dns_{name} {kind}");
        };
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);

        family(
            &mut out,
            "queries_total",
            "counter",
            "DNS queries received.",
        );
        let _ = writeln!(out, "daygle_dns_queries_total {}", get(&self.total_queries));

        family(
            &mut out,
            "answers_total",
            "counter",
            "Queries by how they were answered.",
        );
        for (source, counter) in [
            ("authoritative", &self.authoritative),
            ("recursive", &self.recursive),
            ("split_horizon", &self.split_horizon),
            ("blocked", &self.blocked),
            ("rate_limited", &self.rate_limited),
            ("error", &self.errors),
        ] {
            let _ = writeln!(
                out,
                "daygle_dns_answers_total{{source=\"{source}\"}} {}",
                get(counter)
            );
        }

        family(
            &mut out,
            "cache_lookups_total",
            "counter",
            "Resolver cache lookups.",
        );
        let _ = writeln!(
            out,
            "daygle_dns_cache_lookups_total{{result=\"hit\"}} {}",
            get(&self.cache_hits)
        );
        let _ = writeln!(
            out,
            "daygle_dns_cache_lookups_total{{result=\"miss\"}} {}",
            get(&self.cache_misses)
        );

        family(
            &mut out,
            "dnssec_validated_total",
            "counter",
            "Recursive answers that passed DNSSEC validation.",
        );
        let _ = writeln!(
            out,
            "daygle_dns_dnssec_validated_total {}",
            get(&self.dnssec_validated)
        );

        family(&mut out, "bytes_total", "counter", "DNS message bytes.");
        let _ = writeln!(
            out,
            "daygle_dns_bytes_total{{direction=\"in\"}} {}",
            get(&self.bytes_in)
        );
        let _ = writeln!(
            out,
            "daygle_dns_bytes_total{{direction=\"out\"}} {}",
            get(&self.bytes_out)
        );

        let r = &self.resolver;
        family(
            &mut out,
            "resolver_routes_total",
            "counter",
            "Recursive lookups by the route that answered them.",
        );
        for (route, counter) in [
            ("recursive", &r.route_recursive),
            ("forwarding", &r.route_forwarding),
            ("conditional", &r.route_conditional),
            ("stub", &r.route_stub),
            ("client_policy", &r.route_client_policy),
            ("local_root", &r.route_local_root),
        ] {
            let _ = writeln!(
                out,
                "daygle_dns_resolver_routes_total{{route=\"{route}\"}} {}",
                get(counter)
            );
        }

        family(
            &mut out,
            "resolver_responses_total",
            "counter",
            "Recursive lookups by outcome.",
        );
        for (outcome, counter) in [
            ("noerror", &r.rcode_noerror),
            ("nodata", &r.rcode_nodata),
            ("nxdomain", &r.rcode_nxdomain),
            ("servfail", &r.rcode_servfail),
            ("refused", &r.rcode_refused),
            ("other", &r.rcode_other),
            ("failure", &r.failures),
        ] {
            let _ = writeln!(
                out,
                "daygle_dns_resolver_responses_total{{outcome=\"{outcome}\"}} {}",
                get(counter)
            );
        }

        family(
            &mut out,
            "resolver_stale_answers_total",
            "counter",
            "Expired answers served while upstreams were failing.",
        );
        let _ = writeln!(
            out,
            "daygle_dns_resolver_stale_answers_total {}",
            get(&r.stale_served)
        );
        family(
            &mut out,
            "resolver_cached_failures_total",
            "counter",
            "Failures answered from the failure cache.",
        );
        let _ = writeln!(
            out,
            "daygle_dns_resolver_cached_failures_total {}",
            get(&r.failures_replayed)
        );

        family(
            &mut out,
            "resolver_upstream_connections_total",
            "counter",
            "Connections opened to upstream servers, by transport.",
        );
        for (transport, counter) in [
            ("udp", &r.conn_udp),
            ("tcp", &r.conn_tcp),
            ("tls", &r.conn_tls),
            ("quic", &r.conn_quic),
        ] {
            let _ = writeln!(
                out,
                "daygle_dns_resolver_upstream_connections_total{{transport=\"{transport}\"}} {}",
                get(counter)
            );
        }

        family(
            &mut out,
            "resolver_lookup_duration_seconds",
            "histogram",
            "How long recursive lookups took.",
        );
        let mut cumulative = 0u64;
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += get(&r.latency[i]);
            let _ = writeln!(
                out,
                "daygle_dns_resolver_lookup_duration_seconds_bucket{{le=\"{}\"}} {cumulative}",
                *bound as f64 / 1000.0
            );
        }
        cumulative += get(&r.latency[LATENCY_BUCKETS_MS.len()]);
        let _ = writeln!(
            out,
            "daygle_dns_resolver_lookup_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}"
        );
        let _ = writeln!(
            out,
            "daygle_dns_resolver_lookup_duration_seconds_sum {}",
            get(&r.latency_sum_us) as f64 / 1_000_000.0
        );
        let _ = writeln!(
            out,
            "daygle_dns_resolver_lookup_duration_seconds_count {cumulative}"
        );

        for gauge in gauges {
            family(&mut out, gauge.name, "gauge", gauge.help);
            let _ = writeln!(out, "daygle_dns_{} {}", gauge.name, gauge.value);
        }
        out
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
    pub split_horizon: u64,
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

    #[test]
    fn prometheus_text_format() {
        let m = Metrics::default();
        m.inc(&m.total_queries);
        m.inc(&m.blocked);
        m.resolver
            .observe_latency(std::time::Duration::from_millis(3));
        m.resolver
            .observe_latency(std::time::Duration::from_secs(9));
        let text = m.render_prometheus(&[Gauge {
            name: "zones",
            help: "Zones served.",
            value: 4.0,
        }]);
        assert!(
            text.contains("# TYPE daygle_dns_queries_total counter\ndaygle_dns_queries_total 1\n")
        );
        assert!(text.contains("daygle_dns_answers_total{source=\"blocked\"} 1\n"));
        // Cumulative buckets in seconds, ending at +Inf with the count.
        assert!(
            text.contains("daygle_dns_resolver_lookup_duration_seconds_bucket{le=\"0.001\"} 0\n")
        );
        assert!(
            text.contains("daygle_dns_resolver_lookup_duration_seconds_bucket{le=\"0.005\"} 1\n")
        );
        assert!(
            text.contains("daygle_dns_resolver_lookup_duration_seconds_bucket{le=\"+Inf\"} 2\n")
        );
        assert!(text.contains("daygle_dns_resolver_lookup_duration_seconds_count 2\n"));
        assert!(text.contains("# TYPE daygle_dns_zones gauge\ndaygle_dns_zones 4\n"));
        // Every sample line is a name, optional labels and a number.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (series, value) = line.rsplit_once(' ').unwrap();
            assert!(series.starts_with("daygle_dns_"), "{line}");
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[test]
    fn latency_histogram_and_percentiles() {
        let m = ResolverMetrics::default();
        assert_eq!(m.snapshot().latency.p50_ms, None);
        for ms in [0, 0, 0, 3, 40, 40, 40, 40, 300, 9000] {
            m.observe_latency(std::time::Duration::from_millis(ms));
        }
        let snap = m.snapshot().latency;
        assert_eq!(snap.counts.len(), LATENCY_BUCKETS_MS.len() + 1);
        assert_eq!(snap.counts[0], 3); // < 1 ms
        assert_eq!(snap.counts[1], 1); // < 5 ms
        assert_eq!(snap.counts[4], 4); // < 50 ms
        assert_eq!(snap.counts[10], 1); // >= 2.5 s
        assert_eq!(snap.p50_ms, Some(50));
        assert_eq!(snap.p90_ms, Some(500));
        assert_eq!(snap.p99_ms, Some(2500));

        m.observe_outcome(Some(0), true);
        m.observe_outcome(Some(3), false);
        m.observe_outcome(None, false);
        let outcomes = m.snapshot().outcomes;
        assert_eq!(
            (outcomes.nodata, outcomes.nxdomain, outcomes.failures),
            (1, 1, 1)
        );
    }
}
