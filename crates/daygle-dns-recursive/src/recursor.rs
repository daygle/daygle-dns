//! Recursive mode: iterative resolution from the root servers (root -> TLD ->
//! authoritative), built on Hickory's recursor.
//!
//! The recursor speaks to authoritative servers directly, so it validates
//! DNSSEC itself (against the built-in root trust anchor), keeps its own
//! nameserver and response caches, and minimizes query names (RFC 9156).
//! Results are converted to [`Lookup`] so the rest of the crate (failure
//! cache, serve-stale, prefetch) treats both modes alike.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::config::{RecursiveSettings, PRIVATE_NETWORKS};
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::Metrics;
use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{
    ConnectionConfig, OpportunisticEncryption, OpportunisticEncryptionConfig, ProtocolConfig,
    ResolverOpts,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorError, RecursorOptions,
};
use hickory_resolver::{ConnectionProvider, PoolContext, TtlConfig};

/// The IANA root servers (a.root-servers.net .. m.root-servers.net), IPv4
/// and IPv6. The recursor primes the current list from these on start-up, so
/// a renumbered root server only needs one of the others to still answer.
pub const ROOT_HINTS: &[&str] = &[
    "198.41.0.4",
    "2001:503:ba3e::2:30",
    "170.247.170.2",
    "2801:1b8:10::b",
    "192.33.4.12",
    "2001:500:2::c",
    "199.7.91.13",
    "2001:500:2d::d",
    "192.203.230.10",
    "2001:500:a8::e",
    "192.5.5.241",
    "2001:500:2f::f",
    "192.112.36.4",
    "2001:500:12::d0d",
    "198.97.190.53",
    "2001:500:1::53",
    "192.36.148.17",
    "2001:7fe::53",
    "192.58.128.30",
    "2001:503:c27::2:30",
    "193.0.14.129",
    "2001:7fd::1",
    "199.7.83.42",
    "2001:500:9f::42",
    "202.12.27.33",
    "2001:dc3::35",
];

/// Connection provider for the recursor: Tokio sockets, sending root
/// queries to the local root zone responder when there is one, with an
/// optional port override so tests can stand up a fake root/TLD/authoritative
/// hierarchy on unprivileged ports.
#[derive(Clone, Default)]
pub struct RecursorConnections {
    runtime: TokioRuntimeProvider,
    local_root: Option<SocketAddr>,
    port_override: Option<u16>,
    /// Counts outbound connections by transport for the dashboard.
    metrics: Option<Arc<Metrics>>,
}

impl ConnectionProvider for RecursorConnections {
    type Conn = <TokioRuntimeProvider as ConnectionProvider>::Conn;
    type FutureConn = <TokioRuntimeProvider as ConnectionProvider>::FutureConn;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> std::result::Result<Self::FutureConn, NetError> {
        let encrypted = !matches!(config.protocol, ProtocolConfig::Udp | ProtocolConfig::Tcp);
        if encrypted && self.local_root.is_some_and(|root| root.ip() == ip) {
            // The local root responder only speaks plain DNS on loopback:
            // fail the opportunistic encryption probe right away.
            return Err(NetError::from(
                "the local root zone is served without encryption",
            ));
        }
        if let Some(metrics) = &self.metrics {
            let r = &metrics.resolver;
            metrics.inc(match config.protocol {
                ProtocolConfig::Udp => &r.conn_udp,
                ProtocolConfig::Tcp => &r.conn_tcp,
                ProtocolConfig::Quic { .. } => &r.conn_quic,
                _ => &r.conn_tls,
            });
        }
        let port = match self.local_root {
            // The responder listens on an unprivileged loopback port.
            Some(root) if root.ip() == ip => Some(root.port()),
            _ => self.port_override,
        };
        match port {
            Some(port) => {
                let mut config = config.clone();
                config.port = port;
                self.runtime.new_connection(ip, &config, cx)
            }
            None => self.runtime.new_connection(ip, config, cx),
        }
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

/// The recursor type used by recursive mode.
pub type DaygleRecursor = Recursor<RecursorConnections>;

/// Build a recursor from the recursive settings. With `local_root` (the
/// address of the local root zone responder, RFC 8806) every root query goes
/// there instead of to the root servers. Outbound connections are counted in
/// `metrics`.
pub fn build(
    settings: &RecursiveSettings,
    local_root: Option<SocketAddr>,
    metrics: Arc<Metrics>,
) -> Result<DaygleRecursor> {
    let hints: Vec<IpAddr> = if let Some(root) = local_root {
        vec![root.ip()]
    } else if settings.root_hints.is_empty() {
        ROOT_HINTS.iter().filter_map(|h| h.parse().ok()).collect()
    } else {
        settings
            .root_hints
            .iter()
            .map(|h| {
                h.trim()
                    .parse()
                    .map_err(|_| DaygleError::Config(format!("invalid root hint '{h}'")))
            })
            .collect::<Result<_>>()?
    };

    let mut options = RecursorOptions {
        // The recursor's own caches replace the forwarding resolver's.
        response_cache_size: settings.cache_size as u64,
        cache_policy: ttl_config(settings),
        case_randomization: settings.case_randomization,
        // Relaxed: some authoritative servers wrongly answer NXDOMAIN for
        // empty non-terminals, which strict RFC 8020 handling would turn into
        // false NXDOMAINs for the names below them.
        qname_minimization: QNameMinimization::Relaxed,
        opportunistic_encryption: if settings.opportunistic_encryption {
            // RFC 9539 defaults: remember a working encrypted transport for
            // 3 days and a failed probe for 1 day.
            OpportunisticEncryption::Enabled {
                config: OpportunisticEncryptionConfig::default(),
            }
        } else {
            OpportunisticEncryption::Disabled
        },
        ..RecursorOptions::default()
    };
    if settings.rebinding_protection {
        options.deny_answers = PRIVATE_NETWORKS
            .iter()
            .filter_map(|n| n.parse().ok())
            .collect();
    }
    let mut connections = RecursorConnections {
        local_root,
        metrics: Some(metrics),
        ..RecursorConnections::default()
    };
    if let Some(port) = settings.test_outbound_port {
        // Tests run the fake hierarchy on loopback, which the default
        // server filters (rightly) refuse to query.
        options.deny_server.clear();
        connections.port_override = Some(port);
    }

    let dnssec = if settings.dnssec_validate {
        // The default config carries no trust anchor, which selects the
        // built-in root key.
        DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default())
    } else {
        DnssecPolicy::SecurityUnaware
    };

    Recursor::new(&hints, dnssec, None, options, connections)
        .map_err(|e| DaygleError::Config(format!("cannot build recursive resolver: {e}")))
}

/// Resolve `name`/`record_type` iteratively and convert the answer to a
/// [`Lookup`]. NXDOMAIN, NODATA and upstream error codes come back as
/// [`DaygleError::Resolution`] with their response code (NODATA as
/// `NoError`), matching the forwarding path; transport failures carry no
/// code so serve-stale can cover them.
pub async fn lookup(
    recursor: &DaygleRecursor,
    name: Name,
    record_type: RecordType,
) -> Result<Lookup> {
    let mut name = name;
    name.set_fqdn(true);
    let query = Query::query(name, record_type);
    match recursor.resolve(query.clone(), Instant::now(), false).await {
        Ok(message) => match message.metadata.response_code {
            ResponseCode::NoError if !message.answers.is_empty() => {
                let ttl = message.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
                let mut lookup = Lookup::new_with_deadline(
                    query,
                    message.answers.iter().cloned(),
                    Instant::now() + Duration::from_secs(u64::from(ttl)),
                );
                lookup.extend_authorities(message.authorities.iter().cloned());
                lookup.extend_additionals(message.additionals.iter().cloned());
                Ok(lookup)
            }
            ResponseCode::NoError => Err(negative(ResponseCode::NoError, "no records")),
            code => Err(negative(code, "negative response")),
        },
        Err(e) => Err(DaygleError::Resolution {
            message: e.to_string(),
            response_code: recursor_error_code(&e),
        }),
    }
}

fn negative(code: ResponseCode, message: &str) -> DaygleError {
    DaygleError::Resolution {
        message: message.to_string(),
        response_code: Some(code.into()),
    }
}

/// The response code a recursor error stands for: NXDOMAIN, NODATA
/// (`NoError`) or none for transport/timeout/limit failures.
fn recursor_error_code(e: &RecursorError) -> Option<u16> {
    if e.is_nx_domain() {
        Some(ResponseCode::NXDomain.into())
    } else if e.is_no_records_found() {
        Some(ResponseCode::NoError.into())
    } else {
        None
    }
}

/// Map the cache TTL bounds onto the recursor's cache policy (the same
/// bounds the forwarding resolver applies).
fn ttl_config(settings: &RecursiveSettings) -> TtlConfig {
    let mut opts = ResolverOpts::default();
    opts.positive_min_ttl = Some(Duration::from_secs(u64::from(settings.min_cache_ttl)));
    opts.negative_max_ttl = Some(Duration::from_secs(u64::from(settings.negative_cache_ttl)));
    if settings.max_cache_ttl > 0 {
        opts.positive_max_ttl = Some(Duration::from_secs(u64::from(settings.max_cache_ttl)));
    }
    TtlConfig::from_opts(&opts)
}

/// A recursor and the local root responder it was built for.
pub struct RecursorSlot {
    pub recursor: Arc<DaygleRecursor>,
    pub local_root: Option<SocketAddr>,
}

/// A shared, rebuildable recursor: flushing the cache rebuilds it (the
/// recursor has no cache-clear call), and so does the local root zone
/// starting or stopping being served (the root hints are fixed at build).
pub type SharedRecursor = Arc<arc_swap::ArcSwap<RecursorSlot>>;
