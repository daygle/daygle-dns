//! Recursive mode: iterative resolution from the root servers (root -> TLD ->
//! authoritative), built on Hickory's recursor.
//!
//! The recursor speaks to authoritative servers directly, so it validates
//! DNSSEC itself (against the built-in root trust anchor), keeps its own
//! nameserver and response caches, and minimizes query names (RFC 9156).
//! Results are converted to [`Lookup`] so the rest of the crate (failure
//! cache, serve-stale, prefetch) treats both modes alike.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::config::{IpVersions, RecursiveSettings};
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::Metrics;
use futures_util::stream::{BoxStream, StreamExt};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::config::{
    ConnectionConfig, OpportunisticEncryption, OpportunisticEncryptionConfig, ProtocolConfig,
    ResolverOpts,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{DnsRequest, DnsResponse};
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorError, RecursorOptions,
};
use hickory_resolver::{ConnectionProvider, PoolContext, TtlConfig};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

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

/// Connection provider for every upstream query (the recursor and the
/// forwarding resolvers): Tokio sockets, with outbound connections counted by
/// transport and every request flagged for [`track_upstream`]. For the
/// recursor it also sends root queries to the local root zone responder when
/// there is one, with an optional port override so tests can stand up a fake
/// root/TLD/authoritative hierarchy on unprivileged ports.
#[derive(Clone, Default)]
pub struct UpstreamConnections {
    runtime: TokioRuntimeProvider,
    local_root: Option<SocketAddr>,
    port_override: Option<u16>,
    /// Counts outbound connections by transport for the dashboard.
    metrics: Option<Arc<Metrics>>,
    /// Add the EDNS Client Subnet option set by [`with_client_subnet`]
    /// (forwarding only: walking the hierarchy would hand the client's
    /// network to every root and TLD server).
    client_subnet: bool,
    /// Read a referral's glue as the answer to a query for it (see
    /// [`glue_as_answer`]). Recursive mode only.
    glue_answers: bool,
}

impl UpstreamConnections {
    /// The provider for a forwarding resolver (no local root, no test port).
    pub fn forwarding(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics: Some(metrics),
            client_subnet: true,
            ..Self::default()
        }
    }
}

tokio::task_local! {
    /// Set when the lookup running in this task sends a query upstream.
    static SENT_UPSTREAM: std::cell::Cell<bool>;
    /// The EDNS Client Subnet (RFC 7871) to send upstream for the lookup
    /// running in this task.
    static CLIENT_SUBNET: Option<EcsSubnet>;
}

/// The EDNS Client Subnet a lookup sends to forwarding upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcsSubnet {
    /// The network sent (host bits zero).
    pub net: IpNet,
    /// Whether it is the client's own network rather than one subnet sent
    /// for everyone. The answer is then for that network alone (RFC 7871
    /// section 7.3), so it is neither taken from nor kept in the caches
    /// other clients share.
    pub per_client: bool,
}

/// Run a lookup sending `subnet` upstream as its EDNS Client Subnet (to
/// forwarding upstreams).
pub async fn with_client_subnet<F: Future>(subnet: Option<EcsSubnet>, lookup: F) -> F::Output {
    CLIENT_SUBNET.scope(subnet, lookup).await
}

/// Whether the lookup running in this task sends the client's own network
/// (see [`EcsSubnet::per_client`]).
pub(crate) fn per_client_subnet() -> bool {
    CLIENT_SUBNET
        .try_with(|s| s.is_some_and(|s| s.per_client))
        .unwrap_or(false)
}

/// Run a lookup and report whether it sent any query upstream. A lookup
/// that did not was answered from a resolver cache.
pub async fn track_upstream<F: Future>(lookup: F) -> (F::Output, bool) {
    SENT_UPSTREAM
        .scope(std::cell::Cell::new(false), async {
            let output = lookup.await;
            (output, SENT_UPSTREAM.with(|sent| sent.get()))
        })
        .await
}

/// A connection handle that flags each request it sends (see
/// [`track_upstream`]).
#[derive(Clone)]
pub struct TrackedConn<C> {
    conn: C,
    client_subnet: bool,
    glue_answers: bool,
}

impl<C: DnsHandle> DnsHandle for TrackedConn<C> {
    type Response = BoxStream<'static, std::result::Result<DnsResponse, NetError>>;
    type Runtime = C::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        self.conn.is_verifying_dnssec()
    }

    fn is_using_edns(&self) -> bool {
        self.conn.is_using_edns()
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        // Outside a tracked lookup (prefetch refreshes, probes) there is
        // nothing to flag.
        let _ = SENT_UPSTREAM.try_with(|sent| sent.set(true));
        if self.client_subnet {
            if let Ok(Some(EcsSubnet { net: subnet, .. })) = CLIENT_SUBNET.try_with(|s| *s) {
                // Only on requests already using EDNS (not a retry without).
                if let Some(edns) = request.edns.as_mut() {
                    edns.options_mut()
                        .insert(EdnsOption::Subnet(ClientSubnet::new(
                            subnet.network(),
                            subnet.prefix_len(),
                            0,
                        )));
                }
            }
        }
        if !self.glue_answers {
            return self.conn.send(request).boxed();
        }
        let query = request.queries.first().cloned();
        self.conn
            .send(request)
            .map(move |response| match (response, &query) {
                (Ok(response), Some(query)) => Ok(glue_as_answer(query, response)),
                (response, _) => response,
            })
            .boxed()
    }
}

/// A referral that carries the address asked for as glue, turned into an
/// answer with that address.
///
/// The recursor asks a zone's parent for the address of a name server that
/// lies inside the zone when it has the zone's NS records without their
/// glue: after the zone's own NS answer (often sent without addresses)
/// replaced the parent's referral in its cache and the zone's name servers
/// were dropped from the name server cache. The parent replies with the
/// referral again, the address in the additional section, where the recursor
/// does not look - so the zone, and every zone served from it, failed with
/// "no glue found for any nameservers" until the cached answer expired.
fn glue_as_answer(query: &Query, response: DnsResponse) -> DnsResponse {
    let is_glue = |r: &Record| r.record_type() == query.query_type() && r.name == *query.name();
    let referral = matches!(query.query_type(), RecordType::A | RecordType::AAAA)
        && response.response_code == ResponseCode::NoError
        && !response.authoritative
        && response.answers.is_empty()
        && response
            .authorities
            .iter()
            .any(|r| r.record_type() == RecordType::NS && r.name.zone_of(query.name()))
        && response.additionals.iter().any(is_glue);
    if !referral {
        return response;
    }
    let mut message = response.clone().into_message();
    let (glue, rest) = std::mem::take(&mut message.additionals)
        .into_iter()
        .partition(is_glue);
    message.answers = glue;
    message.additionals = rest;
    DnsResponse::from_message(message).unwrap_or(response)
}

type TokioConn = <TokioRuntimeProvider as ConnectionProvider>::Conn;

impl ConnectionProvider for UpstreamConnections {
    type Conn = TrackedConn<TokioConn>;
    type FutureConn =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Conn, NetError>> + Send>>;
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
        let connecting = match port {
            Some(port) => {
                let mut config = config.clone();
                config.port = port;
                self.runtime.new_connection(ip, &config, cx)?
            }
            None => self.runtime.new_connection(ip, config, cx)?,
        };
        let client_subnet = self.client_subnet;
        let glue_answers = self.glue_answers;
        Ok(Box::pin(async move {
            connecting.await.map(|conn| TrackedConn {
                conn,
                client_subnet,
                glue_answers,
            })
        }))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

/// The recursor type used by recursive mode.
pub type DaygleRecursor = Recursor<UpstreamConnections>;

/// Build a recursor from the recursive settings. With `local_root` (the
/// address of the local root zone responder, RFC 8806) every root query goes
/// there instead of to the root servers. Outbound connections are counted in
/// `metrics`.
pub fn build(
    settings: &RecursiveSettings,
    local_root: Option<SocketAddr>,
    metrics: Arc<Metrics>,
) -> Result<DaygleRecursor> {
    let versions = settings.outbound_ip_versions;
    let hints: Vec<IpAddr> = if let Some(root) = local_root {
        // The local root responder is on this host, whatever the version.
        vec![root.ip()]
    } else if settings.root_hints.is_empty() {
        ROOT_HINTS
            .iter()
            .filter_map(|h| h.parse().ok())
            .filter(|ip| versions.allows(*ip))
            .collect()
    } else {
        let hints: Vec<IpAddr> = settings
            .root_hints
            .iter()
            .map(|h| {
                h.trim()
                    .parse()
                    .map_err(|_| DaygleError::Config(format!("invalid root hint '{h}'")))
            })
            .collect::<Result<_>>()?;
        let hints: Vec<IpAddr> = hints
            .into_iter()
            .filter(|ip| versions.allows(*ip))
            .collect();
        if hints.is_empty() {
            return Err(DaygleError::Config(format!(
                "no root hint is an {} address, the only IP version Outbound IP Versions allows",
                versions.label()
            )));
        }
        hints
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
    // Rebinding protection is applied by the dispatcher to every answer
    // (forwarded or recursive), so blocks are logged with their reason.
    let mut connections = UpstreamConnections {
        local_root,
        metrics: Some(metrics),
        glue_answers: true,
        ..UpstreamConnections::default()
    };
    if let Some(port) = settings.test_outbound_port {
        // Tests run the fake hierarchy on loopback, which the default
        // server filters (rightly) refuse to query.
        options.deny_server.clear();
        connections.port_override = Some(port);
    }
    // Never contact name servers of a version the resolver may not use.
    match versions {
        IpVersions::Both => {}
        IpVersions::Ipv4 => options.deny_server.push(IpNet::V6(Ipv6Net::default())),
        IpVersions::Ipv6 => options.deny_server.push(IpNet::V4(Ipv4Net::default())),
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

/// How many CNAMEs [`follow_cnames`] follows before giving up.
const MAX_CNAME_HOPS: usize = 16;

/// One query to the recursor, sorted by what the rest of the crate does
/// with it.
enum Resolved {
    /// Records for the question.
    Answer(Message),
    /// NXDOMAIN, NODATA or an upstream error code, with the SOA it came with.
    Negative(DaygleError, Option<Record>),
    /// A negative answer whose DNSSEC denial did not validate.
    Unproven(DaygleError),
    /// Transport failure, timeout or a resolution limit.
    Failed(DaygleError),
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
    let query = Query::query(name.clone(), record_type);
    match resolve_one(recursor, query.clone()).await {
        Resolved::Answer(message) => Ok(to_lookup(query, message.answers.clone(), &message)),
        Resolved::Negative(e, soa) => {
            crate::note_negative_soa(soa);
            Err(e)
        }
        // The recursor follows CNAMEs itself and, when the chain ends in a
        // negative answer, validates the last zone's denial (its SOA and
        // NSEC records) against the name that was asked. With the target in
        // another, signed zone that never matches, so "no such record" for a
        // name such as `www.shop.example -> shop.cdn.example` read as bogus
        // and became SERVFAIL. Following the chain one name at a time has
        // each denial validated against the name it is about.
        Resolved::Unproven(e)
            if !matches!(
                record_type,
                RecordType::CNAME | RecordType::ANY | RecordType::DS
            ) =>
        {
            follow_cnames(|q| resolve_one(recursor, q), name, record_type, e).await
        }
        Resolved::Unproven(e) | Resolved::Failed(e) => Err(e),
    }
}

async fn resolve_one(recursor: &DaygleRecursor, query: Query) -> Resolved {
    match recursor.resolve(query, Instant::now(), false).await {
        Ok(message) => match message.metadata.response_code {
            ResponseCode::NoError if !message.answers.is_empty() => Resolved::Answer(message),
            code => {
                let soa = message
                    .authorities
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .cloned();
                let e = if code == ResponseCode::NoError {
                    negative(ResponseCode::NoError, "no records")
                } else {
                    negative(code, "negative response")
                };
                Resolved::Negative(e, soa)
            }
        },
        // A negative answer the validator could neither prove nor disprove
        // (NSEC3 with more hash iterations than it will compute, RFC 9276):
        // an unsigned answer, not a failure.
        Err(RecursorError::Net(NetError::Dns(DnsError::Nsec {
            response, proof, ..
        }))) if proof.is_insecure() => {
            let soa = response
                .soa()
                .map(|soa| soa.to_owned().into_record_of_rdata());
            Resolved::Negative(negative(response.response_code, "unsigned denial"), soa)
        }
        Err(e) => {
            let error = DaygleError::Resolution {
                message: e.to_string(),
                response_code: recursor_error_code(&e),
            };
            if recursor_error_code(&e).is_some() {
                Resolved::Negative(error, recursor_error_soa(&e))
            } else if matches!(e, RecursorError::Net(NetError::Dns(DnsError::Nsec { .. }))) {
                Resolved::Unproven(error)
            } else {
                Resolved::Failed(error)
            }
        }
    }
}

/// Walk the CNAME chain from `name` one name at a time, asking for
/// `record_type` at each target, until one answers (positively or
/// negatively). Every step is a query of its own, so it is validated on its
/// own. `unproven` is the failure that led here: it stands when `name` is
/// not a CNAME after all, or the chain loops or runs too long.
async fn follow_cnames<F, Fut>(
    resolve: F,
    name: Name,
    record_type: RecordType,
    unproven: DaygleError,
) -> Result<Lookup>
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    let query = Query::query(name.clone(), record_type);
    let mut chain: Vec<Record> = Vec::new();
    let mut current = name;
    for _ in 0..MAX_CNAME_HOPS {
        let Resolved::Answer(message) =
            resolve(Query::query(current.clone(), RecordType::CNAME)).await
        else {
            return Err(unproven);
        };
        let Some((record, target)) = message.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(cname) if r.name == current => Some((r, cname.0.clone())),
            _ => None,
        }) else {
            return Err(unproven);
        };
        if target == query.name || chain.iter().any(|seen| seen.name == target) {
            return Err(unproven);
        }
        chain.push(record.clone());
        current = target;
        match resolve(Query::query(current.clone(), record_type)).await {
            Resolved::Answer(message) => {
                chain.extend(message.answers.iter().cloned());
                return Ok(to_lookup(query, chain, &message));
            }
            Resolved::Negative(e, soa) => {
                crate::note_negative_soa(soa);
                return Err(e);
            }
            // The target is itself a CNAME into yet another zone.
            Resolved::Unproven(_) => continue,
            Resolved::Failed(e) => return Err(e),
        }
    }
    Err(unproven)
}

/// A [`Lookup`] of `answers`, with the other sections of `message`.
fn to_lookup(query: Query, answers: Vec<Record>, message: &Message) -> Lookup {
    let ttl = answers.iter().map(|r| r.ttl).min().unwrap_or(0);
    let mut lookup = Lookup::new_with_deadline(
        query,
        answers,
        Instant::now() + Duration::from_secs(u64::from(ttl)),
    );
    lookup.extend_authorities(message.authorities.iter().cloned());
    lookup.extend_additionals(message.additionals.iter().cloned());
    lookup
}

fn negative(code: ResponseCode, message: &str) -> DaygleError {
    DaygleError::Resolution {
        message: message.to_string(),
        response_code: Some(code.into()),
    }
}

/// The SOA a negative recursor answer came with.
fn recursor_error_soa(e: &RecursorError) -> Option<hickory_proto::rr::Record> {
    match e {
        RecursorError::Negative(data) => data
            .soa
            .as_ref()
            .map(|soa| soa.as_ref().clone().into_record_of_rdata()),
        RecursorError::Net(net) => crate::negative_soa(net),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use std::net::Ipv4Addr;

    fn name(n: &str) -> Name {
        Name::from_ascii(n).unwrap()
    }

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    fn answer(records: Vec<Record>) -> Resolved {
        let mut message = Message::query();
        message.add_answers(records);
        Resolved::Answer(message)
    }

    fn failure(message: &str, code: Option<ResponseCode>) -> DaygleError {
        DaygleError::Resolution {
            message: message.to_string(),
            response_code: code.map(Into::into),
        }
    }

    /// `www.shop.test -> shop.host.test -> shop.cdn.test`, where a query
    /// through a CNAME into the next zone fails validation, as the
    /// recursor's own chain following does for a signed target zone.
    async fn zones(query: Query) -> Resolved {
        let owner = query.name().to_ascii();
        match (owner.as_str(), query.query_type()) {
            ("www.shop.test.", RecordType::CNAME) => {
                answer(vec![cname("www.shop.test.", "shop.host.test.")])
            }
            ("shop.host.test.", RecordType::CNAME) => {
                answer(vec![cname("shop.host.test.", "shop.cdn.test.")])
            }
            ("shop.host.test.", _) => Resolved::Unproven(failure("unproven", None)),
            ("shop.cdn.test.", RecordType::A) => answer(vec![Record::from_rdata(
                name("shop.cdn.test."),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
            )]),
            ("shop.cdn.test.", RecordType::HTTPS) => {
                Resolved::Negative(failure("no records", Some(ResponseCode::NoError)), None)
            }
            ("loop.test.", RecordType::CNAME) => answer(vec![cname("loop.test.", "pool.test.")]),
            ("pool.test.", RecordType::CNAME) => answer(vec![cname("pool.test.", "loop.test.")]),
            ("pool.test.", _) => Resolved::Unproven(failure("unproven", None)),
            ("down.test.", RecordType::CNAME) => answer(vec![cname("down.test.", "gone.test.")]),
            ("gone.test.", _) => Resolved::Failed(failure("timed out", None)),
            _ => Resolved::Negative(failure("no records", Some(ResponseCode::NoError)), None),
        }
    }

    fn code(result: Result<Lookup>) -> (String, Option<u16>) {
        match result {
            Err(DaygleError::Resolution {
                message,
                response_code,
            }) => (message, response_code),
            other => panic!("expected a resolution error, got {other:?}"),
        }
    }

    async fn follow(owner: &str, record_type: RecordType) -> Result<Lookup> {
        follow_cnames(zones, name(owner), record_type, failure("bogus", None)).await
    }

    #[tokio::test]
    async fn a_chain_ending_in_no_data_is_no_data() {
        let result = follow("www.shop.test.", RecordType::HTTPS).await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
    }

    #[tokio::test]
    async fn a_chain_ending_in_records_answers_with_the_chain_in_order() {
        let lookup = follow("www.shop.test.", RecordType::A).await.unwrap();
        let owners: Vec<String> = lookup.answers().iter().map(|r| r.name.to_ascii()).collect();
        assert_eq!(
            owners,
            ["www.shop.test.", "shop.host.test.", "shop.cdn.test."]
        );
    }

    #[tokio::test]
    async fn the_first_failure_stands_without_a_cname_to_follow() {
        let result = follow("shop.cdn.test.", RecordType::HTTPS).await;
        assert_eq!(code(result), ("bogus".to_string(), None));
    }

    #[tokio::test]
    async fn a_cname_loop_keeps_the_first_failure() {
        let result = follow("loop.test.", RecordType::A).await;
        assert_eq!(code(result), ("bogus".to_string(), None));
    }

    #[tokio::test]
    async fn a_failure_at_the_target_is_reported_as_it_is() {
        let result = follow("down.test.", RecordType::A).await;
        assert_eq!(code(result), ("timed out".to_string(), None));
    }
}
