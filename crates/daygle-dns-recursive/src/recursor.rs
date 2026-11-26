//! Recursive mode: iterative resolution from the root servers (root -> TLD ->
//! authoritative), built on Hickory's recursor.
//!
//! The recursor speaks to authoritative servers directly, so it validates
//! DNSSEC itself (against the built-in root trust anchor), keeps its own
//! nameserver and response caches, and minimizes query names (RFC 9156).
//! Results are converted to [`Lookup`] so the rest of the crate (failure
//! cache, serve-stale, prefetch) treats both modes alike.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::config::{IpVersions, RecursiveSettings, RECURSOR_MAX_TIMEOUT_SECS};
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::Metrics;
use futures_util::stream::{BoxStream, StreamExt};
use hickory_proto::dnssec::Proof;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::config::{
    ConnectionConfig, OpportunisticEncryption, OpportunisticEncryptionConfig, ProtocolConfig,
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
use parking_lot::Mutex;
use tracing::{debug, warn};

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
    /// Turn REFUSED and SERVFAIL from a name server into a failure to
    /// reach it, so the recursor asks the zone's next server (see
    /// [`lame_as_unreachable`]). Recursive mode only.
    skip_lame_servers: bool,
    /// NS questions name servers sent a broken reply to (see
    /// [`BrokenNsReplies`]). Recursive mode only.
    broken_ns: Option<Arc<BrokenNsReplies>>,
    /// How long one upstream query is waited for (`recursive.timeout_secs`).
    /// The recursor's own connections are built with a fixed 5s timeout, so
    /// the setting is applied here, on every reply stream, to make the
    /// lookup give up when it says it does.
    timeout: Option<Duration>,
}

/// How long a broken reply to an NS question is remembered.
const BROKEN_NS_TTL: Duration = Duration::from_secs(300);

/// The most broken NS replies remembered at once.
const MAX_BROKEN_NS: usize = 4096;

/// NS questions that a name server answered with a reply that could not be
/// read, each with the error it gave, so the question is not sent to that
/// server again for a while.
///
/// Walking down to a name, the recursor asks for the NS records of each
/// name on the way (QNAME minimisation) and moves on when a question fails,
/// but it caches nothing for a failure, so it asks again every time it
/// walks down to the name. The load balancer answering for `wip.accv.es`
/// sends a reply cut short to every NS question, and its non-authoritative
/// answers are not served from the recursor's cache without walking down to
/// the name again, so one lookup of `www.accv.es` asked it the same NS
/// question five times, at a quarter of a second each. Asked again, the
/// remembered error comes back at once and the recursor moves on as it did
/// the first time.
#[derive(Default)]
struct BrokenNsReplies {
    replies: Mutex<HashMap<(IpAddr, Name), (Instant, NetError)>>,
}

impl BrokenNsReplies {
    fn key(server: IpAddr, query: &Query) -> Option<(IpAddr, Name)> {
        (query.query_type() == RecordType::NS).then(|| (server, query.name().to_lowercase()))
    }

    /// The error `server` gave to `query`, when it is remembered.
    fn get(&self, server: IpAddr, query: &Query) -> Option<NetError> {
        let key = Self::key(server, query)?;
        let mut replies = self.replies.lock();
        match replies.get(&key) {
            Some((until, error)) if *until > Instant::now() => Some(error.clone()),
            Some(_) => {
                replies.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Remember `error` as `server`'s reply to `query`, when it is an NS
    /// question and the reply could not be read.
    fn note(&self, server: IpAddr, query: &Query, error: &NetError) {
        if !matches!(error, NetError::Proto(_)) {
            return;
        }
        let Some(key) = Self::key(server, query) else {
            return;
        };
        let now = Instant::now();
        let mut replies = self.replies.lock();
        if replies.len() >= MAX_BROKEN_NS {
            replies.retain(|_, (until, _)| *until > now);
            if replies.len() >= MAX_BROKEN_NS {
                replies.clear();
            }
        }
        replies.insert(key, (now + BROKEN_NS_TTL, error.clone()));
    }
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
    /// The queries the lookup running in this task sent upstream, for
    /// [`trace_queries`].
    static QUERY_TRACE: std::cell::RefCell<TraceLog>;
    /// Servers that did not answer a query during the lookup running in
    /// this task. The lookup asks such a server once: waiting on it again
    /// for its next question would spend a second full wait, and a lookup
    /// that walked the zone twice (the NS question for the name, then the
    /// answer itself) then ran past the pool's budget for the walk and
    /// failed even though the zone's other server was answering.
    static SILENT_SERVERS: std::cell::RefCell<std::collections::HashSet<IpAddr>>;
}

/// The most queries [`trace_queries`] records for one lookup.
const MAX_TRACE_STEPS: usize = 256;

/// One query sent upstream during a traced lookup.
#[derive(Debug, Clone)]
pub struct TraceStep {
    /// The name server (or forwarding upstream) asked.
    pub server: IpAddr,
    /// The name asked about.
    pub name: String,
    /// The record type asked for.
    pub record_type: String,
    /// The response code, when the server answered.
    pub rcode: Option<String>,
    /// What came back: an answer, a referral, a denial, or the error.
    pub outcome: String,
    /// How long the server took, or how long the query was waited for when
    /// no reply came.
    pub elapsed: Duration,
}

/// The outcome shown for a query that has been sent but not answered yet.
const AWAITING_REPLY: &str = "waiting for a reply";

/// The queries one traced lookup sent upstream, with when each was sent and
/// how long it was given to answer.
#[derive(Default)]
struct TraceLog {
    steps: Vec<TraceStep>,
    /// When each step's query was sent and the timeout it was sent with,
    /// alongside `steps`.
    sent: Vec<(Instant, Option<Duration>)>,
}

impl TraceLog {
    /// The trace as reported. A query that was never answered - the
    /// resolver's timeout elapsed, or the lookup ended while it was still
    /// out - is marked here, when the lookup is done, so its row stays in
    /// the list with no response code instead of reading as still waiting.
    fn finish(self) -> Vec<TraceStep> {
        let mut steps = self.steps;
        for (step, (sent, timeout)) in steps.iter_mut().zip(self.sent) {
            if step.outcome != AWAITING_REPLY {
                continue;
            }
            // How long the query was waited for: its own timeout at most,
            // whatever the rest of the lookup went on to do.
            let mut waited = sent.elapsed();
            if let Some(timeout) = timeout {
                waited = waited.min(timeout);
            }
            step.elapsed = waited;
            step.outcome = format!(
                "no reply after {:.1}s, the resolver gave up on it",
                waited.as_secs_f64()
            );
        }
        steps
    }
}

/// Run a lookup and report every query it sent upstream, in the order the
/// queries were sent. Queries answered from a cache are not sent, so they
/// do not appear. A query the resolver never got an answer to is listed
/// with no response code and how long it went unanswered.
pub async fn trace_queries<F: Future>(lookup: F) -> (F::Output, Vec<TraceStep>) {
    QUERY_TRACE
        .scope(std::cell::RefCell::new(TraceLog::default()), async {
            let output = lookup.await;
            let log = QUERY_TRACE.with(|log| std::mem::take(&mut *log.borrow_mut()));
            (output, log.finish())
        })
        .await
}

/// Record a query as sent for [`trace_queries`], and return its row so the
/// reply can fill it in with [`finish_trace`] (nothing outside a traced
/// lookup).
///
/// The row is written when the query leaves, not when it is answered: the
/// recursor resolves the addresses of a zone's glueless name servers before
/// it can ask them anything, and when one of those lookups hangs the
/// resolver's timeout leaves no reply to record. Written at send time, the
/// query stays in the list with no answer rather than vanishing; rows still
/// waiting when the trace is collected are marked there.
fn begin_trace(server: IpAddr, query: Option<&Query>, timeout: Option<Duration>) -> Option<usize> {
    QUERY_TRACE
        .try_with(|log| {
            let mut log = log.borrow_mut();
            if log.steps.len() >= MAX_TRACE_STEPS {
                return None;
            }
            log.steps.push(TraceStep {
                server,
                name: query.map(|q| q.name().to_string()).unwrap_or_default(),
                record_type: query
                    .map(|q| q.query_type().to_string())
                    .unwrap_or_default(),
                rcode: None,
                outcome: AWAITING_REPLY.to_string(),
                elapsed: Duration::ZERO,
            });
            log.sent.push((Instant::now(), timeout));
            Some(log.steps.len() - 1)
        })
        .ok()
        .flatten()
}

/// Fill in the row [`begin_trace`] wrote for a query with what came back.
fn finish_trace(
    slot: Option<usize>,
    response: &std::result::Result<DnsResponse, NetError>,
    elapsed: Duration,
) {
    let Some(slot) = slot else {
        return;
    };
    let _ = QUERY_TRACE.try_with(|log| {
        let mut log = log.borrow_mut();
        let Some(step) = log.steps.get_mut(slot) else {
            return;
        };
        let (rcode, outcome) = match response {
            Ok(response) => (
                Some(rcode_name(response.response_code)),
                describe_response(response),
            ),
            Err(e) => (None, e.to_string()),
        };
        step.rcode = rcode;
        step.outcome = outcome;
        step.elapsed = elapsed;
    });
}

/// A response code as it is written in DNS tools (`NXDOMAIN`, `REFUSED`).
pub fn rcode_name(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        ResponseCode::NotAuth => "NOTAUTH".into(),
        other => format!("{other:?}").to_ascii_uppercase(),
    }
}

/// What a name server's response says, in a few words.
fn describe_response(response: &DnsResponse) -> String {
    let truncated = if response.truncation {
        " (truncated, retrying over TCP)"
    } else {
        ""
    };
    if response.response_code != ResponseCode::NoError {
        let zone = response
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .map(|r| format!(" from zone {}", r.name))
            .unwrap_or_default();
        return format!("{}{zone}{truncated}", rcode_name(response.response_code));
    }
    if let Some(first) = response.answers.first() {
        let more = match response.answers.len() {
            1 => String::new(),
            n => format!(" (+{} more)", n - 1),
        };
        return format!(
            "answer: {} {}{more}{truncated}",
            first.record_type(),
            first.data
        );
    }
    let referral = response
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .collect::<Vec<_>>();
    if let (false, Some(first)) = (response.authoritative, referral.first()) {
        let servers = referral
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        return format!(
            "referral to {} ({}){truncated}",
            first.name,
            servers.join(", ")
        );
    }
    let zone = response
        .authorities
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .map(|r| format!(" in zone {}", r.name))
        .unwrap_or_default();
    format!("no records of this type{zone}{truncated}")
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
    server: IpAddr,
    client_subnet: bool,
    glue_answers: bool,
    skip_lame_servers: bool,
    broken_ns: Option<Arc<BrokenNsReplies>>,
    /// How long this connection's replies are waited for (see
    /// [`UpstreamConnections::timeout`]).
    timeout: Option<Duration>,
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
        if let (Some(broken), Some(query)) = (&self.broken_ns, request.queries.first()) {
            if let Some(error) = broken.get(self.server, query) {
                debug!(server = %self.server, query = %query.name(), "not asking again: the reply was broken");
                return futures_util::stream::once(async move { Err(error) }).boxed();
            }
        }
        if SILENT_SERVERS
            .try_with(|silent| silent.borrow().contains(&self.server))
            .unwrap_or(false)
        {
            debug!(server = %self.server, "not asking again: the server did not answer this lookup");
            return futures_util::stream::once(async move { Err(NetError::Timeout) }).boxed();
        }
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
        let traced = QUERY_TRACE.try_with(|_| ()).is_ok();
        if !traced && !self.glue_answers && !self.skip_lame_servers && self.broken_ns.is_none() {
            return self.conn.send(request).boxed();
        }
        let query = request.queries.first().cloned();
        let (server, glue_answers, skip_lame) =
            (self.server, self.glue_answers, self.skip_lame_servers);
        let broken_ns = self.broken_ns.clone();
        let timeout = self.timeout;
        let sent = Instant::now();
        let traced_query = query.clone();
        let slot = begin_trace(server, traced_query.as_ref(), timeout);
        let replies = self
            .conn
            .send(request)
            .map(move |response| {
                finish_trace(slot, &response, sent.elapsed());
                if let (Some(broken), Some(query), Err(error)) =
                    (&broken_ns, traced_query.as_ref(), &response)
                {
                    broken.note(server, query, error);
                }
                response
            })
            .map(move |response| match response {
                Ok(response) if skip_lame => lame_as_unreachable(server, response),
                response => response,
            })
            .map(move |response| match (response, &query) {
                (Ok(response), Some(query)) if glue_answers => Ok(glue_as_answer(query, response)),
                (response, _) => response,
            })
            .boxed();
        // The recursor builds its name server connections with a fixed 5s
        // timeout, so the wait is enforced here. A server that does not
        // answer is reported as unreachable, as a lame reply already is, and
        // is remembered as silent for the rest of this lookup: a stream that
        // merely ends leaves the pool nothing to act on, and the walk asks
        // the zone's servers again for the name, so a dead one would cost a
        // second full wait (see [`unreachable_after`]).
        match timeout {
            Some(timeout) => unreachable_after(replies, server, timeout),
            None => replies,
        }
    }
}

/// `replies`, with a server that stops answering reported as unreachable.
///
/// The recursor's name server pool asks a zone's servers in turn and moves
/// on only when one cannot be reached; a reply stream that merely ends
/// leaves the query unanswered, and the lookup fails at the first server of
/// a delegation that no longer answers however well the rest of the zone
/// does. `update.videolan.org` was SERVFAIL for that reason: the `org`
/// delegation still publishes the address of a decommissioned
/// `ns2.videolan.org`, while `ns1` answered the name in milliseconds.
fn unreachable_after(
    mut replies: BoxStream<'static, std::result::Result<DnsResponse, NetError>>,
    server: IpAddr,
    timeout: Duration,
) -> BoxStream<'static, std::result::Result<DnsResponse, NetError>> {
    let mut sleep = Box::pin(tokio::time::sleep(timeout));
    let mut done = false;
    let mut reported = false;
    futures_util::stream::poll_fn(move |cx| {
        if done {
            return std::task::Poll::Ready(None);
        }
        if reported {
            // The timeout was reported; the stream is over.
            done = true;
            return std::task::Poll::Ready(None);
        }
        match replies.poll_next_unpin(cx) {
            std::task::Poll::Ready(Some(reply)) => std::task::Poll::Ready(Some(reply)),
            std::task::Poll::Ready(None) => {
                done = true;
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => {
                if sleep.as_mut().poll(cx).is_ready() {
                    reported = true;
                    let _ = SILENT_SERVERS.try_with(|silent| silent.borrow_mut().insert(server));
                    debug!(%server, ?timeout, "no reply, trying the zone's next server");
                    std::task::Poll::Ready(Some(Err(NetError::from(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("name server {server} did not answer within {timeout:?}"),
                    )))))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    })
    .boxed()
}

/// A REFUSED or SERVFAIL answer from a name server, as a failure to reach
/// that server.
///
/// The recursor's name server pool moves on to a zone's next server only
/// when one cannot be reached; any other error ends the lookup. One lame
/// server in a zone's NS set (one that refuses queries for it, or fails
/// them) then failed every name it was asked about first - "Query Refused"
/// for `tapi.telstra.com`, which the zone's other servers answer. Read as
/// unreachable, it is skipped, ranked down for later queries, and the
/// lookup still fails when every server answers that way.
fn lame_as_unreachable(
    server: IpAddr,
    response: DnsResponse,
) -> std::result::Result<DnsResponse, NetError> {
    let code = response.response_code;
    if !matches!(code, ResponseCode::Refused | ResponseCode::ServFail) {
        return Ok(response);
    }
    debug!(%server, ?code, "name server failed the query, trying the zone's next server");
    Err(NetError::from(std::io::Error::other(format!(
        "name server {server} answered {code}"
    ))))
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
        let skip_lame_servers = self.skip_lame_servers;
        let broken_ns = self.broken_ns.clone();
        let timeout = self.timeout;
        Ok(Box::pin(async move {
            connecting.await.map(|conn| TrackedConn {
                conn,
                server: ip,
                client_subnet,
                glue_answers,
                skip_lame_servers,
                broken_ns,
                timeout,
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
        // The recursor spends one step of this limit on each label it adds
        // while looking for the zone cut above a name, and relaxed
        // minimisation (above) keeps adding them past NXDOMAIN. The default
        // of 24 is fewer labels than an IPv6 reverse name has (34), so every
        // PTR lookup under a short delegation such as `8.1.0.0.2.ip6.arpa`
        // (Telstra's 2001:8000::/20) failed with "maximum recursion limit
        // exceeded". The per-request query budget still bounds the work.
        ns_recursion_limit: RECURSION_LIMIT,
        // The same depth counter carries on through each CNAME in a chain:
        // every hop adds the labels walked to find its zone, then the
        // chain is checked against this limit. At the default of 24, a
        // chain of a few deep names (`global.cainiao.com` through Alibaba's
        // GDS, with names of ten labels) failed with "maximum recursion
        // limit exceeded" though it was only four CNAMEs long. The CNAME
        // and per-request query budgets still bound the work.
        recursion_limit: RECURSION_LIMIT,
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
        skip_lame_servers: true,
        broken_ns: Some(Arc::default()),
        // The recursor's own name server connections are built with a fixed
        // 5s timeout whatever the settings say, so the wait is applied to
        // each reply stream instead (see [`TrackedConn::send`]), short enough
        // that the zone's next servers are asked inside the pool's budget for
        // the walk and inside the client's answer (see [`per_server_wait`]).
        // Validation refuses a setting above what the recursor can wait, and
        // stored settings are clamped to it; the clamp here guards settings
        // built in code from claiming a wait the recursor cannot give.
        timeout: Some(per_server_wait(settings)),
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

/// The time the recursor's name server pool gives one query's walk to a
/// zone's servers (Hickory's `ResolverOpts::timeout` default, which the
/// recursor sets for itself and does not expose). The pool asks the servers
/// one at a time within it, and a server that never answers waits out
/// everything it is given: given the whole budget, the zone's second server
/// was never asked and a name it serves failed with SERVFAIL (a delegation
/// listed with a dead server first, `tracker.openbittorrent.com` among
/// them). One server is therefore given at most a third of it: a zone can
/// list two dead servers before a working one, as `yoyo.org` does from the
/// `.org` parent (its glue points at two hosts that no longer answer, with
/// the working one listed third), and reaching only two of its three
/// servers leaves the lookup failing exactly as before.
const POOL_BUDGET: Duration = Duration::from_secs(5);

/// How many of a zone's name servers one walk should reach within
/// [`POOL_BUDGET`] (see [`POOL_BUDGET`] for why more than two).
const SERVERS_TRIED: u32 = 3;

/// How long one name server is waited for before the zone's next one is
/// tried.
///
/// Two limits apply. One server may have no more than its share of the
/// pool's budget for the walk ([`POOL_BUDGET`] over [`SERVERS_TRIED`]), or
/// a zone whose dead servers are listed first never reaches the working one.
/// Half the client's answer budget (`server.client_timeout_ms`, 8s by
/// default) is the other limit: with a short Client Timeout it is the smaller
/// of the two, so the retry to the zone's next server happens inside the
/// client's wait, not after `recursive.timeout_secs`. `update.videolan.org`
/// failed exactly so: the wait outlasted the client's answer while `ns1`
/// replied at once. Settings built without a client budget (the recursor's
/// unit tests) keep the share of the pool's budget.
fn per_server_wait(settings: &RecursiveSettings) -> Duration {
    let configured = Duration::from_secs(settings.timeout_secs.clamp(1, RECURSOR_MAX_TIMEOUT_SECS))
        .min(POOL_BUDGET / SERVERS_TRIED);
    match settings.client_timeout_ms {
        0 => configured,
        budget => configured.min(Duration::from_millis((budget / 2).max(1))),
    }
}

/// How deep the recursor may go for one client query. The recursor counts
/// one step for each label it walks looking for a zone's name servers, and
/// keeps counting through each CNAME of a chain, so this needs room for the
/// 34 labels of an IPv6 reverse name and for a chain of several deep names,
/// with name servers' addresses resolved on the way. The recursor's own
/// budgets (200 queries and 64 CNAMEs per request) bound the work.
const RECURSION_LIMIT: u8 = 128;

/// How many CNAMEs [`follow_cnames`] follows before giving up.
const MAX_CNAME_HOPS: usize = 16;

/// The negative answer behind an unproven denial: NXDOMAIN or NODATA, and
/// the SOA of the zone that gave it. A denial without an SOA (some load
/// balancers send none) is kept only when it is about the name asked, not
/// the end of a CNAME chain from it.
struct Denial {
    error: DaygleError,
    soa: Option<Record>,
}

/// One query to the recursor, sorted by what the rest of the crate does
/// with it.
enum Resolved {
    /// Records for the question.
    Answer(Message),
    /// NXDOMAIN, NODATA or an upstream error code, with the SOA it came with.
    Negative(DaygleError, Option<Record>),
    /// A negative answer whose DNSSEC denial did not validate, with the
    /// plain negative answer it stands for (see [`Denial`]).
    Unproven(DaygleError, Option<Denial>),
    /// Transport failure, timeout or a resolution limit.
    Failed(DaygleError),
}

/// Resolve `name`/`record_type` iteratively and convert the answer to a
/// [`Lookup`]. NXDOMAIN, NODATA and upstream error codes come back as
/// [`DaygleError::Resolution`] with their response code (NODATA as
/// `NoError`), matching the forwarding path; transport failures carry no
/// code so serve-stale can cover them.
pub async fn lookup(slot: &RecursorSlot, name: Name, record_type: RecordType) -> Result<Lookup> {
    // A silent name server is asked once per lookup, not once per question
    // it is asked (see [`SILENT_SERVERS`]).
    SILENT_SERVERS
        .scope(
            Default::default(),
            lookup_asking_once(slot, name, record_type),
        )
        .await
}

/// The body of [`lookup`], inside the scope of its per-lookup memories.
async fn lookup_asking_once(
    slot: &RecursorSlot,
    name: Name,
    record_type: RecordType,
) -> Result<Lookup> {
    let mut name = name;
    name.set_fqdn(true);
    let query = Query::query(name.clone(), record_type);
    // RFC 8198: a validated NSEC already in the cache can prove the answer
    // without a query leaving the server.
    if let Some(aggressive) = slot.aggressive.as_deref() {
        if let Some(proved) = aggressive.synthesize(&query) {
            crate::note_negative_proofs(proved.proofs.clone());
            crate::note_negative_soa(Some(proved.soa));
            crate::note_aggressive_synthesis();
            debug!(
                query = %query.name(),
                rtype = ?record_type,
                code = ?proved.code,
                "negative answer synthesized from cached NSEC proofs"
            );
            return Err(negative(proved.code, "proved by a cached NSEC record"));
        }
    }
    let recursor = slot.recursor.as_ref();
    let aggressive = slot.aggressive.as_deref();
    let resolve = |q| resolve_one(recursor, aggressive, q);
    match resolve(query.clone()).await {
        Resolved::Answer(message) => {
            let mut answers = message.answers.clone();
            clear_false_bogus(&resolve, &mut answers).await;
            Ok(to_lookup(query, answers, &message))
        }
        Resolved::Negative(e, soa) => {
            crate::note_negative_soa(soa);
            Err(e)
        }
        Resolved::Unproven(e, denial) => {
            settle_unproven(&resolve, name, record_type, e, denial).await
        }
        Resolved::Failed(e) => Err(e),
    }
}

/// Answer a query whose negative answer the validator could not prove.
async fn settle_unproven<F, Fut>(
    resolve: &F,
    name: Name,
    record_type: RecordType,
    unproven: DaygleError,
    denial: Option<Denial>,
) -> Result<Lookup>
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    // A denial from a zone the validator proves unsigned has nothing to be
    // proven against: it is a plain negative answer. This is the negative
    // side of `clear_false_bogus`: "no HTTPS record" for
    // `cm.g.doubleclick.net`, in a zone delegated from its parent on the
    // same servers, read as unproven and became SERVFAIL.
    if let Some(Denial { error, soa }) = insecure_denial(resolve, &name, denial).await {
        crate::note_negative_soa(soa);
        return Err(error);
    }
    // The recursor follows CNAMEs itself and, when the chain ends in a
    // negative answer, validates the last zone's denial (its SOA and NSEC
    // records) against the name that was asked. With the target in another,
    // signed zone that never matches, so "no such record" for a name such
    // as `www.shop.example -> shop.cdn.example` read as bogus and became
    // SERVFAIL. Following the chain one name at a time has each denial
    // validated against the name it is about.
    if matches!(
        record_type,
        RecordType::CNAME | RecordType::ANY | RecordType::DS
    ) {
        return Err(unproven);
    }
    follow_cnames(resolve, name, record_type, unproven).await
}

/// `denial`, when it is about `name` and comes from a zone the validator
/// proves unsigned. A denial whose SOA does not enclose `name` (the end of
/// a CNAME chain into another zone) is left to [`follow_cnames`], so a
/// signed zone's denial is never excused by an unsigned zone in front.
///
/// A denial without an SOA is about `name` itself (see [`resolve_one`]),
/// and stands when `name` lies under a zone proven unsigned: nothing below
/// one can be signed. The load balancer serving `wip.accv.es` sends its
/// "no AAAA records" without an SOA, which the validator cannot prove, so
/// `www.accv.es AAAA` was SERVFAIL though `accv.es` is unsigned.
///
/// Both checks above ask the zone's own servers (the validator finds the
/// zone cut and asks them for their NS records, and [`in_unsigned_zone`]
/// asks them for the zone's SOA), so a zone whose servers answer nothing
/// this resolver can read is never proved insecure that way. Its parent is
/// asked instead: see [`has_no_ds`].
async fn insecure_denial<F, Fut>(resolve: &F, name: &Name, denial: Option<Denial>) -> Option<Denial>
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    let denial = denial?;
    let zone = match &denial.soa {
        Some(soa) if !soa.name.zone_of(name) => return None,
        Some(soa) => soa.name.clone(),
        None => name.clone(),
    };
    if in_unsigned_zone(resolve, &zone).await {
        return Some(denial);
    }
    // The zone's servers may be unreadable, but its parent has the last word
    // on whether it is signed: a zone with no DS record is unsigned.
    if denial.soa.is_some() && has_no_ds(resolve, &zone).await {
        return Some(denial);
    }
    None
}

async fn resolve_one(
    recursor: &DaygleRecursor,
    aggressive: Option<&crate::aggressive::AggressiveNsec>,
    query: Query,
) -> Resolved {
    match recursor.resolve(query, Instant::now(), false).await {
        Ok(message) => match message.metadata.response_code {
            ResponseCode::NoError if !message.answers.is_empty() => Resolved::Answer(message),
            code => {
                let soa = message
                    .authorities
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .cloned();
                if let (Some(cache), Some(soa)) = (aggressive, &soa) {
                    cache.insert(soa, &message.authorities);
                }
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
            if let Some(cache) = aggressive {
                harvest(cache, &e);
            }
            let error = DaygleError::Resolution {
                message: e.to_string(),
                response_code: recursor_error_code(&e),
            };
            if recursor_error_code(&e).is_some() {
                Resolved::Negative(error, recursor_error_soa(&e))
            } else if let RecursorError::Net(NetError::Dns(DnsError::Nsec { response, .. })) = &e {
                let code = response.response_code;
                let soa = response
                    .soa()
                    .map(|soa| soa.to_owned().into_record_of_rdata());
                // Without an SOA nothing says which zone denied the name, so
                // the denial is kept only when no CNAME led elsewhere.
                let about_query = soa.is_some()
                    || !response
                        .answers
                        .iter()
                        .any(|r| r.record_type() == RecordType::CNAME);
                let denial = (matches!(code, ResponseCode::NoError | ResponseCode::NXDomain)
                    && about_query)
                    .then(|| Denial {
                        error: negative(code, "negative response from an unsigned zone"),
                        soa,
                    });
                Resolved::Unproven(error, denial)
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
                clear_false_bogus(&resolve, &mut chain).await;
                return Ok(to_lookup(query, chain, &message));
            }
            Resolved::Negative(e, soa) => {
                crate::note_negative_soa(soa);
                return Err(e);
            }
            Resolved::Unproven(_, denial) => {
                if let Some(Denial { error, soa }) =
                    insecure_denial(&resolve, &current, denial).await
                {
                    crate::note_negative_soa(soa);
                    return Err(error);
                }
                // The target is itself a CNAME into yet another zone, or
                // its denial is unproven: carry on down the chain.
                continue;
            }
            Resolved::Failed(e) => return Err(e),
        }
    }
    Err(unproven)
}

/// Take the bogus mark off answer records that lie in a zone the validator
/// itself proves unsigned.
///
/// To tell an unsigned zone from one stripped of its signatures the
/// validator asks the zone's parent for its DS record. Servers that hold
/// both a zone and a zone delegated from it (`google.com` and
/// `l.google.com`, say) answer that from the delegated zone, with its own
/// SOA, which sends the validator round in a circle: it gives up and marks
/// everything in the delegated zone bogus. With bogus answers refused, that
/// took out every name there.
///
/// A zone under an unsigned zone has no chain of trust to be bogus against.
/// So for each bogus owner name the SOA of every enclosing name is asked
/// for, from the top down, and the mark comes off when the validator proves
/// one of them insecure. A name under a signed zone finds none and stays
/// bogus, forged SOA answers included: those are bogus themselves.
async fn clear_false_bogus<F, Fut>(resolve: &F, answers: &mut [Record])
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    let mut unsigned: Vec<(Name, bool)> = Vec::new();
    for record in answers.iter_mut() {
        if record.proof != Proof::Bogus {
            continue;
        }
        let known = unsigned.iter().find(|(name, _)| *name == record.name);
        let clear = match known {
            Some((_, clear)) => *clear,
            None => {
                let clear = in_unsigned_zone(resolve, &record.name).await;
                unsigned.push((record.name.clone(), clear));
                clear
            }
        };
        if clear {
            record.proof = Proof::Insecure;
        }
    }
}

/// Whether `owner` is at or under a zone whose SOA the validator marks
/// insecure (provably unsigned).
async fn in_unsigned_zone<F, Fut>(resolve: &F, owner: &Name) -> bool
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    for labels in 1..=owner.num_labels() {
        let apex = owner.trim_to(usize::from(labels));
        let Resolved::Answer(message) = resolve(Query::query(apex.clone(), RecordType::SOA)).await
        else {
            continue;
        };
        let insecure = message.answers.iter().any(|r| {
            r.record_type() == RecordType::SOA && r.name == apex && r.proof == Proof::Insecure
        });
        if insecure {
            return true;
        }
    }
    false
}

/// Whether the zone's parent answers that the zone has no DS record, which
/// proves the zone unsigned (RFC 4035 section 5.2) without asking the zone's
/// own servers anything.
///
/// The validator finds the zone cut by asking the zone's servers for their NS
/// records, and [`in_unsigned_zone`] asks them for the zone's SOA. A zone
/// whose servers answer with something this resolver cannot read defeats
/// both: `ptsecurity.com`'s servers answer FORMERR to every query carrying
/// EDNS, so no reply from them decodes, and `rules.ptsecurity.com AAAA` (a
/// name in an unsigned zone with no AAAA records) was SERVFAIL in 90 ms
/// although the `com` NSEC3 proves the zone has no DS. The DS record lives at
/// the parent, which answers it.
///
/// `zone` is the owner of the SOA that denied the name, so it is a zone apex
/// - only one has an SOA - and only a NODATA answer counts: the name exists
/// and has no DS. NXDOMAIN says nothing about a zone that does not exist at
/// the parent, and a failure proves nothing at all.
async fn has_no_ds<F, Fut>(resolve: &F, zone: &Name) -> bool
where
    F: Fn(Query) -> Fut,
    Fut: Future<Output = Resolved>,
{
    let Resolved::Negative(error, soa) = resolve(Query::query(zone.clone(), RecordType::DS)).await
    else {
        return false;
    };
    if !matches!(
        &error,
        DaygleError::Resolution { response_code, .. }
            if *response_code == Some(ResponseCode::NoError.into())
    ) {
        return false;
    }
    // The SOA must name an enclosing zone, not the zone itself: a server that
    // answers the DS question for its own zone sends the validator round in a
    // circle (see [`clear_false_bogus`]) and proves nothing.
    soa.as_ref()
        .is_some_and(|soa| soa.name != *zone && soa.name.zone_of(zone))
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

/// Keep the validated NSEC records of a negative recursor answer
/// (RFC 8198), so later queries they cover are answered from the cache.
fn harvest(cache: &crate::aggressive::AggressiveNsec, e: &RecursorError) {
    let RecursorError::Net(NetError::Dns(DnsError::NoRecordsFound(no_records))) = e else {
        return;
    };
    let Some(soa) = no_records
        .soa
        .as_ref()
        .map(|soa| soa.as_ref().clone().into_record_of_rdata())
    else {
        return;
    };
    let Some(authorities) = no_records.authorities.as_deref() else {
        return;
    };
    cache.insert(&soa, authorities);
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
    let max = (settings.max_cache_ttl > 0).then_some(settings.max_cache_ttl);
    let bounds = |min: u32| {
        serde_json::json!({
            "positive_min_ttl": min,
            "positive_max_ttl": max,
            "negative_max_ttl": settings.negative_cache_ttl,
        })
    };
    // NS questions get a floor of their own. The recursor asks for the NS
    // records of every name on the way down to the one it resolves, and the
    // cache keeps an NS answer only as long as the NS records in it: one
    // answered with a CNAME instead (every name in a CNAME chain) has none,
    // so it fell to `min_cache_ttl` (0 by default) and was asked again on
    // every pass. `www.aliexpress.com`, a chain bouncing between Alibaba's
    // zones on servers 100-800 ms away, sent 98 queries and took 17 s, past
    // the client's 5 s limit.
    let ns_min = settings
        .min_cache_ttl
        .max(NS_MIN_CACHE_TTL)
        .min(max.unwrap_or(u32::MAX));
    serde_json::from_value(serde_json::json!({
        "default": bounds(settings.min_cache_ttl),
        "NS": bounds(ns_min),
    }))
    .unwrap_or_else(|e| {
        warn!("cannot build the cache TTL limits ({e}); using the defaults");
        TtlConfig::default()
    })
}

/// The shortest time an answer to an NS question is cached (see
/// [`ttl_config`]), unless `max_cache_ttl` is shorter.
const NS_MIN_CACHE_TTL: u32 = 300;

/// A recursor and the local root responder it was built for.
pub struct RecursorSlot {
    pub recursor: Arc<DaygleRecursor>,
    pub local_root: Option<SocketAddr>,
    /// Cached, validated NSEC proofs (RFC 8198), when
    /// `recursive.aggressive_nsec` is on and DNSSEC validation is too.
    pub aggressive: Option<Arc<crate::aggressive::AggressiveNsec>>,
}

impl RecursorSlot {
    /// A slot for a freshly built recursor, with the aggressive proof cache
    /// its settings ask for. The cache is per recursor, so flushing the
    /// cache (which rebuilds the recursor) clears the proofs as well.
    pub fn new(
        recursor: DaygleRecursor,
        local_root: Option<SocketAddr>,
        settings: &RecursiveSettings,
    ) -> Self {
        let aggressive = (settings.aggressive_nsec && settings.dnssec_validate).then(|| {
            Arc::new(crate::aggressive::AggressiveNsec::new(
                settings.max_cache_ttl,
            ))
        });
        Self {
            recursor: Arc::new(recursor),
            local_root,
            aggressive,
        }
    }
}

/// A shared, rebuildable recursor: flushing the cache rebuilds it (the
/// recursor has no cache-clear call), and so does the local root zone
/// starting or stopping being served (the root hints are fixed at build).
pub type SharedRecursor = Arc<arc_swap::ArcSwap<RecursorSlot>>;

#[cfg(test)]
mod hierarchy_tests;

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

    /// A query the resolver gave up on stays in the trace with no response
    /// code, instead of the trace ending at the last reply: resolving a
    /// zone's glueless name server addresses sends queries whose timeout
    /// left no reply to record.
    #[tokio::test]
    async fn a_query_that_gets_no_reply_stays_in_the_trace() {
        let (_, trace) = trace_queries(async {
            let query = Query::query(name("ns1.example.test."), RecordType::A);
            // No reply ever fills the row in, as when the resolver's timeout
            // fires while a name server stays silent.
            begin_trace(IpAddr::from([192, 0, 2, 1]), Some(&query), None)
                .expect("a traced query gets a row");
        })
        .await;
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].name, "ns1.example.test.");
        assert_eq!(trace[0].record_type, "A");
        assert!(trace[0].rcode.is_none());
        assert!(
            trace[0].outcome.contains("no reply"),
            "{}",
            trace[0].outcome
        );
    }

    /// A reply fills its row in, and collecting the trace afterwards does
    /// not overwrite it with "no reply".
    #[tokio::test]
    async fn an_answered_query_keeps_its_reply() {
        let (_, trace) = trace_queries(async {
            let query = Query::query(name("www.example.test."), RecordType::A);
            let slot = begin_trace(IpAddr::from([192, 0, 2, 2]), Some(&query), None)
                .expect("a traced query gets a row");
            let message = Message::response(0, hickory_proto::op::OpCode::Query);
            let response = DnsResponse::from_message(message).expect("a response");
            finish_trace(Some(slot), &Ok(response), Duration::from_millis(7));
        })
        .await;
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].rcode.as_deref(), Some("NOERROR"));
        assert_eq!(trace[0].elapsed, Duration::from_millis(7));
    }

    /// The address queries the recursor sends for a zone's glueless name
    /// servers are traced, and one that is never answered stays in the list
    /// with its server and how long it was waited for - the case where a
    /// lookup fails on such a timeout and the trace used to stop at the last
    /// reply.
    ///
    /// The wait reported is `recursive.timeout_secs`, not the 5s the
    /// recursor gives one of its name server connections of its own accord:
    /// 2s here is short enough to be the setting that ends the query.
    #[tokio::test]
    async fn a_glueless_nameserver_query_that_times_out_is_traced() {
        use hickory_proto::op::MessageType;
        use hickory_proto::rr::rdata::NS;

        // A root server on loopback that delegates `test.` to `ns.test.`
        // without glue, and drops the address question for that name server
        // as an unreachable server does.
        let socket = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(question) = query.queries.first() else {
                    continue;
                };
                if question.name().to_ascii() != "test." || question.query_type() != RecordType::NS
                {
                    continue;
                }
                let mut response = Message::new(
                    query.metadata.id,
                    MessageType::Response,
                    query.metadata.op_code,
                );
                response.queries.push(question.clone());
                response.add_authority(Record::from_rdata(
                    name("test."),
                    300,
                    RData::NS(NS(name("ns.test."))),
                ));
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });

        let settings = RecursiveSettings {
            dnssec_validate: false,
            root_hints: vec!["127.0.0.2".to_string()],
            test_outbound_port: Some(port),
            timeout_secs: 1,
            ..RecursiveSettings::default()
        };
        let recursor = build(&settings, None, Arc::new(Metrics::default())).expect("a recursor");
        let slot = RecursorSlot::new(recursor, None, &settings);
        let started = Instant::now();
        let (result, trace) = trace_queries(lookup(&slot, name("www.test."), RecordType::A)).await;

        assert!(
            result.is_err(),
            "the lookup cannot finish without reaching a name server"
        );
        let asked: Vec<&TraceStep> = trace
            .iter()
            .filter(|s| s.name == "ns.test." && s.record_type == "A")
            .collect();
        assert_eq!(asked.len(), 1, "{trace:#?}");
        assert!(asked[0].rcode.is_none());
        assert!(
            asked[0].outcome.contains("no reply after 1.0s"),
            "{}",
            asked[0].outcome
        );
        assert_eq!(asked[0].elapsed, Duration::from_secs(1), "{:#?}", asked[0]);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the lookup gave up at the 1s setting, not the recursor's built-in 5s"
        );
    }

    // The fake hierarchy the dead-name-server test walks.
    const FAKE_ROOT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const FAKE_TLD: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
    const FAKE_SILENT_NS1: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);
    const FAKE_ALIVE_NS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
    const FAKE_SILENT_NS2: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 6);

    /// One server of the fake hierarchy: the root refers `test.` to the TLD,
    /// the TLD refers `fallback.test.` to three name servers (the first two
    /// silent), and the zone's working server answers the name.
    fn spawn_fake(socket: tokio::net::UdpSocket, server: Ipv4Addr) {
        use hickory_proto::op::MessageType;
        use hickory_proto::rr::rdata::NS;

        // Bound and never answered, as a name server on stale glue is.
        if server == FAKE_SILENT_NS1 || server == FAKE_SILENT_NS2 {
            tokio::spawn(async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            });
            return;
        }
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(question) = query.queries.first() else {
                    continue;
                };
                let mut response = Message::new(
                    query.metadata.id,
                    MessageType::Response,
                    query.metadata.op_code,
                );
                response.queries.push(question.clone());
                let owner = question.name().to_ascii().to_ascii_lowercase();
                if server == FAKE_TLD {
                    response.add_authority(Record::from_rdata(
                        name("fallback.test."),
                        300,
                        RData::NS(NS(name("ns1.fallback.test."))),
                    ));
                    response.add_authority(Record::from_rdata(
                        name("fallback.test."),
                        300,
                        RData::NS(NS(name("ns2.fallback.test."))),
                    ));
                    response.add_authority(Record::from_rdata(
                        name("fallback.test."),
                        300,
                        RData::NS(NS(name("ns3.fallback.test."))),
                    ));
                    response.add_additional(Record::from_rdata(
                        name("ns1.fallback.test."),
                        300,
                        RData::A(A(FAKE_SILENT_NS1)),
                    ));
                    response.add_additional(Record::from_rdata(
                        name("ns2.fallback.test."),
                        300,
                        RData::A(A(FAKE_SILENT_NS2)),
                    ));
                    response.add_additional(Record::from_rdata(
                        name("ns3.fallback.test."),
                        300,
                        RData::A(A(FAKE_ALIVE_NS)),
                    ));
                } else if server == FAKE_ROOT {
                    response.add_authority(Record::from_rdata(
                        name("test."),
                        300,
                        RData::NS(NS(name("ns.test."))),
                    ));
                    response.add_additional(Record::from_rdata(
                        name("ns.test."),
                        300,
                        RData::A(A(FAKE_TLD)),
                    ));
                } else if owner == "www.fallback.test." && question.query_type() == RecordType::A {
                    response.metadata.authoritative = true;
                    response.add_answer(Record::from_rdata(
                        name("www.fallback.test."),
                        300,
                        RData::A(A(Ipv4Addr::new(198, 51, 100, 77))),
                    ));
                } else {
                    // The zone's working server, for its other questions.
                    response.metadata.authoritative = true;
                }
                if let Ok(bytes) = response.to_vec() {
                    if socket.send_to(&bytes, peer).await.is_err() {
                        return;
                    }
                }
            }
        });
    }

    /// A zone whose first two name servers never answer resolves from its
    /// third one anyway.
    ///
    /// The recursor's name server pool gives a query one 5s budget for all
    /// of a zone's servers and asks them one at a time, so a wait for one
    /// silent server that fills most of the budget leaves no room for the
    /// servers after it: `yoyo.org` is delegated with two dead servers listed
    /// before the working one, and reaching only the first two still failed
    /// with SERVFAIL. The default 5s setting is used, as shipped.
    #[tokio::test]
    async fn a_zone_with_two_silent_nameservers_resolves_from_its_third() {
        // One port for the whole fake hierarchy, which outbound queries are
        // redirected to (see `test_outbound_port`).
        let port = 'retry: loop {
            let root = tokio::net::UdpSocket::bind((FAKE_ROOT, 0)).await.unwrap();
            let port = root.local_addr().unwrap().port();
            let mut sockets = vec![(root, FAKE_ROOT)];
            for server in [FAKE_TLD, FAKE_SILENT_NS1, FAKE_ALIVE_NS, FAKE_SILENT_NS2] {
                match tokio::net::UdpSocket::bind((server, port)).await {
                    Ok(socket) => sockets.push((socket, server)),
                    Err(_) => continue 'retry,
                }
            }
            for (socket, server) in sockets {
                spawn_fake(socket, server);
            }
            break port;
        };

        let settings = RecursiveSettings {
            dnssec_validate: false,
            root_hints: vec![FAKE_ROOT.to_string()],
            test_outbound_port: Some(port),
            timeout_secs: 5,
            ..RecursiveSettings::default()
        };
        let recursor = build(&settings, None, Arc::new(Metrics::default())).expect("a recursor");
        let slot = RecursorSlot::new(recursor, None, &settings);
        let started = Instant::now();
        let (result, trace) =
            trace_queries(lookup(&slot, name("www.fallback.test."), RecordType::A)).await;
        let took = started.elapsed();

        assert!(result.is_ok(), "{result:?}\n{trace:#?}");
        assert!(
            took < Duration::from_secs(4),
            "two silent servers must leave room for the third ({took:?})\n{trace:#?}"
        );

        for silent_ns in [FAKE_SILENT_NS1, FAKE_SILENT_NS2] {
            let asked: Vec<&TraceStep> = trace
                .iter()
                .filter(|step| step.server == IpAddr::V4(silent_ns))
                .collect();
            assert!(!asked.is_empty(), "{silent_ns} was asked\n{trace:#?}");
            for step in asked {
                assert!(step.rcode.is_none(), "{step:#?}");
                assert!(step.outcome.contains("no reply"), "{step:#?}");
                assert!(
                    step.elapsed < Duration::from_secs(2),
                    "one server's wait leaves the pool room for the next ({:?})",
                    step.elapsed
                );
            }
        }

        let answered: Vec<&TraceStep> = trace
            .iter()
            .filter(|step| {
                step.server == IpAddr::V4(FAKE_ALIVE_NS) && step.rcode.as_deref() == Some("NOERROR")
            })
            .collect();
        assert!(
            !answered.is_empty(),
            "the zone's third name server answered\n{trace:#?}"
        );
    }

    /// `www.shop.test -> shop.host.test -> shop.cdn.test`, where a query
    /// through a CNAME into the next zone fails validation, as the
    /// recursor's own chain following does for a signed target zone.
    ///
    /// `www.hop.test -> cm.l.plain.test` ends in a denial from
    /// `l.plain.test`, delegated from the unsigned `plain.test` on the same
    /// servers, which the validator cannot prove (`g.doubleclick.net`).
    async fn zones(query: Query) -> Resolved {
        if query.query_type() == RecordType::SOA {
            return apexes(query).await;
        }
        let owner = query.name().to_ascii();
        match (owner.as_str(), query.query_type()) {
            ("www.hop.test.", RecordType::CNAME) => {
                answer(vec![cname("www.hop.test.", "cm.l.plain.test.")])
            }
            ("www.lb.test.", RecordType::CNAME) => {
                answer(vec![cname("www.lb.test.", "www.wip.plain.test.")])
            }
            ("www.lb.test.", _) => Resolved::Unproven(failure("unproven", None), None),
            ("www.wip.plain.test.", _) => {
                Resolved::Unproven(failure("unproven", None), Some(bare_denial()))
            }
            ("www.hop.test.", _) | ("cm.l.plain.test.", RecordType::HTTPS) => {
                Resolved::Unproven(failure("unproven", None), Some(denial("l.plain.test.")))
            }
            ("www.shop.test.", RecordType::CNAME) => {
                answer(vec![cname("www.shop.test.", "shop.host.test.")])
            }
            ("shop.host.test.", RecordType::CNAME) => {
                answer(vec![cname("shop.host.test.", "shop.cdn.test.")])
            }
            ("shop.host.test.", _) => Resolved::Unproven(failure("unproven", None), None),
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
            ("pool.test.", _) => Resolved::Unproven(failure("unproven", None), None),
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

    fn soa(zone: &str, proof: Proof) -> Resolved {
        let mut record = Record::from_rdata(
            name(zone),
            300,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                name("ns.test."),
                name("hostmaster.test."),
                1,
                3600,
                600,
                86400,
                60,
            )),
        );
        record.proof = proof;
        answer(vec![record])
    }

    /// A DS record, as the parent of a signed zone publishes it.
    fn ds(zone: &str) -> Resolved {
        answer(vec![Record::from_rdata(
            name(zone),
            300,
            RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::DS(
                hickory_proto::dnssec::rdata::DS::new(
                    1234,
                    hickory_proto::dnssec::Algorithm::ECDSAP256SHA256,
                    hickory_proto::dnssec::DigestType::SHA256,
                    vec![0xab; 32],
                ),
            )),
        )])
    }

    /// The parent's answer that a zone has no DS record: a NODATA carrying
    /// the parent's SOA.
    fn no_ds(zone: &str) -> Resolved {
        let parent = name(zone).base_name().to_ascii();
        let Resolved::Answer(message) = soa(&parent, Proof::Secure) else {
            unreachable!()
        };
        Resolved::Negative(
            failure("no records", Some(ResponseCode::NoError)),
            Some(message.answers[0].clone()),
        )
    }

    /// `test.` and `signed.test.` are signed; `plain.test.` is not, and its
    /// delegated `l.plain.test.` cannot be proven either way. An SOA forged
    /// under the signed zone comes back bogus. `broken.test.` is unsigned as
    /// well, but its own servers answer with something this resolver cannot
    /// read (as `ptsecurity.com`'s do), so only its parent can say so: the
    /// parent has a DS for the signed zones, none for the unsigned ones.
    async fn apexes(query: Query) -> Resolved {
        let owner = query.name().to_ascii();
        match (query.query_type(), owner.as_str()) {
            (RecordType::SOA, "test." | "signed.test.") => soa(&owner, Proof::Secure),
            (RecordType::SOA, "plain.test.") => soa("plain.test.", Proof::Insecure),
            (RecordType::SOA, "l.plain.test." | "forged.signed.test.") => soa(&owner, Proof::Bogus),
            (RecordType::SOA, "broken.test.") => {
                Resolved::Failed(failure("unreadable reply", None))
            }
            (RecordType::DS, "test." | "signed.test." | "forged.signed.test.") => ds(&owner),
            (RecordType::DS, "plain.test." | "l.plain.test." | "broken.test.") => no_ds(&owner),
            _ => Resolved::Negative(failure("no records", Some(ResponseCode::NoError)), None),
        }
    }

    fn bogus_a(owner: &str) -> Record {
        let mut record =
            Record::from_rdata(name(owner), 60, RData::A(A(Ipv4Addr::new(192, 0, 2, 7))));
        record.proof = Proof::Bogus;
        record
    }

    /// A NODATA denial carrying the SOA of `zone`.
    fn denial(zone: &str) -> Denial {
        let Resolved::Answer(message) = soa(zone, Proof::Bogus) else {
            unreachable!()
        };
        Denial {
            error: failure("no records", Some(ResponseCode::NoError)),
            soa: Some(message.answers[0].clone()),
        }
    }

    /// A NODATA denial sent without an SOA.
    fn bare_denial() -> Denial {
        Denial {
            error: failure("no records", Some(ResponseCode::NoError)),
            soa: None,
        }
    }

    async fn settle(owner: &str, record_type: RecordType, from: &str) -> Result<Lookup> {
        settle_unproven(
            &zones,
            name(owner),
            record_type,
            failure("bogus", None),
            Some(denial(from)),
        )
        .await
    }

    #[tokio::test]
    async fn an_unproven_denial_from_an_unsigned_zone_is_no_data() {
        let result = settle("cm.l.plain.test.", RecordType::HTTPS, "l.plain.test.").await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
    }

    #[tokio::test]
    async fn an_unproven_denial_from_a_signed_zone_stays_unproven() {
        for zone in ["signed.test.", "forged.signed.test."] {
            let owner = format!("www.{zone}");
            let result = settle(&owner, RecordType::HTTPS, zone).await;
            assert_eq!(code(result), ("bogus".to_string(), None), "{zone}");
        }
    }

    #[tokio::test]
    async fn an_unsigned_soa_for_another_name_does_not_excuse_a_denial() {
        let result = settle("www.signed.test.", RecordType::HTTPS, "plain.test.").await;
        assert_eq!(code(result), ("bogus".to_string(), None));
    }

    /// A zone whose own servers answer with something the resolver cannot
    /// read cannot be proved unsigned by asking them, which is what both the
    /// validator's zone-cut probe and [`in_unsigned_zone`] do. Its parent
    /// still can: a zone the parent has no DS for is unsigned (RFC 4035
    /// section 5.2).
    ///
    /// `rules.ptsecurity.com AAAA` was SERVFAIL in 90 ms for this, while
    /// validating resolvers answer NODATA: `ptsecurity.com` is unsigned (the
    /// `.com` NSEC3 proves no DS), but both of its servers answer FORMERR to
    /// every query carrying EDNS, so the recursor's reply to the zone-cut and
    /// SOA questions cannot be decoded.
    #[tokio::test]
    async fn a_denial_from_a_zone_whose_servers_cannot_be_probed_is_no_data() {
        // `apexes` is the fake whose zones have parents: `settle`'s mere
        // `zones` answers every DS question without an SOA, which proves
        // nothing (see `has_no_ds`).
        let result = settle_unproven(
            &apexes,
            name("rules.broken.test."),
            RecordType::AAAA,
            failure("bogus", None),
            Some(denial("broken.test.")),
        )
        .await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
    }

    /// The same unreadable zone, but with a DS record at its parent: it is
    /// signed, so its denial stays unproven. The parent's answer is what
    /// decides, not the zone's servers being reachable.
    #[tokio::test]
    async fn a_denial_from_a_signed_zone_whose_servers_cannot_be_probed_stays_unproven() {
        let result = settle_unproven(
            &apexes,
            name("rules.forged.signed.test."),
            RecordType::AAAA,
            failure("bogus", None),
            Some(denial("forged.signed.test.")),
        )
        .await;
        assert_eq!(code(result), ("bogus".to_string(), None));
    }

    #[tokio::test]
    async fn a_denial_without_an_soa_under_an_unsigned_zone_is_no_data() {
        let result = settle_unproven(
            &zones,
            name("www.wip.plain.test."),
            RecordType::AAAA,
            failure("bogus", None),
            Some(bare_denial()),
        )
        .await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
        // Followed down a CNAME chain, as for `www.accv.es`.
        let result = follow("www.lb.test.", RecordType::AAAA).await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
    }

    #[tokio::test]
    async fn a_denial_without_an_soa_under_a_signed_zone_stays_unproven() {
        for owner in ["www.signed.test.", "www.forged.signed.test."] {
            let result = settle_unproven(
                &zones,
                name(owner),
                RecordType::AAAA,
                failure("bogus", None),
                Some(bare_denial()),
            )
            .await;
            assert_eq!(code(result), ("bogus".to_string(), None), "{owner}");
        }
    }

    #[tokio::test]
    async fn a_chain_into_an_unsigned_zone_ending_in_no_data_is_no_data() {
        let result = follow("www.hop.test.", RecordType::HTTPS).await;
        assert_eq!(
            code(result),
            ("no records".to_string(), Some(ResponseCode::NoError.into()))
        );
    }

    #[tokio::test]
    async fn a_bogus_mark_under_an_unsigned_zone_comes_off() {
        let mut answers = vec![
            bogus_a("clients.l.plain.test."),
            bogus_a("clients.l.plain.test."),
        ];
        clear_false_bogus(&apexes, &mut answers).await;
        assert!(answers.iter().all(|r| r.proof == Proof::Insecure));
    }

    #[tokio::test]
    async fn a_bogus_mark_under_a_signed_zone_stays() {
        let mut answers = vec![
            bogus_a("www.signed.test."),
            bogus_a("www.forged.signed.test."),
            bogus_a("www.nowhere."),
        ];
        clear_false_bogus(&apexes, &mut answers).await;
        assert!(answers.iter().all(|r| r.proof == Proof::Bogus));
    }

    #[tokio::test]
    async fn records_that_are_not_bogus_are_left_alone() {
        let mut secure = bogus_a("www.plain.test.");
        secure.proof = Proof::Secure;
        let mut answers = vec![secure];
        clear_false_bogus(&apexes, &mut answers).await;
        assert_eq!(answers[0].proof, Proof::Secure);
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

    #[test]
    fn ns_answers_are_cached_for_at_least_five_minutes() {
        let secs = |d: Duration| d.as_secs();
        let mut settings = RecursiveSettings {
            min_cache_ttl: 0,
            max_cache_ttl: 86400,
            negative_cache_ttl: 3600,
            ..RecursiveSettings::default()
        };
        let config = ttl_config(&settings);
        let ns = config.positive_response_ttl_bounds(RecordType::NS);
        assert_eq!((secs(*ns.start()), secs(*ns.end())), (300, 86400));
        let a = config.positive_response_ttl_bounds(RecordType::A);
        assert_eq!((secs(*a.start()), secs(*a.end())), (0, 86400));
        // The NS bounds replace the defaults for NS questions, so they keep
        // the negative limit too.
        let negative = config.negative_response_ttl_bounds(RecordType::NS);
        assert_eq!(secs(*negative.end()), 3600);

        // A longer configured minimum wins, and a shorter maximum caps it.
        settings.min_cache_ttl = 900;
        let ns = ttl_config(&settings).positive_response_ttl_bounds(RecordType::NS);
        assert_eq!(secs(*ns.start()), 900);
        settings.min_cache_ttl = 0;
        settings.max_cache_ttl = 120;
        let ns = ttl_config(&settings).positive_response_ttl_bounds(RecordType::NS);
        assert_eq!((secs(*ns.start()), secs(*ns.end())), (120, 120));
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
