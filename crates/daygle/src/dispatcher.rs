//! The combined DNS dispatcher: policy → authoritative → recursive.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use daygle_authoritative::model::SPLIT_HORIZON_RECORD_TYPES;
use daygle_authoritative::AuthorityCatalog;
use daygle_core::{DaygleError, LogStore, Metrics, RateLimiter};
use daygle_policy::{Action, PolicyEngine};
use daygle_recursive::RecursiveResolver;
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

/// The single [`RequestHandler`] used by every listener (UDP, TCP, DoT).
///
/// Query flow:
/// 1. **Policy** - ACLs, blocklists, per-client rules and plugins decide
///    whether to allow, refuse, block, or redirect the query.
/// 2. **Authoritative** - if the query name falls inside a hosted zone, the
///    Hickory [`hickory_server::zone_handler::Catalog`] answers (with DNSSEC
///    signing when enabled).
/// 3. **Recursive** - otherwise the query is resolved through
///    [`RecursiveResolver`].
pub struct DnsDispatcher {
    catalog: Arc<AuthorityCatalog>,
    resolver: Arc<ArcSwapOption<RecursiveResolver>>,
    policy: Arc<ArcSwap<PolicyEngine>>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<Metrics>,
    logs: Arc<LogStore>,
}

impl DnsDispatcher {
    /// Build a dispatcher whose policy and recursive resolver can be swapped
    /// at runtime (live reload). The rate limiter reads its limits from the
    /// shared [`RateLimiter`], which reload swaps in place, so the dispatcher
    /// itself never needs rebuilding for rate-limit changes.
    pub fn new(
        catalog: Arc<AuthorityCatalog>,
        resolver: Arc<ArcSwapOption<RecursiveResolver>>,
        policy: Arc<ArcSwap<PolicyEngine>>,
        rate_limiter: Arc<RateLimiter>,
        metrics: Arc<Metrics>,
        logs: Arc<LogStore>,
    ) -> Self {
        Self {
            catalog,
            resolver,
            policy,
            rate_limiter,
            metrics,
            logs,
        }
    }

    /// Convenience constructor for callers that do not need live reload (e.g.
    /// tests and simple embeddings).
    pub fn from_components(
        catalog: Arc<AuthorityCatalog>,
        resolver: Option<Arc<RecursiveResolver>>,
        policy: PolicyEngine,
        metrics: Arc<Metrics>,
        logs: Arc<LogStore>,
    ) -> Self {
        Self::new(
            catalog,
            Arc::new(ArcSwapOption::from(resolver)),
            Arc::new(ArcSwap::from_pointee(policy)),
            Arc::new(RateLimiter::default()),
            metrics,
            logs,
        )
    }

    fn log_error(&self, component: &str, message: impl Into<String>) {
        self.logs.error(component, message.into());
    }

    /// Serve an AXFR/IXFR zone transfer from the stored zone data.
    ///
    /// The response answer section is `SOA, records…, SOA` as RFC 5936
    /// requires. IXFR is answered with a full transfer, which RFC 1995 always
    /// permits (a server may answer IXFR with the full zone when it does not
    /// implement incremental deltas).
    async fn handle_transfer<R: ResponseHandler>(
        &self,
        request: &Request,
        qname: &str,
        client: IpAddr,
        mut response_handle: R,
    ) -> ResponseInfo {
        let settings = self.catalog.settings();
        if !settings.axfr_enabled || !transfer_client_allowed(&settings.axfr_networks, client) {
            debug!(query = %qname, %client, "zone transfer refused by policy");
            return send_error(&mut response_handle, request, ResponseCode::Refused).await;
        }

        match self.catalog.transfer_records(qname) {
            Ok(Some((soa, records))) => {
                let mut metadata = request.metadata;
                metadata.message_type = MessageType::Response;
                metadata.response_code = ResponseCode::NoError;
                metadata.authoritative = true;
                metadata.recursion_available = false;

                // RFC 5936: the answer must begin and end with the zone SOA.
                let mut answers = Vec::with_capacity(records.len() + 2);
                answers.push(soa.clone());
                answers.extend(records);
                answers.push(soa);

                let response = MessageResponseBuilder::from_message_request(request).build(
                    metadata,
                    answers.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
                match response_handle.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!("failed to send zone transfer: {e}");
                        fallback_response()
                    }
                }
            }
            Ok(None) => {
                debug!(query = %qname, "zone transfer for unknown zone");
                send_error(&mut response_handle, request, ResponseCode::Refused).await
            }
            Err(e) => {
                warn!(query = %qname, error = %e, "zone transfer failed");
                self.log_error("transfer", format!("transfer for {qname} failed: {e}"));
                send_error(&mut response_handle, request, ResponseCode::ServFail).await
            }
        }
    }
}

/// True when the query type is a zone transfer (AXFR or IXFR).
fn rtype_is_transfer(rtype: &str) -> bool {
    rtype.eq_ignore_ascii_case("AXFR") || rtype.eq_ignore_ascii_case("IXFR")
}

/// Enforce the `axfr_networks` allow-list (empty = allow everyone).
fn transfer_client_allowed(networks: &[String], client: IpAddr) -> bool {
    if networks.is_empty() {
        return true;
    }
    networks.iter().any(|net| {
        net.parse::<ipnet::IpNet>()
            .map(|ipnet| ipnet.contains(&client))
            .unwrap_or(false)
    })
}

#[async_trait]
impl RequestHandler for DnsDispatcher {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        self.metrics.inc(&self.metrics.total_queries);
        self.metrics
            .add(&self.metrics.bytes_in, request.as_slice().len() as u64);

        // 0. Rate limiting (per client). Applied before anything else so a
        // flooding client cannot even reach the update/policy/recursive
        // machinery. Loopback may be exempt via `rate_limit.exempt_loopback`.
        let client = request.src().ip();
        if !self.rate_limiter.check_client(client) {
            debug!(%client, "query rate-limited by client");
            self.metrics.inc(&self.metrics.rate_limited);
            return send_error(&mut response_handle, request, ResponseCode::ServFail).await;
        }

        // RFC 2136 dynamic updates are handled with write-through to SQLite:
        // the catalog is reloaded after each successful update, so changes
        // are immediately live and survive restarts. `allow_dynamic_updates`
        // and `update_networks` gate who may update.
        if request.metadata.op_code == OpCode::Update {
            let edns = request.edns.as_ref();
            return daygle_authoritative::handle_update(
                &self.catalog,
                request,
                edns,
                response_handle,
            )
            .await;
        }

        let info = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                warn!("malformed request from {}: {e}", request.src());
                self.metrics.inc(&self.metrics.errors);
                return send_error(&mut response_handle, request, ResponseCode::FormErr).await;
            }
        };

        let query_name = info.query.name().to_string();
        let qname = query_name.trim_end_matches('.').to_ascii_lowercase();
        let rtype = info.query.query_type().to_string();
        let client = info.src.ip();

        // 0b. Rate limiting (per domain). Tracked independently of the client
        // counter: a client may legitimately ask about many domains, and a hot
        // domain must not be hammered by one client's retries.
        if !self.rate_limiter.check_domain(&qname) {
            debug!(query = %qname, "query rate-limited by domain");
            self.metrics.inc(&self.metrics.rate_limited);
            return send_error(&mut response_handle, request, ResponseCode::ServFail).await;
        }

        // 1. Policy. The engine is swapped atomically on reload; clone out the
        // current one so a single query sees one consistent snapshot.
        let policy = self.policy.load_full();
        let decision = policy.evaluate(client, &qname, &rtype).await;
        match &decision.action {
            Action::Allow => {}
            Action::Refused => {
                debug!(query = %qname, reason = %decision.reason, "refused by policy");
                self.metrics.inc(&self.metrics.blocked);
                return send_error(&mut response_handle, request, ResponseCode::Refused).await;
            }
            Action::Block => {
                debug!(query = %qname, reason = %decision.reason, "blocked by policy");
                self.metrics.inc(&self.metrics.blocked);
                return send_error(&mut response_handle, request, ResponseCode::NXDomain).await;
            }
            Action::Redirect(ip) => {
                debug!(query = %qname, %ip, "redirected by policy");
                self.metrics.inc(&self.metrics.blocked);
                return send_redirect(&mut response_handle, request, info.query.query_type(), *ip)
                    .await;
            }
        }

        // 1c. Split horizon: per-client synthetic answers. This runs after
        // policy (blocklists/redirects win) and before the authoritative
        // catalog, so internal clients see internal answers even for hosted
        // zones. Entries carry typed records (A, AAAA, MX, TXT, CNAME, SRV);
        // a query is answered only by records of its own type (a CNAME
        // answers every type, per RFC 1034 §3.6.2). When the matching entry
        // has nothing for the queried type the lookup returns `None` and the
        // query falls through to normal resolution.
        if rtype.as_str() == "ANY" || SPLIT_HORIZON_RECORD_TYPES.contains(&rtype.as_str()) {
            let index = self.catalog.split_horizon();
            if let Some(m) = index.lookup(client, &qname, info.query.query_type()) {
                debug!(query = %qname, %client, "split-horizon answer");
                self.metrics.inc(&self.metrics.split_horizon);
                return send_records(&mut response_handle, request, &m.records).await;
            }
        }

        // 2a. Zone transfers (AXFR/IXFR). These are served from the stored
        // zone data (not the in-memory catalog) so we can enforce the
        // transfer ACL and answer IXFR with a full transfer, which is always
        // valid per RFC 1995.
        if rtype_is_transfer(&rtype) {
            return self.handle_transfer(request, &qname, info.src.ip(), response_handle).await;
        }

        // 2b. Authoritative zones.
        if self.catalog.contains(info.query.name()) {
            self.metrics.inc(&self.metrics.authoritative);
            let now = unix_now();
            let edns = request.edns.as_ref();
            return self.catalog.read().lookup(request, edns, now, response_handle).await;
        }

        // 3. Recursive resolution. The resolver is swapped atomically on
        // reload; clone out the current one for this query.
        let resolver = self.resolver.load_full();
        let Some(resolver) = resolver else {
            // Recursion disabled and not authoritative: REFUSED.
            return send_error(&mut response_handle, request, ResponseCode::Refused).await;
        };

        self.metrics.inc(&self.metrics.recursive);
        match resolver.lookup(&qname, info.query.query_type()).await {
            Ok(lookup) => {
                let answers = lookup.answers().to_vec();
                let authorities = lookup.authorities().to_vec();
                let additionals = lookup.additionals().to_vec();
                let validated = lookup.message().authentic_data;
                if validated {
                    self.metrics.inc(&self.metrics.dnssec_validated);
                }

                let mut metadata = request.metadata;
                metadata.message_type = MessageType::Response;
                metadata.response_code = lookup.message().response_code;
                metadata.recursion_available = true;
                metadata.recursion_desired = request.metadata.recursion_desired;
                metadata.authentic_data = validated;

                let response = MessageResponseBuilder::from_message_request(request).build(
                    metadata,
                    answers.iter(),
                    authorities.iter(),
                    std::iter::empty(),
                    additionals.iter(),
                );
                match response_handle.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        self.log_error("dispatcher", format!("send failure: {e}"));
                        fallback_response()
                    }
                }
            }
            Err(e) => {
                debug!(query = %qname, error = %e, "recursive resolution failed");
                self.metrics.inc(&self.metrics.errors);
                // Negative answers (NXDOMAIN, NODATA) carry their response
                // code so they pass through instead of SERVFAIL.
                let code = match &e {
                    DaygleError::Resolution {
                        response_code: Some(code),
                        ..
                    } => <ResponseCode as From<u16>>::from(*code),
                    _ => ResponseCode::ServFail,
                };
                send_error(&mut response_handle, request, code).await
            }
        }
    }
}

/// Send a response with only an error code.
async fn send_error<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    code: ResponseCode,
) -> ResponseInfo {
    let response = MessageResponseBuilder::from_message_request(request)
        .error_msg(&request.metadata, code);
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!("failed to send error response: {e}");
            fallback_response()
        }
    }
}

/// Send a response whose answer section is exactly `records`.
async fn send_records<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    records: &[Record],
) -> ResponseInfo {
    if records.is_empty() {
        return send_error(handle, request, ResponseCode::NXDomain).await;
    }

    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = ResponseCode::NoError;
    metadata.authoritative = true;
    metadata.recursion_available = true;

    let response = MessageResponseBuilder::from_message_request(request).build(
        metadata,
        records.iter(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!("failed to send answer: {e}");
            fallback_response()
        }
    }
}

/// Synthesize an A/AAAA answer carrying `ips` (used by the policy `redirect`
/// action).
async fn send_address_answer<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    rtype: RecordType,
    ips: &[IpAddr],
    ttl: u32,
) -> ResponseInfo {
    let qname = request
        .request_info()
        .map(|i| i.query.name().to_string())
        .unwrap_or_else(|_| ".".to_string());
    let name = match Name::from_utf8(&format!("{}.", qname.trim_end_matches('.'))) {
        Ok(n) => n,
        Err(_) => return send_error(handle, request, ResponseCode::ServFail).await,
    };

    let records: Vec<Record> = ips
        .iter()
        .filter_map(|ip| {
            let rdata = match (ip, rtype) {
                (IpAddr::V4(v4), RecordType::A | RecordType::ANY) => {
                    Some(RData::A((*v4).into()))
                }
                (IpAddr::V6(v6), RecordType::AAAA | RecordType::ANY) => {
                    Some(RData::AAAA((*v6).into()))
                }
                _ => None,
            };
            rdata.map(|rdata| Record::from_rdata(name.clone(), ttl, rdata))
        })
        .collect();

    // No address of the requested family: the redirect target cannot answer
    // this query, so send NXDOMAIN.
    if records.is_empty() {
        return send_error(handle, request, ResponseCode::NXDomain).await;
    }

    send_records(handle, request, &records).await
}

/// Synthesize a single-address redirect answer (policy `redirect` action).
async fn send_redirect<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    rtype: RecordType,
    ip: IpAddr,
) -> ResponseInfo {
    send_address_answer(handle, request, rtype, std::slice::from_ref(&ip), 60).await
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A minimal `ResponseInfo` used when the transport failed entirely.
fn fallback_response() -> ResponseInfo {
    ResponseInfo::from(hickory_proto::op::Header {
        metadata: hickory_proto::op::Metadata::new(0, MessageType::Response, OpCode::Query),
        counts: hickory_proto::op::HeaderCounts::default(),
    })
}

/// Convert a [`DaygleError`] into a log line (helper for callers).
#[allow(dead_code)]
pub fn log_daygle_error(logs: &LogStore, component: &str, e: &DaygleError) {
    logs.error(component, e.to_string());
}
