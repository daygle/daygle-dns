//! The combined DNS dispatcher: policy → authoritative → recursive.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use daygle_dns_authoritative::model::SPLIT_HORIZON_RECORD_TYPES;
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_core::block_log::BlockReason;
use daygle_dns_core::stats::Outcome;
use daygle_dns_core::{DaygleError, LogStore, Metrics, RateLimiter};
use daygle_dns_policy::{source, Action, AdvancedBlocking, PolicyEngine};
use daygle_dns_recursive::RecursiveResolver;
use hickory_proto::dnssec::Proof;
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

/// TTL of the DDR (RFC 9462) SVCB answers.
const DDR_TTL: u32 = 300;

/// TTL of the CNAME in a Safe Search answer (the safe address's own
/// records keep theirs, capped by it).
const SAFE_SEARCH_TTL: u32 = 300;

/// Admission limit for recursive network work.
///
/// Work holds a permit until its resolver future ends, independently of how
/// long the client waits for it.
pub struct RecursiveAdmission {
    limit: AtomicUsize,
    active: AtomicUsize,
}

/// RAII slot held by one in-flight resolver operation.
pub struct RecursivePermit(Arc<RecursiveAdmission>);

impl RecursiveAdmission {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            active: AtomicUsize::new(0),
        }
    }

    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
    }

    fn try_acquire(self: &Arc<Self>) -> Option<RecursivePermit> {
        loop {
            let limit = self.limit.load(Ordering::Acquire);
            let active = self.active.load(Ordering::Acquire);
            if active >= limit {
                return None;
            }
            if self
                .active
                .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // If a concurrent reload lowered the limit after our first
                // check, roll back instead of admitting above the new cap.
                if self.active.load(Ordering::Acquire) <= self.limit.load(Ordering::Acquire) {
                    return Some(RecursivePermit(Arc::clone(self)));
                }
                self.active.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
        }
    }
}

impl Drop for RecursivePermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

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
#[derive(Clone)]
pub struct DnsDispatcher {
    catalog: Arc<AuthorityCatalog>,
    resolver: Arc<ArcSwapOption<RecursiveResolver>>,
    policy: Arc<ArcSwap<PolicyEngine>>,
    /// Advanced Blocking groups, swapped atomically when the stored groups
    /// change. Defaults to an empty set (no groups) so tests and simple
    /// embeddings need not supply it.
    advanced_blocking: Arc<ArcSwap<AdvancedBlocking>>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<Metrics>,
    logs: Arc<LogStore>,
    /// Optional NOTIFY hooks (outbound sender + inbound handler).
    notify: daygle_dns_authoritative::notify::NotifyHooks,
    /// TSIG keys (RFC 8945) for transfer/update authentication.
    tsig_keys: Arc<daygle_dns_authoritative::tsig::TsigKeyRing>,
    /// Dashboard time-series + top-N tables (per-minute buckets, top
    /// clients/domains/blocked). Optional so tests can omit it.
    stats: Option<Arc<daygle_dns_core::stats::QueryStats>>,
    /// Persistent per-query logger (daily JSON-lines files). `None` unless
    /// `logging.query_log_enabled`; best-effort, never blocks a response.
    query_logger: Option<Arc<daygle_dns_core::QueryLogger>>,
    /// Async SQLite query-log sink feeding the console's searchable Query
    /// Logs view. `None` unless `logging.query_db_enabled`; best-effort.
    query_db_logger: Option<Arc<crate::query_db_log::QueryDbLogger>>,
    /// Coalesces recent authoritative record-use updates so queries do not
    /// serialize SQLite writes at request volume.
    record_use_cache: Arc<Mutex<RecordUseCache>>,
    /// Client Timeout (`server.client_timeout_ms`): how long the recursive
    /// path may take before the client receives SERVFAIL. Default 2000 ms.
    client_timeout: Duration,
    /// Global cap for recursive lookups, including work outliving client timeouts.
    recursive_admission: Arc<RecursiveAdmission>,
    /// DNS cookies (RFC 7873, `server.dns_cookies`).
    cookies: Arc<crate::cookies::Cookies>,
    /// Response rate limiting (`[rrl]`).
    rrl: Arc<daygle_dns_core::rrl::ResponseRateLimiter>,
    /// Response policy zones, published by their manager.
    rpz: Arc<ArcSwap<daygle_dns_authoritative::rpz::RpzSet>>,
    /// Recent block-page answers, for the page to say why.
    block_log: Arc<daygle_dns_core::block_log::BlockLog>,
    /// Remote logging of queries (`[syslog] queries`).
    syslog: Option<Arc<crate::syslog::SyslogSender>>,
    /// The live config, for settings read per query (`[dns64]`).
    config: Option<Arc<ArcSwap<daygle_dns_core::config::DaygleConfig>>>,
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
        Self::with_notify(
            catalog,
            resolver,
            policy,
            rate_limiter,
            metrics,
            logs,
            daygle_dns_authoritative::notify::NotifyHooks::default(),
            Arc::new(daygle_dns_authoritative::tsig::TsigKeyRing::default()),
        )
    }

    /// Like [`Self::new`], with NOTIFY hooks (RFC 1996): the sender is used
    /// after successful dynamic updates, the inbound handler processes
    /// OpCode::Notify requests for configured secondary zones. `tsig_keys`
    /// authenticates TSIG-signed transfers and updates (RFC 8945).
    // Builder-style constructor: each subsystem is passed explicitly rather
    // than bundled into a params struct that callers would only unpack again.
    #[allow(clippy::too_many_arguments)]
    pub fn with_notify(
        catalog: Arc<AuthorityCatalog>,
        resolver: Arc<ArcSwapOption<RecursiveResolver>>,
        policy: Arc<ArcSwap<PolicyEngine>>,
        rate_limiter: Arc<RateLimiter>,
        metrics: Arc<Metrics>,
        logs: Arc<LogStore>,
        notify: daygle_dns_authoritative::notify::NotifyHooks,
        tsig_keys: Arc<daygle_dns_authoritative::tsig::TsigKeyRing>,
    ) -> Self {
        Self {
            catalog,
            resolver,
            policy,
            advanced_blocking: Arc::new(ArcSwap::from_pointee(AdvancedBlocking::default())),
            rate_limiter,
            metrics,
            logs,
            notify,
            tsig_keys,
            stats: None,
            query_logger: None,
            query_db_logger: None,
            record_use_cache: Arc::default(),
            client_timeout: Duration::from_millis(2000),
            recursive_admission: Arc::new(RecursiveAdmission::new(256)),
            cookies: Arc::new(crate::cookies::Cookies::new(true)),
            rrl: Arc::default(),
            rpz: Arc::default(),
            block_log: Arc::default(),
            syslog: None,
            config: None,
        }
    }

    /// Like [`Self::with_notify`], additionally recording dashboard
    /// statistics (time-series buckets + top-N tables).
    #[allow(clippy::too_many_arguments)]
    pub fn with_stats(
        catalog: Arc<AuthorityCatalog>,
        resolver: Arc<ArcSwapOption<RecursiveResolver>>,
        policy: Arc<ArcSwap<PolicyEngine>>,
        rate_limiter: Arc<RateLimiter>,
        metrics: Arc<Metrics>,
        logs: Arc<LogStore>,
        notify: daygle_dns_authoritative::notify::NotifyHooks,
        tsig_keys: Arc<daygle_dns_authoritative::tsig::TsigKeyRing>,
        stats: Arc<daygle_dns_core::stats::QueryStats>,
    ) -> Self {
        Self {
            stats: Some(stats),
            ..Self::with_notify(
                catalog,
                resolver,
                policy,
                rate_limiter,
                metrics,
                logs,
                notify,
                tsig_keys,
            )
        }
    }

    /// Attach a persistent query logger (daily JSON-lines files). When present,
    /// every served query is appended; logging is best-effort and never blocks
    /// or fails a response.
    pub fn with_query_logger(
        mut self,
        query_logger: Option<Arc<daygle_dns_core::QueryLogger>>,
    ) -> Self {
        self.query_logger = query_logger;
        self
    }

    /// Attach the async SQLite query-log sink backing the console's Query
    /// Logs view. Best-effort: a full queue drops entries rather than
    /// blocking a DNS response.
    pub fn with_query_db_logger(
        mut self,
        query_db_logger: Option<Arc<crate::query_db_log::QueryDbLogger>>,
    ) -> Self {
        self.query_db_logger = query_db_logger;
        self
    }

    /// Attach a shared Advanced Blocking set. The same `Arc` is held by the
    /// API layer so CRUD changes are published to the dispatcher by swapping
    /// its contents; the dispatcher never needs rebuilding.
    pub fn with_advanced_blocking(
        mut self,
        advanced_blocking: Arc<ArcSwap<AdvancedBlocking>>,
    ) -> Self {
        self.advanced_blocking = advanced_blocking;
        self
    }

    /// Bound the time spent waiting for an answer (`server.client_timeout_ms`).
    /// When recursion cannot produce a response in time, the client receives
    /// SERVFAIL and the whole recursion is cancelled.
    pub fn with_client_timeout(mut self, client_timeout: Duration) -> Self {
        self.client_timeout = client_timeout;
        self
    }

    /// Use the shared recursive admission gate for this server.
    pub fn with_recursive_admission(mut self, admission: Arc<RecursiveAdmission>) -> Self {
        self.recursive_admission = admission;
        self
    }

    fn try_recursive_permit(&self) -> Option<RecursivePermit> {
        self.recursive_admission.try_acquire()
    }

    /// Send query lines to syslog (when its settings ask for them).
    pub fn with_syslog(mut self, syslog: Option<Arc<crate::syslog::SyslogSender>>) -> Self {
        self.syslog = syslog;
        self
    }

    /// Read per-query settings (DNS64) from the live config.
    pub fn with_config(
        mut self,
        config: Arc<ArcSwap<daygle_dns_core::config::DaygleConfig>>,
    ) -> Self {
        self.config = Some(config);
        self
    }

    /// Share a response rate limiter (`[rrl]`).
    pub fn with_rrl(mut self, rrl: Arc<daygle_dns_core::rrl::ResponseRateLimiter>) -> Self {
        self.rrl = rrl;
        self
    }

    /// Share the block page's log of recent blocks (`[block_page]`).
    pub fn with_block_log(mut self, log: Arc<daygle_dns_core::block_log::BlockLog>) -> Self {
        self.block_log = log;
        self
    }

    /// Share the response policy zones (`[[rpz]]`).
    pub fn with_rpz(mut self, rpz: Arc<ArcSwap<daygle_dns_authoritative::rpz::RpzSet>>) -> Self {
        self.rpz = rpz;
        self
    }

    /// Turn DNS cookies (RFC 7873) on or off.
    pub fn with_cookies(mut self, enabled: bool) -> Self {
        self.cookies = Arc::new(crate::cookies::Cookies::new(enabled));
        self
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

    /// Record one query into the dashboard statistics (no-op when stats are
    /// not attached, e.g. in unit tests).
    fn record_stats(&self, client: IpAddr, qname: &str, outcome: Outcome) {
        if let Some(stats) = &self.stats {
            stats.record(client, qname, outcome);
        }
    }

    /// Append one served query to the persistent log (no-op when query logging
    /// is disabled). `qtype` is the query type string (empty when the query was
    /// rejected before parsing), `rcode` the response code when known, and
    /// `started` the instant the request began (for the logged handling time).
    #[allow(clippy::too_many_arguments)]
    fn log_query(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: &str,
        outcome: Outcome,
        rcode: Option<&str>,
        started: Instant,
        block: Option<BlockReason>,
    ) {
        if let Some(logger) = &self.query_logger {
            logger.log(&daygle_dns_core::QueryLogEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                client: client.to_string(),
                qname: qname.to_string(),
                qtype: qtype.to_string(),
                outcome: outcome_label(outcome).to_string(),
                rcode: rcode.map(|r| r.to_string()),
                elapsed_ms: started.elapsed().as_millis() as u64,
                block,
            });
        }
    }

    /// Queue one served query into the SQLite-backed query log (no-op when
    /// the sink is absent). `protocol` labels the transport the query arrived
    /// on (`udp`, `tcp`, `tls`, `https`, `quic`, `h3`).
    #[allow(clippy::too_many_arguments)]
    fn db_log_query(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: &str,
        protocol: &str,
        outcome: Outcome,
        rcode: Option<&str>,
        started: Instant,
        block: Option<BlockReason>,
    ) {
        if let Some(logger) = &self.query_db_logger {
            logger.log(crate::query_db_log::QueryDbEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                client: client.to_string(),
                qname: qname.to_string(),
                qtype: qtype.to_string(),
                protocol: protocol.to_string(),
                outcome: outcome_label(outcome).to_string(),
                rcode: rcode.map(|r| r.to_string()),
                elapsed_ms: started.elapsed().as_millis() as u64,
                block,
            });
        }
    }

    /// Record a served query into the dashboard statistics, the JSON-lines
    /// log and the SQLite query log in one call (used by the branches that
    /// decide the outcome and response code up front).
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: &str,
        protocol: &str,
        outcome: Outcome,
        rcode: Option<&str>,
        started: Instant,
    ) {
        self.observe_with(
            client, qname, qtype, protocol, outcome, rcode, started, None,
        );
    }

    /// [`Self::observe`], with why the query was blocked when it was.
    #[allow(clippy::too_many_arguments)]
    fn observe_with(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: &str,
        protocol: &str,
        outcome: Outcome,
        rcode: Option<&str>,
        started: Instant,
        block: Option<BlockReason>,
    ) {
        self.record_stats(client, qname, outcome);
        if let Some(syslog) = &self.syslog {
            syslog.query(crate::syslog::QueryLine {
                client,
                qname,
                qtype,
                protocol,
                outcome: outcome_label(outcome),
                rcode,
                elapsed_ms: started.elapsed().as_millis() as u64,
                block: block.as_ref(),
            });
        }
        self.log_query(client, qname, qtype, outcome, rcode, started, block.clone());
        self.db_log_query(
            client, qname, qtype, protocol, outcome, rcode, started, block,
        );
    }

    /// [`Self::observe`] for a blocked query, keeping why it was blocked
    /// in the query logs.
    #[allow(clippy::too_many_arguments)]
    fn observe_blocked(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: &str,
        protocol: &str,
        rcode: Option<&str>,
        started: Instant,
        block: BlockReason,
    ) {
        self.observe_with(
            client,
            qname,
            qtype,
            protocol,
            Outcome::Blocked,
            rcode,
            started,
            Some(block),
        );
    }

    /// Whether `key` is used for the first time this clock minute (and so
    /// needs a "last used" database write). Past [`RECORD_USE_CACHE_CAP`]
    /// keys seen within the last two minutes - a flood of unique names under
    /// a wildcard - further writes are skipped: each would cost a blocking
    /// task and a database write, and the cache itself would grow without
    /// bound for as long as the flood lasts.
    fn first_use_this_minute(&self, key: (String, String)) -> bool {
        let current_minute = chrono::Utc::now().timestamp().div_euclid(60);
        let Ok(mut cache) = self.record_use_cache.lock() else {
            return false;
        };
        if cache
            .last_use
            .get(&key)
            .is_some_and(|last_minute| *last_minute >= current_minute)
        {
            return false;
        }
        // Sweep at most once a minute: sweeping on every call once the map
        // was large rescanned it in full per query while the lock was held.
        if cache.last_use.len() >= RECORD_USE_CACHE_SWEEP_AT && cache.swept_minute != current_minute
        {
            cache
                .last_use
                .retain(|_, minute| *minute >= current_minute - 1);
            cache.swept_minute = current_minute;
        }
        if cache.last_use.len() >= RECORD_USE_CACHE_CAP {
            return false;
        }
        cache.last_use.insert(key, current_minute);
        true
    }

    /// Mark eligible stored records at an authoritative owner as used,
    /// coalescing database writes for each name/type within each clock minute.
    fn mark_authoritative_records_used(&self, qname: &str, qtype: &str) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if !self.first_use_this_minute((qname.to_ascii_lowercase(), qtype.to_ascii_uppercase())) {
            return;
        }
        let store = self.catalog.store_handle();
        let name = qname.to_string();
        let rtype = qtype.to_string();
        let used_at = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || store.mark_records_used(&name, &rtype, &used_at));
    }

    /// Mark a split-horizon entry as used, coalescing database writes per
    /// entry within each clock minute (the record-use cache under a
    /// namespaced key).
    fn mark_split_horizon_entry_used(&self, entry_id: &str) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if !self.first_use_this_minute(("@split-horizon".to_string(), entry_id.to_string())) {
            return;
        }
        let store = self.catalog.store_handle();
        let id = entry_id.to_string();
        let used_at = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || store.mark_split_horizon_used(&id, &used_at));
    }

    /// Serve an AXFR/IXFR zone transfer from the stored zone data.
    ///
    /// The response answer section is `SOA, records..., SOA` as RFC 5936
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
            return send_error(&mut response_handle, request, ResponseCode::Refused, None).await;
        }

        // TSIG gate (RFC 8945): when the zone requires a signed transfer,
        // verify the request signature first. The response is signed with
        // the same key, chaining the request MAC.
        let tsig = match self.catalog.tsig_transfer_key(qname) {
            Some(required) => {
                match daygle_dns_authoritative::tsig::verify_request(
                    &self.tsig_keys,
                    request.as_slice(),
                    request.metadata.id,
                ) {
                    daygle_dns_authoritative::tsig::TsigVerifyOutcome::Valid {
                        key,
                        response_context,
                        ..
                    } if key.name == required.name => {
                        Some((key, Some(response_context)))
                    }
                    daygle_dns_authoritative::tsig::TsigVerifyOutcome::Valid { .. } => {
                        debug!(query = %qname, %client, "zone transfer signed with wrong TSIG key");
                        return send_error(&mut response_handle, request, ResponseCode::Refused, None).await;
                    }
                    daygle_dns_authoritative::tsig::TsigVerifyOutcome::Invalid(failure) => {
                        debug!(query = %qname, %client, ?failure, "zone transfer TSIG verification failed");
                        return send_error(&mut response_handle, request, ResponseCode::Refused, None).await;
                    }
                    daygle_dns_authoritative::tsig::TsigVerifyOutcome::Unsigned => {
                        debug!(query = %qname, %client, "zone transfer requires TSIG");
                        return send_error(&mut response_handle, request, ResponseCode::Refused, None).await;
                    }
                }
            }
            None => None,
        }
        .map(|(key, context)| {
            let context = context.unwrap_or_else(|| daygle_dns_authoritative::tsig::response_context_for(&key));
            (key, context)
        });

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

                // A DNS message holds at most 64 KiB, so a larger zone goes
                // out as several messages (RFC 5936 §2.2). Each TSIG-signed
                // message chains from the MAC of the one before.
                let (tsig_key, mut first_context) = match tsig {
                    Some((key, context)) => (Some(key), Some(context)),
                    None => (None, None),
                };
                let mut previous_mac: Option<Vec<u8>> = None;
                let mut info = None;
                for chunk in transfer_chunks(&answers) {
                    let mut response = MessageResponseBuilder::from_message_request(request).build(
                        metadata,
                        chunk.iter(),
                        std::iter::empty(),
                        std::iter::empty(),
                        std::iter::empty(),
                    );
                    if let Some(key) = &tsig_key {
                        let mut tbs_buf = Vec::with_capacity(16 * 1024);
                        let mut encoder =
                            hickory_proto::serialize::binary::BinEncoder::new(&mut tbs_buf);
                        let tbs_response = MessageResponseBuilder::from_message_request(request)
                            .build(
                                metadata,
                                chunk.iter(),
                                std::iter::empty(),
                                std::iter::empty(),
                                std::iter::empty(),
                            );
                        if let Err(e) = tbs_response.destructive_emit(&mut encoder) {
                            warn!(query = %qname, error = %e, "failed to encode signed transfer");
                            return send_error(
                                &mut response_handle,
                                request,
                                ResponseCode::ServFail,
                                None,
                            )
                            .await;
                        }
                        let signature = match (&previous_mac, first_context.take()) {
                            (None, Some(context)) => {
                                context.sign(&tbs_buf).map_err(|e| e.to_string())
                            }
                            _ => daygle_dns_authoritative::tsig::sign_subsequent(
                                key,
                                previous_mac.as_deref().unwrap_or_default(),
                                &tbs_buf,
                                request.metadata.id,
                            ),
                        };
                        match signature {
                            Ok(signature) => {
                                previous_mac = Some(signature.data.mac.clone());
                                response.set_signature(signature);
                            }
                            Err(e) => {
                                warn!(query = %qname, error = %e, "failed to sign zone transfer");
                                return send_error(
                                    &mut response_handle,
                                    request,
                                    ResponseCode::ServFail,
                                    None,
                                )
                                .await;
                            }
                        }
                    }
                    match response_handle.send_response(response).await {
                        Ok(sent) => {
                            info.get_or_insert(sent);
                        }
                        Err(e) => {
                            warn!("failed to send zone transfer: {e}");
                            return fallback_response();
                        }
                    }
                }
                info.unwrap_or_else(fallback_response)
            }
            Ok(None) => {
                debug!(query = %qname, "zone transfer for unknown zone");
                send_error(&mut response_handle, request, ResponseCode::Refused, None).await
            }
            Err(e) => {
                warn!(query = %qname, error = %e, "zone transfer failed");
                self.log_error("transfer", format!("transfer for {qname} failed: {e}"));
                send_error(&mut response_handle, request, ResponseCode::ServFail, None).await
            }
        }
    }
}

/// Split a zone transfer's answers into groups that each fit one DNS
/// message: sizes are counted uncompressed, so the real messages come out
/// smaller still, well under the 64 KiB limit.
fn transfer_chunks(answers: &[Record]) -> Vec<&[Record]> {
    const BUDGET: usize = 16 * 1024;
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut size = 0;
    for (i, record) in answers.iter().enumerate() {
        let len = hickory_proto::serialize::binary::BinEncodable::to_bytes(record)
            .map(|b| b.len())
            .unwrap_or(BUDGET);
        if size > 0 && size + len > BUDGET {
            chunks.push(&answers[start..i]);
            start = i;
            size = 0;
        }
        size += len;
    }
    if start < answers.len() {
        chunks.push(&answers[start..]);
    }
    chunks
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
    // `parse_network` also takes a bare address (a single host), which the
    // config check accepts; a plain `IpNet` parse rejected it and refused
    // that secondary.
    networks.iter().any(|net| {
        daygle_dns_core::config::parse_network(net).is_some_and(|ipnet| ipnet.contains(&client))
    })
}

#[async_trait]
impl RequestHandler for DnsDispatcher {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let started = Instant::now();
        self.metrics.inc(&self.metrics.total_queries);
        self.metrics
            .add(&self.metrics.bytes_in, request.as_slice().len() as u64);

        // 0. Rate limiting (per client). Applied before anything else so a
        // flooding client cannot even reach the update/policy/recursive
        // machinery. Loopback may be exempt via `rate_limit.exempt_loopback`.
        // IPv4-mapped IPv6 sources (an IPv4 client on a dual-stack `::`
        // listener) are canonicalized to plain IPv4 so IPv4 ACLs, rate
        // limits, split-horizon networks and transfer allow-lists match them.
        // Behind a PROXY protocol or bounded listener front, the original
        // remote address is restored through the bridge peer mapping.
        let client = crate::proxy_protocol::real_client(request.src())
            .ip()
            .to_canonical();
        let protocol = protocol_label(request.protocol());

        // Enforce encrypted-listener ACLs before opcode-specific handlers.
        // In particular, UPDATE and NOTIFY take early paths below and must
        // not bypass dot/doh/doq.allowed_networks.
        let listener_allowed = self.listener_gate(client, request.protocol());
        if matches!(listener_allowed, Some(false)) {
            debug!(%client, protocol, "client not allowed on this listener");
            self.metrics.inc(&self.metrics.blocked);
            self.observe_blocked(
                client,
                "(listener-denied)",
                "",
                protocol,
                Some("REFUSED"),
                started,
                block_reason(
                    source::LISTENER,
                    None,
                    None,
                    "client is not allowed on this listener",
                ),
            );
            return send_error(
                &mut response_handle,
                request,
                ResponseCode::Refused,
                Some(Ede::new(
                    ede::PROHIBITED,
                    "client is not allowed on this listener",
                )),
            )
            .await;
        }

        // DNS cookies (RFC 7873): every response to a client that sent one
        // carries a fresh server cookie, and a request whose server cookie
        // checks out provably comes from its source address. Such a client
        // cannot be a spoofed flood, so it gets a larger per-client
        // allowance - not an exemption, or any real client could flood the
        // server by echoing its cookie back.
        let (cookie_ok, cookie_reply) =
            match self
                .cookies
                .check(request.edns.as_ref(), client, unix_now() as u32)
            {
                crate::cookies::CookieCheck::Absent => (false, None),
                crate::cookies::CookieCheck::Malformed => {
                    return send_error(&mut response_handle, request, ResponseCode::FormErr, None)
                        .await;
                }
                crate::cookies::CookieCheck::Present { valid, reply } => (valid, Some(reply)),
            };
        // Response rate limiting (RRL) counts every UDP response that goes
        // out from here on; the cookie layer sits outside it, so a truncated
        // (slipped) reply still carries a cookie the client can retry with.
        let response_handle = crate::rrl::RrlResponder::new(
            response_handle,
            request,
            client,
            cookie_ok,
            &self.rrl,
            &self.metrics,
        );
        let mut response_handle =
            crate::cookies::CookieResponder::new(response_handle, cookie_reply);
        let admitted = if cookie_ok {
            self.rate_limiter.check_verified_client(client)
        } else {
            self.rate_limiter.check_client(client)
        };
        if !admitted {
            debug!(%client, "query rate-limited by client");
            self.metrics.inc(&self.metrics.rate_limited);
            self.observe(
                client,
                "(rate-limited)",
                "",
                protocol,
                Outcome::RateLimited,
                Some("SERVFAIL"),
                started,
            );
            return send_error(
                &mut response_handle,
                request,
                ResponseCode::ServFail,
                Some(Ede::new(ede::OTHER, "rate limit exceeded")),
            )
            .await;
        }

        // DNS labels are case-insensitive by design, so queries are normalized to
        // lowercase early. This is the canonical form used by policy evaluation,
        // authoritative lookup, split-horizon matching, recursive resolution, and the
        // statistics/logs. Any cookie, header, or other non-DNS identifier layer added
        // later must not assume this casing contract; cookies in particular have their
        // own RFC 6265 matching rules and should be normalized separately at the
        // response layer rather than inheriting DNS lowercasing.
        //
        // RFC 2136 dynamic updates and RFC 1996 NOTIFY do NOT need request_info()
        // parsing - they operate on the raw request and have their own validation
        // paths. Branch on OpCode first and only call request_info() once for
        // ordinary queries; this avoids parsing the request up to 3x per query.
        if request.metadata.op_code == OpCode::Update {
            let edns = request.edns.as_ref();
            return daygle_dns_authoritative::handle_update_with_notify(
                &self.catalog,
                request,
                client,
                edns,
                response_handle,
                // Secondaries are notified of every zone change from the
                // catalog's change feed (see `daygle_dns::run`).
                None,
            )
            .await;
        }
        if request.metadata.op_code == OpCode::Notify {
            return match &self.notify.inbound {
                Some(inbound) => inbound.handle(request, response_handle).await,
                // No inbound NOTIFY configured: NOTIMP, per RFC 1996 §3.9.
                None => send_error(&mut response_handle, request, ResponseCode::NotImp, None).await,
            };
        }

        let info = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                // Garbage on the port (scanners, probes) is counted, not
                // logged one line per packet.
                debug!("malformed request from {}: {e}", request.src());
                self.metrics.inc(&self.metrics.errors);
                return send_error(&mut response_handle, request, ResponseCode::FormErr, None)
                    .await;
            }
        };

        let qname = info
            .query
            .name()
            .to_string()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let rtype = info.query.query_type().to_string();
        // 0b. Rate limiting (per domain). Tracked independently of the client
        // counter: a client may legitimately ask about many domains, and a hot
        // domain must not be hammered by one client's retries.
        if !self.rate_limiter.check_domain(&qname) {
            debug!(query = %qname, "query rate-limited by domain");
            self.metrics.inc(&self.metrics.rate_limited);
            self.observe(
                client,
                &qname,
                &rtype,
                protocol,
                Outcome::RateLimited,
                Some("SERVFAIL"),
                started,
            );
            return send_error(
                &mut response_handle,
                request,
                ResponseCode::ServFail,
                Some(Ede::new(ede::OTHER, "rate limit exceeded")),
            )
            .await;
        }

        // 0c. Discovery of Designated Resolvers (DDR, RFC 9462): a device
        // asks `_dns.resolver.arpa` (or `_dns.<this server's name>`) for
        // SVCB records describing the encrypted DNS it can switch to.
        // `resolver.arpa` is local to every resolver: never forwarded.
        let special_use = qname == "resolver.arpa" || qname.ends_with(".resolver.arpa");
        let ddr_name = qname == "_dns.resolver.arpa" || (!special_use && self.is_ddr_name(&qname));
        if special_use || ddr_name {
            let known = ddr_name || qname == "resolver.arpa";
            self.observe(
                client,
                &qname,
                &rtype,
                protocol,
                Outcome::Authoritative,
                Some(if known { "NOERROR" } else { "NXDOMAIN" }),
                started,
            );
            if !known {
                return send_error(&mut response_handle, request, ResponseCode::NXDomain, None)
                    .await;
            }
            let records = if ddr_name && info.query.query_type() == RecordType::SVCB {
                self.ddr_records(client, &Name::from(info.query.name().clone()))
            } else {
                Vec::new()
            };
            if records.is_empty() {
                return send_empty(&mut response_handle, request, None).await;
            }
            return send_records(&mut response_handle, request, &records, None).await;
        }

        // Listener ACL was checked before opcode-specific handlers above.
        // The result is reused by the recursion gate so membership in the
        // encrypted listener's allow-list grants recursion on that listener.

        // 1. Policy. The engine is swapped atomically on reload; clone out the
        // current one so a single query sees one consistent snapshot. A query
        // on the DoT listener additionally faces the DoT-scoped remote
        // blocklist sources (scope `dot`), giving that endpoint its own
        // stricter policy without touching the LAN's plain-DNS experience.
        let policy = self.policy.load_full();
        let listener = match info.protocol {
            hickory_server::net::xfer::Protocol::Tls => Some("dot"),
            hickory_server::net::xfer::Protocol::Https
            | hickory_server::net::xfer::Protocol::H3 => Some("doh"),
            hickory_server::net::xfer::Protocol::Quic => Some("doq"),
            _ => None,
        };
        let decision = policy.evaluate_on(client, &qname, &rtype, listener).await;
        match &decision.action {
            Action::Allow => {}
            Action::Refused => {
                debug!(query = %qname, reason = %decision.reason, "refused by policy");
                self.metrics.inc(&self.metrics.blocked);
                self.observe_blocked(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Some("REFUSED"),
                    started,
                    block_reason_of(&decision),
                );
                return send_error(
                    &mut response_handle,
                    request,
                    ResponseCode::Refused,
                    Some(Ede::new(ede::BLOCKED, decision.reason.clone())),
                )
                .await;
            }
            Action::Block => {
                debug!(query = %qname, reason = %decision.reason, "blocked by policy");
                self.metrics.inc(&self.metrics.blocked);
                if let Some(answer) = self.block_page_answer(info.query.query_type()) {
                    self.observe_blocked(
                        client,
                        &qname,
                        &rtype,
                        protocol,
                        Some("NOERROR"),
                        started,
                        block_reason_of(&decision),
                    );
                    return self
                        .serve_block_page(
                            &mut response_handle,
                            request,
                            client,
                            &qname,
                            &decision.reason,
                            answer,
                        )
                        .await;
                }
                self.observe_blocked(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Some("NXDOMAIN"),
                    started,
                    block_reason_of(&decision),
                );
                return send_error(
                    &mut response_handle,
                    request,
                    ResponseCode::NXDomain,
                    Some(Ede::new(ede::BLOCKED, decision.reason.clone())),
                )
                .await;
            }
            Action::Redirect(ip) => {
                debug!(query = %qname, %ip, "redirected by policy");
                self.metrics.inc(&self.metrics.blocked);
                self.observe_blocked(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Some("NOERROR"),
                    started,
                    block_reason_of(&decision),
                );
                return send_redirect(
                    &mut response_handle,
                    request,
                    info.query.name(),
                    info.query.query_type(),
                    *ip,
                    Some(Ede::new(ede::BLOCKED, decision.reason.clone())),
                )
                .await;
            }
            Action::NoData => {
                // Filter AAAA: NODATA (empty NOERROR) forces IPv4 fallback.
                debug!(query = %qname, reason = %decision.reason, "AAAA filtered");
                self.metrics.inc(&self.metrics.blocked);
                self.observe_blocked(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Some("NOERROR"),
                    started,
                    block_reason_of(&decision),
                );
                return send_empty(
                    &mut response_handle,
                    request,
                    Some(Ede::new(ede::FILTERED, decision.reason.clone())),
                )
                .await;
            }
        }

        // 1b. Advanced Blocking: per-client-group allow/block policies. Runs
        // after the base policy engine (an explicit allow list inside a group
        // can still let a name through) and before split-horizon/authoritative
        // resolution. `evaluate` only ever returns a blocking action.
        if !policy.is_allowlisted(&qname) {
            let encrypted_listener = match info.protocol {
                hickory_server::net::xfer::Protocol::Tls => Some("dot"),
                hickory_server::net::xfer::Protocol::Https
                | hickory_server::net::xfer::Protocol::H3 => Some("doh"),
                hickory_server::net::xfer::Protocol::Quic => Some("doq"),
                _ => None,
            };
            if let Some(decision) =
                self.advanced_blocking
                    .load()
                    .evaluate(client, &qname, encrypted_listener)
            {
                debug!(query = %qname, reason = %decision.reason, "blocked by advanced blocking");
                self.metrics.inc(&self.metrics.blocked);
                if decision.action == Action::Block {
                    if let Some(answer) = self.block_page_answer(info.query.query_type()) {
                        self.observe_blocked(
                            client,
                            &qname,
                            &rtype,
                            protocol,
                            Some("NOERROR"),
                            started,
                            block_reason_of(&decision),
                        );
                        return self
                            .serve_block_page(
                                &mut response_handle,
                                request,
                                client,
                                &qname,
                                &decision.reason,
                                answer,
                            )
                            .await;
                    }
                }
                let rcode = match decision.action {
                    Action::Refused => "REFUSED",
                    Action::Redirect(_) | Action::NoData => "NOERROR",
                    _ => "NXDOMAIN",
                };
                self.observe_blocked(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Some(rcode),
                    started,
                    block_reason_of(&decision),
                );
                // Per-client-group filtering (RFC 8914 "Filtered").
                let why = Some(Ede::new(ede::FILTERED, decision.reason.clone()));
                return match decision.action {
                    Action::Refused => {
                        send_error(&mut response_handle, request, ResponseCode::Refused, why).await
                    }
                    Action::Redirect(ip) => {
                        send_redirect(
                            &mut response_handle,
                            request,
                            info.query.name(),
                            info.query.query_type(),
                            ip,
                            why,
                        )
                        .await
                    }
                    Action::NoData => send_empty(&mut response_handle, request, why).await,
                    // Block (NXDOMAIN) and any future action default to NXDOMAIN.
                    _ => {
                        send_error(&mut response_handle, request, ResponseCode::NXDomain, why).await
                    }
                };
            }
        }

        // 1c. Response policy zones (RPZ): client-IP and QNAME triggers, in
        // zone order. They apply to what the blocklists and filtering groups
        // let through; an allowlisted name is exempt, and a PASSTHRU rule
        // exempts the query from the rest of RPZ (its answer included).
        let rpz = self.rpz.load_full();
        let mut rpz_done = rpz.is_empty() || policy.is_allowlisted(&qname);
        if !rpz_done {
            if let Some(hit) = rpz.check_query(client, &qname) {
                if rpz_lets_through(&hit.action, info.protocol) {
                    rpz_done = true;
                } else {
                    return self
                        .serve_rpz(
                            hit,
                            request,
                            &mut response_handle,
                            client,
                            &qname,
                            &rtype,
                            protocol,
                            started,
                        )
                        .await;
                }
            }
        }

        // 1d. Safe Search and YouTube Restricted Mode: a search engine's name
        // is answered with a CNAME to its "safe" address plus that address's
        // records. Only for clients that may use recursion (everyone else is
        // refused below anyway) and names not hosted here; HTTPS/SVCB are
        // answered empty so browsers cannot learn other endpoints from them,
        // and every other type resolves as usual.
        if let Some(target) = self.safe_search_target(&policy, client, listener, &qname) {
            let may_recurse = self.resolver.load().as_ref().is_some_and(|r| {
                r.allows_client_with_listener(client, matches!(listener_allowed, Some(true)))
            });
            let qtype = info.query.query_type();
            if may_recurse && !self.catalog.contains(info.query.name()) {
                if matches!(qtype, RecordType::HTTPS | RecordType::SVCB) {
                    self.metrics.inc(&self.metrics.recursive);
                    self.observe(
                        client,
                        &qname,
                        &rtype,
                        protocol,
                        Outcome::Recursive,
                        Some("NOERROR"),
                        started,
                    );
                    return send_empty(&mut response_handle, request, None).await;
                }
                if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::CNAME) {
                    debug!(query = %qname, %target, "safe search rewrite");
                    let ttl = SAFE_SEARCH_TTL;
                    let owner = Name::from(info.query.name().clone());
                    let target_name = Name::from_ascii(format!("{target}.")).expect("valid name");
                    let mut answers = vec![Record::from_rdata(
                        owner,
                        ttl,
                        RData::CNAME(hickory_proto::rr::rdata::CNAME(target_name.clone())),
                    )];
                    let mut rcode = ResponseCode::NoError;
                    let mut ede = None;
                    if qtype != RecordType::CNAME {
                        let alias = daygle_dns_authoritative::catalog::Alias {
                            target: format!("{target}."),
                            ttl,
                        };
                        let (code, records, why) = self.resolve_alias(alias, client, qtype).await;
                        rcode = code;
                        ede = why;
                        answers.extend(records.into_iter().map(|(ttl, rdata)| {
                            Record::from_rdata(target_name.clone(), ttl, rdata)
                        }));
                    }
                    self.metrics.inc(&self.metrics.recursive);
                    self.observe(
                        client,
                        &qname,
                        &rtype,
                        protocol,
                        Outcome::Recursive,
                        Some(&rcode_label(rcode)),
                        started,
                    );
                    if rcode != ResponseCode::NoError {
                        return send_error(&mut response_handle, request, rcode, ede).await;
                    }
                    return send_records(&mut response_handle, request, &answers, None).await;
                }
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
                self.mark_split_horizon_entry_used(&m.entry_id);
                self.observe(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Outcome::SplitHorizon,
                    Some("NOERROR"),
                    started,
                );
                return send_records(&mut response_handle, request, &m.records, None).await;
            }
        }

        // 2a. Zone transfers (AXFR/IXFR). These are served from the stored
        // zone data (not the in-memory catalog) so we can enforce the
        // transfer ACL and answer IXFR with a full transfer, which is always
        // valid per RFC 1995.
        if rtype_is_transfer(&rtype) {
            return self
                .handle_transfer(request, &qname, client, response_handle)
                .await;
        }

        // 2b. ALIAS records: A/AAAA at an ALIAS name are answered with the
        // target's addresses, looked up now (the catalog has no record for
        // them).
        if matches!(info.query.query_type(), RecordType::A | RecordType::AAAA) {
            if let Some(alias) = self.catalog.alias(&qname) {
                let (rcode, records, ede) = self
                    .resolve_alias(alias, client, info.query.query_type())
                    .await;
                self.metrics.inc(&self.metrics.authoritative);
                self.observe(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Outcome::Authoritative,
                    Some(&rcode_label(rcode)),
                    started,
                );
                if rcode != ResponseCode::NoError {
                    return send_error(&mut response_handle, request, rcode, ede).await;
                }
                if records.is_empty() {
                    return send_empty(&mut response_handle, request, None).await;
                }
                self.mark_authoritative_records_used(&qname, &rtype);
                let owner = Name::from(info.query.name().clone());
                let answers: Vec<Record> = records
                    .into_iter()
                    .map(|(ttl, rdata)| Record::from_rdata(owner.clone(), ttl, rdata))
                    .collect();
                return send_records(&mut response_handle, request, &answers, None).await;
            }
        }

        // 2c. Authoritative zones.
        if self.catalog.contains(info.query.name()) {
            self.metrics.inc(&self.metrics.authoritative);
            // The catalog builds and sends the response itself; its exact
            // rcode is not surfaced here, so the log records the outcome
            // without one.
            self.observe(
                client,
                &qname,
                &rtype,
                protocol,
                Outcome::Authoritative,
                None,
                started,
            );
            let now = unix_now();
            let edns = request.edns.as_ref();
            let response = self
                .catalog
                .read()
                .lookup(request, edns, now, response_handle)
                .await;
            if response.counts().answers > 0 {
                self.mark_authoritative_records_used(&qname, &rtype);
            }
            return response;
        }

        // 3. Recursive resolution. The resolver is swapped atomically on
        // reload; clone out the current one for this query.
        let resolver = self.resolver.load_full();
        let Some(resolver) = resolver else {
            // Recursion disabled and not authoritative: REFUSED (recorded
            // like the other refusals, so it shows in the logs and stats).
            self.observe(
                client,
                &qname,
                &rtype,
                protocol,
                Outcome::Error,
                Some(&rcode_label(ResponseCode::Refused)),
                started,
            );
            return send_error(
                &mut response_handle,
                request,
                ResponseCode::Refused,
                Some(Ede::new(
                    ede::NOT_AUTHORITATIVE,
                    "recursion is not available",
                )),
            )
            .await;
        };
        // Recursion access control (`recursive.recursion_access`): clients
        // outside the allowed networks get REFUSED for anything not answered
        // above, so the server is not an open resolver by default.
        if !resolver.allows_client_with_listener(client, matches!(listener_allowed, Some(true))) {
            debug!(query = %qname, %client, "recursion refused for this client");
            self.observe(
                client,
                &qname,
                &rtype,
                protocol,
                Outcome::Error,
                Some(&rcode_label(ResponseCode::Refused)),
                started,
            );
            return send_error(
                &mut response_handle,
                request,
                ResponseCode::Refused,
                Some(Ede::new(
                    ede::PROHIBITED,
                    "recursion is not allowed for this client",
                )),
            )
            .await;
        }

        let permit = match self.try_recursive_permit() {
            Some(permit) => permit,
            None => {
                self.metrics.inc(&self.metrics.errors);
                self.observe(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Outcome::Error,
                    Some(&rcode_label(ResponseCode::ServFail)),
                    started,
                );
                return send_error(
                    &mut response_handle,
                    request,
                    ResponseCode::ServFail,
                    Some(Ede::new(ede::OTHER, "recursive lookup capacity exhausted")),
                )
                .await;
            }
        };
        self.metrics.inc(&self.metrics.recursive);
        // The lookup runs as its own task, so one that outlasts the client
        // timeout still finishes and fills the cache for the client's retry.
        let lookup_task = {
            let resolver = Arc::clone(&resolver);
            let name = qname.clone();
            let rtype = info.query.query_type();
            let subnet = self.client_subnet(client);
            tokio::spawn(async move {
                let _permit = permit;
                daygle_dns_recursive::with_client_subnet(
                    subnet,
                    daygle_dns_recursive::track_stale(async move {
                        resolver.lookup_for_client(client, &name, rtype).await
                    }),
                )
                .await
            })
        };
        let lookup = match tokio::time::timeout(self.client_timeout, lookup_task).await {
            Ok(Ok((result, stale))) => result.map(|lookup| (lookup, stale)),
            Ok(Err(e)) => Err(DaygleError::Resolution {
                message: format!("lookup task failed: {e}"),
                response_code: None,
            }),
            Err(_elapsed) => {
                debug!(
                    query = %qname,
                    client_timeout = ?self.client_timeout,
                    "no answer within server.client_timeout_ms, replying SERVFAIL"
                );
                Err(DaygleError::Resolution {
                    message: format!(
                        "no answer within the client timeout of {} ms",
                        self.client_timeout.as_millis()
                    ),
                    response_code: None,
                })
            }
        };
        match lookup {
            Ok((lookup, stale)) => {
                // CNAME inspection: a name that is allowed, but answers
                // through a CNAME to a blocked one, is blocked too (trackers
                // put on a first-party subdomain, `metrics.shop.example ->
                // tracker.example`). An allowlisted query name is trusted.
                if policy.cname_inspection() && !policy.is_allowlisted(&qname) {
                    if let Some((target, decision)) = self
                        .blocked_cname_target(&policy, client, listener, lookup.answers())
                        .await
                    {
                        debug!(query = %qname, %target, reason = %decision.reason, "blocked by CNAME inspection");
                        self.metrics.inc(&self.metrics.blocked);
                        if decision.action == Action::Block {
                            if let Some(answer) = self.block_page_answer(info.query.query_type()) {
                                self.observe_blocked(
                                    client,
                                    &qname,
                                    &rtype,
                                    protocol,
                                    Some("NOERROR"),
                                    started,
                                    cname_block_reason(&target, &decision),
                                );
                                let reason = format!(
                                    "CNAME target {target} is blocked: {}",
                                    decision.reason
                                );
                                return self
                                    .serve_block_page(
                                        &mut response_handle,
                                        request,
                                        client,
                                        &qname,
                                        &reason,
                                        answer,
                                    )
                                    .await;
                            }
                        }
                        let why = Some(Ede::new(
                            ede::BLOCKED,
                            format!("CNAME target {target} is blocked: {}", decision.reason),
                        ));
                        let rcode = match decision.action {
                            Action::Refused => "REFUSED",
                            Action::Redirect(_) | Action::NoData => "NOERROR",
                            _ => "NXDOMAIN",
                        };
                        self.observe_blocked(
                            client,
                            &qname,
                            &rtype,
                            protocol,
                            Some(rcode),
                            started,
                            cname_block_reason(&target, &decision),
                        );
                        return match decision.action {
                            Action::Refused => {
                                send_error(
                                    &mut response_handle,
                                    request,
                                    ResponseCode::Refused,
                                    why,
                                )
                                .await
                            }
                            Action::Redirect(ip) => {
                                send_redirect(
                                    &mut response_handle,
                                    request,
                                    info.query.name(),
                                    info.query.query_type(),
                                    ip,
                                    why,
                                )
                                .await
                            }
                            Action::NoData => send_empty(&mut response_handle, request, why).await,
                            _ => {
                                send_error(
                                    &mut response_handle,
                                    request,
                                    ResponseCode::NXDomain,
                                    why,
                                )
                                .await
                            }
                        };
                    }
                }
                // Response policy zones: a name in the CNAME chain matching a
                // QNAME trigger, or an address in the answer matching an IP
                // trigger.
                if !rpz_done && rpz.checks_answers() {
                    let mut names = Vec::new();
                    let mut ips = Vec::new();
                    for record in lookup.answers() {
                        match &record.data {
                            RData::CNAME(target) => names.push(
                                target
                                    .0
                                    .to_ascii()
                                    .trim_end_matches('.')
                                    .to_ascii_lowercase(),
                            ),
                            RData::A(a) => ips.push(IpAddr::V4(a.0)),
                            RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
                            _ => {}
                        }
                    }
                    // NSDNAME/NSIP triggers need the domain's name servers:
                    // looked up (from the cache, mostly) only when a zone
                    // has such triggers, within the client timeout.
                    let ns = if rpz.checks_name_servers() {
                        tokio::time::timeout(
                            self.client_timeout,
                            self.name_servers_of(
                                Arc::clone(&resolver),
                                client,
                                &qname,
                                rpz.checks_name_server_ips(),
                            ),
                        )
                        .await
                        .ok()
                    } else {
                        None
                    };
                    if let Some(hit) = rpz.check_answer(&names, &ips, ns.as_ref()) {
                        if !rpz_lets_through(&hit.action, info.protocol) {
                            return self
                                .serve_rpz(
                                    hit,
                                    request,
                                    &mut response_handle,
                                    client,
                                    &qname,
                                    &rtype,
                                    protocol,
                                    started,
                                )
                                .await;
                        }
                    }
                }
                let mut answers = lookup.answers().to_vec();
                let mut authorities = lookup.authorities().to_vec();
                let mut additionals = lookup.additionals().to_vec();
                // DNS64 (RFC 6147): no AAAA, so make them from the A records.
                let mut synthesized = false;
                if info.query.query_type() == RecordType::AAAA
                    && lookup.message().response_code == ResponseCode::NoError
                    && !answers.iter().any(|r| match &r.data {
                        // Mapped addresses count as none (RFC 6147 §5.1.4).
                        RData::AAAA(a) => a.0.to_ipv4_mapped().is_none(),
                        _ => false,
                    })
                {
                    if let Some(dns64) = self.dns64_for(client, request) {
                        if let Some(records) = self
                            .synthesize_aaaa(&dns64, resolver.clone(), client, &qname, &authorities)
                            .await
                        {
                            answers = records;
                            authorities.clear();
                            additionals.clear();
                            synthesized = true;
                        }
                    }
                }
                // Forwarding: the upstream's AD bit. Recursive mode validates
                // locally and records the outcome on each record instead.
                // Synthesized answers are never validated (RFC 6147 §5.5).
                let validated = !synthesized
                    && (lookup.message().authentic_data
                        || (!answers.is_empty()
                            && answers.iter().all(|r| r.proof == Proof::Secure)));
                if validated {
                    self.metrics.inc(&self.metrics.dnssec_validated);
                }
                let mut metadata = request.metadata;
                metadata.message_type = MessageType::Response;
                metadata.response_code = lookup.message().response_code;
                metadata.recursion_available = true;
                // RFC 6840 §5.8: AD only for a client that asked for it (AD
                // or DO set); others may not understand the bit.
                metadata.authentic_data = validated
                    && (request.metadata.authentic_data
                        || request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));

                // Log with the upstream response code and the full handling
                // time (the lookup is the bulk of a recursive query's latency).
                let rcode = rcode_label(metadata.response_code);
                self.observe(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    Outcome::Recursive,
                    Some(&rcode),
                    started,
                );

                let ede = if stale {
                    Some(Ede::new(
                        ede::STALE_ANSWER,
                        "upstream unreachable; serving an expired answer",
                    ))
                } else {
                    None
                };
                let edns = response_edns(request, ede.as_ref());
                let mut builder = MessageResponseBuilder::from_message_request(request);
                if let Some(edns) = &edns {
                    builder.edns(edns);
                }
                let response = builder.build(
                    metadata,
                    answers.iter(),
                    authorities.iter(),
                    std::iter::empty(),
                    additionals.iter(),
                );
                match response_handle.send_response(response).await {
                    Ok(info) => info,
                    Err(e) => {
                        // Usually a TCP or DoT client that left before a
                        // slow lookup finished: not a server fault.
                        debug!(query = %qname, error = %e, "answer not sent");
                        fallback_response()
                    }
                }
            }
            Err(e) => {
                debug!(query = %qname, error = %e, "recursive resolution failed");
                // Negative answers (NXDOMAIN, NODATA) carry their response
                // code so they pass through instead of SERVFAIL.
                let code = match &e {
                    DaygleError::Resolution {
                        response_code: Some(code),
                        ..
                    } => <ResponseCode as From<u16>>::from(*code),
                    _ => ResponseCode::ServFail,
                };
                // A negative answer is a normal resolution, not an error.
                let negative = matches!(code, ResponseCode::NoError | ResponseCode::NXDomain);
                if !negative {
                    self.metrics.inc(&self.metrics.errors);
                }
                // NODATA for AAAA: DNS64 may have an answer after all.
                if code == ResponseCode::NoError && info.query.query_type() == RecordType::AAAA {
                    if let Some(dns64) = self.dns64_for(client, request) {
                        if let Some(records) = self
                            .synthesize_aaaa(&dns64, resolver.clone(), client, &qname, &[])
                            .await
                        {
                            self.observe(
                                client,
                                &qname,
                                &rtype,
                                protocol,
                                Outcome::Recursive,
                                Some(&rcode_label(ResponseCode::NoError)),
                                started,
                            );
                            return send_recursive_answer(&mut response_handle, request, &records)
                                .await;
                        }
                    }
                }
                self.observe(
                    client,
                    &qname,
                    &rtype,
                    protocol,
                    if negative {
                        Outcome::Recursive
                    } else {
                        Outcome::Error
                    },
                    Some(&rcode_label(code)),
                    started,
                );
                let why = if code == ResponseCode::ServFail {
                    Some(failure_ede(&e))
                } else {
                    None
                };
                send_error(&mut response_handle, request, code, why).await
            }
        }
    }
}

/// An Extended DNS Error (RFC 8914): says why a response is what it is
/// (blocked, filtered, refused, failed upstream...), for clients and tools
/// such as `dig` that show it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ede {
    code: u16,
    text: String,
}

/// RFC 8914 info codes used here.
mod ede {
    pub const OTHER: u16 = 0;
    pub const STALE_ANSWER: u16 = 3;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const BLOCKED: u16 = 15;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const NOT_AUTHORITATIVE: u16 = 20;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
}

impl Ede {
    fn new(code: u16, text: impl Into<String>) -> Self {
        let mut text: String = text.into();
        // Keep the OPT record small: a short explanation is enough.
        if text.len() > 200 {
            let mut end = 200;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        Self { code, text }
    }
}

/// The EDE for a recursive lookup that failed without an answer.
fn failure_ede(error: &DaygleError) -> Ede {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("dnssec") || lower.contains("bogus") {
        Ede::new(ede::DNSSEC_BOGUS, "DNSSEC validation failed")
    } else {
        Ede::new(ede::NO_REACHABLE_AUTHORITY, message)
    }
}

/// Largest UDP response offered in our OPT record (the DNS Flag Day 2020
/// value, which avoids IP fragmentation).
const RESPONSE_UDP_PAYLOAD: u16 = 1232;

/// Size at which the record-use cache drops entries older than a minute.
const RECORD_USE_CACHE_SWEEP_AT: usize = 4096;
/// Hard bound on the record-use cache (see
/// [`DnsDispatcher::first_use_this_minute`]).
const RECORD_USE_CACHE_CAP: usize = 16_384;

/// When each (name, type) - or split-horizon entry - was last recorded as
/// used, by clock minute, and when the map was last swept.
#[derive(Default)]
struct RecordUseCache {
    last_use: HashMap<(String, String), i64>,
    swept_minute: i64,
}

/// The OPT record for a response: only when the client sent one (RFC 6891),
/// echoing its DO bit, and carrying `ede` when given.
fn response_edns(request: &Request, ede: Option<&Ede>) -> Option<hickory_proto::op::Edns> {
    let asked = request.edns.as_ref()?;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(asked.max_payload().clamp(512, RESPONSE_UDP_PAYLOAD));
    edns.set_version(0);
    edns.set_dnssec_ok(asked.flags().dnssec_ok);
    if let Some(ede) = ede {
        let mut data = ede.code.to_be_bytes().to_vec();
        data.extend_from_slice(ede.text.as_bytes());
        edns.options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(15, data));
    }
    Some(edns)
}

impl DnsDispatcher {
    /// The EDNS Client Subnet to send upstream for `client` (`[ecs]`).
    fn client_subnet(&self, client: IpAddr) -> Option<ipnet::IpNet> {
        let config = self.config.as_ref()?.load();
        config.ecs.compile().ok().flatten()?.subnet_for(client)
    }

    /// The DNS64 settings, when they apply to this request: DNS64 is on,
    /// the client is one it serves, and the client did not ask to validate
    /// for itself (DO and CD both set, RFC 6147 §5.5).
    fn dns64_for(
        &self,
        client: IpAddr,
        request: &Request,
    ) -> Option<daygle_dns_core::config::Dns64> {
        let config = self.config.as_ref()?.load();
        let dns64 = config
            .dns64
            .compile(&config.all_networks())
            .ok()
            .flatten()?;
        let validating = request.metadata.checking_disabled
            && request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        (dns64.applies_to(client) && !validating).then_some(dns64)
    }

    /// Whether the encrypted listener a query arrived on carries a
    /// non-empty `allowed_networks` list, and whether `client` is in it:
    /// `Some(allowed)` for a transport with a list, `None` for plain
    /// UDP/TCP, an empty list (the default), or no live config. Entries
    /// are literal addresses/CIDRs or names of Settings -> Networks (the
    /// stored config keeps names).
    fn listener_gate(
        &self,
        client: IpAddr,
        protocol: hickory_server::net::xfer::Protocol,
    ) -> Option<bool> {
        use hickory_server::net::xfer::Protocol as P;
        let config = self.config.as_ref()?.load();
        let networks = match protocol {
            P::Tls => &config.dot.allowed_networks,
            P::Quic => &config.doq.allowed_networks,
            P::Https | P::H3 => &config.doh.allowed_networks,
            _ => return None,
        };
        if networks.is_empty() {
            return None;
        }
        Some(networks.iter().any(|entry| {
            match daygle_dns_core::config::parse_network(entry) {
                Some(net) => net.contains(&client),
                // A Settings -> Networks name. An unresolvable entry
                // matches nobody - the config validator rejects those,
                // and failing open here could expose the listener.
                None => config.named_network(entry).is_some_and(|n| {
                    n.cidrs
                        .iter()
                        .filter_map(|c| daygle_dns_core::config::parse_network(c))
                        .any(|net| net.contains(&client))
                }),
            }
        }))
    }

    /// AAAA records made from `qname`'s A records (with any CNAMEs leading
    /// to them), or `None` when it has no A records to map. Their TTL is
    /// capped by the negative-caching TTL of the empty AAAA answer
    /// (RFC 6147 §5.1.7).
    async fn synthesize_aaaa(
        &self,
        dns64: &daygle_dns_core::config::Dns64,
        resolver: Arc<RecursiveResolver>,
        client: IpAddr,
        qname: &str,
        aaaa_authorities: &[Record],
    ) -> Option<Vec<Record>> {
        let negative_ttl = aaaa_authorities
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) => Some(soa.minimum.min(r.ttl)),
                _ => None,
            })
            .unwrap_or(600);
        let lookup_task = {
            let permit = self.try_recursive_permit()?;
            let subnet = self.client_subnet(client);
            let qname = qname.to_string();
            tokio::spawn(async move {
                let _permit = permit;
                daygle_dns_recursive::with_client_subnet(
                    subnet,
                    resolver.lookup_for_client(client, &qname, RecordType::A),
                )
                .await
            })
        };
        let lookup = tokio::time::timeout(self.client_timeout, lookup_task)
            .await
            .ok()?
            .ok()?
            .ok()?;
        let mut records = Vec::new();
        let mut mapped = 0usize;
        for record in lookup.answers() {
            match &record.data {
                RData::A(a) => {
                    if let Some(v6) = dns64.synthesize(a.0) {
                        records.push(Record::from_rdata(
                            record.name.clone(),
                            record.ttl.min(negative_ttl),
                            RData::AAAA(v6.into()),
                        ));
                        mapped += 1;
                    }
                }
                RData::CNAME(_) => records.push(record.clone()),
                _ => {}
            }
        }
        (mapped > 0).then_some(records)
    }

    /// The first CNAME target in `answers` that the blocklists, the
    /// client's per-client rules or its filtering groups block, with the
    /// blocking decision. Allowlisted targets are skipped.
    async fn blocked_cname_target(
        &self,
        policy: &PolicyEngine,
        client: IpAddr,
        listener: Option<&'static str>,
        answers: &[Record],
    ) -> Option<(String, daygle_dns_policy::Decision)> {
        let groups = self.advanced_blocking.load();
        for record in answers {
            let RData::CNAME(target) = &record.data else {
                continue;
            };
            let name = target
                .0
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if policy.is_allowlisted(&name) {
                continue;
            }
            // Evaluated as an A query: a NODATA from the AAAA filter is not
            // a block of the target.
            let decision = policy.evaluate_on(client, &name, "A", listener).await;
            if !matches!(decision.action, Action::Allow) {
                return Some((name, decision));
            }
            if let Some(decision) = groups.evaluate(client, &name, listener) {
                return Some((name, decision));
            }
        }
        None
    }

    /// Whether `qname` is `_dns.<name>` for a name this server's encrypted
    /// listeners go by, and not hosted in a zone here (RFC 9462 §5).
    fn is_ddr_name(&self, qname: &str) -> bool {
        let Some(name) = qname.strip_prefix("_dns.") else {
            return false;
        };
        let Some(config) = self.config.as_ref().map(|c| c.load()) else {
            return false;
        };
        if !config.ddr.enabled || name.ends_with(".resolver.arpa") || name == "resolver.arpa" {
            return false;
        }
        let hosted = Name::from_ascii(format!("{qname}."))
            .map(|n| self.catalog.contains(&n.into()))
            .unwrap_or(false);
        !hosted
            && self
                .ddr_targets(&config)
                .iter()
                .any(|(_, target)| target.eq_ignore_ascii_case(name))
    }

    /// The enabled encrypted listeners and the name each is reached by:
    /// `ddr.name`, else the name its certificate was made for.
    fn ddr_targets(
        &self,
        config: &daygle_dns_core::config::DaygleConfig,
    ) -> Vec<(&'static str, String)> {
        let name_of = |certificate: &str, server_name: &str| -> String {
            let fixed = config.ddr.name.trim().trim_end_matches('.');
            if !fixed.is_empty() {
                return fixed.to_ascii_lowercase();
            }
            let stored = (!certificate.trim().is_empty())
                .then(|| {
                    self.catalog
                        .store()
                        .get_tls_certificate(certificate.trim())
                        .ok()
                        .flatten()
                })
                .flatten()
                .map(|c| c.server_name);
            stored
                .unwrap_or_else(|| server_name.to_string())
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        };
        let mut out = Vec::new();
        if config.doh.enabled {
            out.push((
                "doh",
                name_of(&config.doh.certificate, &config.doh.server_name),
            ));
        }
        if config.dot.enabled {
            out.push((
                "dot",
                name_of(&config.dot.certificate, &config.dot.server_name),
            ));
        }
        if config.doq.enabled {
            out.push((
                "doq",
                name_of(&config.doq.certificate, &config.doq.server_name),
            ));
        }
        out
    }

    /// The SVCB records (RFC 9461/9462) describing the encrypted listeners
    /// `client` may use, owned by `owner`.
    fn ddr_records(&self, client: IpAddr, owner: &Name) -> Vec<Record> {
        use hickory_proto::rr::rdata::svcb::{
            Alpn, IpHint, SvcParamKey, SvcParamValue, Unknown, SVCB,
        };
        use hickory_server::net::xfer::Protocol as P;
        let Some(config) = self.config.as_ref().map(|c| c.load_full()) else {
            return Vec::new();
        };
        if !config.ddr.enabled {
            return Vec::new();
        }
        let mut records = Vec::new();
        for (priority, (kind, target)) in (1u16..).zip(self.ddr_targets(&config)) {
            let (protocol, listen, port, mut alpn) = match kind {
                "doh" => (
                    P::Https,
                    &config.doh.listen,
                    config.doh.port,
                    vec!["h2".to_string()],
                ),
                "dot" => (
                    P::Tls,
                    &config.dot.listen,
                    config.dot.port,
                    vec!["dot".to_string()],
                ),
                _ => (
                    P::Quic,
                    &config.doq.listen,
                    config.doq.port,
                    vec!["doq".to_string()],
                ),
            };
            // Only listeners this client is allowed on.
            if matches!(self.listener_gate(client, protocol), Some(false)) {
                continue;
            }
            let Ok(target_name) = Name::from_ascii(format!("{target}.")) else {
                continue;
            };
            if kind == "doh" && config.doh.http3 {
                alpn.push("h3".to_string());
            }
            let mut params = vec![
                (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(alpn))),
                (SvcParamKey::Port, SvcParamValue::Port(port)),
            ];
            // Address hints, when the listener is bound to specific addresses.
            let addrs: Vec<IpAddr> = daygle_dns_core::config::listen_socket_addrs(listen, port)
                .unwrap_or_default()
                .into_iter()
                .map(|a| a.ip())
                .filter(|ip| !ip.is_unspecified())
                .collect();
            let v4: Vec<hickory_proto::rr::rdata::A> = addrs
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some((*v4).into()),
                    _ => None,
                })
                .collect();
            let v6: Vec<hickory_proto::rr::rdata::AAAA> = addrs
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some((*v6).into()),
                    _ => None,
                })
                .collect();
            if !v4.is_empty() {
                params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(v4))));
            }
            if !v6.is_empty() {
                params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(v6))));
            }
            if kind == "doh" {
                // dohpath (RFC 9461 §5): the URI template.
                let path = format!("{}{{?dns}}", config.doh.endpoint.trim());
                params.push((
                    SvcParamKey::Unknown(7),
                    SvcParamValue::Unknown(Unknown(path.into_bytes())),
                ));
            }
            records.push(Record::from_rdata(
                owner.clone(),
                DDR_TTL,
                RData::SVCB(SVCB::new(priority, target_name, params)),
            ));
        }
        records
    }

    /// One recursive lookup's answers, or `None` when it failed or there
    /// was no capacity for it.
    async fn resolver_answers(
        &self,
        resolver: Arc<RecursiveResolver>,
        client: IpAddr,
        name: &str,
        rtype: RecordType,
    ) -> Option<Vec<Record>> {
        let lookup_task = {
            let permit = self.try_recursive_permit()?;
            let subnet = self.client_subnet(client);
            let name = name.to_string();
            tokio::spawn(async move {
                let _permit = permit;
                daygle_dns_recursive::with_client_subnet(
                    subnet,
                    resolver.lookup_for_client(client, &name, rtype),
                )
                .await
            })
        };
        let lookup = lookup_task.await.ok()?.ok()?;
        Some(lookup.answers().to_vec())
    }

    /// The name servers of the zone `qname` is in: the closest enclosing
    /// name with NS records (stopping above the top-level domain), and with
    /// `with_ips` the addresses of the first few of them.
    async fn name_servers_of(
        &self,
        resolver: Arc<RecursiveResolver>,
        client: IpAddr,
        qname: &str,
        with_ips: bool,
    ) -> daygle_dns_authoritative::rpz::NameServers {
        let mut found = daygle_dns_authoritative::rpz::NameServers::default();
        let mut candidate = qname;
        loop {
            let answers = self
                .resolver_answers(Arc::clone(&resolver), client, candidate, RecordType::NS)
                .await
                .unwrap_or_default();
            found.names = answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::NS(ns) => {
                        Some(ns.0.to_ascii().trim_end_matches('.').to_ascii_lowercase())
                    }
                    _ => None,
                })
                .collect();
            if !found.names.is_empty() {
                break;
            }
            match candidate.split_once('.') {
                Some((_, parent)) if parent.contains('.') => candidate = parent,
                _ => break,
            }
        }
        if with_ips {
            for name in found.names.clone().iter().take(4) {
                for rtype in [RecordType::A, RecordType::AAAA] {
                    for record in self
                        .resolver_answers(Arc::clone(&resolver), client, name, rtype)
                        .await
                        .unwrap_or_default()
                    {
                        match &record.data {
                            RData::A(a) => found.ips.push(IpAddr::V4(a.0)),
                            RData::AAAA(a) => found.ips.push(IpAddr::V6(a.0)),
                            _ => {}
                        }
                    }
                }
            }
        }
        found
    }

    /// With the block page on, how a blocked query of `qtype` is answered
    /// instead of NXDOMAIN: `Some(Some(ip))` with the page's address,
    /// `Some(None)` empty (NODATA); `None` leaves it to NXDOMAIN.
    fn block_page_answer(&self, qtype: RecordType) -> Option<Option<IpAddr>> {
        let config = self.config.as_ref()?.load();
        let page = &config.block_page;
        if !page.enabled {
            return None;
        }
        let v4 = page.ipv4.trim().parse::<std::net::Ipv4Addr>().ok();
        let v6 = page.ipv6.trim().parse::<std::net::Ipv6Addr>().ok();
        match qtype {
            RecordType::A => v4.map(|ip| Some(IpAddr::V4(ip))),
            RecordType::AAAA if v4.is_some() || v6.is_some() => Some(v6.map(IpAddr::V6)),
            // No other endpoints for browsers to try.
            RecordType::HTTPS | RecordType::SVCB if v4.is_some() || v6.is_some() => Some(None),
            _ => None,
        }
    }

    /// Answer a blocked query with the block page's address (or empty),
    /// remembering why for the page.
    #[allow(clippy::too_many_arguments)]
    async fn serve_block_page<R: ResponseHandler>(
        &self,
        response_handle: &mut R,
        request: &Request,
        client: IpAddr,
        qname: &str,
        reason: &str,
        answer: Option<IpAddr>,
    ) -> ResponseInfo {
        let why = Some(Ede::new(ede::BLOCKED, reason.to_string()));
        let Some(ip) = answer else {
            return send_empty(response_handle, request, why).await;
        };
        self.block_log.record(client, qname, reason);
        let Some(query) = request.queries.queries().first() else {
            return send_error(response_handle, request, ResponseCode::FormErr, None).await;
        };
        let name = Name::from(query.name().clone());
        send_redirect(response_handle, request, &name, query.query_type(), ip, why).await
    }

    /// Carry out a response policy zone's action.
    #[allow(clippy::too_many_arguments)]
    async fn serve_rpz<R: ResponseHandler>(
        &self,
        hit: daygle_dns_authoritative::rpz::RpzHit,
        request: &Request,
        response_handle: &mut R,
        client: IpAddr,
        qname: &str,
        rtype: &str,
        protocol: &str,
        started: Instant,
    ) -> ResponseInfo {
        use daygle_dns_authoritative::rpz::RpzAction;
        debug!(query = %qname, zone = %hit.zone, trigger = %hit.trigger, action = hit.action.label(), "response policy zone");
        self.metrics.inc(&self.metrics.rpz_hits);
        self.metrics.inc(&self.metrics.blocked);
        let why = || {
            Some(Ede::new(
                ede::BLOCKED,
                format!("response policy zone {}: {}", hit.zone, hit.trigger),
            ))
        };
        let observe = |rcode: &str| {
            self.observe_blocked(
                client,
                qname,
                rtype,
                protocol,
                Some(rcode),
                started,
                block_reason(
                    source::RPZ,
                    None,
                    Some(hit.zone.clone()),
                    format!("response policy zone {}: {}", hit.zone, hit.trigger),
                ),
            )
        };
        match &hit.action {
            // PASSTHRU never gets here (the callers carry on instead).
            RpzAction::NxDomain | RpzAction::Passthru => {
                observe("NXDOMAIN");
                send_error(response_handle, request, ResponseCode::NXDomain, why()).await
            }
            RpzAction::NoData => {
                observe("NOERROR");
                send_empty(response_handle, request, why()).await
            }
            RpzAction::Drop => {
                observe("DROPPED");
                fallback_response()
            }
            RpzAction::TcpOnly => {
                observe("TRUNCATED");
                send_truncated(response_handle, request).await
            }
            RpzAction::Local(records) => {
                let Some(query) = request.queries.queries().first() else {
                    return send_error(response_handle, request, ResponseCode::FormErr, None).await;
                };
                let owner = Name::from(query.name().clone());
                let qtype = query.query_type();
                let matching: Vec<Record> = records
                    .iter()
                    .filter(|r| r.rtype == qtype || qtype == RecordType::ANY)
                    .map(|r| Record::from_rdata(owner.clone(), r.ttl, r.rdata.clone()))
                    .collect();
                if !matching.is_empty() {
                    observe("NOERROR");
                    return send_records(response_handle, request, &matching, why()).await;
                }
                let cname = records.iter().find_map(|r| match &r.rdata {
                    RData::CNAME(target) => Some((r.ttl, target.0.clone())),
                    _ => None,
                });
                let Some((ttl, target)) = cname else {
                    observe("NOERROR");
                    return send_empty(response_handle, request, why()).await;
                };
                // `*.garden.example.` stands for the query name under the
                // garden.
                let target = match target.to_ascii().strip_prefix("*.") {
                    Some(rest) => Name::from_ascii(format!("{qname}.{rest}")).unwrap_or(target),
                    None => target,
                };
                let mut answers = vec![Record::from_rdata(
                    owner,
                    ttl,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                )];
                if qtype != RecordType::CNAME {
                    let alias = daygle_dns_authoritative::catalog::Alias {
                        target: target.to_ascii(),
                        ttl,
                    };
                    let (rcode, records, _) = self.resolve_alias(alias, client, qtype).await;
                    if rcode == ResponseCode::NoError {
                        answers.extend(
                            records
                                .into_iter()
                                .map(|(ttl, rdata)| Record::from_rdata(target.clone(), ttl, rdata)),
                        );
                    }
                }
                observe("NOERROR");
                send_records(response_handle, request, &answers, why()).await
            }
        }
    }

    /// The Safe Search address to answer `qname` with for `client`, if any:
    /// the global switches apply to everyone, and the first filtering group
    /// a client belongs to can turn them on for its clients.
    fn safe_search_target(
        &self,
        policy: &PolicyEngine,
        client: IpAddr,
        listener: Option<&str>,
        qname: &str,
    ) -> Option<&'static str> {
        use daygle_dns_policy::safe_search::safe_target;
        // Most names are no search engine at all: skip the group lookup.
        safe_target(qname, true, true)?;
        let (mut search, mut youtube) = (policy.safe_search(), policy.youtube_restricted());
        if !(search && youtube) {
            let (s, y, _) = self.advanced_blocking.load().safe_search(client, listener);
            search |= s;
            youtube |= y;
        }
        safe_target(qname, search, youtube)
    }

    /// Look up an ALIAS target's `rtype` records: from the zones here when
    /// the target is hosted (following ALIAS chains a few steps), otherwise
    /// through the resolver. Returns the response code, the answers' TTLs
    /// (capped by the ALIAS's) and data, and an EDE for a failure.
    async fn resolve_alias(
        &self,
        alias: daygle_dns_authoritative::catalog::Alias,
        client: IpAddr,
        rtype: RecordType,
    ) -> (ResponseCode, Vec<(u32, RData)>, Option<Ede>) {
        let mut target = alias.target;
        let mut ttl = alias.ttl;
        for _ in 0..8 {
            match self.catalog.alias(&target) {
                Some(next) => {
                    ttl = ttl.min(next.ttl);
                    target = next.target;
                }
                None => break,
            }
        }
        let collect = |records: Vec<Record>| -> Vec<(u32, RData)> {
            records
                .into_iter()
                .filter(|r| r.record_type() == rtype)
                .map(|r| (r.ttl.min(ttl), r.data.clone()))
                .collect()
        };
        let hosted = Name::from_utf8(&target)
            .map(|n| self.catalog.contains(&n.into()))
            .unwrap_or(false);
        if hosted {
            return match self.catalog.local_records(&target, rtype) {
                Ok(records) => (ResponseCode::NoError, collect(records), None),
                Err(e) => (
                    ResponseCode::ServFail,
                    Vec::new(),
                    Some(Ede::new(ede::OTHER, format!("ALIAS target {target}: {e}"))),
                ),
            };
        }
        let Some(resolver) = self.resolver.load_full() else {
            return (
                ResponseCode::ServFail,
                Vec::new(),
                Some(Ede::new(
                    ede::NOT_AUTHORITATIVE,
                    format!("recursion is off, so the ALIAS target {target} cannot be looked up"),
                )),
            );
        };
        let lookup_task = {
            let Some(permit) = self.try_recursive_permit() else {
                return (
                    ResponseCode::ServFail,
                    Vec::new(),
                    Some(Ede::new(ede::OTHER, "recursive lookup capacity exhausted")),
                );
            };
            let subnet = self.client_subnet(client);
            let target = target.trim_end_matches('.').to_string();
            tokio::spawn(async move {
                let _permit = permit;
                daygle_dns_recursive::track_stale(daygle_dns_recursive::with_client_subnet(
                    subnet,
                    resolver.lookup(&target, rtype),
                ))
                .await
            })
        };
        let lookup = tokio::time::timeout(self.client_timeout, lookup_task).await;
        match lookup {
            Ok(Ok((Ok(found), _stale))) => (
                ResponseCode::NoError,
                collect(found.answers().to_vec()),
                None,
            ),
            // The target has no such records (or does not exist): the alias
            // name exists here, so that is NODATA, not NXDOMAIN.
            Ok(Ok((
                Err(DaygleError::Resolution {
                    response_code: Some(0 | 3),
                    ..
                }),
                _stale,
            ))) => (ResponseCode::NoError, Vec::new(), None),
            Ok(Ok((Err(e), _stale))) => (ResponseCode::ServFail, Vec::new(), Some(failure_ede(&e))),
            Ok(Err(e)) => (
                ResponseCode::ServFail,
                Vec::new(),
                Some(Ede::new(ede::OTHER, e.to_string())),
            ),
            Err(_) => (
                ResponseCode::ServFail,
                Vec::new(),
                Some(Ede::new(
                    ede::NO_REACHABLE_AUTHORITY,
                    format!("no answer for the ALIAS target {target} in time"),
                )),
            ),
        }
    }
}

/// Send a response with only an error code.
/// A block reason for the query logs.
fn block_reason(
    source: &str,
    group: Option<String>,
    matched: Option<String>,
    reason: impl Into<String>,
) -> BlockReason {
    BlockReason {
        source: source.to_string(),
        group,
        matched,
        reason: reason.into(),
    }
}

/// The block reason of a policy or filtering-group decision.
fn block_reason_of(decision: &daygle_dns_policy::Decision) -> BlockReason {
    block_reason(
        if decision.source.is_empty() {
            source::PLUGIN
        } else {
            decision.source
        },
        decision.group.clone(),
        decision.matched.clone(),
        decision.reason.clone(),
    )
}

/// The block reason of a query whose answer led, through a CNAME, to the
/// blocked name `target`.
fn cname_block_reason(target: &str, decision: &daygle_dns_policy::Decision) -> BlockReason {
    block_reason(
        source::CNAME,
        decision.group.clone(),
        Some(target.to_string()),
        format!("CNAME target {target} is blocked: {}", decision.reason),
    )
}

async fn send_error<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    code: ResponseCode,
    ede: Option<Ede>,
) -> ResponseInfo {
    let edns = response_edns(request, ede.as_ref());
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let response = builder.error_msg(&request.metadata, code);
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            debug!("failed to send error response: {e}");
            fallback_response()
        }
    }
}

/// Upper-case DNS name for a response code, for the persistent query log.
fn rcode_label(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        ResponseCode::FormErr => "FORMERR".to_string(),
        ResponseCode::NotImp => "NOTIMP".to_string(),
        other => format!("{other:?}").to_uppercase(),
    }
}

/// Transport label for a query, recorded in the SQLite query log.
fn protocol_label(protocol: hickory_server::net::xfer::Protocol) -> &'static str {
    use hickory_server::net::xfer::Protocol as P;
    match protocol {
        P::Udp => "udp",
        P::Tcp => "tcp",
        P::Tls => "tls",
        P::Https => "https",
        P::H3 => "h3",
        P::Quic => "quic",
        _ => "other",
    }
}

/// Stable lowercase label for a query outcome, used in the persistent log.
fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Authoritative => "authoritative",
        Outcome::Recursive => "recursive",
        Outcome::SplitHorizon => "split_horizon",
        Outcome::Blocked => "blocked",
        Outcome::RateLimited => "rate_limited",
        Outcome::Error => "error",
    }
}

/// Send an empty NODATA response: NOERROR with no answer records, echoing the
/// question. Used by the AAAA filter so dual-stack clients fall back to IPv4
/// (an NXDOMAIN would wrongly claim the whole name does not exist).
async fn send_empty<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    ede: Option<Ede>,
) -> ResponseInfo {
    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = ResponseCode::NoError;
    metadata.recursion_available = true;

    let edns = response_edns(request, ede.as_ref());
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let response = builder.build(
        metadata,
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            debug!("failed to send empty answer: {e}");
            fallback_response()
        }
    }
}

/// Whether an RPZ action lets the query carry on as usual: PASSTHRU, and
/// TCP-only over anything but UDP.
fn rpz_lets_through(
    action: &daygle_dns_authoritative::rpz::RpzAction,
    protocol: hickory_server::net::xfer::Protocol,
) -> bool {
    use daygle_dns_authoritative::rpz::RpzAction;
    match action {
        RpzAction::Passthru => true,
        RpzAction::TcpOnly => protocol != hickory_server::net::xfer::Protocol::Udp,
        _ => false,
    }
}

/// Send an empty, truncated (TC) answer: the client retries over TCP.
async fn send_truncated<R: ResponseHandler>(handle: &mut R, request: &Request) -> ResponseInfo {
    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = ResponseCode::NoError;
    metadata.recursion_available = true;
    metadata.truncation = true;
    let edns = response_edns(request, None);
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    match handle
        .send_response(builder.build_no_records(metadata))
        .await
    {
        Ok(info) => info,
        Err(e) => {
            debug!("failed to send truncated answer: {e}");
            fallback_response()
        }
    }
}

/// Send a response whose answer section is exactly `records`.
async fn send_records<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    records: &[Record],
    ede: Option<Ede>,
) -> ResponseInfo {
    if records.is_empty() {
        return send_error(handle, request, ResponseCode::NXDomain, ede).await;
    }

    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = ResponseCode::NoError;
    metadata.authoritative = true;
    metadata.recursion_available = true;

    let edns = response_edns(request, ede.as_ref());
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let response = builder.build(
        metadata,
        records.iter(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            debug!("failed to send answer: {e}");
            fallback_response()
        }
    }
}

/// Send `records` as a recursive (not authoritative, not validated) answer.
async fn send_recursive_answer<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    records: &[Record],
) -> ResponseInfo {
    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = ResponseCode::NoError;
    metadata.recursion_available = true;
    metadata.authentic_data = false;
    let edns = response_edns(request, None);
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let response = builder.build(
        metadata,
        records.iter(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            debug!("failed to send answer: {e}");
            fallback_response()
        }
    }
}

/// Synthesize a single-address redirect answer (policy `redirect` action).
///
/// A query whose type the redirect target cannot answer (e.g. AAAA for a
/// specific IPv4 address, or MX) gets an empty NOERROR (NODATA) response: the name is
/// deliberately made to exist, so NXDOMAIN would wrongly tell caching
/// resolvers that no record of *any* type exists for it (RFC 8020).
async fn send_redirect<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    name: &Name,
    rtype: RecordType,
    ip: IpAddr,
    ede: Option<Ede>,
) -> ResponseInfo {
    let rdata = match (ip, rtype) {
        (IpAddr::V4(v4), RecordType::A | RecordType::ANY) => RData::A(v4.into()),
        (IpAddr::V6(v6), RecordType::AAAA | RecordType::ANY) => RData::AAAA(v6.into()),
        // A null sinkhole (0.0.0.0 or ::) answers the other family with its
        // own null address too, as Pi-hole and AdGuard do, so IPv6 clients
        // are blocked as plainly as IPv4 ones.
        (IpAddr::V4(v4), RecordType::AAAA) if v4.is_unspecified() => {
            RData::AAAA(std::net::Ipv6Addr::UNSPECIFIED.into())
        }
        (IpAddr::V6(v6), RecordType::A) if v6.is_unspecified() => {
            RData::A(std::net::Ipv4Addr::UNSPECIFIED.into())
        }
        _ => return send_empty(handle, request, ede).await,
    };
    let record = Record::from_rdata(name.clone(), 60, rdata);
    send_records(handle, request, std::slice::from_ref(&record), ede).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_acl_accepts_bare_addresses_and_networks() {
        let client: IpAddr = "192.0.2.10".parse().unwrap();
        // A bare address passes the config check, so it must match too.
        assert!(transfer_client_allowed(&["192.0.2.10".to_string()], client));
        assert!(transfer_client_allowed(
            &["192.0.2.0/24".to_string()],
            client
        ));
        assert!(!transfer_client_allowed(
            &["192.0.2.11".to_string()],
            client
        ));
        assert!(!transfer_client_allowed(
            &["not-a-network".to_string()],
            client
        ));
        assert!(transfer_client_allowed(&[], client));
    }

    #[test]
    fn failures_map_to_extended_errors() {
        let failure = |message: &str| DaygleError::Resolution {
            message: message.to_string(),
            response_code: None,
        };
        assert_eq!(
            failure_ede(&failure("DNSSEC validation failed")).code,
            ede::DNSSEC_BOGUS
        );
        let timeout = failure_ede(&failure("no answer within the client timeout of 2000 ms"));
        assert_eq!(timeout.code, ede::NO_REACHABLE_AUTHORITY);
        assert!(timeout.text.contains("client timeout"));
    }

    #[test]
    fn extended_error_text_is_kept_short() {
        let long = "é".repeat(300);
        let e = Ede::new(ede::BLOCKED, long);
        assert!(e.text.len() <= 200);
        assert!(e.text.chars().all(|c| c == 'é'));
    }

    #[test]
    fn recursive_admission_holds_capacity_until_permit_drop_and_respects_reload() {
        let admission = Arc::new(RecursiveAdmission::new(1));
        let permit = admission.try_acquire().expect("initial slot");
        assert!(admission.try_acquire().is_none());
        admission.set_limit(2);
        let second = admission.try_acquire().expect("raised limit admits");
        assert!(admission.try_acquire().is_none());
        drop(permit);
        assert!(admission.try_acquire().is_some());
        admission.set_limit(1);
        assert!(admission.try_acquire().is_none());
        drop(second);
    }
}
