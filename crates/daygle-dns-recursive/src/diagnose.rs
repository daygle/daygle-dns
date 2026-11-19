//! Diagnostic lookups for the console's Lookup page: resolve one name the
//! way client queries are resolved, and report how it went - the route it
//! took, the answer or the failure and its reason, and every query sent
//! upstream on the way.

use std::sync::Arc;
use std::time::{Duration, Instant};

use daygle_dns_core::error::{DaygleError, Result};
use hickory_proto::dnssec::Proof;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

use crate::recursor::{self, rcode_name, RecursorSlot, TraceStep};
use crate::{reject_bogus, track_negative_soa, RecursiveResolver, Route, RouteKind};

/// One record of a diagnostic answer.
#[derive(Debug, Clone)]
pub struct DiagnosticRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
    /// The DNSSEC verdict: `secure`, `insecure`, `bogus` or
    /// `indeterminate` (not validated).
    pub dnssec: &'static str,
}

/// How a diagnostic lookup went.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    /// The name asked, fully qualified.
    pub name: String,
    pub record_type: String,
    /// How the name is resolved: `recursive`, `forwarding`, `conditional`,
    /// `stub` or `local-root`.
    pub route: &'static str,
    /// Whether the lookup started from empty caches.
    pub fresh: bool,
    /// The response code a client would get.
    pub rcode: String,
    pub answers: Vec<DiagnosticRecord>,
    /// The zone whose SOA came with a negative answer.
    pub negative_zone: Option<String>,
    /// Why the lookup failed, for a failure (not for NXDOMAIN or NODATA).
    pub error: Option<String>,
    pub elapsed: Duration,
    /// Whether DNSSEC validation is on.
    pub dnssec_validation: bool,
    /// Every query sent upstream, in the order the queries were sent. A
    /// query that got no reply is listed with the reason it was given up on.
    pub trace: Vec<TraceStep>,
}

fn route_label(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::Recursive | RouteKind::ClientPolicy => "recursive",
        RouteKind::Forwarding => "forwarding",
        RouteKind::Conditional => "conditional",
        RouteKind::Stub => "stub",
        RouteKind::LocalRoot => "local-root",
    }
}

fn proof_label(proof: Proof) -> &'static str {
    match proof {
        Proof::Secure => "secure",
        Proof::Insecure => "insecure",
        Proof::Bogus => "bogus",
        _ => "indeterminate",
    }
}

impl RecursiveResolver {
    /// Resolve `name`/`record_type` for the diagnostics page and report
    /// how it went. Filtering does not apply, and neither do client
    /// resolution policies: this is the default route.
    ///
    /// With `fresh`, recursive lookups go through a recursor of their own
    /// with empty caches, so every step from the root servers is taken
    /// (and traced) as for a name never seen before, and forwarded names
    /// are flushed from the cache first. Without it, cached answers are
    /// used as for a client query, but the separate failure cache is not,
    /// so a failure is retried and its reason reported.
    pub async fn diagnose(&self, name: &str, record_type: &str, fresh: bool) -> Result<Diagnosis> {
        let mut qname = Name::from_utf8(name.trim())
            .map_err(|e| DaygleError::InvalidRecord(format!("invalid name '{name}': {e}")))?;
        qname.set_fqdn(true);
        let rtype: RecordType = record_type
            .trim()
            .to_ascii_uppercase()
            .parse()
            .map_err(|_| {
                DaygleError::InvalidRecord(format!("unknown record type '{record_type}'"))
            })?;

        let inner = &self.inner;
        let (route, kind, _) = inner.route(&qname, None, false);
        let route = match route {
            Route::Recursive(slot) if fresh => {
                let recursor =
                    recursor::build(&inner.settings, slot.local_root, inner.metrics.clone())?;
                Route::Recursive(Arc::new(RecursorSlot::new(
                    recursor,
                    slot.local_root,
                    &inner.settings,
                )))
            }
            Route::Forward(resolver) if fresh => {
                self.flush_name(&qname.to_string(), Some(&rtype.to_string()))?;
                Route::Forward(resolver)
            }
            route => route,
        };

        let started = Instant::now();
        let ((result, negative), trace) =
            recursor::trace_queries(track_negative_soa(route.lookup(qname.clone(), rtype))).await;
        let elapsed = started.elapsed();
        let result = reject_bogus(&inner.settings, result);

        let negative_zone = negative.map(|n| n.soa.name.to_string());
        let (rcode, answers, error, negative_zone) = match result {
            Ok(lookup) => {
                let answers = lookup
                    .answers()
                    .iter()
                    .map(|r| DiagnosticRecord {
                        name: r.name.to_string(),
                        record_type: r.record_type().to_string(),
                        ttl: r.ttl,
                        data: r.data.to_string(),
                        dnssec: proof_label(r.proof),
                    })
                    .collect();
                ("NOERROR".to_string(), answers, None, None)
            }
            Err(DaygleError::Resolution {
                message,
                response_code: Some(code),
            }) => {
                let code = <ResponseCode as From<u16>>::from(code);
                // NXDOMAIN and NODATA are answers, not failures.
                let error = (!matches!(code, ResponseCode::NoError | ResponseCode::NXDomain))
                    .then_some(message);
                (rcode_name(code), Vec::new(), error, negative_zone)
            }
            Err(e) => (
                "SERVFAIL".to_string(),
                Vec::new(),
                Some(e.to_string()),
                None,
            ),
        };

        Ok(Diagnosis {
            name: qname.to_string(),
            record_type: rtype.to_string(),
            route: route_label(kind),
            fresh,
            rcode,
            answers,
            negative_zone,
            error,
            elapsed,
            dnssec_validation: inner.settings.dnssec_validate,
            trace,
        })
    }
}
