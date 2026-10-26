//! Response rate limiting (RRL) on the way out: every UDP response is
//! counted against the client network's account for that response (see
//! [`daygle_dns_core::rrl`]), and dropped or sent truncated when the
//! account is over its rate.

use std::net::IpAddr;
use std::sync::Arc;

use daygle_dns_core::rrl::{ResponseClass, ResponseRateLimiter, Verdict};
use daygle_dns_core::Metrics;
use hickory_proto::op::{Header, HeaderCounts, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::BinDecoder;
use hickory_server::net::NetError;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder, Queries};

/// What a response is counted against.
#[derive(Clone)]
struct Context {
    limiter: Arc<ResponseRateLimiter>,
    metrics: Arc<Metrics>,
    client: IpAddr,
    /// Query name (lowercase, no trailing dot) and type.
    name: String,
    rtype: String,
    /// The question section as received, to build a truncated reply.
    queries: Box<[u8]>,
    query_count: usize,
}

/// Wraps a response handler with response rate limiting.
#[derive(Clone)]
pub struct RrlResponder<R> {
    inner: R,
    context: Option<Context>,
}

impl<R> RrlResponder<R> {
    /// Limit responses to `request` from `client` when `limiter` is on and
    /// the request came over UDP (a TCP client's address is proven, so it
    /// cannot be a reflection victim). `verified` (a valid DNS cookie)
    /// likewise exempts the request.
    pub fn new(
        inner: R,
        request: &Request,
        client: IpAddr,
        verified: bool,
        limiter: &Arc<ResponseRateLimiter>,
        metrics: &Arc<Metrics>,
    ) -> Self {
        let udp = request.protocol() == hickory_server::net::xfer::Protocol::Udp;
        let context = (udp && !verified && limiter.enabled())
            .then(|| {
                let query = request.queries.queries().first()?;
                Some(Context {
                    limiter: Arc::clone(limiter),
                    metrics: Arc::clone(metrics),
                    client,
                    name: query
                        .name()
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                    rtype: query.query_type().to_string(),
                    queries: request.queries.as_bytes().into(),
                    query_count: request.queries.len(),
                })
            })
            .flatten();
        Self { inner, context }
    }
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for RrlResponder<R> {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let Some(context) = &self.context else {
            return self.inner.send_response(response).await;
        };
        let (class, name) = match response.metadata().response_code {
            ResponseCode::NoError => (
                ResponseClass::Answer,
                format!("{}/{}", context.name, context.rtype),
            ),
            ResponseCode::NXDomain => (ResponseClass::NxDomain, context.name.clone()),
            _ => (ResponseClass::Error, String::new()),
        };
        let verdict = context.limiter.check(context.client, class, &name);
        if verdict == Verdict::Send {
            return self.inner.send_response(response).await;
        }
        if context.limiter.log_only() {
            context.metrics.inc(&context.metrics.rrl_would_limit);
            return self.inner.send_response(response).await;
        }
        let mut metadata = *response.metadata();
        match verdict {
            Verdict::Slip => {
                context.metrics.inc(&context.metrics.rrl_slipped);
                metadata.truncation = true;
                let mut decoder = BinDecoder::new(&context.queries);
                let Ok(queries) = Queries::read(&mut decoder, context.query_count) else {
                    return Ok(ResponseInfo::from(Header {
                        metadata,
                        counts: HeaderCounts::default(),
                    }));
                };
                let truncated = MessageResponseBuilder::new(&queries, response.edns())
                    .build_no_records(metadata);
                self.inner.send_response(truncated).await
            }
            _ => {
                // Dropped: nothing goes out.
                context.metrics.inc(&context.metrics.rrl_dropped);
                Ok(ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }))
            }
        }
    }
}
