//! # DNS over HTTPS (RFC 8484) listener
//!
//! Built directly on `tokio-rustls` and `h2` rather than Hickory's HTTPS
//! listener, which cannot answer the standard's GET method (`?dns=`,
//! RFC 8484 §4.1): its request decoder rejects GET out of hand, and clients
//! such as `dig +https` send GET by default. Here, on each connection:
//!
//! - `GET /<endpoint>?dns=<base64url>` and `POST /<endpoint>` (with an
//!   `application/dns-message` body) are both accepted and fed into the same
//!   dispatcher as the other listeners, so filtering, DNSSEC validation and
//!   access control apply identically to both methods;
//! - to keep the surface identical with DoT, admission is part of the
//!   listener: at most `doh.max_connections` connections (handshakes
//!   included, an eighth per public client), and a trusted load balancer's
//!   PROXY header (`server.proxy_protocol`) names the real client, which
//!   every limit, ACL and log then sees.
//!
//! Like Hickory's listener, a connection or its streams are dropped when the
//! client goes silent for `doh.handshake_timeout_secs`, and a malformed
//! HTTP request gets an HTTP error status rather than a DNS FORMERR, which
//! is valid behavior for the HTTP layer (RFC 8484 §4.1).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use hickory_proto::op::MessageType;
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use http::{Method, Response, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::dispatcher::DnsDispatcher;
use crate::dot::{error_message, per_client_limit, ClientSlots};
use crate::tls_diag::{SessionLog, HTTPS};

/// How long a trusted load balancer has to send its PROXY header (the DoT
/// listener uses the same bound).
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest encoded message the `dns` parameter or the POST body may carry
/// (the EDNS payload cap is smaller, but a valid request may ask for one,
/// so the message envelope itself is bounded by this).
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// The `application/dns-message` media type (RFC 8484 §2.1).
const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// Listener settings.
#[derive(Clone)]
pub struct DohOptions {
    /// Connections served at once, TLS handshakes included (IPv6 clients per
    /// /64, as with DoT).
    pub max_connections: usize,
    /// The TLS handshake timeout, which is also the HTTP/2 idle timeout.
    pub timeout: Duration,
    /// Load balancers whose PROXY header names the real client.
    pub proxy_trusted: Option<Arc<Vec<ipnet::IpNet>>>,
    /// The HTTP path that serves DNS messages, e.g. `/dns-query`.
    pub endpoint: String,
}

/// Serve DoH on `listener` until `shutdown` is cancelled.
pub async fn serve_doh(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    shutdown: CancellationToken,
    options: DohOptions,
) {
    let acceptor = TlsAcceptor::from(tls);
    let sessions = Arc::new(Semaphore::new(options.max_connections));
    let clients = Arc::new(ClientSlots::new(per_client_limit(options.max_connections)));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    debug!(%error, "DoH accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            debug!(%peer, "DoH connection refused: listener at max_connections");
            continue;
        };
        let connection = Connection {
            acceptor: acceptor.clone(),
            handler: handler.clone(),
            session: session.clone(),
            clients: clients.clone(),
            options: options.clone(),
            shutdown: shutdown.clone(),
        };
        connections.spawn(async move {
            let _permit = permit;
            connection.run(stream, peer).await;
        });
    }
    // Dropping the set aborts every live session.
    connections.shutdown().await;
}

/// One accepted connection: TLS, then one HTTP/2 connection whose streams
/// are answered concurrently.
struct Connection {
    acceptor: TlsAcceptor,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    clients: Arc<ClientSlots>,
    options: DohOptions,
    shutdown: CancellationToken,
}

impl Connection {
    async fn run(self, mut stream: TcpStream, peer: SocketAddr) {
        let _ = stream.set_nodelay(true);
        let peer_ip = peer.ip().to_canonical();

        let client = match &self.options.proxy_trusted {
            Some(trusted) if trusted.iter().any(|net| net.contains(&peer_ip)) => {
                match tokio::time::timeout(
                    PROXY_HEADER_TIMEOUT,
                    crate::proxy_protocol::read_header(&mut stream),
                )
                .await
                {
                    Ok(Ok(client)) => client.unwrap_or(peer),
                    Ok(Err(e)) => {
                        self.session.record(
                            HTTPS,
                            Some(peer_ip),
                            &format!("bad PROXY header: {e}"),
                        );
                        return;
                    }
                    Err(_) => {
                        self.session
                            .record(HTTPS, Some(peer_ip), "no PROXY header in time");
                        return;
                    }
                }
            }
            _ => peer,
        };
        let client = SocketAddr::new(client.ip().to_canonical(), client.port());

        let Some(_slot) = self.clients.acquire(client.ip()) else {
            self.session.record(
                HTTPS,
                Some(client.ip()),
                "connection refused: too many connections from this client",
            );
            return;
        };

        let tls =
            match tokio::time::timeout(self.options.timeout, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                // Connected and closed (or reset) without a word: a load
                // balancer's or monitor's TCP check, or a port scan.
                Ok(Err(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    debug!(%client, "DoH connection closed before the TLS handshake");
                    return;
                }
                Ok(Err(e)) => {
                    self.session.record(
                        HTTPS,
                        Some(client.ip()),
                        &format!("TLS handshake failed: {e}"),
                    );
                    return;
                }
                Err(_) => {
                    self.session
                        .record(HTTPS, Some(client.ip()), "TLS handshake timed out");
                    return;
                }
            };
        self.serve(tls, client).await;
    }

    /// Serve HTTP/2 until the client closes, goes idle or the listener
    /// stops; answer each DNS request concurrently.
    async fn serve(self, tls: tokio_rustls::server::TlsStream<TcpStream>, client: SocketAddr) {
        let idle = self.options.timeout;
        let mut h2 = match h2::server::handshake(tls).await {
            Ok(h2) => h2,
            Err(e) => {
                debug!(%client, %e, "DoH HTTP/2 handshake failed");
                return;
            }
        };
        loop {
            let accept = tokio::select! {
                _ = self.shutdown.cancelled() => return,
                accept = tokio::time::timeout(idle, h2.accept()) => accept,
            };
            let Ok(Some(Ok((request, respond)))) = accept else {
                // Idle past the timeout, connection closed, or a request
                // error: drop. DoH connection churn is routine, so failures
                // here are debug-only (like Hickory's listener).
                return;
            };
            let handler = self.handler.clone();
            let endpoint = self.options.endpoint.clone();
            let session = self.session.clone();
            tokio::spawn(async move {
                if let Err(detail) =
                    answer(request, respond, client, handler, &endpoint, idle, &session).await
                {
                    debug!(%client, detail, "DoH request rejected");
                }
            });
        }
    }
}

/// Decode and answer one HTTP/2 request.
///
/// Returns the detail for the caller's debug log on rejection (everything
/// the client can learn has already been sent as an HTTP status).
async fn answer(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    client: SocketAddr,
    handler: DnsDispatcher,
    endpoint: &str,
    timeout: Duration,
    session: &SessionLog,
) -> Result<(), String> {
    let (parts, mut body) = request.into_parts();
    if parts.uri.path() != endpoint {
        return Err(rejected(
            session,
            client,
            &mut respond,
            StatusCode::NOT_FOUND,
            "bad path",
        ));
    }
    let bytes = match parts.method {
        Method::GET => {
            // RFC 8484 §4.1: GET with `dns=` (base64url) carries the
            // message; other query parameters are ignored.
            let Some(dns) = parts
                .uri
                .query()
                .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("dns=")))
            else {
                return Err(reject(
                    &mut respond,
                    StatusCode::BAD_REQUEST,
                    "missing dns parameter",
                ));
            };
            decode_dns_param(dns)
                .map_err(|e| rejected(session, client, &mut respond, StatusCode::BAD_REQUEST, e))?
        }
        Method::POST => {
            match parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .map(|v| v.to_str())
            {
                Some(Ok(ctype)) if ctype == MIME_APPLICATION_DNS => {}
                _ => {
                    return Err(reject(
                        &mut respond,
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "unsupported content type",
                    ))
                }
            }
            fetch_body(&mut body, timeout)
                .await
                .map_err(|e| rejected(session, client, &mut respond, StatusCode::BAD_REQUEST, e))?
        }
        _ => {
            return Err(reject(
                &mut respond,
                StatusCode::METHOD_NOT_ALLOWED,
                "bad method",
            ))
        }
    };
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(reject(
            &mut respond,
            StatusCode::PAYLOAD_TOO_LARGE,
            "message too long",
        ));
    }

    let request = match Request::from_bytes(bytes, client, Protocol::Https) {
        Ok(request) => request,
        Err(e) => {
            // A malformed DNS message is an HTTP 400: the client gets no DNS
            // id to match a DNS error against, so the status is the signal.
            debug!(%client, %e, "DoH malformed request");
            return Err(reject(
                &mut respond,
                StatusCode::BAD_REQUEST,
                "malformed dns message",
            ));
        }
    };
    // Never answer a response (reflection), as Hickory's listeners do not.
    if request.metadata.message_type != MessageType::Query {
        return Ok(());
    }
    let responder = H2Responder::new(respond);
    handler
        .handle_request::<_, TokioTime>(&request, responder)
        .await;
    Ok(())
}

/// Decode the GET `dns` parameter: base64url (RFC 4648), padding optional
/// per RFC 8484 §4.1, after optional percent-decoding.
fn decode_dns_param(value: &str) -> Result<Vec<u8>, String> {
    // The base64url alphabet needs no percent-encoding, but tolerate
    // clients that encode anyway (RFC 8484 §4.1 allows it).
    let raw: Vec<u8> = if value.contains('%') {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3).ok_or("truncated % escape")?)
                    .map_err(|_| "bad % escape")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad % escape")?);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out
    } else {
        value.as_bytes().to_vec()
    };
    // The padding is already counted in the length: strip it and use the
    // no-pad engine (whose alphabet is what the standard prescribes).
    let trimmed: &[u8] = if raw.last() == Some(&b'=') {
        let end = raw.iter().rposition(|&b| b != b'=').map_or(0, |p| p + 1);
        &raw[..end]
    } else {
        &raw
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| format!("bad base64url dns parameter: {e}"))
}

/// Read the POST body, bounded by `timeout` and [`MAX_MESSAGE_LEN`].
async fn fetch_body(body: &mut RecvStream, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = tokio::time::timeout(timeout, body.data())
        .await
        .map_err(|_| "the POST body took too long to arrive".to_string())?
    {
        let chunk = chunk.map_err(|e| format!("POST body error: {e}"))?;
        out.extend_from_slice(&chunk);
        if out.len() > MAX_MESSAGE_LEN {
            return Err("the POST body is too large".to_string());
        }
        if body.is_end_stream() {
            break;
        }
    }
    Ok(out)
}

/// Send a bare HTTP status with no body, and return the detail for the
/// caller's debug log. The client learns why from the code alone; RFC 8484
/// clients read only an `application/dns-message` payload.
/// Record a rejected request in the Server Log (coalesced per client, like
/// Hickory's bridge does for its own rejections), then send the bare HTTP
/// status.
fn rejected(
    session: &SessionLog,
    client: SocketAddr,
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    reason: impl std::fmt::Display,
) -> String {
    session.record(
        HTTPS,
        Some(client.ip()),
        &format!("request rejected: {reason}"),
    );
    reject(respond, status, reason)
}

fn reject(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    reason: impl std::fmt::Display,
) -> String {
    let response = Response::builder()
        .status(status)
        .body(())
        .expect("a valid response");
    let outcome = respond
        .send_response(response, true)
        .map_err(|e| format!("cannot send the HTTP status: {e}"));
    if let Err(e) = outcome {
        return format!("cannot reject a request with {status}: {e}");
    }
    format!("request rejected with {status}: {reason}")
}

/// Sends the encoded DNS answer as an HTTP/2 response. The HTTP/2 stream
/// handle is shared behind a mutex because Hickory requires the responder
/// to be `Clone` (one clone per encoding attempt).
#[derive(Clone)]
struct H2Responder {
    respond: Arc<std::sync::Mutex<SendResponse<Bytes>>>,
}

impl H2Responder {
    fn new(respond: SendResponse<Bytes>) -> Self {
        Self {
            respond: Arc::new(std::sync::Mutex::new(respond)),
        }
    }

    async fn send(&self, bytes: Vec<u8>) -> Result<(), NetError> {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(())
            .expect("a valid response");
        let mut stream = self
            .respond
            .lock()
            .expect("h2 send lock poisoned")
            .send_response(response, false)
            .map_err(|e| NetError::Msg(format!("h2: {e}")))?;
        stream
            .send_data(Bytes::from(bytes), true)
            .map_err(|e| NetError::Msg(format!("h2: {e}")))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ResponseHandler for H2Responder {
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
        let id = response.metadata().id;
        let mut bytes = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(u16::MAX);
            match response.destructive_emit(&mut encoder) {
                Ok(info) => {
                    self.send(bytes).await?;
                    return Ok(info);
                }
                Err(error) => error!(%error, "error encoding DoH response"),
            }
        }
        // Like Hickory's own listeners: a bare SERVFAIL, so the client gets
        // an answer instead of waiting for one that never comes.
        let bytes = error_message(id, hickory_proto::op::ResponseCode::ServFail);
        let header = hickory_proto::op::Header::read(&mut BinDecoder::new(&bytes))
            .map_err(|e| NetError::Msg(format!("servfail frame: {e}")))?;
        self.send(bytes).await?;
        Ok(ResponseInfo::from(header))
    }
}
