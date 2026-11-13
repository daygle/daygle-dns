//! # DNS over TLS (RFC 7858) and plain DNS over TCP listeners
//!
//! Both are served here, on `tokio-rustls` for DoT, rather than by
//! Hickory's listeners, which answer the queries of one connection strictly
//! one after another: a client that pipelines queries over its connection -
//! Android's Private DNS does, as do resolvers forwarding over TCP - waited
//! for every slow recursive lookup ahead of a cached answer. Hickory's TCP
//! listener also admitted any number of connections. Here, on each
//! connection:
//!
//! - queries are answered **concurrently** (up to [`MAX_IN_FLIGHT`] at a
//!   time) and **out of order** as each completes (RFC 7766 §6.2.1.1; the
//!   client matches answers by message ID), with back-pressure: past the
//!   limit the connection reads at most one more message and then waits,
//!   framing no further query until one of the running ones finishes;
//! - DoT responses are padded to [`PADDING_BLOCK`] octets when the query was
//!   padded (RFC 8467), so their size says little about the name asked;
//! - `dot.handshake_timeout_secs` bounds the TLS handshake, and
//!   `dot.idle_timeout_secs` (`server.tcp_timeout_ms` for plain TCP) the
//!   read inactivity of an established session (advertised to clients in
//!   EDNS TCP Keepalive, RFC 7828); an idle session closes once its last
//!   answer is written.
//!
//! Admission is part of the listener (no loopback bridge): at most
//! `dot.max_connections` (`server.tcp_max_connections`) sessions,
//! handshakes included, and at most an
//! eighth of them from one public client (an IPv4 address or an IPv6 /64),
//! so a single address cannot take every slot of a public listener. Private
//! and loopback addresses are not capped: a load balancer that does not
//! speak the PROXY protocol shows every client from its own (private)
//! address, and LAN clients are distinct addresses anyway. A trusted
//! load balancer's PROXY header (`server.proxy_protocol`) names the real
//! client, which every limit, ACL and log then sees. Failed and timed-out
//! handshakes are reported with the client address through the coalescing
//! [`SessionLog`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{
    Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::dispatcher::DnsDispatcher;
use crate::tls_diag::{SessionLog, TCP, TLS};

/// Queries of one connection answered at the same time. Past it the
/// connection is not read until one finishes (TCP back-pressure).
pub const MAX_IN_FLIGHT: usize = 32;

/// Responses to padded queries are padded to a multiple of this many octets
/// (RFC 8467 §4.1, the recommended block-length strategy for responses).
pub const PADDING_BLOCK: usize = 468;

/// Encoded answers queued for one connection's writer.
const WRITE_QUEUE: usize = MAX_IN_FLIGHT * 2;

/// Queued answers are gathered into one write up to about this many octets:
/// the largest TLS record's plaintext, beyond which rustls splits it anyway.
const WRITE_BATCH: usize = 16 * 1024;

/// How long a trusted load balancer has to send its PROXY header.
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest message the 2-octet length prefix can describe (RFC 1035
/// §4.2.2).
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// Listener settings.
#[derive(Clone)]
pub struct DotOptions {
    /// Sessions served at once, TLS handshakes included.
    pub max_connections: usize,
    /// The TLS handshake timeout.
    pub timeout: Duration,
    /// The read-inactivity timeout of an established session.
    pub idle: Duration,
    /// Load balancers whose PROXY header names the real client.
    pub proxy_trusted: Option<Arc<Vec<ipnet::IpNet>>>,
}

/// The transport a listener serves: what requests are tagged with and
/// where its session failures are logged.
#[derive(Clone, Copy)]
struct Transport {
    protocol: Protocol,
    /// Server Log component (the query log's protocol value).
    tag: &'static str,
    /// For debug lines.
    label: &'static str,
}

const DOT: Transport = Transport {
    protocol: Protocol::Tls,
    tag: TLS,
    label: "DoT",
};

const PLAIN_TCP: Transport = Transport {
    protocol: Protocol::Tcp,
    tag: TCP,
    label: "TCP",
};

/// Serve DoT on `listener` until `shutdown` is cancelled.
pub async fn serve_dot(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    shutdown: CancellationToken,
    options: DotOptions,
) {
    let acceptor = Some(TlsAcceptor::from(tls));
    serve(listener, acceptor, DOT, handler, session, shutdown, options).await;
}

/// Serve plain DNS over TCP on `listener` until `shutdown` is cancelled
/// (`options.timeout`, the handshake timeout, does not apply).
pub async fn serve_tcp(
    listener: TcpListener,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    shutdown: CancellationToken,
    options: DotOptions,
) {
    serve(
        listener, None, PLAIN_TCP, handler, session, shutdown, options,
    )
    .await;
}

/// Accept connections (TLS ones when there is an `acceptor`) and serve each.
async fn serve(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    transport: Transport,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    shutdown: CancellationToken,
    options: DotOptions,
) {
    let label = transport.label;
    let sessions = Arc::new(Semaphore::new(options.max_connections));
    let clients = Arc::new(ClientSlots::new(per_client_limit(options.max_connections)));
    let mut connections = JoinSet::new();
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            // Reap finished connections so the set does not grow by one
            // entry per connection for the listener's lifetime.
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    // Out of file descriptors and the like: back off instead
                    // of spinning on a failing accept.
                    debug!(%error, "{label} accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            debug!(%peer, "{label} connection refused: listener at max_connections");
            continue;
        };
        let connection = Connection {
            acceptor: acceptor.clone(),
            transport,
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

/// Connections one client may hold: an eighth of the listener, at least 4.
/// Shared with the DoH listener, which uses the same admission surface.
pub(crate) fn per_client_limit(max_connections: usize) -> usize {
    (max_connections / 8).max(4)
}

/// Live connections per public client. IPv6 clients are counted per /64,
/// the smallest prefix a single subscriber normally gets. Shared with the
/// DoH listener, which uses the same admission surface.
pub(crate) struct ClientSlots {
    limit: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
    /// Private and loopback networks, which are not capped.
    uncapped: Vec<ipnet::IpNet>,
}

impl ClientSlots {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            open: Mutex::new(HashMap::new()),
            uncapped: daygle_dns_core::config::PRIVATE_NETWORKS
                .iter()
                .filter_map(|n| n.parse().ok())
                .collect(),
        }
    }

    fn key(ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::from(octets)
            }
            v4 => v4,
        }
    }

    /// A slot for `ip`, released when the guard drops; `None` past the
    /// per-client limit.
    pub(crate) fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ClientSlot> {
        let ip = ip.to_canonical();
        if self.uncapped.iter().any(|net| net.contains(&ip)) {
            return Some(ClientSlot {
                slots: self.clone(),
                key: None,
            });
        }
        let key = Self::key(ip);
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(key).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(ClientSlot {
            slots: self.clone(),
            key: Some(key),
        })
    }
}

pub(crate) struct ClientSlot {
    slots: Arc<ClientSlots>,
    /// `None` for an uncapped (private) client.
    key: Option<IpAddr>,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let Some(key) = self.key else {
            return;
        };
        let mut open = self.slots.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                open.remove(&key);
            }
        }
    }
}

/// What one accepted connection needs.
struct Connection {
    /// `None` for plain TCP.
    acceptor: Option<TlsAcceptor>,
    transport: Transport,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    clients: Arc<ClientSlots>,
    options: DotOptions,
    shutdown: CancellationToken,
}

impl Connection {
    async fn run(self, mut stream: TcpStream, peer: SocketAddr) {
        // Answers are small and latency-bound: do not wait to coalesce.
        let _ = stream.set_nodelay(true);
        let peer_ip = peer.ip().to_canonical();
        let tag = self.transport.tag;

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
                        self.session
                            .record(tag, Some(peer_ip), &format!("bad PROXY header: {e}"));
                        return;
                    }
                    Err(_) => {
                        self.session
                            .record(tag, Some(peer_ip), "no PROXY header in time");
                        return;
                    }
                }
            }
            _ => peer,
        };
        let client = SocketAddr::new(client.ip().to_canonical(), client.port());

        let Some(_slot) = self.clients.acquire(client.ip()) else {
            self.session.record(
                tag,
                Some(client.ip()),
                "connection refused: too many connections from this client",
            );
            return;
        };

        let Some(acceptor) = self.acceptor.clone() else {
            // Plain TCP: no handshake, and no server name to read an account
            // from.
            return self.serve(stream, client, None).await;
        };
        let tls = match tokio::time::timeout(self.options.timeout, acceptor.accept(stream)).await {
            Ok(Ok(tls)) => tls,
            // Connected and closed (or reset) without a word: a load
            // balancer's or monitor's TCP check, or a port scan - not a
            // failed client. (A client rejecting the certificate sends an
            // alert, logged below.)
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                debug!(%client, "DoT connection closed before the TLS handshake");
                return;
            }
            Ok(Err(e)) => {
                self.session.record(
                    TLS,
                    Some(client.ip()),
                    &format!("TLS handshake failed: {e}"),
                );
                return;
            }
            Err(_) => {
                self.session
                    .record(TLS, Some(client.ip()), "TLS handshake timed out");
                return;
            }
        };
        // The name the device asked for, for DNS accounts
        // (`<client id>.<accounts.domain>`). It is resolved against the
        // live account list for every query, so disabling, deleting,
        // renaming or re-keying an account applies to connections already
        // open.
        let server_name: Option<Arc<str>> = tls.get_ref().1.server_name().map(Arc::from);
        self.serve(tls, client, server_name).await;
    }

    /// Read framed queries until the client closes, goes idle, sends
    /// garbage or the listener stops; answer each concurrently.
    async fn serve<S>(self, stream: S, client: SocketAddr, server_name: Option<Arc<str>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let label = self.transport.label;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);

        let idle = self.options.idle;
        // Cancelled when the writer stops: the client is gone, or it stopped
        // reading its answers (each write may block at most `idle`). Without
        // this, a client that never read filled the queue, every in-flight
        // slot waited on it, and the connection was held forever.
        let closed = CancellationToken::new();

        // One writer per connection: answers arrive in completion order and
        // are written whole. Whatever is already queued is gathered into one
        // write: tokio-rustls seals and sends a TLS record on every write
        // call, so writing frames one by one cost a record, a `send` and
        // (with TCP_NODELAY) a segment per answer of a burst.
        let write = {
            let on_exit = closed.clone().drop_guard();
            tokio::spawn(async move {
                let _on_exit = on_exit;
                let bounded = |result: Result<std::io::Result<()>, _>| matches!(result, Ok(Ok(())));
                while let Some(mut batch) = rx.recv().await {
                    while batch.len() < WRITE_BATCH {
                        match rx.try_recv() {
                            Ok(frame) => batch.extend_from_slice(&frame),
                            Err(_) => break,
                        }
                    }
                    if !bounded(tokio::time::timeout(idle, writer.write_all(&batch)).await) {
                        return;
                    }
                    if !bounded(tokio::time::timeout(idle, writer.flush()).await) {
                        return;
                    }
                }
                let _ = tokio::time::timeout(idle, writer.shutdown()).await;
            })
        };

        let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let mut queries = JoinSet::new();
        loop {
            while queries.try_join_next().is_some() {}

            let mut len_buf = [0u8; 2];
            let read = tokio::select! {
                _ = self.shutdown.cancelled() => return,
                _ = closed.cancelled() => break,
                read = tokio::time::timeout(idle, reader.read_exact(&mut len_buf)) => read,
            };
            match read {
                Ok(Ok(_)) => {}
                // Closed by the client, or idle past the timeout (normal
                // keep-alive expiry, not a failure).
                Ok(Err(_)) | Err(_) => break,
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len < 12 {
                // Not even a DNS header: the stream is out of step.
                debug!(%client, len, "{label}: malformed frame length, closing");
                break;
            }
            let mut body = vec![0u8; len];
            match tokio::time::timeout(idle, reader.read_exact(&mut body)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }

            let permit = tokio::select! {
                _ = self.shutdown.cancelled() => return,
                _ = closed.cancelled() => break,
                permit = in_flight.clone().acquire_owned() => {
                    permit.expect("the in-flight semaphore is never closed")
                }
            };
            let handler = self.handler.clone();
            let session = self.session.clone();
            let tx = tx.clone();
            let server_name = server_name.clone();
            let transport = self.transport;
            queries.spawn(async move {
                let _permit = permit;
                let identity = handler.accounts().identify(server_name.as_deref(), None);
                daygle_dns_policy::identity::scope(
                    identity,
                    answer(body, client, handler, &session, tx, transport),
                )
                .await;
            });
        }

        // The client stopped sending: finish what it already asked, then
        // close (the writer ends once every sender is gone).
        drop(tx);
        tokio::select! {
            _ = self.shutdown.cancelled() => {}
            _ = async {
                while queries.join_next().await.is_some() {}
                let _ = write.await;
            } => {}
        }
    }
}

/// Decode and answer one query, queueing the framed answer on `tx`.
async fn answer(
    body: Vec<u8>,
    client: SocketAddr,
    handler: DnsDispatcher,
    session: &SessionLog,
    tx: mpsc::Sender<Vec<u8>>,
    transport: Transport,
) {
    let id_hint = Header::read(&mut BinDecoder::new(&body))
        .map(|h| h.metadata.id)
        .unwrap_or(0);
    let request = match Request::from_bytes(body, client, transport.protocol) {
        Ok(request) => request,
        Err(e) => {
            // Coalesced: a client looping malformed queries must not flood
            // the log.
            session.record(
                transport.tag,
                Some(client.ip()),
                &format!("malformed request: {e}"),
            );
            if let Some(frame) = frame(&error_message(id_hint, ResponseCode::FormErr)) {
                let _ = tx.send(frame).await;
            }
            return;
        }
    };
    // Never answer a response (reflection), as Hickory's listeners do not.
    if request.metadata.message_type != MessageType::Query {
        return;
    }
    // Padding only hides sizes on an encrypted transport (RFC 8467).
    let pad = transport.protocol == Protocol::Tls
        && request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Padding).is_some());
    let responder = DotResponder { tx, pad };
    handler
        .handle_request::<_, TokioTime>(&request, responder)
        .await;
}

/// Length-prefix an encoded message (`None` when it cannot be framed).
fn frame(message: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(message.len()).ok()?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Some(framed)
}

/// A bare response header with `code` (FORMERR for an undecodable query,
/// SERVFAIL when an answer cannot be encoded).
pub(crate) fn error_message(id: u16, code: ResponseCode) -> Vec<u8> {
    let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
    metadata.response_code = code;
    let header = Header {
        metadata,
        counts: HeaderCounts::default(),
    };
    let mut bytes = Vec::with_capacity(12);
    let mut encoder = BinEncoder::new(&mut bytes);
    let _ = header.emit(&mut encoder);
    bytes
}

/// Pad an encoded response with an EDNS(0) Padding option (RFC 7830) to a
/// multiple of [`PADDING_BLOCK`] octets. Unchanged when it has no OPT
/// record, is TSIG-signed (padding would break the signature), cannot be
/// re-read, or would outgrow a DNS message.
///
/// Every answer to a padded query comes through here (most DoT, DoH and
/// DoQ clients pad), so the usual shape is handled in place: see
/// [`pad_in_place`]. Anything else is decoded and re-encoded.
pub(crate) fn pad_response(bytes: Vec<u8>) -> Vec<u8> {
    match pad_in_place(bytes) {
        Ok(padded) => padded,
        Err(bytes) => pad_by_reencoding(bytes),
    }
}

/// EDNS option code of Padding (RFC 7830).
const PADDING_OPTION: u16 = 12;
/// Record type of OPT (RFC 6891).
const OPT_TYPE: u16 = 41;

/// Pad without decoding: when the OPT record is the message's last record
/// (as the encoder writes an unsigned message: a TSIG or SIG(0) would follow
/// it) and carries no Padding yet, the option is appended to the end of the
/// buffer and the OPT record's length adjusted. `Err` hands the message back
/// unchanged for any other shape, or anything that does not walk cleanly.
fn pad_in_place(mut bytes: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let Some((rdlen_at, rdata_at)) = last_record_if_opt(&bytes) else {
        return Err(bytes);
    };
    if opt_has_padding(&bytes[rdata_at..]) {
        return Err(bytes);
    }
    let len = bytes.len() + 4;
    let pad = (PADDING_BLOCK - len % PADDING_BLOCK) % PADDING_BLOCK;
    if len + pad > MAX_MESSAGE_LEN {
        return Ok(bytes);
    }
    let rdlen = bytes.len() - rdata_at + 4 + pad;
    let Ok(rdlen) = u16::try_from(rdlen) else {
        return Err(bytes);
    };
    bytes[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    bytes.reserve_exact(4 + pad);
    bytes.extend_from_slice(&PADDING_OPTION.to_be_bytes());
    bytes.extend_from_slice(&(pad as u16).to_be_bytes());
    bytes.resize(bytes.len() + pad, 0);
    Ok(bytes)
}

/// Where the RDLENGTH field and the RDATA of the message's last record
/// start, when that record is an OPT record ending exactly at the end of
/// the message. `None` for any other shape or a malformed message.
fn last_record_if_opt(bytes: &[u8]) -> Option<(usize, usize)> {
    let count = |at: usize| -> Option<usize> {
        Some(usize::from(u16::from_be_bytes(
            bytes.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let questions = count(4)?;
    let records = count(6)? + count(8)? + count(10)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(bytes, at)? + 4;
    }
    let mut last = None;
    for _ in 0..records {
        at = skip_name(bytes, at)?;
        let rtype = count(at)?;
        let rdlen_at = at + 8;
        let rdata_at = rdlen_at + 2;
        at = rdata_at + count(rdlen_at)?;
        last = Some((rtype, rdlen_at, rdata_at));
    }
    match last {
        Some((rtype, rdlen_at, rdata_at))
            if rtype == usize::from(OPT_TYPE) && at == bytes.len() =>
        {
            Some((rdlen_at, rdata_at))
        }
        _ => None,
    }
}

/// The offset just past the (possibly compressed) name at `at`.
fn skip_name(bytes: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *bytes.get(at)?;
        match len >> 6 {
            0 if len == 0 => return Some(at + 1),
            0 => at += 1 + usize::from(len),
            // A compression pointer ends the name.
            0b11 => return (at + 2 <= bytes.len()).then_some(at + 2),
            _ => return None,
        }
    }
}

/// Whether OPT RDATA `options` already holds a Padding option (or does not
/// walk cleanly, which the slow path then sorts out).
fn opt_has_padding(mut options: &[u8]) -> bool {
    while !options.is_empty() {
        let Some(header) = options.get(..4) else {
            return true;
        };
        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if code == PADDING_OPTION {
            return true;
        }
        let Some(rest) = options.get(4 + len..) else {
            return true;
        };
        options = rest;
    }
    false
}

/// The general path: decode, replace any Padding option, re-encode.
fn pad_by_reencoding(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(mut message) = Message::from_vec(&bytes) else {
        return bytes;
    };
    if message.signature.is_some() {
        return bytes;
    }
    let Some(edns) = message.edns.as_mut() else {
        return bytes;
    };
    edns.options_mut().remove(EdnsCode::Padding);
    // Measure the message as it will be re-encoded, plus the option's own
    // 4-octet header.
    let Ok(unpadded) = message.to_vec() else {
        return bytes;
    };
    let len = unpadded.len() + 4;
    let pad = (PADDING_BLOCK - len % PADDING_BLOCK) % PADDING_BLOCK;
    if len + pad > MAX_MESSAGE_LEN {
        return bytes;
    }
    if let Some(edns) = message.edns.as_mut() {
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            vec![0; pad],
        ));
    }
    message.to_vec().unwrap_or(bytes)
}

/// Queues encoded answers for the connection's writer.
#[derive(Clone)]
struct DotResponder {
    tx: mpsc::Sender<Vec<u8>>,
    /// The query was padded, so the answer is too (RFC 8467).
    pad: bool,
}

impl DotResponder {
    async fn send(&self, bytes: Vec<u8>) -> Result<(), NetError> {
        let bytes = if self.pad { pad_response(bytes) } else { bytes };
        let framed = frame(&bytes).ok_or(NetError::Message("DNS message exceeds 65535 bytes"))?;
        self.tx
            .send(framed)
            .await
            .map_err(|_| NetError::Message("connection closed"))
    }
}

#[async_trait]
impl ResponseHandler for DotResponder {
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
                Err(error) => error!(%error, "error encoding a TCP or DoT response"),
            }
        }
        // Like Hickory's own listeners: a bare SERVFAIL, so the client gets
        // an answer instead of waiting for one that never comes.
        let bytes = error_message(id, ResponseCode::ServFail);
        let header = Header::read(&mut BinDecoder::new(&bytes))?;
        self.send(bytes).await?;
        Ok(ResponseInfo::from(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn per_client_limit_is_an_eighth_with_a_floor() {
        assert_eq!(per_client_limit(1024), 128);
        assert_eq!(per_client_limit(8), 4);
        assert_eq!(per_client_limit(1), 4);
    }

    #[test]
    fn client_slots_cap_per_address_and_ipv6_prefix() {
        let slots = Arc::new(ClientSlots::new(2));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let first = slots.acquire(a).unwrap();
        let _second = slots.acquire(a).unwrap();
        assert!(slots.acquire(a).is_none());
        // Another address has its own slots.
        assert!(slots.acquire("192.0.2.2".parse().unwrap()).is_some());
        // Releasing one frees a slot.
        drop(first);
        assert!(slots.acquire(a).is_some());

        // Two addresses in one /64 share a count; another /64 does not.
        let slots = Arc::new(ClientSlots::new(1));
        let _held = slots.acquire("2001:db8::1".parse().unwrap()).unwrap();
        assert!(slots.acquire("2001:db8::ffff".parse().unwrap()).is_none());
        assert!(slots.acquire("2001:db8:0:1::1".parse().unwrap()).is_some());
        // An IPv4-mapped address counts as the IPv4 client.
        let slots = Arc::new(ClientSlots::new(1));
        let _held = slots.acquire("192.0.2.9".parse().unwrap()).unwrap();
        assert!(slots.acquire("::ffff:192.0.2.9".parse().unwrap()).is_none());
        // Private and loopback clients are not capped.
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        let held: Vec<_> = (0..5).map(|_| slots.acquire(lan).unwrap()).collect();
        assert!(slots.acquire("127.0.0.1".parse().unwrap()).is_some());
        drop(held);
        assert!(slots.open.lock().unwrap().get(&lan).is_none());
    }

    fn response_with_edns() -> Vec<u8> {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message.edns = Some(Edns::new());
        message.to_vec().unwrap()
    }

    #[test]
    fn pads_responses_to_the_block_length() {
        let padded = pad_response(response_with_edns());
        assert_eq!(padded.len() % PADDING_BLOCK, 0, "{} octets", padded.len());
        let message = Message::from_vec(&padded).unwrap();
        assert_eq!(message.metadata.id, 7);
        assert!(message
            .edns
            .as_ref()
            .and_then(|e| e.option(EdnsCode::Padding))
            .is_some());
        // Padding an already padded answer keeps it one block.
        assert_eq!(pad_response(padded).len(), PADDING_BLOCK);
    }

    /// A response with answers (compressed names), an authority, an extra
    /// additional record and EDNS options before the padding.
    fn rich_response() -> Vec<u8> {
        use hickory_proto::rr::rdata::{A, NS};
        use hickory_proto::rr::RData;
        let name = Name::from_ascii("www.example.com.").unwrap();
        let zone = Name::from_ascii("example.com.").unwrap();
        let ns = Name::from_ascii("ns1.example.com.").unwrap();
        let mut message = Message::new(11, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        for last in 1..=3 {
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(A::new(192, 0, 2, last)),
            ));
        }
        message.add_authority(Record::from_rdata(zone, 300, RData::NS(NS(ns.clone()))));
        message.add_additional(Record::from_rdata(ns, 300, RData::A(A::new(192, 0, 2, 53))));
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Cookie),
            vec![7; 24],
        ));
        message.edns = Some(edns);
        message.to_vec().unwrap()
    }

    #[test]
    fn pads_in_place_exactly_as_reencoding_would() {
        for bytes in [response_with_edns(), rich_response()] {
            let fast = pad_in_place(bytes.clone()).expect("the usual shape is padded in place");
            assert_eq!(fast.len() % PADDING_BLOCK, 0, "{} octets", fast.len());
            let slow = pad_by_reencoding(bytes.clone());
            assert_eq!(fast.len(), slow.len());
            // Same message apart from where the encoder put things.
            let (fast, slow) = (
                Message::from_vec(&fast).unwrap(),
                Message::from_vec(&slow).unwrap(),
            );
            assert_eq!(fast, slow);
            assert_eq!(fast, {
                let mut original = Message::from_vec(&bytes).unwrap();
                let padding = slow
                    .edns
                    .as_ref()
                    .unwrap()
                    .option(EdnsCode::Padding)
                    .cloned();
                original
                    .edns
                    .as_mut()
                    .unwrap()
                    .options_mut()
                    .insert(padding.unwrap());
                original
            });
        }
    }

    #[test]
    fn falls_back_for_other_shapes() {
        // No OPT record.
        let mut message = Message::new(9, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(pad_in_place(message.to_vec().unwrap()).is_err());
        // Already padded: the slow path replaces the option.
        let padded = pad_response(response_with_edns());
        assert!(pad_in_place(padded.clone()).is_err());
        assert_eq!(pad_response(padded).len(), PADDING_BLOCK);
        // Truncated or garbage input is handed back untouched.
        let bytes = rich_response();
        for cut in [0, 5, 12, 20, bytes.len() - 1] {
            let short = bytes[..cut].to_vec();
            assert_eq!(pad_response(short.clone()), short, "cut at {cut}");
        }
        assert_eq!(pad_response(vec![0xff; 40]), vec![0xff; 40]);
    }

    #[test]
    fn leaves_tsig_signed_responses_unchanged() {
        let mut message = Message::from_vec(&response_with_edns()).unwrap();
        message.signature = Some(Box::new(Record::from_rdata(
            Name::from_ascii("key.example.").unwrap(),
            0,
            hickory_proto::rr::rdata::TSIG::new(
                hickory_proto::rr::rdata::tsig::TsigAlgorithm::HmacSha256,
                1,
                300,
                vec![1; 32],
                7,
                None,
                Vec::new(),
            ),
        )));
        let bytes = message.to_vec().unwrap();
        assert_eq!(pad_response(bytes.clone()), bytes);
    }

    #[test]
    fn leaves_responses_without_edns_alone() {
        let mut message = Message::new(9, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = message.to_vec().unwrap();
        assert_eq!(pad_response(bytes.clone()), bytes);
    }

    #[test]
    fn frames_with_a_length_prefix() {
        assert_eq!(frame(&[1, 2, 3]).unwrap(), vec![0, 3, 1, 2, 3]);
        assert!(frame(&vec![0; MAX_MESSAGE_LEN + 1]).is_none());
        let formerr = error_message(42, ResponseCode::FormErr);
        let message = Message::from_vec(&formerr).unwrap();
        assert_eq!(message.metadata.id, 42);
        assert_eq!(message.metadata.response_code, ResponseCode::FormErr);
    }
}
