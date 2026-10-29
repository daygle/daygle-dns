//! # DNS over TLS (RFC 7858) listener
//!
//! Built directly on `tokio-rustls` rather than Hickory's TLS listener, which
//! answers the queries of one connection strictly one after another: a
//! client that pipelines queries over its connection - Android's Private DNS
//! does - waited for every slow recursive lookup ahead of a cached answer.
//! Here, on each connection:
//!
//! - queries are answered **concurrently** (up to [`MAX_IN_FLIGHT`] at a
//!   time) and **out of order** as each completes (RFC 7766 §6.2.1.1; the
//!   client matches answers by message ID), with back-pressure: past the
//!   limit the connection is simply not read until a query finishes;
//! - responses are padded to [`PADDING_BLOCK`] octets when the query was
//!   padded (RFC 8467), so their size says little about the name asked;
//! - `dot.handshake_timeout_secs` bounds the TLS handshake and is also the
//!   read-inactivity timeout of an established session, as before; an idle
//!   session closes once its last answer is written.
//!
//! Admission is part of the listener (no loopback bridge): at most
//! `dot.max_connections` sessions, handshakes included, and at most an
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::dispatcher::DnsDispatcher;
use crate::tls_diag::{SessionLog, TLS};

/// Queries of one connection answered at the same time. Past it the
/// connection is not read until one finishes (TCP back-pressure).
pub const MAX_IN_FLIGHT: usize = 32;

/// Responses to padded queries are padded to a multiple of this many octets
/// (RFC 8467 §4.1, the recommended block-length strategy for responses).
pub const PADDING_BLOCK: usize = 468;

/// Encoded answers queued for one connection's writer.
const WRITE_QUEUE: usize = MAX_IN_FLIGHT * 2;

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
    /// The TLS handshake timeout, which is also the session's
    /// read-inactivity timeout.
    pub timeout: Duration,
    /// Load balancers whose PROXY header names the real client.
    pub proxy_trusted: Option<Arc<Vec<ipnet::IpNet>>>,
}

/// Serve DoT on `listener` until `shutdown` is cancelled.
pub async fn serve_dot(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    handler: DnsDispatcher,
    session: Arc<SessionLog>,
    shutdown: CancellationToken,
    options: DotOptions,
) {
    let acceptor = TlsAcceptor::from(tls);
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
                    debug!(%error, "DoT accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            debug!(%peer, "DoT connection refused: listener at max_connections");
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
    acceptor: TlsAcceptor,
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
                            .record(TLS, Some(peer_ip), &format!("bad PROXY header: {e}"));
                        return;
                    }
                    Err(_) => {
                        self.session
                            .record(TLS, Some(peer_ip), "no PROXY header in time");
                        return;
                    }
                }
            }
            _ => peer,
        };
        let client = SocketAddr::new(client.ip().to_canonical(), client.port());

        let Some(_slot) = self.clients.acquire(client.ip()) else {
            self.session.record(
                TLS,
                Some(client.ip()),
                "connection refused: too many connections from this client",
            );
            return;
        };

        let tls =
            match tokio::time::timeout(self.options.timeout, self.acceptor.accept(stream)).await {
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
        self.serve(tls, client).await;
    }

    /// Read framed queries until the client closes, goes idle, sends
    /// garbage or the listener stops; answer each concurrently.
    async fn serve(self, tls: tokio_rustls::server::TlsStream<TcpStream>, client: SocketAddr) {
        let (mut reader, mut writer) = tokio::io::split(tls);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);

        let idle = self.options.timeout;
        // Cancelled when the writer stops: the client is gone, or it stopped
        // reading its answers (each write may block at most `idle`). Without
        // this, a client that never read filled the queue, every in-flight
        // slot waited on it, and the connection was held forever.
        let closed = CancellationToken::new();

        // One writer per connection: answers arrive in completion order and
        // are written whole. Whatever is queued is written before a flush,
        // so a burst of answers shares TLS records.
        let write = {
            let on_exit = closed.clone().drop_guard();
            tokio::spawn(async move {
                let _on_exit = on_exit;
                let bounded = |result: Result<std::io::Result<()>, _>| matches!(result, Ok(Ok(())));
                while let Some(frame) = rx.recv().await {
                    if !bounded(tokio::time::timeout(idle, writer.write_all(&frame)).await) {
                        return;
                    }
                    while let Ok(frame) = rx.try_recv() {
                        if !bounded(tokio::time::timeout(idle, writer.write_all(&frame)).await) {
                            return;
                        }
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
                debug!(%client, len, "DoT: malformed frame length, closing");
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
            queries.spawn(async move {
                let _permit = permit;
                answer(body, client, handler, &session, tx).await;
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
) {
    let id_hint = Header::read(&mut BinDecoder::new(&body))
        .map(|h| h.metadata.id)
        .unwrap_or(0);
    let request = match Request::from_bytes(body, client, Protocol::Tls) {
        Ok(request) => request,
        Err(e) => {
            // Coalesced: a client looping malformed queries must not flood
            // the log.
            session.record(TLS, Some(client.ip()), &format!("malformed request: {e}"));
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
    let pad = request
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
fn pad_response(bytes: Vec<u8>) -> Vec<u8> {
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
        let framed = frame(&bytes).ok_or(NetError::Message("DoT message exceeds 65535 bytes"))?;
        self.tx
            .send(framed)
            .await
            .map_err(|_| NetError::Message("DoT connection closed"))
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
                Err(error) => error!(%error, "error encoding DoT response"),
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
