//! dnstap: client queries and their responses, as dnstap `Message` events,
//! streamed to a collector with [Frame Streams].
//!
//! The format is the one every dnstap collector speaks (`dnstap-ldns`,
//! `fstrm_capture`, dnstap-receiver, DNS-collector, ...): each frame is a
//! `dnstap.Dnstap` protobuf carrying the verbatim wire-format DNS message
//! plus who sent it, over which transport, and when. A collector therefore
//! decodes real queries without a packet capture.
//!
//! A `CLIENT_QUERY` event is emitted when a query arrives and a
//! `CLIENT_RESPONSE` event when the answer is about to be written, so the
//! pair describes exactly what went over the wire - after cookies, response
//! rate limiting and truncation. Events go through a bounded queue to one
//! background task that owns the connection, does the Frame Streams
//! handshake, and reconnects with backoff; a collector that is down or slow
//! never delays a query, its events are dropped and counted.
//!
//! [Frame Streams]: https://github.com/farsightsec/fstrm

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use daygle_dns_core::config::{DaygleConfig, DnstapSettings, DnstapTarget};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecoder, BinEncoder};
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder, Queries};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Queued events before new ones are dropped.
const QUEUE: usize = 8192;
/// The content type dnstap streams advertise in the Frame Streams handshake.
const CONTENT_TYPE: &str = "protobuf:dnstap.Dnstap";
/// Frame Streams control frame types (fstrm/control.h).
const FSTRM_ACCEPT: u32 = 0x01;
const FSTRM_START: u32 = 0x02;
const FSTRM_STOP: u32 = 0x03;
const FSTRM_READY: u32 = 0x04;
/// The content-type control field (fstrm/control.h).
const FSTRM_FIELD_CONTENT_TYPE: u32 = 0x01;
/// First wait after a failed connection, doubled up to the maximum.
const RETRY_INITIAL: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// How long the handshake may take before the collector is given up on.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// dnstap `Message.Type` values (dnstap.proto).
const CLIENT_QUERY: u32 = 5;
const CLIENT_RESPONSE: u32 = 6;
/// dnstap `SocketFamily` values.
const INET: u32 = 1;
const INET6: u32 = 2;
/// dnstap `SocketProtocol` values.
const UDP: u32 = 1;
const TCP: u32 = 2;
const DOT: u32 = 3;
const DOH: u32 = 4;
const DOQ: u32 = 7;
/// dnstap `HttpProtocol` values, for DoH.
const HTTP2: u32 = 2;
const HTTP3: u32 = 3;

/// Sends dnstap events the dispatcher produces; owns the collector
/// connection through a background task.
pub struct DnstapSender {
    tx: mpsc::Sender<Vec<u8>>,
    config: Arc<ArcSwap<DaygleConfig>>,
    dropped: AtomicU64,
}

impl DnstapSender {
    /// Start the sender. It connects only while `[dnstap]` is enabled.
    pub fn start(config: Arc<ArcSwap<DaygleConfig>>, shutdown: CancellationToken) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE);
        let sender = Arc::new(Self {
            tx,
            config,
            dropped: AtomicU64::new(0),
        });
        tokio::spawn(run(sender.clone(), rx, shutdown));
        sender
    }

    /// Whether events are being produced (`[dnstap] enabled`).
    pub fn enabled(&self) -> bool {
        self.config.load().dnstap.enabled
    }

    /// Events dropped because the queue was full or the collector was gone.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Queue one event, encoding it with the settings in force now.
    fn emit(&self, event: Event) {
        let config = self.config.load();
        let settings = &config.dnstap;
        if !settings.enabled {
            return;
        }
        let frame = encode(settings, &event);
        if self.tx.try_send(frame).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// One dnstap `Message`, before encoding.
struct Event {
    /// A dnstap `Message.Type`.
    msg_type: u32,
    /// The client (the message initiator).
    client: SocketAddr,
    /// This server's address, when the transport knows it.
    server: Option<SocketAddr>,
    /// The transport, as a dnstap `SocketProtocol` (and `HttpProtocol`).
    transport: (u32, Option<u32>),
    /// When the query arrived.
    query_time: SystemTime,
    /// When the response was sent (responses only).
    response_time: Option<SystemTime>,
    /// The wire-format DNS message.
    message: Vec<u8>,
}

/// Wraps the transport's response handler: emits `CLIENT_QUERY` on
/// construction and `CLIENT_RESPONSE` with the bytes that actually go out.
#[derive(Clone)]
pub struct DnstapResponder<R> {
    inner: R,
    sender: Arc<DnstapSender>,
    client: SocketAddr,
    transport: (u32, Option<u32>),
    query_time: SystemTime,
    /// The question section as received, to rebuild the response for sending.
    questions: Box<[u8]>,
    question_count: usize,
}

impl<R> DnstapResponder<R> {
    /// A responder for `request`, which emits its `CLIENT_QUERY` event now.
    ///
    /// `client` is the address the event reports: the caller resolves the
    /// real peer first (behind a PROXY-protocol hop, `request.src()` is the
    /// proxy). The request's questions are re-read from these bytes when the
    /// answer goes out, because Hickory hands out the response's records but
    /// not the question section.
    pub fn new(inner: R, request: &Request, sender: Arc<DnstapSender>, client: SocketAddr) -> Self {
        let transport = transport_of(request.protocol());
        let query_time = SystemTime::now();
        let questions: Box<[u8]> = request.queries.as_bytes().into();
        let responder = Self {
            inner,
            sender,
            client,
            transport,
            query_time,
            questions,
            question_count: request.queries.len(),
        };
        responder.sender.emit(Event {
            msg_type: CLIENT_QUERY,
            client,
            server: None,
            transport,
            query_time,
            response_time: None,
            message: request.as_slice().to_vec(),
        });
        responder
    }
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for DnstapResponder<R> {
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
        // The question section, for rebuilding the answer after encoding it.
        let mut decoder = BinDecoder::new(&self.questions);
        let Ok(questions) = Queries::read(&mut decoder, self.question_count) else {
            return self.inner.send_response(response).await;
        };
        let metadata = *response.metadata();
        let mut bytes = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(u16::MAX);
            if response.destructive_emit(&mut encoder).is_err() {
                debug!("cannot encode the response for dnstap");
                let servfail = MessageResponseBuilder::new(&questions, None)
                    .error_msg(&metadata, ResponseCode::ServFail);
                return self.inner.send_response(servfail).await;
            }
        }
        if self.sender.enabled() {
            self.sender.emit(Event {
                msg_type: CLIENT_RESPONSE,
                client: self.client,
                server: None,
                transport: self.transport,
                query_time: self.query_time,
                response_time: Some(SystemTime::now()),
                message: bytes.clone(),
            });
        }
        // Re-read what was just encoded and hand an equivalent response on:
        // the frame above is the one that goes to the collector, and the
        // rebuilt one is what the client receives.
        let message = match Message::from_vec(&bytes) {
            Ok(message) => message,
            Err(e) => {
                debug!(error = %e, "cannot re-read the encoded response");
                let servfail = MessageResponseBuilder::new(&questions, None)
                    .error_msg(&metadata, ResponseCode::ServFail);
                return self.inner.send_response(servfail).await;
            }
        };
        let rebuilt = MessageResponseBuilder::new(&questions, message.edns.as_ref()).build(
            message.metadata,
            message.answers.iter(),
            message.authorities.iter(),
            std::iter::empty::<&Record>(),
            message.additionals.iter(),
        );
        self.inner.send_response(rebuilt).await
    }
}

/// The dnstap transport for a Hickory protocol: `SocketProtocol` and, for
/// DoH, the `HttpProtocol`.
fn transport_of(protocol: Protocol) -> (u32, Option<u32>) {
    match protocol {
        Protocol::Udp => (UDP, None),
        Protocol::Tcp => (TCP, None),
        Protocol::Tls => (DOT, None),
        Protocol::Https => (DOH, Some(HTTP2)),
        Protocol::H3 => (DOH, Some(HTTP3)),
        Protocol::Quic => (DOQ, None),
        _ => (TCP, None),
    }
}

/// A protobuf wire-format writer, just enough for dnstap's messages.
#[derive(Default)]
struct Proto(Vec<u8>);

impl Proto {
    fn varint(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                self.0.push(byte);
                return;
            }
            self.0.push(byte | 0x80);
        }
    }

    fn tag(&mut self, field: u32, wire: u32) {
        self.varint(u64::from((field << 3) | wire));
    }

    /// An `optional uint32`/`uint64`/enum field (varint).
    fn uint(&mut self, field: u32, value: u64) {
        self.tag(field, 0);
        self.varint(value);
    }

    /// An `optional fixed32` field, such as the nanoseconds of a timestamp.
    fn fixed32(&mut self, field: u32, value: u32) {
        self.tag(field, 5);
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    /// An `optional bytes`/`string`/embedded-message field.
    fn bytes(&mut self, field: u32, value: &[u8]) {
        self.tag(field, 2);
        self.varint(value.len() as u64);
        self.0.extend_from_slice(value);
    }
}

/// Encode one event as a `dnstap.Dnstap` protobuf.
fn encode(settings: &DnstapSettings, event: &Event) -> Vec<u8> {
    let (protocol, http) = event.transport;
    let family = match event.client.ip() {
        IpAddr::V4(_) => INET,
        IpAddr::V6(_) => INET6,
    };

    let mut message = Proto::default();
    message.uint(1, u64::from(event.msg_type));
    message.uint(2, u64::from(family));
    message.uint(3, u64::from(protocol));
    message.bytes(4, &address_bytes(event.client.ip()));
    message.uint(6, u64::from(event.client.port()));
    if let Some(server) = event.server {
        message.bytes(5, &address_bytes(server.ip()));
        message.uint(7, u64::from(server.port()));
    }
    let (secs, nanos) = split_time(event.query_time);
    message.uint(8, secs);
    message.fixed32(9, nanos);
    if event.msg_type == CLIENT_QUERY {
        // The initiator's own query, verbatim.
        message.bytes(10, &event.message);
    }
    if let Some(response_time) = event.response_time {
        let (secs, nanos) = split_time(response_time);
        message.uint(12, secs);
        message.fixed32(13, nanos);
        // The responder's own answer, verbatim.
        message.bytes(14, &event.message);
    }
    if let Some(http) = http {
        message.uint(16, u64::from(http));
    }

    let mut dnstap = Proto::default();
    let configured = settings.identity.trim();
    let identity = if configured.is_empty() {
        default_identity()
    } else {
        configured.to_string()
    };
    if !identity.is_empty() {
        dnstap.bytes(1, identity.as_bytes());
    }
    let version = match settings.version.trim() {
        "" => env!("CARGO_PKG_VERSION"),
        version => version,
    };
    dnstap.bytes(2, version.as_bytes());
    // Dnstap.Type: MESSAGE = 1.
    dnstap.uint(15, 1);
    dnstap.bytes(14, &message.0);
    dnstap.0
}

fn address_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn split_time(time: SystemTime) -> (u64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs(), elapsed.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

/// The identity sent when none is configured: the machine's host name.
fn default_identity() -> String {
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(name) = std::env::var(key) {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    "daygle-dns".to_string()
}

/// A Frame Streams control frame carrying `content_type`.
fn control_frame(kind: u32, content_type: Option<&str>) -> Vec<u8> {
    let field_count = u32::from(content_type.is_some());
    let mut payload = Vec::with_capacity(12 + content_type.map_or(0, str::len));
    payload.extend_from_slice(&kind.to_be_bytes());
    payload.extend_from_slice(&field_count.to_be_bytes());
    if let Some(content_type) = content_type {
        payload.extend_from_slice(&FSTRM_FIELD_CONTENT_TYPE.to_be_bytes());
        payload.extend_from_slice(&(content_type.len() as u32).to_be_bytes());
        payload.extend_from_slice(content_type.as_bytes());
    }

    let mut frame = Vec::with_capacity(8 + payload.len());
    // A zero length marks a control frame; the next four bytes are its size.
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Read a Frame Streams control frame (the escape word, control-frame
/// length, and control payload).
async fn read_control_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    if header[..4] != [0, 0, 0, 0] {
        return Err(std::io::Error::other(
            "expected a Frame Streams control frame",
        ));
    }
    let length = u32::from_be_bytes(header[4..].try_into().expect("4-byte length"));
    if length > 512 {
        return Err(std::io::Error::other(format!(
            "control frame of {length} bytes exceeds the maximum"
        )));
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Perform the Frame Streams handshake a dnstap collector expects: send
/// READY, require an ACCEPT with the same content type, then send START.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    stream
        .write_all(&control_frame(FSTRM_READY, Some(CONTENT_TYPE)))
        .await?;
    stream.flush().await?;
    let accept = read_control_frame(stream).await?;
    if accept.len() < 8 || u32::from_be_bytes(accept[..4].try_into().unwrap()) != FSTRM_ACCEPT {
        return Err(std::io::Error::other(
            "collector did not answer the Frame Streams handshake with ACCEPT",
        ));
    }
    let field_count = u32::from_be_bytes(accept[4..8].try_into().unwrap());
    let mut cursor = 8usize;
    let mut accepted = None;
    for _ in 0..field_count {
        let field_type = u32::from_be_bytes(
            accept
                .get(cursor..cursor + 4)
                .ok_or_else(|| std::io::Error::other("short Frame Streams control field"))?
                .try_into()
                .unwrap(),
        );
        cursor += 4;
        let field_len = u32::from_be_bytes(
            accept
                .get(cursor..cursor + 4)
                .ok_or_else(|| std::io::Error::other("short Frame Streams control field"))?
                .try_into()
                .unwrap(),
        ) as usize;
        cursor += 4;
        let value = accept
            .get(cursor..cursor + field_len)
            .ok_or_else(|| std::io::Error::other("short Frame Streams control field"))?;
        cursor += field_len;
        if field_type == FSTRM_FIELD_CONTENT_TYPE && accepted.is_none() {
            accepted = Some(value);
        }
    }
    if cursor != accept.len() || accepted != Some(CONTENT_TYPE.as_bytes()) {
        return Err(std::io::Error::other(
            "collector did not accept protobuf:dnstap.Dnstap",
        ));
    }
    stream
        .write_all(&control_frame(FSTRM_START, Some(CONTENT_TYPE)))
        .await?;
    stream.flush().await?;
    Ok(())
}

/// A connected collector: TCP, or a Unix domain socket where there is one.
enum Collector {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl Collector {
    /// Connect to the collector and complete the Frame Streams handshake.
    async fn connect(target: &DnstapTarget) -> std::io::Result<Self> {
        match target {
            DnstapTarget::Tcp { host, port } => {
                let stream = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    tokio::net::TcpStream::connect((host.as_str(), *port)),
                )
                .await
                .map_err(|_| {
                    std::io::Error::other("timed out connecting to the dnstap collector")
                })??;
                let mut collector = Self::Tcp(stream);
                collector.handshake().await?;
                Ok(collector)
            }
            DnstapTarget::Unix { path } => {
                #[cfg(unix)]
                {
                    let stream = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        tokio::net::UnixStream::connect(path.as_str()),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::other("timed out connecting to the dnstap socket")
                    })??;
                    let mut collector = Self::Unix(stream);
                    collector.handshake().await?;
                    Ok(collector)
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(std::io::Error::other(
                        "Unix domain sockets are not available on this platform",
                    ))
                }
            }
        }
    }

    async fn handshake(&mut self) -> std::io::Result<()> {
        let handshake = async {
            match self {
                Self::Tcp(stream) => handshake(stream).await,
                #[cfg(unix)]
                Self::Unix(stream) => handshake(stream).await,
            }
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| std::io::Error::other("timed out in the dnstap Frame Streams handshake"))?
    }

    /// Write one frame (or control frame) to the collector.
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await?,
            #[cfg(unix)]
            Self::Unix(stream) => stream.write_all(bytes).await?,
        }
        match self {
            Self::Tcp(stream) => stream.flush().await,
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush().await,
        }
    }
}

/// The background task: connect, stream queued events, reconnect on failure.
async fn run(
    sender: Arc<DnstapSender>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    shutdown: CancellationToken,
) {
    let mut backoff = RETRY_INITIAL;
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        let settings = sender.config.load().dnstap.clone();
        let target = if settings.enabled {
            match settings.target() {
                Ok(target) => target,
                Err(e) => {
                    warn!(error = %e, "dnstap is enabled but its collector is unusable");
                    None
                }
            }
        } else {
            None
        };
        let Some(target) = target else {
            // Disabled (or misconfigured): drop what was queued, so turning
            // it on later does not replay old queries.
            while rx.try_recv().is_ok() {}
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            continue;
        };
        match Collector::connect(&target).await {
            Ok(mut collector) => {
                backoff = RETRY_INITIAL;
                info!(collector = ?target, "dnstap collector connected");
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            let stop = control_frame(FSTRM_STOP, None);
                            let _ = collector.write(&stop).await;
                            return;
                        }
                        queued = rx.recv() => {
                            let Some(frame) = queued else { return };
                            let mut framed = Vec::with_capacity(4 + frame.len());
                            framed.extend_from_slice(&(frame.len() as u32).to_be_bytes());
                            framed.extend_from_slice(&frame);
                            if let Err(e) = collector.write(&framed).await {
                                warn!(error = %e, "dnstap collector write failed; reconnecting");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => warn!(
                collector = ?target,
                error = %e,
                retry_in = ?backoff,
                "cannot reach the dnstap collector"
            ),
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(RETRY_MAX);
    }
}

/// A sample event for [`send_test_event`]: a `CLIENT_QUERY` for a name
/// that can never resolve (`.invalid`, RFC 6761), with placeholder
/// addresses, exactly as the dispatcher would encode a real one.
fn sample_event() -> Event {
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    if let Ok(name) = Name::from_ascii("test.daygle-dns.invalid.") {
        message.add_query(Query::query(name, RecordType::A));
    }
    Event {
        msg_type: CLIENT_QUERY,
        client: SocketAddr::from(([127, 0, 0, 1], 53000)),
        server: None,
        transport: (UDP, None),
        query_time: SystemTime::now(),
        response_time: None,
        message: message.to_vec().unwrap_or_default(),
    }
}

/// Connect to `settings`'s collector, complete the Frame Streams
/// handshake, send one sample event and end the stream: what
/// `POST /api/dnstap/test` runs, so a collector can be checked before the
/// settings are saved (or a saved one afterwards). Unlike the background
/// sender this waits for the work and reports why it failed.
pub async fn send_test_event(settings: &DnstapSettings) -> Result<(), String> {
    let target = match settings.target() {
        Ok(Some(target)) => target,
        Ok(None) => {
            return Err("server must name a collector, e.g. tcp://127.0.0.1:6000".to_string())
        }
        Err(e) => return Err(e),
    };
    let mut collector = Collector::connect(&target)
        .await
        .map_err(|e| format!("cannot reach the collector: {e}"))?;
    let frame = encode(settings, &sample_event());
    let mut framed = Vec::with_capacity(4 + frame.len());
    framed.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    framed.extend_from_slice(&frame);
    collector
        .write(&framed)
        .await
        .map_err(|e| format!("the collector did not accept the event: {e}"))?;
    // End the stream the way the background task does on shutdown.
    let _ = collector.write(&control_frame(FSTRM_STOP, None)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn settings() -> DnstapSettings {
        DnstapSettings {
            enabled: true,
            server: "tcp://127.0.0.1:6000".to_string(),
            identity: "resolver-1".to_string(),
            version: "1.2.3".to_string(),
        }
    }

    fn wire_query() -> Vec<u8> {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    /// Millisecond time fractions: Windows SystemTime rounds to
    /// 100-nanosecond ticks, which would eat sub-microsecond values.
    fn event(msg_type: u32) -> Event {
        Event {
            msg_type,
            client: "192.0.2.10:53000".parse().unwrap(),
            server: Some("192.0.2.1:53".parse().unwrap()),
            transport: (UDP, None),
            query_time: UNIX_EPOCH + Duration::new(1_700_000_000, 123_000_000),
            // Only a response event has a response time; the dispatcher
            // builds CLIENT_QUERY events without one.
            response_time: (msg_type == CLIENT_RESPONSE)
                .then(|| UNIX_EPOCH + Duration::new(1_700_000_000, 456_000_000)),
            message: wire_query(),
        }
    }

    /// Read a varint from `bytes` at `*at`.
    fn varint(bytes: &[u8], at: &mut usize) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*at];
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    /// Decode the protobuf into (field number, value) pairs.
    fn fields(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut at = 0;
        let mut out = Vec::new();
        while at < bytes.len() {
            let key = varint(bytes, &mut at);
            let field = (key >> 3) as u32;
            match key & 7 {
                0 => {
                    let start = at;
                    let _ = varint(bytes, &mut at);
                    out.push((field, bytes[start..at].to_vec()));
                }
                2 => {
                    let len = varint(bytes, &mut at) as usize;
                    out.push((field, bytes[at..at + len].to_vec()));
                    at += len;
                }
                5 => {
                    out.push((field, bytes[at..at + 4].to_vec()));
                    at += 4;
                }
                other => panic!("unexpected wire type {other}"),
            }
        }
        out
    }

    fn field(fields: &[(u32, Vec<u8>)], number: u32) -> Option<&[u8]> {
        fields
            .iter()
            .find(|(field, _)| *field == number)
            .map(|(_, value)| value.as_slice())
    }

    fn number(fields: &[(u32, Vec<u8>)], number: u32) -> Option<u64> {
        field(fields, number).map(|value| {
            let mut at = 0;
            varint(value, &mut at)
        })
    }

    #[test]
    fn encodes_a_client_query() {
        let bytes = encode(&settings(), &event(CLIENT_QUERY));
        let dnstap = fields(&bytes);
        assert_eq!(number(&dnstap, 15), Some(1), "Dnstap.type = MESSAGE");
        assert_eq!(field(&dnstap, 1), Some(b"resolver-1".as_slice()));
        assert_eq!(field(&dnstap, 2), Some(b"1.2.3".as_slice()));

        let message = fields(field(&dnstap, 14).expect("message"));
        assert_eq!(number(&message, 1), Some(u64::from(CLIENT_QUERY)));
        assert_eq!(number(&message, 2), Some(u64::from(INET)));
        assert_eq!(number(&message, 3), Some(u64::from(UDP)));
        assert_eq!(field(&message, 4), Some([192, 0, 2, 10].as_slice()));
        assert_eq!(number(&message, 6), Some(53000));
        assert_eq!(number(&message, 8), Some(1_700_000_000));
        assert_eq!(
            field(&message, 9),
            Some(123_000_000u32.to_le_bytes().as_slice())
        );
        assert_eq!(field(&message, 10), Some(wire_query().as_slice()));
        assert!(
            field(&message, 12).is_none(),
            "a query has no response time"
        );
    }

    #[test]
    fn encodes_a_client_response_with_both_times() {
        let bytes = encode(&settings(), &event(CLIENT_RESPONSE));
        let message = fields(field(&fields(&bytes), 14).expect("message"));
        assert_eq!(number(&message, 1), Some(u64::from(CLIENT_RESPONSE)));
        assert_eq!(number(&message, 12), Some(1_700_000_000));
        assert_eq!(
            field(&message, 13),
            Some(456_000_000u32.to_le_bytes().as_slice())
        );
        assert_eq!(field(&message, 14), Some(wire_query().as_slice()));
        assert_eq!(
            field(&message, 5),
            Some([192, 0, 2, 1].as_slice()),
            "the server's address"
        );
    }

    #[test]
    fn http3_is_doh_with_http3() {
        assert_eq!(transport_of(Protocol::H3), (DOH, Some(HTTP3)));
        assert_eq!(transport_of(Protocol::Https), (DOH, Some(HTTP2)));
        assert_eq!(transport_of(Protocol::Quic), (DOQ, None));
        assert_eq!(transport_of(Protocol::Tls), (DOT, None));
        let mut event = event(CLIENT_QUERY);
        event.transport = transport_of(Protocol::H3);
        let bytes = encode(&settings(), &event);
        let message = fields(field(&fields(&bytes), 14).expect("message"));
        assert_eq!(number(&message, 3), Some(u64::from(DOH)));
        assert_eq!(number(&message, 16), Some(u64::from(HTTP3)));
    }

    #[test]
    fn ipv6_addresses_are_sixteen_octets() {
        let mut event = event(CLIENT_QUERY);
        event.client = "[2001:db8::1]:5353".parse().unwrap();
        let bytes = encode(&settings(), &event);
        let message = fields(field(&fields(&bytes), 14).expect("message"));
        assert_eq!(number(&message, 2), Some(u64::from(INET6)));
        let address = field(&message, 4).unwrap();
        assert_eq!(address.len(), 16);
        assert_eq!(
            address,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[tokio::test]
    async fn a_test_event_handshakes_sends_and_closes() {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let collector = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let ready = read_control_frame(&mut stream).await.unwrap();
            assert_eq!(
                u32::from_be_bytes(ready[..4].try_into().unwrap()),
                FSTRM_READY
            );
            stream
                .write_all(&control_frame(FSTRM_ACCEPT, Some(CONTENT_TYPE)))
                .await
                .unwrap();
            let start = read_control_frame(&mut stream).await.unwrap();
            assert_eq!(
                u32::from_be_bytes(start[..4].try_into().unwrap()),
                FSTRM_START
            );
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut frame = vec![0u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut frame).await.unwrap();
            let stop = read_control_frame(&mut stream).await.unwrap();
            assert_eq!(
                u32::from_be_bytes(stop[..4].try_into().unwrap()),
                FSTRM_STOP,
                "the test stream is closed properly"
            );
            frame
        });
        let mut settings = settings();
        settings.server = format!("tcp://127.0.0.1:{port}");
        send_test_event(&settings)
            .await
            .expect("the collector accepted the event");
        let frame = collector.await.unwrap();
        let message = fields(field(&fields(&frame), 14).expect("message"));
        assert_eq!(number(&message, 1), Some(u64::from(CLIENT_QUERY)));
        assert!(field(&message, 10).is_some(), "the sample query, verbatim");
    }

    #[tokio::test]
    async fn a_test_event_reports_an_unreachable_collector() {
        let mut settings = settings();
        // Port 1 on loopback: nothing listens there.
        settings.server = "tcp://127.0.0.1:1".to_string();
        let error = send_test_event(&settings).await.expect_err("unreachable");
        assert!(
            error.contains("cannot reach the collector"),
            "the error says what failed: {error}"
        );
    }

    #[tokio::test]
    async fn a_test_event_needs_a_collector() {
        let mut settings = settings();
        settings.server = String::new();
        let error = send_test_event(&settings).await.expect_err("no collector");
        assert!(
            error.contains("server"),
            "the error names the setting: {error}"
        );
    }

    #[tokio::test]
    async fn the_handshake_requires_an_accept_for_our_content_type() {
        let (mut client, mut collector) = tokio::io::duplex(4096);
        let collector_task = tokio::spawn(async move {
            // Read READY (escape, length, payload), answer ACCEPT, read
            // START, and report the kinds seen.
            let mut header = [0u8; 8];
            use tokio::io::AsyncReadExt as _;
            collector.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; length];
            collector.read_exact(&mut payload).await.unwrap();
            assert_eq!(
                u32::from_be_bytes(payload[..4].try_into().unwrap()),
                FSTRM_READY
            );
            use tokio::io::AsyncWriteExt as _;
            collector
                .write_all(&control_frame(FSTRM_ACCEPT, Some(CONTENT_TYPE)))
                .await
                .unwrap();
            collector.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; length];
            collector.read_exact(&mut payload).await.unwrap();
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        });
        handshake(&mut client).await.expect("handshake succeeds");
        let start = collector_task.await.unwrap();
        assert_eq!(start, FSTRM_START);
    }

    #[tokio::test]
    async fn the_handshake_refuses_a_wrong_content_type() {
        let (mut client, mut collector) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut header = [0u8; 8];
            collector.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; length];
            collector.read_exact(&mut payload).await.unwrap();
            collector
                .write_all(&control_frame(FSTRM_ACCEPT, Some("protobuf:other")))
                .await
                .unwrap();
        });
        let result = handshake(&mut client).await;
        assert!(result.is_err(), "a different content type is refused");
    }

    #[test]
    fn control_frames_match_the_frame_streams_layout() {
        let ready = control_frame(FSTRM_READY, Some(CONTENT_TYPE));
        assert_eq!(&ready[..4], &[0, 0, 0, 0], "a control frame marker");
        let length = u32::from_be_bytes(ready[4..8].try_into().unwrap()) as usize;
        assert_eq!(length, ready.len() - 8);
        assert_eq!(
            u32::from_be_bytes(ready[8..12].try_into().unwrap()),
            FSTRM_READY
        );
        assert_eq!(
            u32::from_be_bytes(ready[12..16].try_into().unwrap()),
            1,
            "one control field"
        );
        assert_eq!(
            u32::from_be_bytes(ready[16..20].try_into().unwrap()),
            FSTRM_FIELD_CONTENT_TYPE
        );
        let field_len = u32::from_be_bytes(ready[20..24].try_into().unwrap()) as usize;
        assert_eq!(&ready[24..24 + field_len], CONTENT_TYPE.as_bytes());
        assert_eq!(24 + field_len, ready.len());
    }
}
