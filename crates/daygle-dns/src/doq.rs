//! # DNS over QUIC (RFC 9250) listener
//!
//! `doq` lands DNS on top of QUIC. Each DNS transaction occupies exactly one
//! QUIC bidirectional stream, and every message is framed with a 2-octet
//! length prefix - the same wire format as DNS over TCP (RFC 9250 §4.2).
//!
//! The listener is built directly on `quinn` so the QUIC connection idle
//! timeout is configurable (`server doq.idle_timeout_secs`). Hickory's own
//! QUIC listener hard-codes its transport settings, so it cannot honor the
//! Daygle configuration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use daygle_dns_core::error::DaygleError;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig, VarInt};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::dispatcher::DnsDispatcher;

/// Largest message the 2-octet length prefix can describe (RFC 1035 §4.2.2).
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// DoQ reserved error codes (RFC 9250 §4.3).
const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;

/// Build a QUIC [`Endpoint`] bound to `socket` that speaks DoQ (RFC 9250).
///
/// `tls_config` is the rustls server configuration produced by
/// [`daygle_dns_dot::build_doq_tls_config`] (ALPN `doq`, TLS 1.3 only).
/// Idle connections are torn down after `idle_timeout` (RFC 9250 recommends
/// at least two minutes; Daygle validates the configured seconds at >= 30).
pub fn build_doq_endpoint(
    socket: tokio::net::UdpSocket,
    tls_config: Arc<rustls::ServerConfig>,
    idle_timeout: Duration,
) -> Result<quinn::Endpoint, DaygleError> {
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config)
            .map_err(|e| DaygleError::Tls(format!("DoQ TLS config: {e}")))?,
    ));

    // DoQ transport profile: only bidirectional streams and no application
    // datagrams (RFC 9250 §4.2). On top of those defaults we apply the
    // configured connection idle timeout.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.max_idle_timeout(Some(idle_timeout.try_into().map_err(|_| {
        DaygleError::Config("doq idle_timeout_secs is too large".to_string())
    })?));
    server_config.transport = Arc::new(transport);

    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(0x45ac)
        .map_err(|e| DaygleError::Config(format!("DoQ max_udp_payload_size: {e}")))?;

    // The socket was already bound by the caller; quinn takes over from here.
    let socket = socket.into_std()?;
    let endpoint = Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| DaygleError::Config(format!("cannot create DoQ endpoint: {e}")))?;
    Ok(endpoint)
}

/// Serve DoQ on `endpoint` until `shutdown` is cancelled, dispatching queries
/// to `handler`.
pub async fn serve_doq(endpoint: Endpoint, handler: DnsDispatcher, shutdown: CancellationToken) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                endpoint.close(VarInt::from_u32(DOQ_NO_ERROR), b"server shutting down");
                while connections.join_next().await.is_some() {}
                break;
            }
            incoming = endpoint.accept() => {
                let Some(connecting) = incoming else { break };
                let handler = handler.clone();
                connections.spawn(async move {
                    if let Err(e) = handle_connection(connecting, handler).await {
                        debug!("DoQ connection error: {e}");
                    }
                });
            }
        }
    }
}

/// Handle one inbound QUIC connection: complete the handshake, then serve one
/// task per DNS query stream.
async fn handle_connection(
    connecting: quinn::Incoming,
    handler: DnsDispatcher,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let src = connecting.remote_address();
    let connection = connecting.await?;
    loop {
        match connection.accept_bi().await {
            Ok((send_stream, recv_stream)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send_stream, recv_stream, src, handler).await {
                        debug!(%src, "DoQ stream error: {e}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(%src, "DoQ connection closed by client");
                break;
            }
            Err(e) => {
                debug!(%src, "DoQ connection ended: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Serve one DNS query/response transaction on a single QUIC stream
/// (RFC 9250 §4.2: one message per stream, 2-octet length prefix, Message ID
/// MUST be 0).
async fn handle_stream(
    send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    src: SocketAddr,
    handler: DnsDispatcher,
) -> Result<(), NetError> {
    // Read the framed request. A client that closes the stream without
    // sending a query has nothing to answer.
    let mut len_buf = [0u8; 2];
    if recv_stream.read_exact(&mut len_buf).await.is_err() {
        return Ok(());
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    if recv_stream.read_exact(&mut body).await.is_err() {
        return Ok(());
    }

    let responder = DoqResponseHandle::new(send_stream, recv_stream);

    // Recover the Message ID from the header so a FORMERR answer (or a
    // protocol-error abort) can still be correlated by the client.
    let id_hint = {
        let mut decoder = BinDecoder::new(&body);
        Header::read(&mut decoder)
            .map(|h| h.metadata.id)
            .unwrap_or(0)
    };

    let request = match Request::from_bytes(body, src, Protocol::Quic) {
        Ok(request) => request,
        Err(e) => {
            warn!(%e, %src, "malformed DoQ request");
            responder.formerr(id_hint).await;
            return Ok(());
        }
    };

    // RFC 9250 §4.2.1: response messages are discarded (they cannot be
    // answered) and the DoQ Message ID is always 0, so a non-zero ID is a
    // protocol violation.
    if request.metadata.message_type != MessageType::Query {
        debug!(%src, "ignoring non-query message over DoQ");
        return Ok(());
    }
    if request.metadata.id != 0 {
        debug!(id = request.metadata.id, %src, "rejecting DoQ query with non-zero Message ID");
        responder.reject(VarInt::from_u32(DOQ_PROTOCOL_ERROR)).await;
        return Ok(());
    }

    handler
        .handle_request::<_, TokioTime>(&request, responder.clone())
        .await;
    responder.finish().await;
    Ok(())
}

/// A [`ResponseHandler`] that writes the encoded response onto the QUIC send
/// stream (length-prefixed), finishing the stream, and can abort the stream
/// on protocol violations.
#[derive(Clone)]
struct DoqResponseHandle {
    send: Arc<Mutex<Option<quinn::SendStream>>>,
    recv: Arc<Mutex<Option<quinn::RecvStream>>>,
}

impl DoqResponseHandle {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Arc::new(Mutex::new(Some(send))),
            recv: Arc::new(Mutex::new(Some(recv))),
        }
    }

    /// Close the stream after a final response.
    async fn finish(&self) {
        let mut guard = self.send.lock().await;
        if let Some(mut send) = guard.take() {
            let _ = send.finish();
        }
    }

    /// Abort the stream with a DoQ application error code (RFC 9250 §4.3).
    async fn reject(&self, code: VarInt) {
        let mut guard = self.send.lock().await;
        if let Some(send) = guard.as_mut() {
            let _ = send.reset(code);
        }
        drop(guard);
        if let Some(recv) = self.recv.lock().await.as_mut() {
            let _ = recv.stop(code);
        }
    }

    /// Emit a length-prefixed FORMERR answer for a request that failed to
    /// parse, then close the stream.
    async fn formerr(&self, id_hint: u16) {
        let mut bytes = Vec::with_capacity(64);
        let mut encoder = BinEncoder::new(&mut bytes);
        let mut metadata = Metadata::new(id_hint, MessageType::Response, OpCode::Query);
        metadata.response_code = ResponseCode::FormErr;
        let header = Header {
            metadata,
            counts: HeaderCounts::default(),
        };
        if header.emit(&mut encoder).is_err() {
            return;
        }
        let _ = self.write_framed(&bytes).await;
        self.finish().await;
    }

    /// Length-prefix and write `bytes` onto the stream (RFC 9250 §4.2
    /// framing).
    async fn write_framed(&self, bytes: &[u8]) -> Result<(), NetError> {
        if bytes.len() > MAX_MESSAGE_LEN {
            return Err(NetError::Message("DoQ message exceeds 65535 bytes"));
        }
        let mut guard = self.send.lock().await;
        let Some(send) = guard.as_mut() else {
            return Err(NetError::Message("DoQ stream already closed"));
        };
        let len = (bytes.len() as u16).to_be_bytes();
        send.write_all(&len).await?;
        send.write_all(bytes).await?;
        Ok(())
    }
}

#[async_trait]
impl ResponseHandler for DoqResponseHandle {
    async fn send_response<'a>(
        &mut self,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // RFC 9250 §4.2.1: the DNS Message ID MUST be 0 in DoQ responses.
        let id = response.metadata().id;
        response.metadata_mut().id = 0;

        let mut bytes = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(u16::MAX);
            match response.destructive_emit(&mut encoder) {
                Ok(info) => {
                    self.write_framed(&bytes).await?;
                    return Ok(info);
                }
                Err(error) => error!(%error, "error encoding DoQ response"),
            }
        }

        // Fallback: like Hickory's MessageResponse::encode, answer with a bare
        // SERVFAIL so the client gets a message instead of a stalled stream.
        bytes.clear();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(512);
        let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
        metadata.response_code = ResponseCode::ServFail;
        let header = Header {
            metadata,
            counts: HeaderCounts::default(),
        };
        header.emit(&mut encoder)?;
        self.write_framed(&bytes).await?;
        Ok(ResponseInfo::from(header))
    }
}
