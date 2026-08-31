//! RFC 1996 NOTIFY support.
//!
//! Two independent pieces:
//!
//! - [`NotifySender`] - when a primary zone changes (dynamic update applied),
//!   send a NOTIFY (OpCode 4, QTYPE SOA) over UDP to each configured target.
//!   Secondaries that receive it immediately query our SOA and pull an
//!   IXFR/AXFR when the serial advanced.
//!
//! - [`NotifyInbound`] - NOTIFY requests (OpCode 4) arriving on the regular
//!   DNS listeners are intercepted by the dispatcher and routed here: a
//!   NOTIFY for a configured secondary zone is answered with the current SOA
//!   and triggers an immediate refresh (serial compare + IXFR/AXFR), so
//!   replication latency no longer equals the refresh interval.
//!
//! NOTIFY is a hint, not a command: the refresh path still compares serials
//! and only accepts hints from one of the zone's configured masters, so
//! replayed or spoofed NOTIFYs cannot corrupt zone data.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daygle_core::config::SecondaryZoneConfig;
use daygle_core::error::{DaygleError, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::secondary::SecondaryRefresher;

/// How long to wait for a NOTIFY acknowledgment (best effort; loss is fine,
/// the refresh interval remains the safety net).
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(3);

/// Outbound and inbound NOTIFY hooks, wired into the dispatcher together.
#[derive(Default, Clone)]
pub struct NotifyHooks {
    /// Sends NOTIFYs after successful primary-zone changes.
    pub sender: Option<Arc<NotifySender>>,
    /// Processes inbound NOTIFYs for configured secondary zones.
    pub inbound: Option<Arc<NotifyInbound>>,
}

/// Send RFC 1996 NOTIFY messages to the configured targets.
#[derive(Debug, Clone)]
pub struct NotifySender {
    targets: Vec<SocketAddr>,
}

impl NotifySender {
    /// Build a sender for `targets` (each `IP`, `IP:port`, or `[IPv6]:port`;
    /// port defaults to 53). Empty targets make the sender a no-op.
    pub fn new(targets: &[String]) -> std::result::Result<Self, String> {
        let mut addrs = Vec::with_capacity(targets.len());
        for target in targets {
            let addr = daygle_core::config::parse_master_addr(target)
                .map_err(|e| format!("invalid notify target '{target}': {e}"))?;
            addrs.push(addr);
        }
        Ok(Self { targets: addrs })
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Send a NOTIFY for `zone` to every target. Failures are logged and
    /// otherwise ignored: NOTIFY is unreliable by design and the refresh
    /// interval is the fallback.
    pub async fn notify_zone(&self, zone: &str) {
        if self.targets.is_empty() {
            return;
        }
        let zone_name = match fqdn(zone) {
            Ok(name) => name,
            Err(e) => {
                warn!(zone = %zone, error = %e, "cannot build NOTIFY query");
                return;
            }
        };
        let mut msg = Message::new(0, MessageType::Query, OpCode::Notify);
        msg.add_query(Query::query(zone_name.clone(), RecordType::SOA));
        let bytes = match msg.to_vec() {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(zone = %zone, error = %e, "cannot encode NOTIFY");
                return;
            }
        };

        let bind_addr = if self.targets.iter().any(|t| t.is_ipv6()) {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(e) => {
                warn!(zone = %zone, error = %e, "cannot bind NOTIFY socket");
                return;
            }
        };

        for target in &self.targets {
            let send = async {
                socket.send_to(&bytes, target).await?;
                // Best-effort wait for the acknowledgment; its content is not
                // consulted (the pull path re-checks the SOA anyway).
                let mut buf = vec![0u8; 512];
                let _ = socket.recv_from(&mut buf).await;
                Ok::<(), std::io::Error>(())
            };
            match tokio::time::timeout(NOTIFY_TIMEOUT, send).await {
                Ok(Ok(())) => debug!(zone = %zone, %target, "NOTIFY sent"),
                Ok(Err(e)) => warn!(zone = %zone, %target, error = %e, "NOTIFY send failed"),
                Err(_) => debug!(zone = %zone, %target, "NOTIFY ack timed out"),
            }
        }
        info!(zone = %zone, targets = self.targets.len(), "NOTIFY dispatched");
    }
}

/// Handle inbound NOTIFYs (OpCode 4) for configured secondary zones.
pub struct NotifyInbound {
    /// Secondary zones we accept NOTIFYs for; also used to check that the
    /// sender is one of the zone's configured masters.
    zones: Vec<SecondaryZoneConfig>,
    refresher: Arc<SecondaryRefresher>,
}

impl NotifyInbound {
    pub fn new(zones: Vec<SecondaryZoneConfig>, refresher: Arc<SecondaryRefresher>) -> Self {
        Self { zones, refresher }
    }

    /// Process one NOTIFY request. Replies with the zone's current SOA and
    /// wakes the refresher for an immediate pull; unknown or unauthorized
    /// NOTIFYs get NOTIMP without any refresh.
    pub async fn handle<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let Some(query) = request.queries.queries().first() else {
            debug!(src = %request.src(), "NOTIFY without a zone section");
            return send_notify_reply(&mut response_handle, request, ResponseCode::NotImp, None)
                .await;
        };
        if query.query_type() != RecordType::SOA {
            debug!(
                src = %request.src(),
                qtype = %query.query_type(),
                "NOTIFY with non-SOA zone section"
            );
            return send_notify_reply(&mut response_handle, request, ResponseCode::NotImp, None)
                .await;
        }

        let zone = normalize(query.name().to_string());
        let Some(config) = self
            .zones
            .iter()
            .find(|c| c.enabled && normalize(c.name.clone()) == zone)
        else {
            debug!(zone = %zone, src = %request.src(), "NOTIFY for unconfigured secondary zone");
            return send_notify_reply(&mut response_handle, request, ResponseCode::NotImp, None)
                .await;
        };

        // Defense in depth: only accept hints from one of the zone's masters
        // (source ports are ephemeral, so compare IPs only). The refresh path
        // re-checks serials, so an accepted spoof could only cause an extra
        // SOA query - but there is no reason to accept one.
        let src_ip = request.src().ip();
        let is_master = config.masters.iter().any(|m| {
            daygle_core::config::parse_master_addr(m)
                .map(|addr| addr.ip() == src_ip)
                .unwrap_or(false)
        });
        if !is_master {
            debug!(zone = %zone, %src_ip, "NOTIFY from a non-master address");
            return send_notify_reply(&mut response_handle, request, ResponseCode::NotImp, None)
                .await;
        }

        info!(zone = %zone, %src_ip, "NOTIFY received");

        // Answer first (with the current SOA, RFC 1996 §3.7) so the master is
        // not left waiting, then pull in the background.
        let current_soa = self.refresher.current_soa(&zone).await;
        let info =
            send_notify_reply(&mut response_handle, request, ResponseCode::NoError, current_soa)
                .await;

        let refresher = self.refresher.clone();
        let config = config.clone();
        tokio::spawn(async move {
            match refresher.refresh_zone(&config).await {
                Ok(true) => info!(zone = %config.name, "secondary zone refreshed after NOTIFY"),
                Ok(false) => debug!(zone = %config.name, "NOTIFY refresh: no change"),
                Err(e) => warn!(zone = %config.name, error = %e, "NOTIFY-triggered refresh failed"),
            }
        });

        info
    }
}

/// Send a NOTIFY response carrying only the response code (plus an optional
/// current-SOA answer). The request's OpCode (Notify) is preserved so the
/// master can correlate the acknowledgment.
async fn send_notify_reply<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    code: ResponseCode,
    soa: Option<hickory_proto::rr::Record>,
) -> ResponseInfo {
    let mut metadata = request.metadata;
    metadata.message_type = MessageType::Response;
    metadata.response_code = code;
    metadata.authoritative = code == ResponseCode::NoError;
    metadata.recursion_available = false;
    metadata.recursion_desired = false;

    let soa_buf = soa.into_iter().collect::<Vec<_>>();
    let answers: &[hickory_proto::rr::Record] = &soa_buf;

    let response = MessageResponseBuilder::from_message_request(request).build(
        metadata,
        answers.iter(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            warn!("failed to send NOTIFY reply: {e}");
            fallback_response()
        }
    }
}

/// A minimal `ResponseInfo` used when the transport failed entirely.
fn fallback_response() -> ResponseInfo {
    ResponseInfo::from(hickory_proto::op::Header {
        metadata: hickory_proto::op::Metadata::new(0, MessageType::Response, OpCode::Notify),
        counts: hickory_proto::op::HeaderCounts::default(),
    })
}

fn normalize(name: String) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn fqdn(name: &str) -> Result<Name> {
    Name::from_utf8(&format!("{}.", name.trim().trim_end_matches('.')))
        .map_err(|e| DaygleError::InvalidRecord(format!("name '{name}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_parses_targets() {
        let sender = NotifySender::new(&["192.0.2.1".to_string(), "192.0.2.2:5353".to_string()])
            .expect("valid targets");
        assert!(!sender.is_empty());
        assert!(NotifySender::new(&[]).unwrap().is_empty());
        assert!(NotifySender::new(&["nope".to_string()]).is_err());
    }

    #[test]
    fn normalizes_zone_names() {
        assert_eq!(normalize("Example.COM.".to_string()), "example.com");
        assert_eq!(normalize("example.com".to_string()), "example.com");
    }
}
