//! # Plain DNS over UDP listener (Linux)
//!
//! A UDP socket bound to a wildcard address (`0.0.0.0`, `::` - the default
//! listen address) receives queries sent to every address of the host, but
//! a reply sent with plain `sendto` leaves from whichever address the
//! kernel's routing and source-address selection pick. On a host with more
//! than one address a client can reach - secondary addresses, a VRRP or
//! keepalived virtual address, or IPv6's stable and temporary privacy
//! addresses side by side - that is often not the address the client asked,
//! and the client drops the reply as a possible spoof. Hickory's UDP
//! listener does exactly that.
//!
//! Here each query's destination address and interface are read from its
//! `IP_PKTINFO` / `IPV6_PKTINFO` control message, and the reply is sent from
//! that same address. Answers are sized as Hickory's listener sizes them:
//! the payload the response's OPT record offers, or 512 octets without one,
//! truncated (TC) beyond it. Each query is answered in its own task, from
//! the task itself (no hop through a shared writer).

use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Header, MessageType, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::NetError;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use nix::libc;
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
    SockaddrStorage,
};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::dispatcher::DnsDispatcher;
use crate::dot::error_message;

/// The largest UDP payload, so no datagram is cut short.
const RECV_BUFFER: usize = 65_535;

/// The local address a datagram was sent to, and the interface it came in
/// on (needed to answer from an IPv6 link-local address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Arrival {
    local: IpAddr,
    ifindex: u32,
}

/// Ask the kernel to report each datagram's destination address.
pub fn enable_destination_info(socket: &UdpSocket) -> io::Result<()> {
    match socket.local_addr()? {
        SocketAddr::V4(_) => setsockopt(socket, sockopt::Ipv4PacketInfo, &true),
        SocketAddr::V6(_) => setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true),
    }
    .map_err(io::Error::from)
}

/// Serve DNS on `socket` until `shutdown` is cancelled
/// ([`enable_destination_info`] must have been called on it).
pub async fn serve_udp(socket: UdpSocket, handler: DnsDispatcher, shutdown: CancellationToken) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; RECV_BUFFER];
    let mut queries = JoinSet::new();
    loop {
        let received = tokio::select! {
            _ = shutdown.cancelled() => break,
            received = recv(&socket, &mut buf) => received,
        };
        // Reap answered queries so the set does not grow with the traffic.
        while queries.try_join_next().is_some() {}
        let (len, src, arrival) = match received {
            Ok(received) => received,
            Err(error) => {
                // ICMP errors from earlier sends surface here: transient.
                // Anything persistent must not spin the loop.
                debug!(%error, "UDP receive failed");
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
        };
        if !answerable(src) {
            debug!(%src, "UDP query from an address that cannot be answered");
            continue;
        }
        let responder = UdpResponder {
            socket: socket.clone(),
            to: src,
            arrival,
        };
        queries.spawn(answer(buf[..len].to_vec(), src, handler.clone(), responder));
    }
}

/// Whether a reply can be sent to `src` (as Hickory's listener checks).
fn answerable(src: SocketAddr) -> bool {
    src.port() != 0
        && match src.ip().to_canonical() {
            IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_broadcast(),
            IpAddr::V6(v6) => !v6.is_unspecified(),
        }
}

/// Decode and answer one query.
async fn answer(body: Vec<u8>, src: SocketAddr, handler: DnsDispatcher, responder: UdpResponder) {
    // Under twelve octets is not a DNS message: dropped, as Hickory does.
    let Ok(header) = Header::read(&mut BinDecoder::new(&body)) else {
        return;
    };
    // Never answer a response (reflection).
    if header.metadata.message_type != MessageType::Query {
        return;
    }
    let request = match Request::from_bytes(body, src, Protocol::Udp) {
        Ok(request) => request,
        Err(error) => {
            debug!(%src, %error, "malformed UDP request");
            let formerr = error_message(header.metadata.id, ResponseCode::FormErr);
            let _ = send(&responder.socket, &formerr, src, responder.arrival).await;
            return;
        }
    };
    handler
        .handle_request::<_, TokioTime>(&request, responder)
        .await;
}

/// Receive one datagram: its length, sender and destination.
async fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<Arrival>)> {
    socket
        .async_io(Interest::READABLE, || {
            let mut iov = [IoSliceMut::new(buf)];
            let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
            let msg = recvmsg::<SockaddrStorage>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .map_err(io::Error::from)?;
            let src = msg
                .address
                .as_ref()
                .and_then(socket_addr)
                .ok_or_else(|| io::Error::other("no sender address"))?;
            let mut arrival = None;
            for message in msg.cmsgs().map_err(io::Error::from)? {
                arrival = match message {
                    ControlMessageOwned::Ipv4PacketInfo(info) => Some(v4_arrival(&info)),
                    ControlMessageOwned::Ipv6PacketInfo(info) => v6_arrival(&info),
                    _ => continue,
                };
            }
            Ok((msg.bytes, src, arrival))
        })
        .await
}

fn socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = address.as_sockaddr_in() {
        return Some(SocketAddr::V4((*v4).into()));
    }
    address
        .as_sockaddr_in6()
        .map(|v6| SocketAddr::V6((*v6).into()))
}

/// `ipi_addr` is the address the datagram was sent to; for a broadcast,
/// answer from the interface's own address (`ipi_spec_dst`) instead.
fn v4_arrival(info: &libc::in_pktinfo) -> Arrival {
    let to = Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr));
    let local = if to.is_broadcast() || to.is_multicast() {
        Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr))
    } else {
        to
    };
    Arrival {
        local: local.into(),
        ifindex: u32::try_from(info.ipi_ifindex).unwrap_or(0),
    }
}

/// A multicast destination cannot be a reply's source: the kernel picks.
fn v6_arrival(info: &libc::in6_pktinfo) -> Option<Arrival> {
    let to = Ipv6Addr::from(info.ipi6_addr.s6_addr);
    (!to.is_multicast()).then_some(Arrival {
        local: to.into(),
        ifindex: info.ipi6_ifindex,
    })
}

/// Send `data` to `to` from the address the query arrived on. Should that
/// fail (the address was removed meanwhile), send it the plain way.
async fn send(
    socket: &UdpSocket,
    data: &[u8],
    to: SocketAddr,
    arrival: Option<Arrival>,
) -> io::Result<()> {
    let dest = SockaddrStorage::from(to);
    if let Some(arrival) = arrival {
        if send_from(socket, data, &dest, arrival).await.is_ok() {
            return Ok(());
        }
    }
    socket
        .async_io(Interest::WRITABLE, || {
            sendmsg(
                socket.as_raw_fd(),
                &[IoSlice::new(data)],
                &[],
                MsgFlags::empty(),
                Some(&dest),
            )
            .map_err(io::Error::from)
        })
        .await
        .map(|_| ())
}

async fn send_from(
    socket: &UdpSocket,
    data: &[u8],
    dest: &SockaddrStorage,
    arrival: Arrival,
) -> io::Result<()> {
    // IPv4: the source address only; the route picks the interface (pinning
    // it would break asymmetric routing). IPv6: the interface too, which a
    // link-local source needs.
    let v4;
    let v6;
    let control = match arrival.local {
        IpAddr::V4(local) => {
            v4 = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from(local).to_be(),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            ControlMessage::Ipv4PacketInfo(&v4)
        }
        IpAddr::V6(local) => {
            v6 = libc::in6_pktinfo {
                ipi6_addr: libc::in6_addr {
                    s6_addr: local.octets(),
                },
                ipi6_ifindex: arrival.ifindex,
            };
            ControlMessage::Ipv6PacketInfo(&v6)
        }
    };
    socket
        .async_io(Interest::WRITABLE, || {
            sendmsg(
                socket.as_raw_fd(),
                &[IoSlice::new(data)],
                &[control],
                MsgFlags::empty(),
                Some(dest),
            )
            .map_err(io::Error::from)
        })
        .await
        .map(|_| ())
}

/// Sends the answer to one query from the address the query was sent to.
#[derive(Clone)]
struct UdpResponder {
    socket: Arc<UdpSocket>,
    to: SocketAddr,
    arrival: Option<Arrival>,
}

#[async_trait]
impl ResponseHandler for UdpResponder {
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
        // As Hickory's UDP responder: what the response's OPT record offers,
        // else RFC 1035's 512 octets. An answer that does not fit is
        // truncated (TC), so the client retries over TCP.
        let max_size = response.edns().map_or(512, |edns| edns.max_payload());
        let mut bytes = Vec::with_capacity(512);
        let encoded = {
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(max_size);
            response.destructive_emit(&mut encoder)
        };
        let info = match encoded {
            Ok(info) => info,
            Err(error) => {
                error!(%error, "error encoding a UDP response");
                bytes = error_message(id, ResponseCode::ServFail);
                ResponseInfo::from(Header::read(&mut BinDecoder::new(&bytes))?)
            }
        };
        send(&self.socket, &bytes, self.to, self.arrival)
            .await
            .map_err(|e| NetError::from(e.to_string()))?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_addresses_a_reply_can_reach_are_answered() {
        let ok: SocketAddr = "192.0.2.1:5353".parse().unwrap();
        assert!(answerable(ok));
        for bad in [
            "192.0.2.1:0",
            "0.0.0.0:53",
            "255.255.255.255:53",
            "[::]:53",
            "[::ffff:0.0.0.0]:53",
        ] {
            assert!(!answerable(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn a_broadcast_query_is_answered_from_the_interface_address() {
        let info = |to: [u8; 4], spec: [u8; 4]| libc::in_pktinfo {
            ipi_ifindex: 3,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::from(spec)).to_be(),
            },
            ipi_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::from(to)).to_be(),
            },
        };
        assert_eq!(
            v4_arrival(&info([192, 0, 2, 53], [192, 0, 2, 53])),
            Arrival {
                local: "192.0.2.53".parse().unwrap(),
                ifindex: 3
            }
        );
        assert_eq!(
            v4_arrival(&info([255, 255, 255, 255], [192, 0, 2, 10])).local,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        let multicast = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: "ff02::fb".parse::<Ipv6Addr>().unwrap().octets(),
            },
            ipi6_ifindex: 2,
        };
        assert_eq!(v6_arrival(&multicast), None);
    }
}
