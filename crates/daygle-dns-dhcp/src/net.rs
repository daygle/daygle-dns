//! Sockets and network interfaces. DHCP needs to know which interface a
//! request arrived on (clients have no address yet) and to broadcast the
//! reply out of that interface, so this uses `IP_PKTINFO` and
//! `IPV6_RECVPKTINFO`, which are only implemented for Linux here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// A network interface and its addresses.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    /// Addresses with their prefix length, e.g. `192.168.1.2/24`.
    pub addresses: Vec<ipnet::IpNet>,
}

impl Interface {
    /// This interface's address inside `net`.
    pub fn v4_in(&self, net: &ipnet::Ipv4Net) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|a| match a.addr() {
            IpAddr::V4(ip) if net.contains(&ip) => Some(ip),
            _ => None,
        })
    }

    /// This interface's address inside `net`.
    pub fn v6_in(&self, net: &ipnet::Ipv6Net) -> Option<Ipv6Addr> {
        self.addresses.iter().find_map(|a| match a.addr() {
            IpAddr::V6(ip) if net.contains(&ip) => Some(ip),
            _ => None,
        })
    }
}

/// Whether DHCP can be served on this platform.
pub const SUPPORTED: bool = cfg!(target_os = "linux");

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;

    use nix::libc;
    use nix::sys::socket::{
        recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
        SockaddrIn, SockaddrIn6,
    };
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    /// The interfaces with at least one address.
    pub fn interfaces() -> Vec<Interface> {
        let mut out: Vec<Interface> = Vec::new();
        let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
            return out;
        };
        for ifa in addrs {
            let (Some(addr), Some(mask)) = (ifa.address, ifa.netmask) else {
                continue;
            };
            let net = if let (Some(a), Some(m)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) {
                let len = u32::from(m.ip()).leading_ones() as u8;
                ipnet::Ipv4Net::new(a.ip(), len).ok().map(ipnet::IpNet::V4)
            } else if let (Some(a), Some(m)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
                let len = u128::from(m.ip()).leading_ones() as u8;
                ipnet::Ipv6Net::new(a.ip(), len).ok().map(ipnet::IpNet::V6)
            } else {
                None
            };
            let Some(net) = net else { continue };
            match out.iter_mut().find(|i| i.name == ifa.interface_name) {
                Some(i) => i.addresses.push(net),
                None => {
                    let index =
                        nix::net::if_::if_nametoindex(ifa.interface_name.as_str()).unwrap_or(0);
                    out.push(Interface {
                        name: ifa.interface_name.clone(),
                        index,
                        addresses: vec![net],
                    });
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// A UDP socket that reports the interface and local address of what
    /// it receives.
    pub struct PktSocket {
        sock: UdpSocket,
    }

    /// What arrived: the length, the sender, the interface index and the
    /// local address it was received on.
    pub struct Received<A> {
        pub len: usize,
        pub from: A,
        pub ifindex: u32,
        pub local: IpAddr,
    }

    impl PktSocket {
        /// A DHCPv4 server socket on `port` (all interfaces).
        pub fn v4(port: u16) -> io::Result<Self> {
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            sock.set_broadcast(true)?;
            sock.set_nonblocking(true)?;
            setsockopt(&sock, sockopt::Ipv4PacketInfo, &true).map_err(io::Error::from)?;
            sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
            Ok(Self {
                sock: UdpSocket::from_std(sock.into())?,
            })
        }

        /// A DHCPv6 server socket on `port`, joined to the
        /// All_DHCP_Relay_Agents_and_Servers group on every interface with
        /// an IPv6 address.
        pub fn v6(port: u16) -> io::Result<Self> {
            let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_only_v6(true)?;
            sock.set_reuse_address(true)?;
            sock.set_nonblocking(true)?;
            setsockopt(&sock, sockopt::Ipv6RecvPacketInfo, &true).map_err(io::Error::from)?;
            sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
            let group: Ipv6Addr = "ff02::1:2".parse().expect("multicast group");
            for iface in interfaces() {
                if iface.index != 0 && iface.addresses.iter().any(|a| a.addr().is_ipv6()) {
                    // An interface without multicast just is not served.
                    let _ = sock.join_multicast_v6(&group, iface.index);
                }
            }
            Ok(Self {
                sock: UdpSocket::from_std(sock.into())?,
            })
        }

        pub async fn recv_v4(&self, buf: &mut [u8]) -> io::Result<Received<SocketAddrV4>> {
            loop {
                self.sock.readable().await?;
                let result = self.sock.try_io(Interest::READABLE, || {
                    let mut iov = [IoSliceMut::new(buf)];
                    let mut cmsg = nix::cmsg_space!(libc::in_pktinfo);
                    let msg = recvmsg::<SockaddrIn>(
                        self.sock.as_raw_fd(),
                        &mut iov,
                        Some(&mut cmsg),
                        MsgFlags::empty(),
                    )
                    .map_err(io::Error::from)?;
                    let mut ifindex = 0;
                    let mut local = Ipv4Addr::UNSPECIFIED;
                    for c in msg.cmsgs().map_err(io::Error::from)? {
                        if let ControlMessageOwned::Ipv4PacketInfo(info) = c {
                            ifindex = info.ipi_ifindex as u32;
                            local = Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr));
                        }
                    }
                    let from = msg
                        .address
                        .map(SocketAddrV4::from)
                        .ok_or_else(|| io::Error::other("no sender address"))?;
                    Ok(Received {
                        len: msg.bytes,
                        from,
                        ifindex,
                        local: IpAddr::V4(local),
                    })
                });
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    r => return r,
                }
            }
        }

        pub async fn recv_v6(&self, buf: &mut [u8]) -> io::Result<Received<SocketAddrV6>> {
            loop {
                self.sock.readable().await?;
                let result = self.sock.try_io(Interest::READABLE, || {
                    let mut iov = [IoSliceMut::new(buf)];
                    let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
                    let msg = recvmsg::<SockaddrIn6>(
                        self.sock.as_raw_fd(),
                        &mut iov,
                        Some(&mut cmsg),
                        MsgFlags::empty(),
                    )
                    .map_err(io::Error::from)?;
                    let mut ifindex = 0;
                    let mut local = Ipv6Addr::UNSPECIFIED;
                    for c in msg.cmsgs().map_err(io::Error::from)? {
                        if let ControlMessageOwned::Ipv6PacketInfo(info) = c {
                            ifindex = info.ipi6_ifindex;
                            local = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                        }
                    }
                    let from = msg
                        .address
                        .map(SocketAddrV6::from)
                        .ok_or_else(|| io::Error::other("no sender address"))?;
                    Ok(Received {
                        len: msg.bytes,
                        from,
                        ifindex,
                        local: IpAddr::V6(local),
                    })
                });
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    r => return r,
                }
            }
        }

        /// Send `data` to `to`, out of interface `ifindex` from `source`
        /// when given (a broadcast needs the interface named).
        pub async fn send_v4(
            &self,
            data: &[u8],
            to: SocketAddrV4,
            ifindex: u32,
            source: Ipv4Addr,
        ) -> io::Result<()> {
            let info = libc::in_pktinfo {
                ipi_ifindex: ifindex as libc::c_int,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from(source).to_be(),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            let addr = SockaddrIn::from(to);
            loop {
                self.sock.writable().await?;
                let result = self.sock.try_io(Interest::WRITABLE, || {
                    let cmsgs = [ControlMessage::Ipv4PacketInfo(&info)];
                    let cmsgs: &[ControlMessage] = if ifindex == 0 { &[] } else { &cmsgs };
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &[IoSlice::new(data)],
                        cmsgs,
                        MsgFlags::empty(),
                        Some(&addr),
                    )
                    .map_err(io::Error::from)
                });
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    r => return r.map(|_| ()),
                }
            }
        }

        pub async fn send_v6(&self, data: &[u8], to: SocketAddrV6) -> io::Result<()> {
            let addr = SockaddrIn6::from(to);
            loop {
                self.sock.writable().await?;
                let result = self.sock.try_io(Interest::WRITABLE, || {
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &[IoSlice::new(data)],
                        &[],
                        MsgFlags::empty(),
                        Some(&addr),
                    )
                    .map_err(io::Error::from)
                });
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    r => return r.map(|_| ()),
                }
            }
        }
    }
}

/// Without Linux there are no interfaces to serve.
#[cfg(not(target_os = "linux"))]
pub fn interfaces() -> Vec<Interface> {
    Vec::new()
}
