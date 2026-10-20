//! Binding listener sockets. A wildcard IPv6 address (`::`) is bound
//! dual-stack explicitly, so it serves IPv4 clients too whatever the host's
//! `net.ipv6.bindv6only` default, unless `ipv6_only` (`server.ipv6_only`)
//! asks for IPv6 clients only; any other address is bound as given.

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

fn socket_for(
    addr: SocketAddr,
    ipv6_only: bool,
    ty: Type,
    protocol: Protocol,
) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
    if let SocketAddr::V6(v6) = addr {
        socket.set_only_v6(ipv6_only || !v6.ip().is_unspecified())?;
    }
    Ok(socket)
}

/// A UDP socket bound to `addr` (blocking; callers configure and convert it).
pub fn bind_udp_std(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket_for(addr, ipv6_only, Type::DGRAM, Protocol::UDP)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// A Tokio UDP socket bound to `addr`.
pub fn bind_udp(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = bind_udp_std(addr, ipv6_only)?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket)
}

/// A Tokio TCP listener on `addr` (SO_REUSEADDR on Unix, as Tokio's own
/// `TcpListener::bind` sets it).
pub fn bind_tcp(addr: SocketAddr, ipv6_only: bool) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket_for(addr, ipv6_only, Type::STREAM, Protocol::TCP)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}
