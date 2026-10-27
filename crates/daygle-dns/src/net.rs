//! Binding listener sockets. A wildcard IPv6 address (`::`) is bound
//! dual-stack explicitly, so it serves IPv4 clients too whatever the host's
//! `net.ipv6.bindv6only` default, unless it is bound IPv6-only (see
//! [`v6_only`]); any other address is bound as given.

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Whether a `::` in the listen list `addrs` is bound IPv6-only: when
/// `server.ipv6_only` asks for it, or when the list also names IPv4
/// addresses (a dual-stack `::` would take their port on every IPv4
/// address, so they could not be bound).
pub fn v6_only(addrs: &[SocketAddr], ipv6_only: bool) -> bool {
    ipv6_only || addrs.iter().any(|a| a.is_ipv4())
}

fn socket_for(
    addr: SocketAddr,
    v6_only: bool,
    ty: Type,
    protocol: Protocol,
) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
    if let SocketAddr::V6(v6) = addr {
        socket.set_only_v6(v6_only || !v6.ip().is_unspecified())?;
    }
    Ok(socket)
}

/// A bind error with the address it was for and, when the port is taken,
/// the likely culprit: the bare OS error ("Address already in use") does
/// not say which listener failed.
fn bind_error(err: std::io::Error, addr: SocketAddr, protocol: &str) -> std::io::Error {
    if err.kind() != std::io::ErrorKind::AddrInUse {
        return std::io::Error::new(
            err.kind(),
            format!("cannot listen on {addr} ({protocol}): {err}"),
        );
    }
    let hint = if addr.port() == 53 {
        " On Ubuntu and other systemd-based systems this is usually systemd-resolved's \
         stub listener: set DNSStubListener=no in a /etc/systemd/resolved.conf.d/ drop-in \
         and restart systemd-resolved (the installer does this). dnsmasq or another DNS \
         server can also hold the port; `ss -lntup 'sport = :53'` shows which."
    } else {
        ""
    };
    std::io::Error::new(
        err.kind(),
        format!(
            "cannot listen on {addr} ({protocol}): port {} is already in use by another program.{hint}",
            addr.port()
        ),
    )
}

/// A UDP socket bound to `addr` (blocking; callers configure and convert it).
pub fn bind_udp_std(addr: SocketAddr, v6_only: bool) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket_for(addr, v6_only, Type::DGRAM, Protocol::UDP)?;
    socket
        .bind(&addr.into())
        .map_err(|e| bind_error(e, addr, "UDP"))?;
    Ok(socket.into())
}

/// A Tokio UDP socket bound to `addr`.
pub fn bind_udp(addr: SocketAddr, v6_only: bool) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = bind_udp_std(addr, v6_only)?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket)
}

/// A Tokio TCP listener on `addr` (SO_REUSEADDR on Unix, as Tokio's own
/// `TcpListener::bind` sets it).
pub fn bind_tcp(addr: SocketAddr, v6_only: bool) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket_for(addr, v6_only, Type::STREAM, Protocol::TCP)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket
        .bind(&addr.into())
        .map_err(|e| bind_error(e, addr, "TCP"))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_in_use_names_the_address() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let msg = bind_tcp(addr, false).unwrap_err().to_string();
        assert!(msg.contains(&format!("{addr} (TCP)")), "{msg}");
        assert!(msg.contains("already in use"), "{msg}");
        assert!(!msg.contains("systemd-resolved"), "{msg}");
    }

    #[test]
    fn port_53_in_use_points_at_systemd_resolved() {
        let addr: SocketAddr = "0.0.0.0:53".parse().unwrap();
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let msg = bind_error(in_use, addr, "TCP").to_string();
        assert!(msg.contains("0.0.0.0:53 (TCP)"), "{msg}");
        assert!(msg.contains("DNSStubListener=no"), "{msg}");
    }
}
