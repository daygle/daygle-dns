//! PROXY protocol (HAProxy, versions 1 and 2) on the TCP, DoT and DoH
//! listeners, so a load balancer in front of the server can pass on each
//! client's real address (`server.proxy_protocol` lists the trusted
//! proxies).
//!
//! TCP-based listeners are fronted by a small proxy which can read the PROXY
//! header and splice the remaining stream to a hidden loopback listener.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::debug;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_MAX: usize = 107;

fn table() -> &'static RwLock<HashMap<SocketAddr, SocketAddr>> {
    static TABLE: OnceLock<RwLock<HashMap<SocketAddr, SocketAddr>>> = OnceLock::new();
    TABLE.get_or_init(Default::default)
}

/// The table, ignoring lock poisoning: the map is a peer mapping, so a panic
/// in an unrelated thread that happened to hold the lock (which poisons it)
/// must not turn every later query into a panic. `real_client` runs on the
/// DNS query path, so an `expect` here would take the whole server down.
fn read_table() -> std::sync::RwLockReadGuard<'static, HashMap<SocketAddr, SocketAddr>> {
    table().read().unwrap_or_else(|e| e.into_inner())
}

fn write_table() -> std::sync::RwLockWriteGuard<'static, HashMap<SocketAddr, SocketAddr>> {
    table().write().unwrap_or_else(|e| e.into_inner())
}

/// Register the peer on a loopback backend connection against its public
/// client's address. Used when a transparent listener bridge is necessary.
pub fn register_client(local: SocketAddr, client: SocketAddr) {
    write_table().insert(local, client);
}

/// Remove a bridge's peer mapping when the bridged connection finishes.
pub fn unregister_client(local: SocketAddr) {
    write_table().remove(&local);
}

/// The real client behind `src` when it is a connection from a front; else src.
pub fn real_client(src: SocketAddr) -> SocketAddr {
    let table = read_table();
    let mut current = src;
    // Listener admission and PROXY protocol can form multiple trusted local
    // bridge hops. Resolve them all to the original remote peer/client.
    for _ in 0..8 {
        match table.get(&current).copied() {
            Some(mapped) if mapped != current => current = mapped,
            _ => break,
        }
    }
    current
}

fn parse_v1(line: &str) -> std::io::Result<Option<SocketAddr>> {
    let bad = || std::io::Error::other(format!("bad PROXY v1 header '{line}'"));
    let mut parts = line.split(' ');
    if parts.next() != Some("PROXY") {
        return Err(bad());
    }
    match parts.next() {
        Some("UNKNOWN") => Ok(None),
        Some(family @ ("TCP4" | "TCP6")) => {
            let src: IpAddr = parts.next().and_then(|a| a.parse().ok()).ok_or_else(bad)?;
            let dst: IpAddr = parts.next().and_then(|a| a.parse().ok()).ok_or_else(bad)?;
            let port: u16 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
            let _: u16 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
            if parts.next().is_some()
                || (family == "TCP4" && (!src.is_ipv4() || !dst.is_ipv4()))
                || (family == "TCP6" && (!src.is_ipv6() || !dst.is_ipv6()))
            {
                return Err(bad());
            }
            Ok(Some(SocketAddr::new(src, port)))
        }
        _ => Err(bad()),
    }
}

fn parse_v2(command: u8, family: u8, body: &[u8]) -> std::io::Result<Option<SocketAddr>> {
    let short = || std::io::Error::other("short PROXY v2 address block");
    if command == 0 {
        return Ok(None);
    }
    if command != 1 {
        return Err(std::io::Error::other("unknown PROXY v2 command"));
    }
    match family {
        0x11 => {
            let b = body.get(..12).ok_or_else(short)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[8], b[9]]),
            )))
        }
        0x21 => {
            let b = body.get(..36).ok_or_else(short)?;
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).expect("16 bytes"));
            Ok(Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[32], b[33]]),
            )))
        }
        // Only TCP listeners use this parser; datagram or unspecified
        // addresses cannot name the peer of a stream connection.
        _ => Ok(None),
    }
}

pub async fn read_header<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Option<SocketAddr>> {
    let mut start = [0u8; 12];
    stream.read_exact(&mut start[..5]).await?;
    if &start[..5] == b"PROXY" {
        let mut line = start[..5].to_vec();
        loop {
            line.push(stream.read_u8().await?);
            if line.ends_with(b"\r\n") {
                break;
            }
            if line.len() >= V1_MAX {
                return Err(std::io::Error::other("PROXY v1 header too long"));
            }
        }
        let text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| std::io::Error::other("PROXY v1 header is not text"))?;
        return parse_v1(text);
    }
    stream.read_exact(&mut start[5..]).await?;
    if start != V2_SIGNATURE {
        return Err(std::io::Error::other(
            "no PROXY header from a trusted proxy",
        ));
    }
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] >> 4 != 2 {
        return Err(std::io::Error::other("unsupported PROXY version"));
    }
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    parse_v2(head[0] & 0x0f, head[1], &body)
}

/// Accept public TCP sessions, validate optional PROXY headers and forward to
/// a hidden listener. Concurrent sessions are hard-capped by `max_connections`.
pub fn spawn_front(
    public: TcpListener,
    backend: SocketAddr,
    trusted: Arc<Vec<ipnet::IpNet>>,
    max_connections: usize,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let permits = Arc::new(tokio::sync::Semaphore::new(max_connections));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => return,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
                accepted = public.accept(), if permits.available_permits() > 0 => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(s) => s,
                Err(e) => {
                    // Out of file descriptors and the like: back off instead
                    // of spinning on a failing accept.
                    debug!("PROXY front accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let trusted = trusted.clone();
            let shutdown = shutdown.clone();
            tasks.spawn(async move {
                let _permit = permit;
                if let Err(e) = splice(stream, peer, backend, &trusted, shutdown).await {
                    debug!(%peer, "PROXY front connection ended: {e}");
                }
            });
        }
    })
}

async fn splice(
    mut stream: TcpStream,
    peer: SocketAddr,
    backend: SocketAddr,
    trusted: &[ipnet::IpNet],
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let peer_ip = peer.ip().to_canonical();
    let client = if trusted.iter().any(|n| n.contains(&peer_ip)) {
        tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut stream))
            .await
            .map_err(|_| std::io::Error::other("no PROXY header in time"))??
            .unwrap_or(peer)
    } else {
        peer
    };
    // Bind the backend socket and register its local address before
    // connecting (as `connection_admission::bridge` does): once connected,
    // the listener may accept and look up the peer immediately.
    let socket = match backend {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(backend.ip(), 0))?;
    let local = socket.local_addr()?;
    register_client(local, client);
    let result = match socket.connect(backend).await {
        Ok(mut inner) => tokio::select! {
            _ = shutdown.cancelled() => Ok(()),
            copied = tokio::io::copy_bidirectional(&mut stream, &mut inner) => copied.map(|_| ()),
        },
        Err(e) => Err(e),
    };
    unregister_client(local);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic while another thread held the peer table's write lock poisons
    /// it. The table is consulted for every DNS query (`real_client`), so
    /// panicking on the poisoned lock would panic every later query - a
    /// whole-server outage from one unrelated panic.
    #[test]
    fn a_poisoned_table_lock_does_not_break_client_lookup() {
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = table().write().unwrap();
            panic!("panic while holding the peer table lock");
        });
        assert!(poisoned.is_err());
        assert!(
            table().read().is_err(),
            "the lock must really be poisoned for this test to prove anything"
        );

        let local: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let client: SocketAddr = "192.0.2.9:1234".parse().unwrap();
        register_client(local, client);
        assert_eq!(real_client(local), client);
        unregister_client(local);
        assert_eq!(real_client(local), local);
    }

    #[test]
    fn chained_bridges_resolve_to_the_original_client() {
        let inner: SocketAddr = "127.0.0.1:53101".parse().unwrap();
        let outer: SocketAddr = "127.0.0.1:53102".parse().unwrap();
        let client: SocketAddr = "198.51.100.7:4444".parse().unwrap();
        register_client(inner, client);
        register_client(outer, inner);
        assert_eq!(real_client(outer), client);
        unregister_client(inner);
        unregister_client(outer);
        assert_eq!(real_client(outer), outer);
    }

    #[test]
    fn proxy_headers_parse_v1_and_v2() {
        assert_eq!(
            parse_v1("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443").unwrap(),
            Some("192.0.2.1:12345".parse().unwrap())
        );
        assert_eq!(parse_v1("PROXY UNKNOWN").unwrap(), None);
        assert!(parse_v1("PROXY TCP4 not-an-address 198.51.100.2 1 2").is_err());
        for malformed in [
            "PROXY TCP4 192.0.2.1 198.51.100.2 1",
            "PROXY TCP4 192.0.2.1 198.51.100.2 1 nope",
            "PROXY TCP4 192.0.2.1 198.51.100.2 1 2 extra",
            "PROXY TCP4 2001:db8::1 198.51.100.2 1 2",
            "PROXY TCP4 192.0.2.1 2001:db8::2 1 2",
            "PROXY TCP6 192.0.2.1 2001:db8::2 1 2",
        ] {
            assert!(parse_v1(malformed).is_err(), "accepted {malformed}");
        }
        assert_eq!(
            parse_v1("PROXY TCP6 2001:db8::1 2001:db8::2 12345 443").unwrap(),
            Some("[2001:db8::1]:12345".parse().unwrap())
        );

        // v2: `parse_v2` takes the version byte's low nibble (the command),
        // so 0x21 reads as PROXY (1) and 0x20 as LOCAL (0), as `read_header`
        // passes them. Family 0x11 is TCP4.
        let mut body = vec![0u8; 12];
        body[..4].copy_from_slice(&[192, 0, 2, 1]);
        body[8..10].copy_from_slice(&12345u16.to_be_bytes());
        assert_eq!(
            parse_v2(0x21 & 0x0f, 0x11, &body).unwrap(),
            Some("192.0.2.1:12345".parse().unwrap())
        );
        // LOCAL carries no address.
        assert_eq!(parse_v2(0x20 & 0x0f, 0x00, &[]).unwrap(), None);
        assert!(parse_v2(0x21 & 0x0f, 0x11, &[0u8; 4]).is_err());
        // A UDP address in a TCP connection cannot identify its peer.
        assert_eq!(parse_v2(1, 0x12, &body).unwrap(), None);
        assert_eq!(parse_v2(1, 0x22, &[0; 36]).unwrap(), None);
        // An unknown command is an error, not a silent "no address".
        assert!(parse_v2(2, 0x11, &body).is_err());
    }
}
