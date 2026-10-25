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

/// Register the peer on a loopback backend connection against its public
/// client's address. Used when a transparent listener bridge is necessary.
pub fn register_client(local: SocketAddr, client: SocketAddr) {
    table()
        .write()
        .expect("proxy table lock poisoned")
        .insert(local, client);
}

/// Remove a bridge's peer mapping when the bridged connection finishes.
pub fn unregister_client(local: SocketAddr) {
    table()
        .write()
        .expect("proxy table lock poisoned")
        .remove(&local);
}

/// The real client behind `src` when it is a connection from a front; else src.
pub fn real_client(src: SocketAddr) -> SocketAddr {
    let table = table().read().expect("proxy table lock poisoned");
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
        Some("TCP4" | "TCP6") => {
            let src: IpAddr = parts.next().and_then(|a| a.parse().ok()).ok_or_else(bad)?;
            let _dst: IpAddr = parts.next().and_then(|a| a.parse().ok()).ok_or_else(bad)?;
            let port: u16 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
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
    match family >> 4 {
        1 => {
            let b = body.get(..12).ok_or_else(short)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[8], b[9]]),
            )))
        }
        2 => {
            let b = body.get(..36).ok_or_else(short)?;
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).expect("16 bytes"));
            Ok(Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[32], b[33]]),
            )))
        }
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
                    debug!("PROXY front accept failed: {e}");
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
