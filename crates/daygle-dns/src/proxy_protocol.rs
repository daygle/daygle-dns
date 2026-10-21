//! PROXY protocol (HAProxy, versions 1 and 2) on the TCP, DoT and DoH
//! listeners, so a load balancer in front of the server can pass on each
//! client's real address (`server.proxy_protocol` lists the trusted
//! proxies).
//!
//! Hickory accepts connections itself, so the header cannot be read there.
//! Instead each public listener gets a small front: it accepts the
//! connection, reads the PROXY header when the peer is a trusted proxy, and
//! splices the rest of the stream (TLS included, untouched) to a hidden
//! loopback listener served by Hickory. The loopback connection's address
//! is recorded with the real client's, and the dispatcher looks it up, so
//! ACLs, rate limits, logs and policies all see the real client.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// A trusted proxy has this long to send its header.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// The v2 signature (and the start of every v2 header).
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// The longest v1 header, CRLF included.
const V1_MAX: usize = 107;

/// Loopback connection address → the real client it carries.
fn table() -> &'static RwLock<HashMap<SocketAddr, SocketAddr>> {
    static TABLE: OnceLock<RwLock<HashMap<SocketAddr, SocketAddr>>> = OnceLock::new();
    TABLE.get_or_init(Default::default)
}

/// The real client behind `src` when it is a connection from a PROXY
/// protocol front; otherwise `src` itself.
pub fn real_client(src: SocketAddr) -> SocketAddr {
    if !src.ip().is_loopback() {
        return src;
    }
    let table = table().read().expect("proxy table lock poisoned");
    table.get(&src).copied().unwrap_or(src)
}

/// Parse a v1 header line (without its CRLF). `None` for `UNKNOWN`.
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

/// Parse a v2 address block for `family` (the header's 14th byte). `None`
/// for LOCAL commands and unsupported families.
fn parse_v2(command: u8, family: u8, body: &[u8]) -> std::io::Result<Option<SocketAddr>> {
    let short = || std::io::Error::other("short PROXY v2 address block");
    if command == 0 {
        // LOCAL: the proxy's own connection (e.g. a health check).
        return Ok(None);
    }
    if command != 1 {
        return Err(std::io::Error::other("unknown PROXY v2 command"));
    }
    match family >> 4 {
        1 => {
            let b = body.get(..12).ok_or_else(short)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[8], b[9]]);
            Ok(Some(SocketAddr::new(ip.into(), port)))
        }
        2 => {
            let b = body.get(..36).ok_or_else(short)?;
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).expect("16 bytes"));
            let port = u16::from_be_bytes([b[32], b[33]]);
            Ok(Some(SocketAddr::new(ip.into(), port)))
        }
        _ => Ok(None),
    }
}

/// Read a PROXY header (v1 or v2) from the start of `stream`, returning
/// the client it names (`None`: use the connection's own address).
pub async fn read_header<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Option<SocketAddr>> {
    let mut start = [0u8; 12];
    stream.read_exact(&mut start[..5]).await?;
    if &start[..5] == b"PROXY" {
        let mut line = start[..5].to_vec();
        loop {
            let byte = stream.read_u8().await?;
            line.push(byte);
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

/// Accept connections on `public`, read the PROXY header from those sent
/// by `trusted` proxies, and splice each to `backend` (the loopback
/// listener Hickory serves), until `shutdown`.
pub fn spawn_front(
    public: TcpListener,
    backend: SocketAddr,
    trusted: Arc<Vec<ipnet::IpNet>>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = public.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        debug!("PROXY front accept failed: {e}");
                        continue;
                    }
                },
            };
            let trusted = trusted.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = splice(stream, peer, backend, &trusted, shutdown).await {
                    debug!(%peer, "PROXY front connection ended: {e}");
                }
            });
        }
    });
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
    let mut inner = TcpStream::connect(backend).await?;
    let local = inner.local_addr()?;
    // Recorded before any byte is sent, so before the first request.
    table()
        .write()
        .expect("proxy table lock poisoned")
        .insert(local, client);
    let result = tokio::select! {
        _ = shutdown.cancelled() => Ok(()),
        copied = tokio::io::copy_bidirectional(&mut stream, &mut inner) => copied.map(|_| ()),
    };
    table()
        .write()
        .expect("proxy table lock poisoned")
        .remove(&local);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn headers_parse() {
        let read = |bytes: Vec<u8>| async move {
            let mut cursor = std::io::Cursor::new(bytes);
            read_header(&mut cursor).await
        };
        assert_eq!(
            read(b"PROXY TCP4 203.0.113.7 192.0.2.1 51234 53\r\nrest".to_vec())
                .await
                .unwrap(),
            Some("203.0.113.7:51234".parse().unwrap())
        );
        assert_eq!(
            read(b"PROXY TCP6 2001:db8::7 2001:db8::1 4000 853\r\n".to_vec())
                .await
                .unwrap(),
            Some("[2001:db8::7]:4000".parse().unwrap())
        );
        assert_eq!(read(b"PROXY UNKNOWN\r\n".to_vec()).await.unwrap(), None);
        assert!(read(b"PROXY TCP4 nope\r\n".to_vec()).await.is_err());
        assert!(read(b"\x00\x1d\x12\x34hello world....".to_vec())
            .await
            .is_err());

        // v2, IPv4, with a TLV after the addresses.
        let mut v2 = V2_SIGNATURE.to_vec();
        v2.extend_from_slice(&[0x21, 0x11, 0, 12 + 4]);
        v2.extend_from_slice(&[198, 51, 100, 9, 192, 0, 2, 1]);
        v2.extend_from_slice(&40000u16.to_be_bytes());
        v2.extend_from_slice(&53u16.to_be_bytes());
        v2.extend_from_slice(&[0x04, 0, 1, 0]);
        assert_eq!(
            read(v2).await.unwrap(),
            Some("198.51.100.9:40000".parse().unwrap())
        );
        // v2 LOCAL (a health check).
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 0]);
        assert_eq!(read(local).await.unwrap(), None);
        // v2 IPv6.
        let mut v6 = V2_SIGNATURE.to_vec();
        v6.extend_from_slice(&[0x21, 0x21, 0, 36]);
        v6.extend_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&5353u16.to_be_bytes());
        v6.extend_from_slice(&53u16.to_be_bytes());
        assert_eq!(
            read(v6).await.unwrap(),
            Some("[2001:db8::9]:5353".parse().unwrap())
        );
    }
}
