//! PROXY protocol (HAProxy, versions 1 and 2) on the TCP, DoT and DoH
//! listeners, so a load balancer in front of the server can pass on each
//! client's real address (`server.proxy_protocol` lists the trusted
//! proxies). Each listener reads the header itself, before anything else on
//! a connection from a trusted proxy, and serves the connection as the
//! client it names.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncReadExt;

const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_MAX: usize = 107;

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

#[cfg(test)]
mod tests {
    use super::*;

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
