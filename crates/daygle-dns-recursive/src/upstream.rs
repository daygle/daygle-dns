//! Parsing of upstream resolver addresses into Hickory [`NameServerConfig`]s.

use std::net::IpAddr;
use std::sync::Arc;

use daygle_dns_core::error::{DaygleError, Result};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};

/// Parse upstream entries into name server configs.
///
/// Supported forms:
/// - `8.8.8.8` or `8.8.8.8:5353` (UDP + TCP)
/// - `udp://8.8.8.8` (UDP only)
/// - `tcp://8.8.8.8:5353` (TCP only)
/// - `tls://1.1.1.1:853@cloudflare-dns.com` (DNS over TLS)
/// - `https://cloudflare-dns.com/dns-query` or `https://1.1.1.1/dns-query`
///   (DNS over HTTPS, RFC 8484; the host may be an IP literal or a name)
/// - `quic://1.1.1.1:853@dns.adguard-dns.com` (DNS over QUIC, RFC 9250)
pub fn parse_upstreams(entries: &[String]) -> Result<Vec<NameServerConfig>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(parse_upstream(entry)?);
    }
    Ok(out)
}

fn parse_upstream(entry: &str) -> Result<NameServerConfig> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(DaygleError::Config("empty upstream entry".to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("tls://") {
        return parse_tls(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("udp://") {
        return parse_plain(rest, true, false);
    }
    if let Some(rest) = trimmed.strip_prefix("tcp://") {
        return parse_plain(rest, false, true);
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        return parse_https(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("quic://") {
        return parse_quic(rest);
    }
    if trimmed.starts_with("h3://") {
        return Err(DaygleError::Config(format!(
            "upstream protocol not enabled in this build: '{trimmed}' (use https://)"
        )));
    }
    parse_plain(trimmed, true, true)
}

/// `https://HOST[:port][/path]` - HOST may be an IP literal or a hostname
/// (resolved by the system when the connection is made). The path defaults
/// to `/dns-query`.
fn parse_https(rest: &str) -> Result<NameServerConfig> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, tail)) => (authority, format!("/{tail}")),
        None => (rest, "/dns-query".to_string()),
    };
    let (host, port) = split_authority(authority)?;
    let mut conn = ConnectionConfig::new(ProtocolConfig::Https {
        server_name: Arc::from(host.as_str()),
        path: Arc::from(path.as_str()),
    });
    conn.port = port;
    // For hostname-based DoH the connection IP is resolved by hickory's
    // internal bootstrap only when the config carries an IP; with a name we
    // must resolve it here via the system resolver (std, blocking, once at
    // config time - acceptable for static upstream lists).
    let ip = resolve_host(&host)?;
    Ok(NameServerConfig::new(ip, true, vec![conn]))
}

/// `quic://IP[:port]@server-name` - like tls:// but over QUIC (RFC 9250).
fn parse_quic(rest: &str) -> Result<NameServerConfig> {
    let (addr, server_name) = match rest.split_once('@') {
        Some((addr, name)) => (addr, name),
        None => {
            return Err(DaygleError::Config(format!(
                "quic upstream '{rest}' must be quic://IP:port@hostname"
            )))
        }
    };
    let (ip, port) = split_host_port(addr)?;
    let mut conn = ConnectionConfig::new(ProtocolConfig::Quic {
        server_name: Arc::from(server_name.trim()),
    });
    conn.port = port;
    Ok(NameServerConfig::new(ip, true, vec![conn]))
}

/// Resolve a hostname to its first address via the system resolver. Used
/// only for `https://` upstreams whose host is a name (hickory needs the
/// literal IP in `NameServerConfig`).
fn resolve_host(host: &str) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    use std::net::ToSocketAddrs;
    let resolved = (host, 443u16)
        .to_socket_addrs()
        .map_err(|e| DaygleError::Config(format!("cannot resolve DoH host '{host}': {e}")))?
        .next()
        .ok_or_else(|| {
            DaygleError::Config(format!("DoH host '{host}' resolved to no addresses"))
        })?;
    Ok(resolved.ip())
}

/// Split `host`, `host:port`, or bracketed `[IPv6]:port`, defaulting to the
/// protocol's default port. Unlike [`split_host_port`], the host may be a
/// DNS name.
fn split_authority(authority: &str) -> Result<(String, u16)> {
    let authority = authority.trim();
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| DaygleError::Config(format!("unbalanced '[' in '{authority}'")))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| DaygleError::Config(format!("bad port in '{authority}'")))?,
            None => 443,
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port
                .parse::<u16>()
                .map_err(|_| DaygleError::Config(format!("bad port in '{authority}'")))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), 443)),
    }
}

fn parse_tls(rest: &str) -> Result<NameServerConfig> {
    // tls://1.1.1.1:853@cloudflare-dns.com
    let (addr, server_name) = match rest.split_once('@') {
        Some((addr, name)) => (addr, name),
        None => {
            return Err(DaygleError::Config(format!(
                "tls upstream '{rest}' must be tls://IP:port@hostname"
            )))
        }
    };
    let (ip, port) = split_host_port(addr)?;
    let mut conn = ConnectionConfig::new(ProtocolConfig::Tls {
        server_name: Arc::from(server_name.trim()),
    });
    conn.port = port;
    Ok(NameServerConfig::new(ip, true, vec![conn]))
}

fn parse_plain(rest: &str, udp: bool, tcp: bool) -> Result<NameServerConfig> {
    let (ip, port) = split_host_port(rest)?;
    let mut connections = Vec::with_capacity(2);
    if udp {
        let mut conn = ConnectionConfig::new(ProtocolConfig::Udp);
        conn.port = port;
        connections.push(conn);
    }
    if tcp {
        let mut conn = ConnectionConfig::new(ProtocolConfig::Tcp);
        conn.port = port;
        connections.push(conn);
    }
    Ok(NameServerConfig::new(ip, true, connections))
}

/// Split `IP`, `IP:port`, `[IPv6]:port`, or `[IPv6]`, defaulting to port 53
/// for plain DNS.
fn split_host_port(rest: &str) -> Result<(IpAddr, u16)> {
    let rest = rest.trim();

    // Bracketed IPv6: `[::1]:53` or `[::1]`.
    if let Some(stripped) = rest.strip_prefix('[') {
        let (host, port) = match stripped.split_once(']') {
            Some((host, tail)) => {
                let port = if let Some(tail) = tail.strip_prefix(':') {
                    tail.parse::<u16>().map_err(|_| {
                        DaygleError::Config(format!("bad port in upstream '{rest}'"))
                    })?
                } else {
                    53
                };
                (host, port)
            }
            None => {
                return Err(DaygleError::Config(format!(
                    "unbalanced '[' in upstream '{rest}'"
                )))
            }
        };
        let ip: IpAddr = host.parse().map_err(|_| {
            DaygleError::Config(format!("upstream '{rest}' is not an IP literal"))
        })?;
        return Ok((ip, port));
    }

    let (host, port) = if let Some((host, port)) = rest.rsplit_once(':') {
        // Guard against bare IPv6 literals which contain colons.
        if host.contains(':') {
            (rest, 53u16)
        } else {
            let port = port
                .parse::<u16>()
                .map_err(|_| DaygleError::Config(format!("bad port in upstream '{rest}'")))?;
            (host, port)
        }
    } else {
        (rest, 53u16)
    };

    let ip: IpAddr = host
        .trim()
        .parse()
        .map_err(|_| DaygleError::Config(format!("upstream '{rest}' is not an IP literal")))?;
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_default_port() {
        let (ip, port) = split_host_port("8.8.8.8").unwrap();
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(port, 53);
    }

    #[test]
    fn plain_custom_port() {
        let (_ip, port) = split_host_port("8.8.8.8:5353").unwrap();
        assert_eq!(port, 5353);
    }

    #[test]
    fn ipv6_literal() {
        let (ip, port) = split_host_port("2001:4860:4860::8888").unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(port, 53);
    }

    #[test]
    fn ipv6_with_port() {
        let (ip, port) = split_host_port("[2001:4860:4860::8888]:53").unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(port, 53);
    }

    #[test]
    fn parses_quic_upstream() {
        let ns = parse_upstreams(&["quic://1.1.1.1:853@dns.adguard-dns.com".to_string()]).unwrap();
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        match &ns[0].connections[0].protocol {
            ProtocolConfig::Quic { server_name } => {
                assert_eq!(&**server_name, "dns.adguard-dns.com");
            }
            other => panic!("expected quic protocol, got {other:?}"),
        }
        assert_eq!(ns[0].connections[0].port, 853);
    }

    #[test]
    fn parses_https_upstream_by_ip() {
        let ns = parse_upstreams(&["https://1.1.1.1/dns-query".to_string()]).unwrap();
        assert_eq!(ns[0].ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        match &ns[0].connections[0].protocol {
            ProtocolConfig::Https { server_name, path } => {
                assert_eq!(&**server_name, "1.1.1.1");
                assert_eq!(&**path, "/dns-query");
            }
            other => panic!("expected https protocol, got {other:?}"),
        }
        assert_eq!(ns[0].connections[0].port, 443);
    }

    #[test]
    fn https_defaults_path_and_port() {
        let ns = parse_upstreams(&["https://8.8.8.8".to_string()]).unwrap();
        match &ns[0].connections[0].protocol {
            ProtocolConfig::Https { path, .. } => assert_eq!(&**path, "/dns-query"),
            other => panic!("expected https protocol, got {other:?}"),
        }
        assert_eq!(ns[0].connections[0].port, 443);
    }

    #[test]
    fn https_custom_port_and_path() {
        let ns = parse_upstreams(&["https://[2606:4700:4700::1111]:8443/custom".to_string()]).unwrap();
        assert!(ns[0].ip.is_ipv6());
        assert_eq!(ns[0].connections[0].port, 8443);
        match &ns[0].connections[0].protocol {
            ProtocolConfig::Https { path, .. } => assert_eq!(&**path, "/custom"),
            other => panic!("expected https protocol, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_quic_upstream() {
        assert!(parse_upstreams(&["quic://1.1.1.1".to_string()]).is_err());
    }
}
