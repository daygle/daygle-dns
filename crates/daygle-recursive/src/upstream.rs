//! Parsing of upstream resolver addresses into Hickory [`NameServerConfig`]s.

use std::net::IpAddr;
use std::sync::Arc;

use daygle_core::error::{DaygleError, Result};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};

/// Parse upstream entries into name server configs.
///
/// Supported forms:
/// - `8.8.8.8` or `8.8.8.8:5353` (UDP + TCP)
/// - `udp://8.8.8.8` (UDP only)
/// - `tcp://8.8.8.8:5353` (TCP only)
/// - `tls://1.1.1.1:853@cloudflare-dns.com` (DNS over TLS)
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
    if trimmed.starts_with("https://") || trimmed.starts_with("h3://") {
        return Err(DaygleError::Config(format!(
            "upstream protocol not enabled in this build: '{trimmed}'"
        )));
    }
    parse_plain(trimmed, true, true)
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
}
