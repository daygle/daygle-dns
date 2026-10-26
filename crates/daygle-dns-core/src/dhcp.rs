//! DHCP settings (`[dhcp]`) and the lease record shared by the server, the
//! store and the API.
//!
//! DHCPv4 scopes hand out IPv4 addresses with the usual options (router,
//! DNS servers, domain, NTP, custom options); DHCPv6 scopes hand out IPv6
//! addresses (IA_NA) or only DNS settings (stateless), for networks whose
//! router advertises the "managed" or "other configuration" flag. Leases
//! can register their host names in a DNS zone hosted here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// The DHCP service.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpSettings {
    pub enabled: bool,
    /// IPv4 scopes.
    pub scopes: Vec<DhcpScope>,
    /// IPv6 scopes.
    pub scopes_v6: Vec<Dhcp6Scope>,
    /// Zone (hosted here) where lease host names are registered, e.g.
    /// `home.arpa`. Empty: names are not registered.
    pub dns_zone: String,
    /// Server ports, for testing (0: the standard 67 and 547).
    #[serde(skip_serializing_if = "is_zero")]
    pub port_v4: u16,
    #[serde(skip_serializing_if = "is_zero")]
    pub port_v6: u16,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// A fixed address for one device.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpReservation {
    /// DHCPv4: the MAC address (`aa:bb:cc:dd:ee:ff`). DHCPv6: the client's
    /// DUID in hex (colons optional).
    pub client: String,
    pub address: String,
    /// The host name registered for it (overrides the device's own).
    pub hostname: String,
    pub description: String,
}

/// An extra DHCPv4 option: `value` is text, or hex with a `0x` prefix.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpCustomOption {
    pub code: u8,
    pub value: String,
}

/// A DHCPv4 scope: one network and the addresses handed out on it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpScope {
    pub name: String,
    pub enabled: bool,
    /// The network interface it serves (e.g. `eth0`); empty: whichever
    /// interface has an address in `subnet`. Relayed requests are matched
    /// by the relay's address instead.
    pub interface: String,
    /// The network, e.g. `192.168.1.0/24`.
    pub subnet: String,
    /// The first and last address handed out.
    pub range_start: String,
    pub range_end: String,
    /// Default gateway (empty: none).
    pub router: String,
    /// DNS servers; empty: this server's address on that network.
    pub dns_servers: Vec<String>,
    /// Domain name (option 15) and search list (option 119).
    pub domain_name: String,
    pub ntp_servers: Vec<String>,
    pub lease_secs: u32,
    pub reservations: Vec<DhcpReservation>,
    pub options: Vec<DhcpCustomOption>,
}

impl Default for DhcpScope {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            interface: String::new(),
            subnet: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            router: String::new(),
            dns_servers: Vec::new(),
            domain_name: String::new(),
            ntp_servers: Vec::new(),
            lease_secs: 86_400,
            reservations: Vec::new(),
            options: Vec::new(),
        }
    }
}

/// A DHCPv6 scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Dhcp6Scope {
    pub name: String,
    pub enabled: bool,
    /// The network interface it serves; empty: whichever interface has an
    /// address in `prefix`.
    pub interface: String,
    /// The network, e.g. `fd00:1::/64`.
    pub prefix: String,
    /// The addresses handed out; both empty: DNS settings only (stateless
    /// DHCPv6).
    pub range_start: String,
    pub range_end: String,
    /// DNS servers; empty: this server's address on that network.
    pub dns_servers: Vec<String>,
    pub domain_search: Vec<String>,
    pub preferred_secs: u32,
    pub valid_secs: u32,
    pub reservations: Vec<DhcpReservation>,
}

impl Default for Dhcp6Scope {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            interface: String::new(),
            prefix: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
            preferred_secs: 43_200,
            valid_secs: 86_400,
            reservations: Vec::new(),
        }
    }
}

/// A lease (or offer) on one address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpLease {
    pub address: IpAddr,
    /// The scope's name.
    pub scope: String,
    /// The client's identity: client identifier or MAC (DHCPv4), DUID and
    /// IAID (DHCPv6), in hex.
    pub client_id: String,
    /// MAC address (DHCPv4) or DUID (DHCPv6), for display and reservations.
    pub hw_address: String,
    pub hostname: String,
    /// `offered`, `bound`, `declined` or `released`.
    pub state: String,
    /// UNIX seconds.
    pub expires: i64,
    /// The DNS name registered for the lease (empty: none).
    pub dns_name: String,
    /// Ids of the DNS records registered for it.
    pub dns_records: Vec<String>,
    /// RFC 3339.
    pub updated_at: String,
}

fn parse_v4(text: &str, what: &str) -> Result<Ipv4Addr, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("'{}' is not an IPv4 address ({what})", text.trim()))
}

fn parse_v6(text: &str, what: &str) -> Result<Ipv6Addr, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("'{}' is not an IPv6 address ({what})", text.trim()))
}

/// Normalize a MAC address to `aa:bb:cc:dd:ee:ff`; `None` when it is not one.
pub fn normalize_mac(text: &str) -> Option<String> {
    let hex: String = text
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Normalize a hex DUID (colons and dashes optional) to lowercase hex.
pub fn normalize_duid(text: &str) -> Option<String> {
    let hex: String = text
        .chars()
        .filter(|c| !matches!(c, ':' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    (hex.len() >= 4
        && hex.len() <= 260
        && hex.len().is_multiple_of(2)
        && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    .then_some(hex)
}

impl DhcpScope {
    /// The subnet, parsed.
    pub fn net(&self) -> Option<ipnet::Ipv4Net> {
        self.subnet
            .trim()
            .parse()
            .ok()
            .map(|n: ipnet::Ipv4Net| n.trunc())
    }

    /// The range, parsed.
    pub fn range(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        Some((
            self.range_start.trim().parse().ok()?,
            self.range_end.trim().parse().ok()?,
        ))
    }

    /// Problems that stop the scope being used.
    pub fn check(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("give the scope a name".to_string());
        }
        let net: ipnet::Ipv4Net = self.subnet.trim().parse().map_err(|_| {
            format!(
                "'{}' is not a network such as 192.168.1.0/24",
                self.subnet.trim()
            )
        })?;
        if net.prefix_len() > 30 {
            return Err("the network must be /30 or larger".to_string());
        }
        let start = parse_v4(&self.range_start, "range start")?;
        let end = parse_v4(&self.range_end, "range end")?;
        if !net.contains(&start) || !net.contains(&end) {
            return Err(format!("the range must be inside {net}"));
        }
        if u32::from(start) > u32::from(end) {
            return Err("the range starts after it ends".to_string());
        }
        if start == net.network() || end == net.broadcast() || start == net.broadcast() {
            return Err("the range cannot include the network or broadcast address".to_string());
        }
        if !self.router.trim().is_empty() {
            let router = parse_v4(&self.router, "router")?;
            if !net.contains(&router) {
                return Err(format!("the router {router} is not in {net}"));
            }
        }
        for dns in &self.dns_servers {
            parse_v4(dns, "DNS server")?;
        }
        for ntp in &self.ntp_servers {
            parse_v4(ntp, "NTP server")?;
        }
        if !(60..=31_536_000).contains(&self.lease_secs) {
            return Err("the lease time must be 1 minute to 1 year".to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for r in &self.reservations {
            let mac = normalize_mac(&r.client)
                .ok_or_else(|| format!("'{}' is not a MAC address", r.client.trim()))?;
            let ip = parse_v4(&r.address, "reservation")?;
            if !net.contains(&ip) || ip == net.network() || ip == net.broadcast() {
                return Err(format!("the reserved address {ip} is not usable in {net}"));
            }
            if !seen.insert(mac.clone()) || !seen.insert(ip.to_string()) {
                return Err(format!("{mac} or {ip} is reserved twice"));
            }
        }
        for o in &self.options {
            if matches!(o.code, 0 | 1 | 3 | 6 | 15 | 50..=61 | 255) {
                return Err(format!(
                    "option {} is set by the scope itself and cannot be added",
                    o.code
                ));
            }
            custom_option_bytes(&o.value).map_err(|e| format!("option {}: {e}", o.code))?;
        }
        Ok(())
    }
}

/// The bytes of a custom option value: text, or hex after `0x`.
pub fn custom_option_bytes(value: &str) -> Result<Vec<u8>, String> {
    let bytes = match value.trim().strip_prefix("0x") {
        Some(hex) => {
            let hex: String = hex
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect();
            if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("not valid hex".to_string());
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or_default())
                .collect()
        }
        None => value.as_bytes().to_vec(),
    };
    if bytes.is_empty() || bytes.len() > 255 {
        return Err("the value must be 1 to 255 bytes".to_string());
    }
    Ok(bytes)
}

impl Dhcp6Scope {
    /// The prefix, parsed.
    pub fn net(&self) -> Option<ipnet::Ipv6Net> {
        self.prefix
            .trim()
            .parse()
            .ok()
            .map(|n: ipnet::Ipv6Net| n.trunc())
    }

    /// The range, parsed; `None` for a stateless scope.
    pub fn range(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        Some((
            self.range_start.trim().parse().ok()?,
            self.range_end.trim().parse().ok()?,
        ))
    }

    /// Whether it only hands out DNS settings.
    pub fn stateless(&self) -> bool {
        self.range_start.trim().is_empty() && self.range_end.trim().is_empty()
    }

    /// Problems that stop the scope being used.
    pub fn check(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("give the scope a name".to_string());
        }
        let net: ipnet::Ipv6Net = self.prefix.trim().parse().map_err(|_| {
            format!(
                "'{}' is not a prefix such as fd00:1::/64",
                self.prefix.trim()
            )
        })?;
        if !self.stateless() {
            let start = parse_v6(&self.range_start, "range start")?;
            let end = parse_v6(&self.range_end, "range end")?;
            if !net.contains(&start) || !net.contains(&end) {
                return Err(format!("the range must be inside {net}"));
            }
            if u128::from(start) > u128::from(end) {
                return Err("the range starts after it ends".to_string());
            }
        }
        for dns in &self.dns_servers {
            parse_v6(dns, "DNS server")?;
        }
        for name in &self.domain_search {
            crate::config::validate_domain_pattern(name)
                .map_err(|_| format!("'{}' is not a domain", name.trim()))?;
        }
        if !(60..=31_536_000).contains(&self.valid_secs) || self.preferred_secs > self.valid_secs {
            return Err(
                "the valid lifetime must be 1 minute to 1 year, and the preferred lifetime no longer"
                    .to_string(),
            );
        }
        for r in &self.reservations {
            normalize_duid(&r.client)
                .ok_or_else(|| format!("'{}' is not a DUID (hex)", r.client.trim()))?;
            let ip = parse_v6(&r.address, "reservation")?;
            if !net.contains(&ip) {
                return Err(format!("the reserved address {ip} is not in {net}"));
            }
        }
        Ok(())
    }
}

impl DhcpSettings {
    /// Problems that stop the settings being used.
    pub fn check(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        let mut nets: Vec<ipnet::Ipv4Net> = Vec::new();
        for scope in &self.scopes {
            scope
                .check()
                .map_err(|e| format!("scope '{}': {e}", scope.name.trim()))?;
            if !names.insert(scope.name.trim().to_ascii_lowercase()) {
                return Err(format!("two scopes are named '{}'", scope.name.trim()));
            }
            let net = scope.net().expect("checked");
            if let Some(other) = nets
                .iter()
                .find(|n| n.contains(&net.network()) || net.contains(&n.network()))
            {
                return Err(format!("scope '{}' overlaps {other}", scope.name.trim()));
            }
            nets.push(net);
        }
        for scope in &self.scopes_v6 {
            scope
                .check()
                .map_err(|e| format!("IPv6 scope '{}': {e}", scope.name.trim()))?;
            if !names.insert(scope.name.trim().to_ascii_lowercase()) {
                return Err(format!("two scopes are named '{}'", scope.name.trim()));
            }
        }
        let zone = self.dns_zone.trim();
        if !zone.is_empty() && crate::config::validate_domain_pattern(zone).is_err() {
            return Err(format!("'{zone}' is not a zone name"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> DhcpScope {
        DhcpScope {
            name: "LAN".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            range_start: "192.168.1.100".to_string(),
            range_end: "192.168.1.199".to_string(),
            router: "192.168.1.1".to_string(),
            ..DhcpScope::default()
        }
    }

    #[test]
    fn scopes_are_checked() {
        assert!(scope().check().is_ok());
        let mut s = scope();
        s.range_end = "192.168.2.10".to_string();
        assert!(s.check().is_err());
        let mut s = scope();
        s.reservations.push(DhcpReservation {
            client: "AA-BB-CC-DD-EE-FF".to_string(),
            address: "192.168.1.50".to_string(),
            ..Default::default()
        });
        assert!(s.check().is_ok());
        s.reservations.push(DhcpReservation {
            client: "aa:bb:cc:dd:ee:ff".to_string(),
            address: "192.168.1.51".to_string(),
            ..Default::default()
        });
        assert!(s.check().unwrap_err().contains("twice"));
        let mut s = scope();
        s.options.push(DhcpCustomOption {
            code: 66,
            value: "tftp.example".to_string(),
        });
        s.options.push(DhcpCustomOption {
            code: 43,
            value: "0x01 02".to_string(),
        });
        assert!(s.check().is_ok());
        s.options.push(DhcpCustomOption {
            code: 51,
            value: "1".to_string(),
        });
        assert!(s.check().is_err());
        let settings = DhcpSettings {
            scopes: vec![
                scope(),
                DhcpScope {
                    name: "Other".to_string(),
                    ..scope()
                },
            ],
            ..Default::default()
        };
        assert!(settings.check().unwrap_err().contains("overlaps"));
    }

    #[test]
    fn identities_are_normalized() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aabb.ccdd.eeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac("aa:bb"), None);
        assert_eq!(normalize_duid("abc"), None);
        assert_eq!(
            normalize_duid("00:03:00:01:aa:bb:cc:dd:ee:ff").as_deref(),
            Some("00030001aabbccddeeff")
        );
        assert_eq!(custom_option_bytes("0x0a0b").unwrap(), vec![10, 11]);
        assert!(custom_option_bytes("0xabc").is_err());
    }

    #[test]
    fn v6_scopes_are_checked() {
        let mut s = Dhcp6Scope {
            name: "LAN6".to_string(),
            prefix: "fd00:1::/64".to_string(),
            range_start: "fd00:1::100".to_string(),
            range_end: "fd00:1::1ff".to_string(),
            ..Dhcp6Scope::default()
        };
        assert!(s.check().is_ok());
        assert!(!s.stateless());
        s.range_start.clear();
        s.range_end.clear();
        assert!(s.check().is_ok());
        assert!(s.stateless());
        s.preferred_secs = s.valid_secs + 1;
        assert!(s.check().is_err());
    }
}
