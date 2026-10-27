//! Automatic PTR answers: an AUTOPTR record in a reverse zone makes up a
//! PTR answer for every address under its name that has no PTR record of
//! its own, from a template such as `ip-{ip}.home.arpa` (so a lookup of
//! 192.168.1.47 answers `ip-192-168-1-47.home.arpa.` instead of NXDOMAIN).
//!
//! Like ALIAS, the answers are made when asked (by the dispatcher), so
//! AUTOPTR records are kept out of signed zones and out of zone transfers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a template puts the address.
pub const IP_PLACEHOLDER: &str = "{ip}";

/// The host name `template` gives `address`: [`IP_PLACEHOLDER`] becomes
/// the address with dashes for separators (`192-168-1-47`, or every
/// IPv6 group in hex, `2001-db8-0-0-0-0-0-1`, so no label starts or ends
/// with a dash).
pub fn expand(template: &str, address: IpAddr) -> String {
    let ip = match address {
        IpAddr::V4(v4) => v4
            .octets()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-"),
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .map(|s| format!("{s:x}"))
            .collect::<Vec<_>>()
            .join("-"),
    };
    template.trim_end_matches('.').replace(IP_PLACEHOLDER, &ip)
}

/// The address a full reverse name stands for: `47.1.168.192.in-addr.arpa`
/// is 192.168.1.47, and 32 nibbles under `ip6.arpa` an IPv6 address.
/// `None` for anything else (a name above a single address, or not a
/// reverse name at all).
pub fn address_of(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = rest
            .split('.')
            .map(|l| {
                // No leading zeros: `01` is not the label for 1.
                if l.len() > 1 && l.starts_with('0') {
                    None
                } else {
                    l.parse().ok()
                }
            })
            .collect::<Option<_>>()?;
        let [d, c, b, a] = octets[..] else {
            return None;
        };
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    let rest = name.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = rest
        .split('.')
        .map(|l| {
            if l.len() == 1 {
                u8::from_str_radix(l, 16).ok()
            } else {
                None
            }
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let value = nibbles
        .iter()
        .rev()
        .fold(0u128, |acc, n| (acc << 4) | u128::from(*n));
    Some(IpAddr::V6(Ipv6Addr::from(value)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    /// The template, lowercase, no trailing dot.
    template: String,
    ttl: u32,
}

/// The AUTOPTR records being served, by owner name, and the names that
/// have PTR records of their own (which always win).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AutoPtrIndex {
    rules: HashMap<String, Rule>,
    ptr_names: HashSet<String>,
}

impl AutoPtrIndex {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Serve AUTOPTR answers under `owner` (lowercase, no trailing dot).
    pub(crate) fn add_rule(&mut self, owner: &str, template: &str, ttl: u32) {
        self.rules.insert(
            owner.trim_end_matches('.').to_ascii_lowercase(),
            Rule {
                template: template.trim_end_matches('.').to_ascii_lowercase(),
                ttl,
            },
        );
    }

    /// `name` has a PTR record of its own.
    pub(crate) fn add_ptr_name(&mut self, name: &str) {
        self.ptr_names
            .insert(name.trim_end_matches('.').to_ascii_lowercase());
    }

    /// The made-up PTR target (with a trailing dot) and TTL for `name`
    /// (lowercase, no trailing dot), when an AUTOPTR record at or above it
    /// covers it and it has no PTR record.
    pub fn lookup(&self, name: &str) -> Option<(String, u32)> {
        if self.rules.is_empty() || self.ptr_names.contains(name) {
            return None;
        }
        let address = address_of(name)?;
        let mut candidate = name;
        loop {
            if let Some(rule) = self.rules.get(candidate) {
                return Some((format!("{}.", expand(&rule.template, address)), rule.ttl));
            }
            candidate = candidate.split_once('.')?.1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_addresses_into_host_names() {
        let v4: IpAddr = "192.168.1.47".parse().unwrap();
        assert_eq!(
            expand("ip-{ip}.home.arpa.", v4),
            "ip-192-168-1-47.home.arpa"
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(expand("{ip}.lan", v6), "2001-db8-0-0-0-0-0-1.lan");
    }

    #[test]
    fn reads_addresses_from_reverse_names() {
        assert_eq!(
            address_of("47.1.168.192.in-addr.arpa"),
            Some("192.168.1.47".parse().unwrap())
        );
        assert_eq!(
            address_of("1.168.192.in-addr.arpa"),
            None,
            "a /24, not an address"
        );
        assert_eq!(address_of("01.1.168.192.in-addr.arpa"), None);
        assert_eq!(address_of("256.1.168.192.in-addr.arpa"), None);
        let v6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
        assert_eq!(address_of(v6), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(address_of("8.b.d.0.1.0.0.2.ip6.arpa"), None);
        assert_eq!(address_of("www.example.com"), None);
    }

    #[test]
    fn rules_cover_their_subtree_unless_a_ptr_exists() {
        let mut index = AutoPtrIndex::default();
        index.add_rule("168.192.in-addr.arpa", "ip-{ip}.lan.", 300);
        index.add_rule("5.168.192.in-addr.arpa", "guest-{ip}.lan.", 60);
        index.add_ptr_name("1.1.168.192.in-addr.arpa");
        assert_eq!(
            index.lookup("47.1.168.192.in-addr.arpa"),
            Some(("ip-192-168-1-47.lan.".to_string(), 300))
        );
        assert_eq!(
            index.lookup("9.5.168.192.in-addr.arpa"),
            Some(("guest-192-168-5-9.lan.".to_string(), 60)),
            "the most specific rule wins"
        );
        assert_eq!(
            index.lookup("1.1.168.192.in-addr.arpa"),
            None,
            "a real PTR wins"
        );
        assert_eq!(index.lookup("1.0.10.in-addr.arpa"), None, "not covered");
        assert_eq!(
            index.lookup("1.168.192.in-addr.arpa"),
            None,
            "not an address"
        );
    }
}
