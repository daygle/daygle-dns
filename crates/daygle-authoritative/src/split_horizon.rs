//! Split-horizon DNS: per-client synthetic answers for a domain.
//!
//! A [`SplitHorizonIndex`] is built from the stored networks and entries. For
//! each query the dispatcher asks the index which IPs a given client should
//! receive for a domain; the first entry whose domain matches and whose
//! networks contain the client wins. Entries with no networks match every
//! client, so a catch-all "external" entry can sit behind specific internal
//! ones (order is controlled by `position`).

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{SplitHorizonEntry, SplitHorizonNetwork};

/// The result of a split-horizon lookup: the addresses to synthesize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitHorizonMatch {
    pub ips: Vec<IpAddr>,
    pub ttl: u32,
}

/// Immutable, pre-resolved split-horizon rules. Cheap to clone (it lives
/// behind an `Arc` inside the [`crate::AuthorityCatalog`]).
pub struct SplitHorizonIndex {
    /// All entries, ordered by `position` (ascending). `Vec::sort_by_key` is
    /// stable, so entries with equal positions keep their insertion order.
    entries: Vec<ResolvedEntry>,
}

/// One rule with network names resolved to CIDRs.
struct ResolvedEntry {
    /// Fully qualified domain, lowercase, no trailing dot.
    domain: String,
    /// Client networks that match; empty means every client *only when the
    /// entry declared no networks at all* (see `match_all`).
    networks: Vec<IpNet>,
    /// True when the entry listed no networks and therefore matches every
    /// client. Distinct from "networks listed but none resolved", which never
    /// matches.
    match_all: bool,
    /// Addresses to synthesize.
    ips: Vec<IpAddr>,
    ttl: u32,
    /// Ordering: lower positions win on ties. Stable sort keeps the original
    /// row order for equal positions.
    position: i64,
}

impl SplitHorizonIndex {
    /// Build the index from stored networks and entries.
    ///
    /// Network names are resolved to their CIDR lists; a name with no
    /// matching network (deleted or never created) is treated as an empty
    /// network, so the entry can never match. Malformed CIDRs, IPs, and
    /// disabled or empty entries are skipped entirely.
    pub fn build(networks: &[SplitHorizonNetwork], entries: &[SplitHorizonEntry]) -> Self {
        let mut by_name: HashMap<&str, Vec<IpNet>> = HashMap::new();
        for net in networks {
            let cidrs: Vec<IpNet> = net
                .cidrs
                .iter()
                .filter_map(|c| c.parse::<IpNet>().ok())
                .collect();
            if !cidrs.is_empty() {
                by_name.insert(net.name.as_str(), cidrs);
            }
        }

        let mut resolved: Vec<ResolvedEntry> = entries
            .iter()
            .filter(|e| !e.disabled && !e.ips.is_empty())
            .map(|e| {
                let networks = if e.networks.is_empty() {
                    Vec::new()
                } else {
                    e.networks
                        .iter()
                        .flat_map(|n| {
                            // A literal CIDR, or the name of a configured network.
                            if let Ok(ipnet) = n.parse::<IpNet>() {
                                vec![ipnet]
                            } else {
                                by_name.get(n.as_str()).cloned().unwrap_or_default()
                            }
                        })
                        .collect()
                };
                ResolvedEntry {
                    domain: e
                        .domain
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                    networks,
                    match_all: e.networks.is_empty(),
                    ips: e
                        .ips
                        .iter()
                        .filter_map(|ip| ip.parse::<IpAddr>().ok())
                        .collect(),
                    ttl: e.ttl,
                    position: e.position,
                }
            })
            .collect();

        // Stable sort: earlier positions take precedence over later ones.
        resolved.sort_by_key(|e| e.position);
        Self { entries: resolved }
    }

    /// Whether the index contains any usable rule.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first matching rule for `client` querying `qname`, if any.
    ///
    /// `qname` may carry a trailing dot and any case; it is normalized before
    /// matching. Returns `None` when no entry matches the domain *and* the
    /// client's network.
    pub fn lookup(&self, client: IpAddr, qname: &str) -> Option<SplitHorizonMatch> {
        let qname = qname.trim().trim_end_matches('.').to_ascii_lowercase();
        for entry in &self.entries {
            if entry.domain != qname {
                continue;
            }
            let in_network =
                entry.match_all || entry.networks.iter().any(|net| net.contains(&client));
            if in_network {
                if entry.ips.is_empty() {
                    continue;
                }
                return Some(SplitHorizonMatch {
                    ips: entry.ips.clone(),
                    ttl: entry.ttl,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SplitHorizonEntryInput, SplitHorizonNetworkInput};
    use crate::store::ZoneStore;

    fn index(networks: &[(&str, &[&str])], entries: &[(u8, &str, &[&str], &[&str])]) -> SplitHorizonIndex {
        let networks: Vec<SplitHorizonNetwork> = networks
            .iter()
            .map(|(name, cidrs)| SplitHorizonNetwork {
                id: name.to_string(),
                name: name.to_string(),
                cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
            })
            .collect();
        let entries: Vec<SplitHorizonEntry> = entries
            .iter()
            .enumerate()
            .map(|(i, (position, domain, nets, ips))| SplitHorizonEntry {
                id: format!("e{i}"),
                domain: domain.to_string(),
                networks: nets.iter().map(|n| n.to_string()).collect(),
                ips: ips.iter().map(|ip| ip.to_string()).collect(),
                ttl: 60,
                disabled: false,
                position: *position as i64,
            })
            .collect();
        SplitHorizonIndex::build(&networks, &entries)
    }

    fn lan() -> IpAddr {
        "192.168.20.10".parse().unwrap()
    }

    fn vpn() -> IpAddr {
        "192.168.30.10".parse().unwrap()
    }

    fn outside() -> IpAddr {
        "8.8.8.8".parse().unwrap()
    }

    #[test]
    fn matches_by_network_name() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[(0, "www.example.com", &["LAN"], &["10.0.0.5"])],
        );
        assert_eq!(
            idx.lookup(lan(), "www.example.com").unwrap().ips,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert!(idx.lookup(vpn(), "www.example.com").is_none());
        assert!(idx.lookup(outside(), "www.example.com").is_none());
    }

    #[test]
    fn empty_networks_match_every_client() {
        let idx = index(&[], &[(0, "www.example.com", &[], &["10.0.0.5"])]);
        assert!(idx.lookup(lan(), "www.example.com").is_some());
        assert!(idx.lookup(outside(), "www.example.com").is_some());
    }

    #[test]
    fn literal_cidr_in_entry() {
        let idx = index(
            &[],
            &[(0, "www.example.com", &["192.168.30.0/24"], &["10.0.0.9"])],
        );
        assert!(idx.lookup(vpn(), "www.example.com").is_some());
        assert!(idx.lookup(lan(), "www.example.com").is_none());
    }

    #[test]
    fn first_position_wins() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[
                (1, "www.example.com", &[], &["203.0.113.1"]),
                (0, "www.example.com", &["LAN"], &["10.0.0.5"]),
            ],
        );
        assert_eq!(
            idx.lookup(lan(), "www.example.com").unwrap().ips,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        // Outside clients fall through to the catch-all.
        assert_eq!(
            idx.lookup(outside(), "www.example.com").unwrap().ips,
            vec!["203.0.113.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn domain_matching_is_case_and_dot_insensitive() {
        let idx = index(&[], &[(0, "WWW.Example.COM", &[], &["10.0.0.5"])]);
        assert!(idx.lookup(lan(), "www.example.com.").is_some());
        assert!(idx.lookup(lan(), "WWW.EXAMPLE.COM").is_some());
        assert!(idx.lookup(lan(), "other.example.com").is_none());
    }

    #[test]
    fn disabled_and_bad_entries_are_skipped() {
        let store = ZoneStore::open(":memory:").unwrap();
        let network = store
            .upsert_split_horizon_network(&SplitHorizonNetworkInput {
                name: "LAN".to_string(),
                cidrs: vec!["192.168.20.0/24".to_string()],
            })
            .unwrap();
        let entry = store
            .create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "www.example.com".to_string(),
                networks: vec!["LAN".to_string()],
                ips: vec!["10.0.0.5".to_string()],
                ttl: 60,
                disabled: true,
            })
            .unwrap();
        let idx = SplitHorizonIndex::build(&[network], &[entry]);
        assert!(idx.is_empty());
        assert!(idx.lookup(lan(), "www.example.com").is_none());
    }

    #[test]
    fn unknown_network_name_never_matches() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[(0, "www.example.com", &["VPN"], &["10.0.0.5"])],
        );
        assert!(idx.lookup(lan(), "www.example.com").is_none());
    }
}
