//! Split-horizon DNS: per-client synthetic answers for a domain.
//!
//! A [`SplitHorizonIndex`] is built from the stored networks and entries. For
//! each query the dispatcher asks the index which records a given client
//! should receive for a domain and query type; the first entry whose domain
//! matches and whose networks contain the client wins. Entries with no
//! networks match every client, so a catch-all "external" entry can sit
//! behind specific internal ones (order is controlled by `position`).
//!
//! An entry holds typed records (A, AAAA, MX, TXT, CNAME, SRV). A query is
//! answered only by records of its own type — except that a CNAME answers
//! every query type, as it does in the real DNS (RFC 1034 §3.6.2). When the
//! matching entry has nothing for the queried type the lookup returns `None`
//! and the dispatcher falls through to normal resolution.

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;

use crate::model::{SplitHorizonEntry, SplitHorizonNetwork};

/// The result of a split-horizon lookup: the records to synthesize for the
/// queried name. An empty `records` list would mean the entry matched but has
/// nothing for the query type; [`SplitHorizonIndex::lookup`] returns `None`
/// in that case instead, so callers fall through to normal resolution.
pub struct SplitHorizonMatch {
    pub records: Vec<Record>,
}

/// Immutable, pre-resolved split-horizon rules. Cheap to clone (it lives
/// behind an `Arc` inside the [`crate::AuthorityCatalog`]).
pub struct SplitHorizonIndex {
    /// All entries, ordered by `position` (ascending). `Vec::sort_by_key` is
    /// stable, so entries with equal positions keep their insertion order.
    entries: Vec<ResolvedEntry>,
}

/// One rule with network names resolved to CIDRs and records pre-parsed.
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
    /// Parsed records: the query type plus its RDATA.
    records: Vec<(RecordType, RData)>,
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
    /// network, so the entry can never match. Disabled, empty, and malformed
    /// entries are skipped entirely.
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
            .filter(|e| !e.disabled && (!e.ips.is_empty() || !e.records.is_empty()))
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
                    records: parse_records(e),
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

    /// The records to synthesize for `client` querying `qname` with `rtype`,
    /// if any entry matches both the domain and the client's network.
    ///
    /// `qname` may carry a trailing dot and any case; it is normalized before
    /// matching. Returns `None` when no entry matches, or when the matching
    /// entry has no record for `rtype` (and no CNAME) — the caller then falls
    /// through to normal resolution.
    pub fn lookup(
        &self,
        client: IpAddr,
        qname: &str,
        rtype: RecordType,
    ) -> Option<SplitHorizonMatch> {
        let qname = qname.trim().trim_end_matches('.').to_ascii_lowercase();
        let name = Name::from_utf8(&format!("{qname}.")).ok()?;
        for entry in &self.entries {
            if entry.domain != qname {
                continue;
            }
            let in_network =
                entry.match_all || entry.networks.iter().any(|net| net.contains(&client));
            if !in_network {
                continue;
            }
            if entry.records.is_empty() {
                continue;
            }

            // A CNAME at the name answers every query type (RFC 1034 §3.6.2).
            let has_cname = entry.records.iter().any(|(t, _)| *t == RecordType::CNAME);
            let selected: Vec<&(RecordType, RData)> = if has_cname {
                entry
                    .records
                    .iter()
                    .filter(|(t, _)| *t == RecordType::CNAME)
                    .collect()
            } else if rtype == RecordType::ANY {
                entry.records.iter().collect()
            } else {
                entry
                    .records
                    .iter()
                    .filter(|(t, _)| *t == rtype)
                    .collect()
            };
            if selected.is_empty() {
                continue;
            }

            let records: Vec<Record> = selected
                .into_iter()
                .map(|(_, rdata)| Record::from_rdata(name.clone(), entry.ttl, rdata.clone()))
                .collect();
            return Some(SplitHorizonMatch { records });
        }
        None
    }
}

/// Parse an entry's records into `(RecordType, RData)` pairs, skipping
/// anything malformed. Entries carrying only `ips` (written before typed
/// records existed) are converted to A/AAAA records.
fn parse_records(e: &SplitHorizonEntry) -> Vec<(RecordType, RData)> {
    if !e.records.is_empty() {
        return e
            .records
            .iter()
            .filter_map(|r| {
                let rtype = r.rtype.parse::<RecordType>().ok()?;
                let rdata = RData::try_from_str(rtype, &r.content).ok()?;
                Some((rtype, rdata))
            })
            .collect();
    }
    e.ips
        .iter()
        .filter_map(|ip| {
            if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                Some((RecordType::A, RData::A(v4.into())))
            } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
                Some((RecordType::AAAA, RData::AAAA(v6.into())))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SplitHorizonEntryInput, SplitHorizonNetworkInput, SplitHorizonRecord};
    use crate::store::ZoneStore;

    fn entry(position: u8, domain: &str, nets: &[&str], records: &[(&str, &str)]) -> SplitHorizonEntry {
        SplitHorizonEntry {
            id: format!("e-{domain}-{position}"),
            domain: domain.to_string(),
            networks: nets.iter().map(|n| n.to_string()).collect(),
            ips: vec![],
            records: records
                .iter()
                .map(|(t, c)| SplitHorizonRecord {
                    rtype: t.to_string(),
                    content: c.to_string(),
                })
                .collect(),
            ttl: 60,
            disabled: false,
            position: position as i64,
        }
    }

    fn index(networks: &[(&str, &[&str])], entries: &[SplitHorizonEntry]) -> SplitHorizonIndex {
        let networks: Vec<SplitHorizonNetwork> = networks
            .iter()
            .map(|(name, cidrs)| SplitHorizonNetwork {
                id: name.to_string(),
                name: name.to_string(),
                cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
            })
            .collect();
        SplitHorizonIndex::build(&networks, entries)
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

    /// `(record_type, rdata presentation)` of the `i`-th synthesized record.
    fn rec(m: &SplitHorizonMatch, i: usize) -> (RecordType, String) {
        (m.records[i].record_type(), m.records[i].data.to_string())
    }

    #[test]
    fn matches_by_network_name() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[entry(0, "www.example.com", &["LAN"], &[("A", "10.0.0.5")])],
        );
        let m = idx
            .lookup(lan(), "www.example.com", RecordType::A)
            .expect("LAN client matches");
        assert_eq!(rec(&m, 0), (RecordType::A, "10.0.0.5".to_string()));
        assert!(idx.lookup(vpn(), "www.example.com", RecordType::A).is_none());
        assert!(idx.lookup(outside(), "www.example.com", RecordType::A).is_none());
    }

    #[test]
    fn empty_networks_match_every_client() {
        let idx = index(&[], &[entry(0, "www.example.com", &[], &[("A", "10.0.0.5")])]);
        assert!(idx.lookup(lan(), "www.example.com", RecordType::A).is_some());
        assert!(idx.lookup(outside(), "www.example.com", RecordType::A).is_some());
    }

    #[test]
    fn literal_cidr_in_entry() {
        let idx = index(
            &[],
            &[entry(0, "www.example.com", &["192.168.30.0/24"], &[("A", "10.0.0.9")])],
        );
        assert!(idx.lookup(vpn(), "www.example.com", RecordType::A).is_some());
        assert!(idx.lookup(lan(), "www.example.com", RecordType::A).is_none());
    }

    #[test]
    fn first_position_wins() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[
                entry(1, "www.example.com", &[], &[("A", "203.0.113.1")]),
                entry(0, "www.example.com", &["LAN"], &[("A", "10.0.0.5")]),
            ],
        );
        let lan_match = idx.lookup(lan(), "www.example.com", RecordType::A).unwrap();
        assert_eq!(rec(&lan_match, 0), (RecordType::A, "10.0.0.5".to_string()));
        let outside_match = idx.lookup(outside(), "www.example.com", RecordType::A).unwrap();
        assert_eq!(
            rec(&outside_match, 0),
            (RecordType::A, "203.0.113.1".to_string())
        );
    }

    #[test]
    fn domain_matching_is_case_and_dot_insensitive() {
        let idx = index(&[], &[entry(0, "WWW.Example.COM", &[], &[("A", "10.0.0.5")])]);
        assert!(idx.lookup(lan(), "www.example.com.", RecordType::A).is_some());
        assert!(idx.lookup(lan(), "WWW.EXAMPLE.COM", RecordType::A).is_some());
        assert!(idx.lookup(lan(), "other.example.com", RecordType::A).is_none());
    }

    #[test]
    fn disabled_entries_are_skipped() {
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
                ips: vec![],
                records: vec![SplitHorizonRecord {
                    rtype: "A".to_string(),
                    content: "10.0.0.5".to_string(),
                }],
                ttl: 60,
                disabled: true,
            })
            .unwrap();
        let idx = SplitHorizonIndex::build(&[network], &[entry]);
        assert!(idx.is_empty());
        assert!(idx.lookup(lan(), "www.example.com", RecordType::A).is_none());
    }

    #[test]
    fn unknown_network_name_never_matches() {
        let idx = index(
            &[("LAN", &["192.168.20.0/24"])],
            &[entry(0, "www.example.com", &["VPN"], &[("A", "10.0.0.5")])],
        );
        assert!(idx.lookup(lan(), "www.example.com", RecordType::A).is_none());
    }

    #[test]
    fn lookup_matches_record_type() {
        let idx = index(
            &[],
            &[entry(
                0,
                "mail.example.com",
                &[],
                &[
                    ("A", "10.0.0.5"),
                    ("MX", "10 mailhost.example.com."),
                    ("TXT", "\"v=spf1 -all\""),
                ],
            )],
        );
        let mx = idx.lookup(lan(), "mail.example.com", RecordType::MX).unwrap();
        assert_eq!(mx.records.len(), 1);
        assert_eq!(rec(&mx, 0).0, RecordType::MX);
        assert!(rec(&mx, 0).1.contains("10 mailhost.example.com"));

        let txt = idx.lookup(lan(), "mail.example.com", RecordType::TXT).unwrap();
        assert_eq!(txt.records.len(), 1);
        assert_eq!(rec(&txt, 0).0, RecordType::TXT);
        assert!(rec(&txt, 0).1.contains("v=spf1 -all"));

        let a = idx.lookup(lan(), "mail.example.com", RecordType::A).unwrap();
        assert_eq!(a.records.len(), 1);
        assert_eq!(rec(&a, 0), (RecordType::A, "10.0.0.5".to_string()));

        // No SRV record: fall through to normal resolution.
        assert!(idx.lookup(lan(), "mail.example.com", RecordType::SRV).is_none());
    }

    #[test]
    fn any_returns_all_records() {
        let idx = index(
            &[],
            &[entry(
                0,
                "x.example.com",
                &[],
                &[("A", "10.0.0.5"), ("MX", "10 mail.example.com.")],
            )],
        );
        let m = idx.lookup(lan(), "x.example.com", RecordType::ANY).unwrap();
        assert_eq!(m.records.len(), 2);
    }

    #[test]
    fn cname_answers_every_query_type() {
        let idx = index(
            &[],
            &[entry(
                0,
                "alias.example.com",
                &[],
                &[("CNAME", "target.example.com."), ("TXT", "\"note\"")],
            )],
        );
        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::TXT,
            RecordType::CNAME,
        ] {
            let m = idx
                .lookup(lan(), "alias.example.com", rtype)
                .expect("a CNAME answers every query type");
            assert_eq!(m.records.len(), 1);
            assert_eq!(rec(&m, 0).0, RecordType::CNAME);
            assert!(rec(&m, 0).1.contains("target.example.com"));
        }
    }

    #[test]
    fn invalid_records_are_skipped() {
        let idx = index(
            &[],
            &[entry(
                0,
                "www.example.com",
                &[],
                &[("A", "not-an-ip"), ("TXT", "\"ok\"")],
            )],
        );
        let m = idx.lookup(lan(), "www.example.com", RecordType::TXT).unwrap();
        assert_eq!(m.records.len(), 1);
        assert_eq!(rec(&m, 0).0, RecordType::TXT);
        assert!(idx.lookup(lan(), "www.example.com", RecordType::A).is_none());
    }

    #[test]
    fn ips_only_entries_still_resolve_as_a_aaaa() {
        let e = SplitHorizonEntry {
            id: "legacy".to_string(),
            domain: "www.example.com".to_string(),
            networks: vec![],
            ips: vec!["10.0.0.5".to_string(), "fd00::5".to_string()],
            records: vec![],
            ttl: 60,
            disabled: false,
            position: 0,
        };
        let idx = SplitHorizonIndex::build(&[], &[e]);
        let a = idx.lookup(lan(), "www.example.com", RecordType::A).unwrap();
        assert_eq!(a.records.len(), 1);
        assert_eq!(rec(&a, 0), (RecordType::A, "10.0.0.5".to_string()));
        let aaaa = idx.lookup(lan(), "www.example.com", RecordType::AAAA).unwrap();
        assert_eq!(rec(&aaaa, 0), (RecordType::AAAA, "fd00::5".to_string()));
        assert!(idx.lookup(lan(), "www.example.com", RecordType::MX).is_none());
    }
}
