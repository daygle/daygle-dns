//! Checks on a resolved answer before it goes back to the client:
//!
//! - **Local network addresses** (DNS rebinding protection): a public name
//!   that answers with a private, loopback or link-local address lets a web
//!   page reach devices on the client's own network. Names that are local by
//!   nature (single labels, `home.arpa`, `.lan`, ...) are left alone, as are
//!   conditional forwarders and stub zones, which the caller skips.
//! - **DNS payloads**: DNS can carry commands and files to malware in TXT and
//!   NULL records. Everyday use needs neither NULL records nor more than a
//!   few hundred bytes of TXT data in one answer (SPF, DKIM and verification
//!   strings), so an answer over those limits is blocked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use daygle_dns_core::config::REBINDING_DENY_NETWORKS;
use daygle_dns_recursive::RecursiveResolver;
use hickory_proto::rr::{RData, Record, RecordType};
use ipnet::IpNet;

/// Most TXT data (the bytes of every string of every TXT record) one answer
/// may carry. A 4096-bit DKIM key is about 750 bytes; SPF records and
/// verification strings are far smaller.
pub const TXT_LIMIT: usize = 1024;

/// Most bytes one record of a type this server does not know may carry.
pub const UNKNOWN_LIMIT: usize = 255;

/// Name suffixes that are local by convention, whose answers are expected to
/// hold private addresses (a home router answering `nas.lan`).
const LOCAL_SUFFIXES: &[&str] = &[
    "home.arpa",
    "local",
    "lan",
    "internal",
    "localdomain",
    "localhost",
    "home",
    "corp",
    "intranet",
    "private",
    "fritz.box",
];

fn deny_networks() -> &'static [IpNet] {
    static NETS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETS.get_or_init(|| {
        REBINDING_DENY_NETWORKS
            .iter()
            .filter_map(|n| n.parse().ok())
            .collect()
    })
}

/// Whether `qname` (lowercase, no trailing dot) is a local name whose
/// answers may hold private addresses.
pub fn is_local_name(qname: &str) -> bool {
    !qname.contains('.')
        || LOCAL_SUFFIXES.iter().any(|suffix| {
            qname == *suffix
                || qname
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
}

/// The first local network address among `answers`' A and AAAA records.
pub fn local_address(answers: &[Record]) -> Option<IpAddr> {
    answers.iter().find_map(|record| {
        let ip = match &record.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(a) => IpAddr::V6(a.0),
            _ => return None,
        };
        deny_networks()
            .iter()
            .any(|net| net.contains(&ip))
            .then_some(ip)
    })
}

/// Why `answers` carry more data than everyday DNS use needs, if they do.
pub fn oversized_payload(answers: &[Record]) -> Option<String> {
    let mut txt = 0;
    for record in answers {
        match &record.data {
            RData::NULL(_) => return Some("NULL record".to_string()),
            RData::Unknown { code, rdata } if rdata.anything.len() > UNKNOWN_LIMIT => {
                return Some(format!("{} bytes in a {code} record", rdata.anything.len()));
            }
            RData::TXT(data) => txt += data.txt_data.iter().map(|s| s.len()).sum::<usize>(),
            _ => {}
        }
    }
    (txt > TXT_LIMIT).then(|| format!("{txt} bytes of TXT data"))
}

/// Most addresses remembered; past it the expired ones are dropped, and all
/// of them if none has expired.
const CACHE_CAP: usize = 50_000;

/// How long an address's origin networks are remembered.
const ORIGIN_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long a failed origin lookup waits before it is tried again.
const ORIGIN_RETRY: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
enum OriginState {
    Pending,
    Known(Vec<u32>, Instant),
}

/// The origin networks (ASNs) of public addresses, from an IP-to-ASN DNS
/// zone (Team Cymru's), filled in the background, for the Residential
/// Hosting category.
#[derive(Debug, Default)]
pub struct IpOrigins {
    addresses: Mutex<HashMap<IpAddr, OriginState>>,
}

impl IpOrigins {
    /// The ASNs announcing `ip`, when known (empty when the zone has none).
    /// When nothing current is known, starts a background lookup of the TXT
    /// record for `ip` under `zone_v4`/`zone_v6` with `resolver` and returns
    /// `None`.
    pub fn check(
        self: &Arc<Self>,
        resolver: &Arc<RecursiveResolver>,
        client: IpAddr,
        ip: IpAddr,
        zone_v4: &str,
        zone_v6: &str,
    ) -> Option<Vec<u32>> {
        let now = Instant::now();
        {
            let mut addresses = self.addresses.lock().unwrap_or_else(|e| e.into_inner());
            match addresses.get(&ip) {
                Some(OriginState::Pending) => return None,
                Some(OriginState::Known(asns, until)) if *until > now => return Some(asns.clone()),
                _ => {}
            }
            if addresses.len() >= CACHE_CAP {
                addresses.retain(
                    |_, state| matches!(state, OriginState::Known(_, until) if *until > now),
                );
                if addresses.len() >= CACHE_CAP {
                    addresses.clear();
                }
            }
            addresses.insert(ip, OriginState::Pending);
        }
        let this = Arc::clone(self);
        let resolver = Arc::clone(resolver);
        let name = daygle_dns_policy::residential::cymru_name(ip, zone_v4, zone_v6);
        tokio::spawn(async move {
            let state = match resolver
                .lookup_for_client(client, &name, RecordType::TXT)
                .await
            {
                Ok(lookup) => {
                    let asns = lookup
                        .answers()
                        .iter()
                        .find_map(|r| match &r.data {
                            RData::TXT(txt) => {
                                let text: String = txt
                                    .txt_data
                                    .iter()
                                    .map(|s| String::from_utf8_lossy(s).into_owned())
                                    .collect();
                                Some(daygle_dns_policy::residential::parse_cymru_txt(&text))
                            }
                            _ => None,
                        })
                        .unwrap_or_default();
                    OriginState::Known(asns, Instant::now() + ORIGIN_TTL)
                }
                // An address the zone does not cover (NXDOMAIN) is known to
                // have no origin; other failures are retried.
                Err(e) if is_nxdomain(&e) => {
                    OriginState::Known(Vec::new(), Instant::now() + ORIGIN_TTL)
                }
                Err(_) => OriginState::Known(Vec::new(), Instant::now() + ORIGIN_RETRY),
            };
            this.addresses
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(ip, state);
        });
        None
    }
}

fn is_nxdomain(error: &daygle_dns_core::DaygleError) -> bool {
    matches!(
        error,
        daygle_dns_core::DaygleError::Resolution {
            response_code: Some(code),
            ..
        } if *code == u16::from(hickory_proto::op::ResponseCode::NXDomain)
    )
}

/// The public addresses among `answers`' A and AAAA records (at most
/// `limit`), for checks that look their networks up.
pub fn public_addresses(answers: &[Record], limit: usize) -> Vec<IpAddr> {
    answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .filter(|ip| !deny_networks().iter().any(|net| net.contains(ip)))
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, NULL, TXT};
    use hickory_proto::rr::Name;

    fn record(data: RData) -> Record {
        Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 60, data)
    }

    #[test]
    fn finds_local_addresses() {
        let public = record(RData::A(A::new(93, 184, 216, 34)));
        assert_eq!(local_address(std::slice::from_ref(&public)), None);
        let private = record(RData::A(A::new(192, 168, 1, 10)));
        assert_eq!(
            local_address(&[public, private]),
            Some("192.168.1.10".parse().unwrap())
        );
        let mapped = record(RData::AAAA(AAAA("::ffff:127.0.0.1".parse().unwrap())));
        assert!(local_address(&[mapped]).is_some());
        let ula = record(RData::AAAA(AAAA("fd00::1".parse().unwrap())));
        assert!(local_address(&[ula]).is_some());
    }

    #[test]
    fn local_names_are_exempt() {
        for name in [
            "nas",
            "nas.lan",
            "printer.home.arpa",
            "box.fritz.box",
            "lan",
        ] {
            assert!(is_local_name(name), "{name}");
        }
        for name in [
            "example.com",
            "plan",
            "evil.example.com",
            "notlan.com",
            "xlan",
        ] {
            assert_eq!(is_local_name(name), !name.contains('.'), "{name}");
        }
        assert!(!is_local_name("myfritz.box.example"));
    }

    #[test]
    fn limits_payloads() {
        let txt = |len: usize| record(RData::TXT(TXT::new(vec!["a".repeat(len)])));
        assert_eq!(oversized_payload(&[txt(200), txt(200)]), None);
        assert_eq!(
            oversized_payload(&[txt(250), txt(250), txt(250), txt(250), txt(250)]).as_deref(),
            Some("1250 bytes of TXT data")
        );
        let null = record(RData::NULL(NULL::with(vec![1, 2, 3])));
        assert_eq!(oversized_payload(&[null]).as_deref(), Some("NULL record"));
    }
}
