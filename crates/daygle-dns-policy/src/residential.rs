//! Residential hosting, for the Residential Hosting security category: a
//! public name whose addresses all belong to home (consumer ISP) networks
//! rather than data centres. Legitimate services rarely run on home
//! connections; botnet command servers and phishing proxies on compromised
//! routers do.
//!
//! An address's network (its origin ASN) comes from Team Cymru's IP-to-ASN
//! DNS service, which the dispatcher queries through its own resolver
//! ([`cymru_name`], [`parse_cymru_txt`]). Whether a network serves homes
//! comes from the network's own PeeringDB record: `Cable/DSL/ISP` networks
//! are consumer access providers ([`NetworkTypes`]). Both are looked up in
//! the background and remembered, so the query path never waits; the first
//! queries for a name are not judged.
//!
//! Large CDNs place cache servers inside consumer ISPs (Google Global Cache,
//! Netflix Open Connect, Meta, Akamai, ...), numbered from the ISP's
//! addresses, so their names are never judged ([`is_embedded_cdn`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tracing::debug;

/// PeeringDB.
pub const DEFAULT_PEERINGDB_URL: &str = "https://www.peeringdb.com";
/// Team Cymru's IP-to-ASN zones for IPv4 and IPv6 addresses.
pub const DEFAULT_ASN_ZONE_V4: &str = "origin.asn.cymru.com";
pub const DEFAULT_ASN_ZONE_V6: &str = "origin6.asn.cymru.com";

/// PeeringDB network types that are consumer access providers.
const RESIDENTIAL_TYPES: &[&str] = &["Cable/DSL/ISP"];

/// How long a network's type is remembered.
const TYPE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a failed or empty lookup waits before it is tried again
/// (anonymous PeeringDB use is rate-limited).
const RETRY: Duration = Duration::from_secs(3600);
/// Most networks remembered.
const CAP: usize = 50_000;
/// PeeringDB lookups running at once.
const CONCURRENT: usize = 2;

/// Name suffixes of CDNs that put caches inside consumer ISPs, and of
/// speed-test servers hosted by ISPs: their addresses look residential.
const EMBEDDED_CDNS: &[&str] = &[
    "googlevideo.com",
    "gvt1.com",
    "gvt2.com",
    "nflxvideo.net",
    "nflxso.net",
    "fbcdn.net",
    "cdninstagram.com",
    "whatsapp.net",
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "akamaized.net",
    "akamaitechnologies.com",
    "edgesuite.net",
    "edgekey.net",
    "aaplimg.com",
    "cdn-apple.com",
    "cloudfront.net",
    "llnwd.net",
    "steamcontent.com",
    "steamserver.net",
    "xboxlive.com",
    "windowsupdate.com",
    "delivery.mp.microsoft.com",
    "ttvnw.net",
    "speedtest.net",
    "ooklaserver.net",
];

/// Whether `name` (lowercase, no trailing dot) is served by a CDN that
/// embeds caches in consumer ISPs.
pub fn is_embedded_cdn(name: &str) -> bool {
    EMBEDDED_CDNS.iter().any(|suffix| {
        name == *suffix
            || name
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// The name whose TXT record gives `ip`'s origin ASN in Team Cymru's
/// zones: the address reversed (bytes for IPv4, nibbles for IPv6) under
/// the zone, as in reverse DNS.
pub fn cymru_name(ip: IpAddr, zone_v4: &str, zone_v6: &str) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.{zone_v4}")
        }
        IpAddr::V6(v6) => {
            let mut labels = String::new();
            for byte in v6.octets().iter().rev() {
                labels.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            format!("{labels}{zone_v6}")
        }
    }
}

/// The origin ASNs of a Team Cymru TXT answer:
/// `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`, where an address
/// announced by several networks lists them space-separated.
pub fn parse_cymru_txt(txt: &str) -> Vec<u32> {
    txt.split('|')
        .next()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|asn| asn.parse().ok())
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum State {
    Pending,
    Known(Option<bool>, Instant),
}

/// Which networks (ASNs) are consumer access providers, from PeeringDB,
/// filled in the background.
pub struct NetworkTypes {
    client: reqwest::Client,
    base_url: String,
    networks: Mutex<HashMap<u32, State>>,
    permits: Semaphore,
}

impl std::fmt::Debug for NetworkTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkTypes")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Default for NetworkTypes {
    fn default() -> Self {
        Self::new(DEFAULT_PEERINGDB_URL)
    }
}

impl NetworkTypes {
    /// Look networks up at the PeeringDB API under `base_url`.
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            networks: Mutex::new(HashMap::new()),
            permits: Semaphore::new(CONCURRENT),
        }
    }

    /// The PeeringDB base URL used.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Whether network `asn` is a consumer access provider, when known
    /// (`Some(false)` too for networks PeeringDB does not list). When
    /// nothing current is known, starts a background lookup and returns
    /// `None`.
    pub fn check(self: &Arc<Self>, asn: u32) -> Option<bool> {
        let now = Instant::now();
        {
            let mut networks = self.networks.lock().unwrap_or_else(|e| e.into_inner());
            match networks.get(&asn) {
                Some(State::Pending) => return None,
                Some(State::Known(kind, until)) if *until > now => {
                    return Some(kind.unwrap_or(false))
                }
                _ => {}
            }
            if networks.len() >= CAP {
                networks.retain(|_, s| matches!(s, State::Known(_, until) if *until > now));
                if networks.len() >= CAP {
                    networks.clear();
                }
            }
            networks.insert(asn, State::Pending);
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let kind = this.look_up(asn).await;
            let ttl = if kind.is_some() { TYPE_TTL } else { RETRY };
            this.networks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(asn, State::Known(kind, Instant::now() + ttl));
        });
        None
    }

    /// `Some(residential)` for a network PeeringDB answered about (`false`
    /// when it has no record), `None` when the lookup failed.
    async fn look_up(&self, asn: u32) -> Option<bool> {
        let _permit = self.permits.acquire().await.ok()?;
        let url = format!("{}/api/net?asn={asn}", self.base_url);
        let response = match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                debug!(asn, status = %r.status(), "PeeringDB lookup refused");
                return None;
            }
            Err(e) => {
                debug!(asn, error = %e, "PeeringDB lookup failed");
                return None;
            }
        };
        let body: serde_json::Value = response.json().await.ok()?;
        Some(is_residential_record(&body))
    }
}

/// Whether a PeeringDB `/api/net` answer describes a consumer access
/// provider: its `info_types` (or the older single `info_type`) include
/// `Cable/DSL/ISP`.
fn is_residential_record(body: &serde_json::Value) -> bool {
    body["data"].as_array().into_iter().flatten().any(|net| {
        let types = net["info_types"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str())
            .chain(net["info_type"].as_str());
        types.into_iter().any(|t| RESIDENTIAL_TYPES.contains(&t))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cymru_names_reverse_the_address() {
        assert_eq!(
            cymru_name(
                "8.8.4.1".parse().unwrap(),
                DEFAULT_ASN_ZONE_V4,
                DEFAULT_ASN_ZONE_V6
            ),
            "1.4.8.8.origin.asn.cymru.com"
        );
        let v6 = cymru_name("2001:db8::1".parse().unwrap(), "v4.test", "v6.test");
        assert!(v6.starts_with("1.0.0.0.0.0.0.0."), "{v6}");
        assert!(v6.ends_with("8.b.d.0.1.0.0.2.v6.test"), "{v6}");
        assert_eq!(v6.split('.').count(), 32 + 2);
    }

    #[test]
    fn cymru_answers_give_asns() {
        assert_eq!(
            parse_cymru_txt("15169 | 8.8.8.0/24 | US | arin | 1992-12-01"),
            vec![15169]
        );
        assert_eq!(
            parse_cymru_txt("23028 3356 | 216.90.108.0/24 | US"),
            vec![23028, 3356]
        );
        assert!(parse_cymru_txt("garbage").is_empty());
    }

    #[test]
    fn peeringdb_types() {
        assert!(is_residential_record(&json!({"data": [
            {"asn": 7922, "info_type": "Cable/DSL/ISP"}
        ]})));
        assert!(is_residential_record(&json!({"data": [
            {"asn": 3320, "info_types": ["NSP", "Cable/DSL/ISP"]}
        ]})));
        assert!(!is_residential_record(&json!({"data": [
            {"asn": 16509, "info_type": "Content", "info_types": ["Content"]}
        ]})));
        assert!(!is_residential_record(&json!({"data": []})));
    }

    #[test]
    fn embedded_cdns() {
        assert!(is_embedded_cdn("rr3---sn-abc.googlevideo.com"));
        assert!(is_embedded_cdn("ipv4-c001-xyz.1.oca.nflxvideo.net"));
        assert!(!is_embedded_cdn("notgooglevideo.com"));
        assert!(!is_embedded_cdn("example.com"));
    }
}
