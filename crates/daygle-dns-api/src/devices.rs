//! Device names: what the console (and the scheduled report) calls a
//! client instead of its IP address. In order: a name given by hand (for
//! the device's MAC address when DHCP knows it, else for the address), the
//! host name from its DHCP lease, then its reverse DNS (PTR) name.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use daygle_dns_core::dhcp::normalize_mac;
use hickory_proto::rr::{RData, RecordType};
use parking_lot::Mutex;
use serde::Serialize;

use crate::AppState;

/// How long a reverse DNS answer (or its absence) is kept.
const PTR_FOUND: Duration = Duration::from_secs(3600);
const PTR_MISSING: Duration = Duration::from_secs(900);
/// Reverse lookups started per request; the rest follow on later ones.
const PTR_PER_CALL: usize = 64;
const PTR_TIMEOUT: Duration = Duration::from_secs(2);
/// Clients looked at from the query log.
const RECENT_CLIENTS: usize = 1000;
/// The longest name accepted.
pub const MAX_NAME: usize = 63;

/// Remembered reverse DNS names.
#[derive(Default)]
pub struct DeviceNames {
    ptr: Mutex<HashMap<IpAddr, (Option<String>, Instant)>>,
}

/// A device and what it is called.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Device {
    pub address: String,
    /// From its DHCP lease (IPv4); empty when unknown.
    pub mac: String,
    /// The name shown; empty when there is none.
    pub name: String,
    /// Where `name` came from: `manual`, `dhcp` or `reverse_dns`.
    pub source: String,
    /// The name given by hand, if any.
    pub manual_name: String,
    pub queries: u64,
    pub blocked: u64,
    /// RFC 3339; empty when it has not asked anything in the period.
    pub last_seen: String,
}

/// Where a manual name for `address` (with `mac`, when known) is kept.
pub fn name_key(address: &str, mac: &str) -> String {
    normalize_mac(mac).unwrap_or_else(|| address.to_string())
}

/// Every device seen in the last `period` or holding a DHCP lease, or
/// named by hand, with its name. Busiest first.
pub async fn devices(state: &AppState, period: Duration) -> Result<Vec<Device>, String> {
    let store = state.catalog.store();
    let since =
        chrono::Utc::now() - chrono::Duration::from_std(period).map_err(|e| e.to_string())?;
    let recent = store
        .recent_clients(&since.to_rfc3339(), RECENT_CLIENTS)
        .map_err(|e| e.to_string())?;
    let manual: HashMap<String, String> = store
        .list_device_names()
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    // Bound leases: address -> (MAC, host name).
    let leases: HashMap<IpAddr, (String, String)> = state
        .dhcp
        .as_ref()
        .map(|d| d.leases())
        .unwrap_or_default()
        .into_iter()
        .filter(|l| l.state == daygle_dns_dhcp::leases::BOUND)
        .map(|l| {
            let mac = if l.address.is_ipv4() {
                l.hw_address
            } else {
                String::new()
            };
            (l.address, (mac, l.hostname))
        })
        .collect();

    let mut devices: Vec<Device> = recent
        .into_iter()
        .map(|c| Device {
            address: c.client,
            mac: String::new(),
            name: String::new(),
            source: String::new(),
            manual_name: String::new(),
            queries: c.queries,
            blocked: c.blocked,
            last_seen: c.last_seen,
        })
        .collect();
    let mut seen: BTreeSet<String> = devices.iter().map(|d| d.address.clone()).collect();
    let extra: Vec<String> = leases
        .keys()
        .map(IpAddr::to_string)
        .chain(
            manual
                .keys()
                .filter(|k| k.parse::<IpAddr>().is_ok())
                .cloned(),
        )
        .collect();
    for address in extra {
        if seen.insert(address.clone()) {
            devices.push(Device {
                address,
                mac: String::new(),
                name: String::new(),
                source: String::new(),
                manual_name: String::new(),
                queries: 0,
                blocked: 0,
                last_seen: String::new(),
            });
        }
    }

    let mut unnamed: Vec<IpAddr> = Vec::new();
    for d in &mut devices {
        let ip = d.address.parse::<IpAddr>().ok();
        let lease = ip.and_then(|ip| leases.get(&ip));
        if let Some((mac, _)) = lease {
            d.mac = mac.clone();
        }
        let by_hand = manual
            .get(&name_key(&d.address, &d.mac))
            .or_else(|| manual.get(&d.address));
        if let Some(name) = by_hand {
            d.manual_name = name.clone();
            d.name = name.clone();
            d.source = "manual".to_string();
        } else if let Some((_, host)) = lease.filter(|(_, h)| !h.is_empty()) {
            d.name = host.clone();
            d.source = "dhcp".to_string();
        } else if let Some(ip) = ip {
            unnamed.push(ip);
        }
    }
    let ptr = state.devices.reverse_names(state, &unnamed).await;
    for d in &mut devices {
        if d.name.is_empty() {
            if let Some(name) = d.address.parse().ok().and_then(|ip: IpAddr| ptr.get(&ip)) {
                d.name = name.clone();
                d.source = "reverse_dns".to_string();
            }
        }
    }
    Ok(devices)
}

/// Client address -> name, for labelling (only the named ones).
pub async fn labels(state: &AppState, period: Duration) -> HashMap<String, String> {
    devices(state, period)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|d| !d.name.is_empty())
        .map(|d| (d.address, d.name))
        .collect()
}

impl DeviceNames {
    /// The reverse DNS names of `ips` that have one: remembered answers,
    /// the hosted reverse zones, then the resolver.
    async fn reverse_names(&self, state: &AppState, ips: &[IpAddr]) -> HashMap<IpAddr, String> {
        let now = Instant::now();
        let mut out = HashMap::new();
        let mut wanted = Vec::new();
        {
            let cache = self.ptr.lock();
            for ip in ips {
                match cache.get(ip) {
                    Some((name, at)) if now < *at => {
                        if let Some(name) = name {
                            out.insert(*ip, name.clone());
                        }
                    }
                    _ => wanted.push(*ip),
                }
            }
        }
        let resolver = state.resolver.load_full();
        let mut lookups = tokio::task::JoinSet::new();
        for ip in wanted.into_iter().take(PTR_PER_CALL) {
            let reverse = daygle_dns_dhcp::ddns::reverse_name(ip);
            let local = state
                .catalog
                .local_records(&reverse, RecordType::PTR)
                .ok()
                .and_then(|records| records.into_iter().find_map(|r| ptr_name(&r.data)));
            if let Some(name) = local {
                self.remember(ip, Some(name.clone()));
                out.insert(ip, name);
                continue;
            }
            let Some(resolver) = resolver.clone() else {
                continue;
            };
            lookups.spawn(async move {
                let name = tokio::time::timeout(
                    PTR_TIMEOUT,
                    resolver.lookup(&format!("{reverse}."), RecordType::PTR),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|lookup| lookup.answers().iter().find_map(|r| ptr_name(&r.data)));
                (ip, name)
            });
        }
        while let Some(Ok((ip, name))) = lookups.join_next().await {
            self.remember(ip, name.clone());
            if let Some(name) = name {
                out.insert(ip, name);
            }
        }
        out
    }

    fn remember(&self, ip: IpAddr, name: Option<String>) {
        let keep = if name.is_some() {
            PTR_FOUND
        } else {
            PTR_MISSING
        };
        let mut cache = self.ptr.lock();
        // Bounded: a long-running server sees many addresses come and go.
        if cache.len() > 10_000 {
            let now = Instant::now();
            cache.retain(|_, (_, at)| *at > now);
        }
        cache.insert(ip, (name, Instant::now() + keep));
    }
}

fn ptr_name(data: &RData) -> Option<String> {
    match data {
        RData::PTR(ptr) => {
            let name = ptr.0.to_ascii();
            let name = name.trim_end_matches('.');
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_mac_when_known() {
        assert_eq!(
            name_key("192.168.1.5", "AA-BB-CC-DD-EE-FF"),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(name_key("192.168.1.5", ""), "192.168.1.5");
        assert_eq!(name_key("fd00::5", "0001000100"), "fd00::5");
    }
}
