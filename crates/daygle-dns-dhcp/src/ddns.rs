//! DNS names for leases: a bound lease with a host name gets an A or AAAA
//! record in the chosen hosted zone, and a PTR record in the hosted
//! reverse zone covering its address. The records are ordinary zone
//! records; the lease keeps their ids so they can be removed again.

use std::collections::HashSet;
use std::net::IpAddr;

use daygle_dns_authoritative::model::RecordInput;
use daygle_dns_authoritative::store::ZoneStore;
use daygle_dns_core::dhcp::DhcpLease;

/// The TTL of lease records: short, as addresses move.
const TTL: u32 = 300;

/// The reverse-lookup name of `ip`, without a trailing dot.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut labels: Vec<String> = v6
                .octets()
                .iter()
                .flat_map(|b| [b >> 4, b & 0xf])
                .map(|n| format!("{n:x}"))
                .collect();
            labels.reverse();
            format!("{}.ip6.arpa", labels.join("."))
        }
    }
}

/// The fully qualified name `lease` should have in `zone`, if any.
pub fn wanted_name(lease: &DhcpLease, zone: &str) -> Option<String> {
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    (!lease.hostname.is_empty() && !zone.is_empty() && lease.state == crate::leases::BOUND)
        .then(|| format!("{}.{zone}", lease.hostname))
}

/// Remove the records registered for `lease`.
pub fn unregister(store: &ZoneStore, lease: &mut DhcpLease) -> bool {
    let changed = !lease.dns_records.is_empty() || !lease.dns_name.is_empty();
    for id in lease.dns_records.drain(..) {
        let _ = store.delete_record(&id);
    }
    lease.dns_name.clear();
    changed
}

/// Whether the records of `lease` are still in place.
pub fn registered(store: &ZoneStore, lease: &DhcpLease) -> bool {
    !lease.dns_records.is_empty()
        && lease
            .dns_records
            .iter()
            .all(|id| store.get_record(id).ok().flatten().is_some())
}

/// Register `lease` as `name` in `zone`. `ours` holds the ids of every
/// record a lease registered: a name that has other records (added by
/// hand) is left alone, as is one another lease already holds.
pub fn register(
    store: &ZoneStore,
    zone: &str,
    name: &str,
    lease: &mut DhcpLease,
    ours: &HashSet<String>,
) -> Result<(), String> {
    let zone_name = zone.trim().trim_end_matches('.');
    let Some(zone) = store
        .find_zone_by_name(zone_name)
        .map_err(|e| e.to_string())?
    else {
        return Err(format!("the zone {zone_name} is not hosted here"));
    };
    let rtype = if lease.address.is_ipv4() { "A" } else { "AAAA" };
    let existing = store.list_records(&zone.id).map_err(|e| e.to_string())?;
    let at_name: Vec<_> = existing
        .iter()
        .filter(|r| r.name.eq_ignore_ascii_case(name))
        .collect();
    if at_name.iter().any(|r| !ours.contains(&r.id)) {
        return Err(format!("{name} already has records of its own"));
    }
    if at_name.iter().any(|r| r.rtype == rtype) {
        return Err(format!("{name} is already registered by another lease"));
    }
    let relative = name
        .strip_suffix(&format!(".{zone_name}"))
        .unwrap_or(name)
        .to_string();
    let record = store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: relative,
                rtype: rtype.to_string(),
                content: lease.address.to_string(),
                ttl: TTL,
                priority: 0,
                disabled: false,
            },
        )
        .map_err(|e| e.to_string())?;
    lease.dns_name = name.to_string();
    lease.dns_records = vec![record.id];

    // The PTR goes in the most specific hosted reverse zone, if there is one.
    let reverse = reverse_name(lease.address);
    let zones = store.list_zones().map_err(|e| e.to_string())?;
    let reverse_zone = zones
        .iter()
        .filter(|z| {
            let z = z.name.to_ascii_lowercase();
            reverse == z || reverse.ends_with(&format!(".{z}"))
        })
        .max_by_key(|z| z.name.len());
    if let Some(rz) = reverse_zone {
        let records = store.list_records(&rz.id).map_err(|e| e.to_string())?;
        let taken = records
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(&reverse) && r.rtype == "PTR");
        if !taken {
            if let Ok(ptr) = store.upsert_record(
                &rz.id,
                &RecordInput {
                    name: format!("{reverse}."),
                    rtype: "PTR".to_string(),
                    content: format!("{name}."),
                    ttl: TTL,
                    priority: 0,
                    disabled: false,
                },
            ) {
                lease.dns_records.push(ptr.id);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.168.1.20".parse().unwrap()),
            "20.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("fd00::1".parse().unwrap()),
            format!("1.{}d.f.ip6.arpa", "0.".repeat(29))
        );
    }
}
