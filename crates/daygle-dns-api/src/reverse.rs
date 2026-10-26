//! Reverse (PTR) records kept in step with A and AAAA records: the record
//! routes' `update_ptr` option adds the PTR for a record's address, moves it
//! when the address or name changes and removes it with the record, and
//! `create_reverse_zone` creates the reverse zone when none is hosted.

use std::net::IpAddr;

use daygle_dns_authoritative::model::{Record, RecordInput, Zone, ZoneInput};
use daygle_dns_authoritative::store::ZoneStore;
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Query options of the record routes.
#[derive(Debug, Default, Deserialize)]
pub struct ReverseOptions {
    /// Keep the PTR record of an A or AAAA record in step.
    #[serde(default)]
    pub update_ptr: bool,
    /// With `update_ptr`: create the reverse zone (a /24 for IPv4, a /64 for
    /// IPv6) when no hosted zone covers the address.
    #[serde(default)]
    pub create_reverse_zone: bool,
}

/// What happened to the reverse records, for the console to report.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ReverseOutcome {
    /// PTR records added (owner names).
    pub added: Vec<String>,
    /// PTR records removed (owner names).
    pub removed: Vec<String>,
    /// A reverse zone created for the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_created: Option<String>,
    /// Why the PTR record could not be added, when it was not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl ReverseOutcome {
    /// Whether any reverse record changed (the catalog needs reloading).
    pub fn changed(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || self.zone_created.is_some()
    }
}

/// The address of an A or AAAA record.
fn address_of(record: &Record) -> Option<IpAddr> {
    matches!(record.rtype.as_str(), "A" | "AAAA")
        .then(|| record.content.trim().parse().ok())
        .flatten()
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim().trim_end_matches('.'))
}

/// The most specific hosted zone that holds `owner`.
fn reverse_zone(store: &ZoneStore, owner: &str) -> Result<Option<Zone>, String> {
    let zones = store.list_zones().map_err(|e| e.to_string())?;
    Ok(zones
        .into_iter()
        .filter(|z| {
            let name = z.name.to_ascii_lowercase();
            owner == name || owner.ends_with(&format!(".{name}"))
        })
        .max_by_key(|z| z.name.len()))
}

/// The reverse zone to create for `ip`: its /24 (IPv4) or /64 (IPv6).
pub fn default_reverse_zone(ip: IpAddr) -> String {
    let owner = daygle_dns_dhcp::ddns::reverse_name(ip);
    // Drop the host part: one octet label, or 16 nibble labels.
    let skip = if ip.is_ipv4() { 1 } else { 16 };
    owner
        .splitn(skip + 1, '.')
        .nth(skip)
        .unwrap_or(&owner)
        .to_string()
}

fn is_secondary(store: &ZoneStore, zone_id: &str) -> bool {
    store
        .list_secondary()
        .is_ok_and(|items| items.iter().any(|item| item.zone_id == zone_id))
}

/// Remove the PTR records for `ip` that point at `name`.
fn remove(
    store: &ZoneStore,
    ip: IpAddr,
    name: &str,
    outcome: &mut ReverseOutcome,
) -> Result<(), String> {
    let owner = daygle_dns_dhcp::ddns::reverse_name(ip);
    let Some(zone) = reverse_zone(store, &owner)? else {
        return Ok(());
    };
    if is_secondary(store, &zone.id) {
        return Ok(());
    }
    for record in store.list_records(&zone.id).map_err(|e| e.to_string())? {
        if record.rtype == "PTR"
            && same_name(&record.name, &owner)
            && same_name(&record.content, name)
            && store.delete_record(&record.id).map_err(|e| e.to_string())?
        {
            outcome.removed.push(owner.clone());
        }
    }
    Ok(())
}

/// Add the PTR record for `ip` pointing at `name` (`ttl`), creating the
/// reverse zone first when asked to.
fn add(
    state: &AppState,
    ip: IpAddr,
    name: &str,
    ttl: u32,
    create_zone: bool,
    outcome: &mut ReverseOutcome,
) -> Result<(), String> {
    let store = state.catalog.store();
    let owner = daygle_dns_dhcp::ddns::reverse_name(ip);
    let zone = match reverse_zone(store, &owner)? {
        Some(zone) => zone,
        None if create_zone => {
            let defaults = crate::handlers::zone_defaults(state);
            let zone = store
                .create_zone(&ZoneInput {
                    name: default_reverse_zone(ip),
                    primary_ns: defaults.primary_ns,
                    admin_mailbox: defaults.admin_mailbox,
                    ..Default::default()
                })
                .map_err(|e| e.to_string())?;
            outcome.zone_created = Some(zone.name.clone());
            zone
        }
        None => {
            outcome.problem = Some(format!(
                "no hosted reverse zone covers {ip}, so no PTR record was added"
            ));
            return Ok(());
        }
    };
    if is_secondary(store, &zone.id) {
        outcome.problem = Some(format!(
            "the reverse zone {} is a secondary zone, so the PTR record was not added",
            zone.name
        ));
        return Ok(());
    }
    let existing: Vec<Record> = store
        .list_records(&zone.id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|r| r.rtype == "PTR" && same_name(&r.name, &owner))
        .collect();
    if existing.iter().any(|r| same_name(&r.content, name)) {
        return Ok(());
    }
    if let Some(other) = existing.first() {
        outcome.problem = Some(format!(
            "{ip} already has a PTR record for {}, which was left as it is",
            other.content.trim_end_matches('.')
        ));
        return Ok(());
    }
    store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: format!("{owner}."),
                rtype: "PTR".to_string(),
                content: format!("{}.", name.trim_end_matches('.')),
                ttl,
                priority: 0,
                disabled: false,
            },
        )
        .map_err(|e| e.to_string())?;
    outcome.added.push(owner);
    Ok(())
}

/// Bring the reverse records in line after an A or AAAA record changed from
/// `before` (none for a new record) to `after` (none when deleted).
pub fn sync(
    state: &AppState,
    before: Option<&Record>,
    after: Option<&Record>,
    options: &ReverseOptions,
) -> Result<ReverseOutcome, String> {
    let mut outcome = ReverseOutcome::default();
    if !options.update_ptr {
        return Ok(outcome);
    }
    let old = before.and_then(|r| address_of(r).map(|ip| (ip, r)));
    let new = after.and_then(|r| address_of(r).map(|ip| (ip, r)));
    let store = state.catalog.store();
    if let Some((ip, record)) = old {
        let unchanged = new.is_some_and(|(new_ip, new_record)| {
            new_ip == ip && same_name(&new_record.name, &record.name)
        });
        if !unchanged {
            remove(store, ip, &record.name, &mut outcome)?;
        }
    }
    if let Some((ip, record)) = new {
        // A disabled record is not served, so neither is its PTR.
        if !record.disabled {
            add(
                state,
                ip,
                &record.name,
                record.ttl,
                options.create_reverse_zone,
                &mut outcome,
            )?;
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_zones_cover_a_24_or_a_64() {
        assert_eq!(
            default_reverse_zone("192.168.20.5".parse().unwrap()),
            "20.168.192.in-addr.arpa"
        );
        assert_eq!(
            default_reverse_zone("2001:db8:1:2::5".parse().unwrap()),
            "2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert!(same_name("Host.Example.com.", "host.example.com"));
    }
}
