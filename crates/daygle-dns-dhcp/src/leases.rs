//! The lease table: every address handed out (or offered, declined), kept
//! in memory and written through to the store. Changes are recorded so the
//! service can persist them and keep DNS registrations in step.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use daygle_dns_core::dhcp::DhcpLease;

pub const OFFERED: &str = "offered";
pub const BOUND: &str = "bound";
pub const DECLINED: &str = "declined";
pub const RELEASED: &str = "released";

/// How long an offer holds its address.
pub const OFFER_SECS: i64 = 120;
/// How long a declined (in use by someone else) address is skipped.
pub const DECLINE_SECS: i64 = 3600;

/// The leases, by address.
#[derive(Debug, Default)]
pub struct Leases {
    by_address: BTreeMap<IpAddr, DhcpLease>,
    /// Addresses changed since the last [`Leases::take_changes`].
    changed: BTreeSet<IpAddr>,
}

impl Leases {
    pub fn new(leases: Vec<DhcpLease>) -> Self {
        Self {
            by_address: leases.into_iter().map(|l| (l.address, l)).collect(),
            changed: BTreeSet::new(),
        }
    }

    pub fn get(&self, address: &IpAddr) -> Option<&DhcpLease> {
        self.by_address.get(address)
    }

    pub fn all(&self) -> impl Iterator<Item = &DhcpLease> {
        self.by_address.values()
    }

    /// The live lease or offer `client_id` holds in `scope`.
    pub fn of_client(&self, scope: &str, client_id: &str, now: i64) -> Option<&DhcpLease> {
        self.by_address.values().find(|l| {
            l.scope == scope
                && l.client_id == client_id
                && matches!(l.state.as_str(), OFFERED | BOUND)
                && l.expires > now
        })
    }

    /// Whether `address` is free for `client_id`: nobody else holds it.
    pub fn free_for(&self, address: &IpAddr, client_id: &str, now: i64) -> bool {
        match self.by_address.get(address) {
            None => true,
            Some(l) if l.client_id == client_id && l.state != DECLINED => true,
            Some(l) => l.expires <= now || l.state == RELEASED,
        }
    }

    /// Insert or replace a lease.
    pub fn put(&mut self, lease: DhcpLease) {
        self.changed.insert(lease.address);
        self.by_address.insert(lease.address, lease);
    }

    /// Update the lease on `address` in place.
    pub fn update(&mut self, address: &IpAddr, change: impl FnOnce(&mut DhcpLease)) {
        if let Some(lease) = self.by_address.get_mut(address) {
            change(lease);
            self.changed.insert(*address);
        }
    }

    /// Forget the lease on `address`.
    pub fn remove(&mut self, address: &IpAddr) -> Option<DhcpLease> {
        let removed = self.by_address.remove(address);
        if removed.is_some() {
            self.changed.insert(*address);
        }
        removed
    }

    /// Replace a lease without recording a change (for bookkeeping the
    /// service has already written out).
    pub fn restore(&mut self, lease: DhcpLease) {
        self.by_address.insert(lease.address, lease);
    }

    /// Record every lease as changed, so all are looked at again.
    pub fn touch_all(&mut self) {
        self.changed.extend(self.by_address.keys().copied());
    }

    /// Whether anything changed since the last [`Leases::take_changes`].
    pub fn has_changes(&self) -> bool {
        !self.changed.is_empty()
    }

    /// Drop a pending change already written out.
    pub fn forget_change(&mut self, address: &IpAddr) {
        self.changed.remove(address);
    }

    /// The addresses changed since the last call.
    pub fn take_changes(&mut self) -> Vec<IpAddr> {
        std::mem::take(&mut self.changed).into_iter().collect()
    }

    /// Mark leases past their expiry: bound ones become released (so their
    /// DNS names are removed), offers and declines are forgotten.
    pub fn expire(&mut self, now: i64) {
        let expired: Vec<IpAddr> = self
            .by_address
            .values()
            .filter(|l| l.expires <= now && l.state != RELEASED)
            .map(|l| l.address)
            .collect();
        for address in expired {
            let bound = self
                .by_address
                .get(&address)
                .is_some_and(|l| l.state == BOUND);
            if bound {
                self.update(&address, |l| l.state = RELEASED.to_string());
            } else {
                self.remove(&address);
            }
        }
        // Released leases are kept a day for the record, then dropped.
        let stale: Vec<IpAddr> = self
            .by_address
            .values()
            .filter(|l| l.state == RELEASED && l.expires + 86_400 <= now)
            .map(|l| l.address)
            .collect();
        for address in stale {
            self.remove(&address);
        }
    }
}

/// A fresh lease record.
pub fn lease(
    address: IpAddr,
    scope: &str,
    client_id: &str,
    hw_address: &str,
    hostname: &str,
    state: &str,
    expires: i64,
) -> DhcpLease {
    DhcpLease {
        address,
        scope: scope.to_string(),
        client_id: client_id.to_string(),
        hw_address: hw_address.to_string(),
        hostname: hostname.to_string(),
        state: state.to_string(),
        expires,
        dns_name: String::new(),
        dns_records: Vec::new(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// A host name made safe for DNS: one lowercase label of letters, digits
/// and hyphens; empty when nothing usable is left.
pub fn clean_hostname(name: &str) -> String {
    let label = name.trim().split('.').next().unwrap_or_default();
    let cleaned: String = label
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    cleaned
        .chars()
        .take(63)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string()
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn leases_are_freed_and_expired() {
        let mut leases = Leases::default();
        leases.put(lease(ip("10.0.0.5"), "lan", "a", "", "", BOUND, 100));
        leases.put(lease(ip("10.0.0.6"), "lan", "b", "", "", OFFERED, 100));
        assert!(leases.free_for(&ip("10.0.0.5"), "a", 50));
        assert!(!leases.free_for(&ip("10.0.0.5"), "b", 50));
        assert!(leases.free_for(&ip("10.0.0.5"), "b", 150));
        assert_eq!(
            leases.of_client("lan", "a", 50).map(|l| l.address),
            Some(ip("10.0.0.5"))
        );
        leases.take_changes();
        leases.expire(150);
        assert_eq!(leases.get(&ip("10.0.0.5")).unwrap().state, RELEASED);
        assert!(leases.get(&ip("10.0.0.6")).is_none());
        assert_eq!(leases.take_changes().len(), 2);
        leases.expire(150 + 86_400);
        assert!(leases.get(&ip("10.0.0.5")).is_none());
    }

    #[test]
    fn host_names_are_cleaned() {
        assert_eq!(clean_hostname("Kids-iPad"), "kids-ipad");
        assert_eq!(clean_hostname("Sam's Phone.local"), "sam-s-phone");
        assert_eq!(clean_hostname("--"), "");
        assert_eq!(clean_hostname(&"a".repeat(80)).len(), 63);
    }
}
