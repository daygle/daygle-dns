//! Client network access control.

use std::net::IpAddr;

use ipnet::IpNet;

/// Access control list for client IP networks.
///
/// Semantics:
/// - A client matching any network in `denied` is refused.
/// - When `allowed` is non-empty, a client not matching any allowed network is
///   refused (default-deny).
/// - Deny always wins over allow.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    denied: Vec<IpNet>,
    allowed: Vec<IpNet>,
}

impl Acl {
    pub fn new(denied: Vec<IpNet>, allowed: Vec<IpNet>) -> Self {
        Self { denied, allowed }
    }

    pub fn deny(mut self, network: IpNet) -> Self {
        self.denied.push(network);
        self
    }

    pub fn allow(mut self, network: IpNet) -> Self {
        self.allowed.push(network);
        self
    }

    /// Returns `false` when the client should be refused.
    pub fn is_allowed(&self, client: IpAddr) -> bool {
        for net in &self.denied {
            if net.contains(&client) {
                return false;
            }
        }
        if self.allowed.is_empty() {
            return true;
        }
        self.allowed.iter().any(|net| net.contains(&client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn default_allows_everything() {
        let acl = Acl::default();
        assert!(acl.is_allowed(ip("8.8.8.8")));
    }

    #[test]
    fn deny_wins() {
        let acl = Acl::new(vec![net("192.168.0.0/16")], vec![net("192.168.1.0/24")]);
        assert!(!acl.is_allowed(ip("192.168.1.5")));
    }

    #[test]
    fn allowlist_default_denies() {
        let acl = Acl::new(vec![], vec![net("10.0.0.0/8")]);
        assert!(acl.is_allowed(ip("10.1.2.3")));
        assert!(!acl.is_allowed(ip("192.168.1.1")));
    }

    #[test]
    fn ipv6_support() {
        let acl = Acl::new(vec![net("fd00::/8")], vec![]);
        assert!(!acl.is_allowed(ip("fd12::1")));
        assert!(acl.is_allowed(ip("2001:db8::1")));
    }
}
