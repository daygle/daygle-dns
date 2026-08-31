//! Per-client / per-domain rules.

use std::net::IpAddr;

use daygle_dns_core::config::{normalize_domains, PolicyRule};
use daygle_dns_core::error::{DaygleError, Result};
use ipnet::IpNet;

use crate::{Action, Blocklist};

/// A rule that matches a client network and an optional set of domains and
/// produces an [`Action`].
#[derive(Debug, Clone)]
pub struct PerClientRule {
    clients: Vec<IpNet>,
    /// `None` matches every domain.
    domains: Option<Blocklist>,
    action: Action,
}

impl PerClientRule {
    pub fn new(
        clients: Vec<IpNet>,
        domains: Option<Vec<String>>,
        action: Action,
    ) -> Self {
        // An empty client list means "every client" (match-all), mirroring
        // `from_config` which defaults to 0.0.0.0/0.
        let clients = if clients.is_empty() {
            vec!["0.0.0.0/0".parse().expect("valid ipnet")]
        } else {
            clients
        };
        let domains = domains
            .map(|d| Blocklist::from_set(normalize_domains(d)))
            .filter(|b| !b.is_empty());
        Self {
            clients,
            domains,
            action,
        }
    }

    /// Build a rule from its configuration representation.
    pub fn from_config(rule: &PolicyRule) -> Result<Self> {
        let mut clients = Vec::new();
        for net in &rule.clients {
            clients.push(net.parse().map_err(|_| {
                DaygleError::InvalidPolicy(format!("bad client network '{net}'"))
            })?);
        }
        if clients.is_empty() {
            clients.push("0.0.0.0/0".parse().unwrap());
        }
        let action = if rule.action == "redirect" {
            Action::Redirect(rule.redirect.ok_or_else(|| {
                DaygleError::InvalidPolicy(
                    "redirect rule is missing `redirect` address".to_string(),
                )
            })?)
        } else {
            rule.action.parse::<Action>()?
        };
        Ok(Self::new(
            clients,
            if rule.domains.is_empty() {
                None
            } else {
                Some(rule.domains.clone())
            },
            action,
        ))
    }

    /// Whether this rule applies to the given client.
    pub fn matches_client(&self, client: IpAddr) -> bool {
        self.clients.iter().any(|net| net.contains(&client))
    }

    /// Whether this rule applies to the given (normalized) domain.
    pub fn matches_domain(&self, domain: &str) -> bool {
        match &self.domains {
            None => true,
            Some(list) => list.contains(domain),
        }
    }

    pub fn action(&self) -> &Action {
        &self.action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn matches_by_client_and_domain() {
        let rule = PerClientRule::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            Some(vec!["*.example.com".to_string()]),
            Action::Block,
        );
        assert!(rule.matches_client(ip("10.1.1.1")));
        assert!(!rule.matches_client(ip("192.168.1.1")));
        assert!(rule.matches_domain("a.example.com"));
        assert!(!rule.matches_domain("example.org"));
    }

    #[test]
    fn rule_without_domains_matches_all() {
        let rule = PerClientRule::new(vec![], None, Action::Allow);
        assert!(rule.matches_domain("anything.test"));
        assert!(rule.matches_client(ip("1.2.3.4")));
    }

    #[test]
    fn config_rule_with_redirect() {
        let rule = PolicyRule {
            clients: vec!["192.168.0.0/16".to_string()],
            domains: vec!["blocked.test".to_string()],
            action: "redirect".to_string(),
            redirect: Some(ip("0.0.0.0")),
        };
        let parsed = PerClientRule::from_config(&rule).unwrap();
        assert_eq!(*parsed.action(), Action::Redirect(ip("0.0.0.0")));
    }

    #[test]
    fn config_rule_redirect_missing_address_fails() {
        let rule = PolicyRule {
            clients: vec![],
            domains: vec![],
            action: "redirect".to_string(),
            redirect: None,
        };
        assert!(PerClientRule::from_config(&rule).is_err());
    }
}
