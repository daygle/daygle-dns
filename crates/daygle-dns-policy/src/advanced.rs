//! Advanced Blocking: per-client-group allow/block policies.
//!
//! Each [`BlockingGroup`] targets a set of client networks and carries its own
//! allow list, block list, allow/block regex patterns and a response to return
//! when it blocks. Groups are evaluated in `position` order; within a matching
//! group the allow rules (domain list or regex) win over the block rules, so an
//! allowed name short-circuits and is never blocked by a later group.
//!
//! The compiled form here (parsed CIDRs and [`RegexSet`]s) is rebuilt whenever
//! the stored groups change; the hot path only does lookups.

use std::net::IpAddr;

use ipnet::IpNet;
use regex::RegexSet;
use tracing::warn;

use daygle_dns_core::blocking::{BlockResponse, BlockingGroup};
use daygle_dns_core::config::normalize_domains;

use crate::{Action, Blocklist, Decision};

/// A single blocking group compiled for evaluation.
struct CompiledGroup {
    name: String,
    /// Client networks this group applies to; empty means every client.
    clients: Vec<IpNet>,
    allow: Blocklist,
    block: Blocklist,
    allow_regex: RegexSet,
    block_regex: RegexSet,
    /// Response returned when this group blocks a query.
    action: Action,
}

impl CompiledGroup {
    fn matches_client(&self, client: IpAddr) -> bool {
        self.clients.is_empty() || self.clients.iter().any(|net| net.contains(&client))
    }

    fn allows(&self, qname: &str) -> bool {
        self.allow.contains(qname) || self.allow_regex.is_match(qname)
    }

    fn blocks(&self, qname: &str) -> bool {
        self.block.contains(qname) || self.block_regex.is_match(qname)
    }
}

/// The compiled set of Advanced Blocking groups.
#[derive(Default)]
pub struct AdvancedBlocking {
    groups: Vec<CompiledGroup>,
}

impl AdvancedBlocking {
    /// Compile the enabled groups. Invalid CIDRs and regex patterns are
    /// skipped with a warning rather than failing the whole build, so one bad
    /// entry can never disable blocking for every group.
    pub fn build(groups: &[BlockingGroup]) -> Self {
        let mut compiled = Vec::new();
        for g in groups {
            if !g.enabled {
                continue;
            }
            let clients = parse_networks(&g.clients, &g.name);
            compiled.push(CompiledGroup {
                clients,
                allow: Blocklist::from_set(normalize_domains(g.allow.iter().cloned())),
                block: Blocklist::from_set(normalize_domains(g.block.iter().cloned())),
                allow_regex: compile_regex(&g.allow_regex, &g.name),
                block_regex: compile_regex(&g.block_regex, &g.name),
                action: response_to_action(&g.response),
                name: g.name.clone(),
            });
        }
        Self { groups: compiled }
    }

    /// Whether any enabled group is configured.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of compiled (enabled) groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Evaluate `qname` (already normalized: lowercase, no trailing dot) for
    /// `client`. Returns `Some(Decision)` when a group blocks the query, or
    /// `None` when it is explicitly allowed or matched by no group.
    pub fn evaluate(&self, client: IpAddr, qname: &str) -> Option<Decision> {
        for group in &self.groups {
            if !group.matches_client(client) {
                continue;
            }
            // Whitelist wins: an allowed name is never blocked, and no later
            // group gets to block it either.
            if group.allows(qname) {
                return None;
            }
            if group.blocks(qname) {
                return Some(Decision::new(
                    format!("'{qname}' blocked by group '{}'", group.name),
                    group.action.clone(),
                ));
            }
        }
        None
    }
}

/// Parse CIDR strings, logging and skipping any that are invalid.
fn parse_networks(cidrs: &[String], group: &str) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|c| match c.trim().parse::<IpNet>() {
            Ok(net) => Some(net),
            Err(_) => {
                // A bare IP is a valid /32 or /128 network.
                match c.trim().parse::<IpAddr>() {
                    Ok(ip) => Some(ip.into()),
                    Err(_) => {
                        warn!(group, cidr = %c, "skipping invalid client network");
                        None
                    }
                }
            }
        })
        .collect()
}

/// Compile a list of regex patterns into a [`RegexSet`], dropping (with a
/// warning) any that do not compile.
fn compile_regex(patterns: &[String], group: &str) -> RegexSet {
    let valid: Vec<&String> = patterns
        .iter()
        .filter(|p| match regex::Regex::new(p) {
            Ok(_) => true,
            Err(e) => {
                warn!(group, pattern = %p, error = %e, "skipping invalid block/allow regex");
                false
            }
        })
        .collect();
    RegexSet::new(valid).unwrap_or_else(|_| RegexSet::empty())
}

/// Validate a single regex pattern, returning the compile error as a string.
/// Used by the API to reject a bad pattern up front instead of silently
/// dropping it at build time.
pub fn validate_regex(pattern: &str) -> std::result::Result<(), String> {
    regex::Regex::new(pattern).map(|_| ()).map_err(|e| e.to_string())
}

/// Map a stored [`BlockResponse`] to the engine [`Action`] the dispatcher
/// already knows how to serve.
fn response_to_action(response: &BlockResponse) -> Action {
    match response {
        BlockResponse::NxDomain => Action::Block,
        BlockResponse::Refused => Action::Refused,
        BlockResponse::NoData => Action::NoData,
        BlockResponse::Redirect(ip) => Action::Redirect(*ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> BlockingGroup {
        BlockingGroup {
            id: name.to_string(),
            name: name.to_string(),
            enabled: true,
            clients: vec![],
            allow: vec![],
            block: vec![],
            allow_regex: vec![],
            block_regex: vec![],
            response: BlockResponse::NxDomain,
            position: 0,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_listed_domain() {
        let mut g = group("ads");
        g.block = vec!["*.doubleclick.net".to_string(), "tracker.test".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "a.doubleclick.net")
                .map(|d| d.action),
            Some(Action::Block)
        );
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "tracker.test").map(|d| d.action),
            Some(Action::Block)
        );
        assert!(ab.evaluate(ip("1.2.3.4"), "example.org").is_none());
    }

    #[test]
    fn allow_overrides_block() {
        let mut g = group("ads");
        g.block = vec!["*.doubleclick.net".to_string()];
        g.allow = vec!["safe.doubleclick.net".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        assert!(ab.evaluate(ip("1.2.3.4"), "safe.doubleclick.net").is_none());
        assert!(ab.evaluate(ip("1.2.3.4"), "x.doubleclick.net").is_some());
    }

    #[test]
    fn regex_block_and_allow() {
        let mut g = group("re");
        g.block_regex = vec![r"^ad[0-9]+\.".to_string()];
        g.allow_regex = vec![r"^ad1\.good\.".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        assert!(ab.evaluate(ip("1.2.3.4"), "ad7.tracker.test").is_some());
        assert!(ab.evaluate(ip("1.2.3.4"), "ad1.good.test").is_none());
        assert!(ab.evaluate(ip("1.2.3.4"), "cdn.test").is_none());
    }

    #[test]
    fn group_scoped_to_client_network() {
        let mut g = group("kids");
        g.clients = vec!["192.168.1.0/24".to_string()];
        g.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        // In-network client is blocked...
        assert!(ab.evaluate(ip("192.168.1.50"), "games.test").is_some());
        // ...an outside client is not.
        assert!(ab.evaluate(ip("10.0.0.1"), "games.test").is_none());
    }

    #[test]
    fn response_type_maps_to_action() {
        let mut g = group("redir");
        g.block = vec!["blocked.test".to_string()];
        g.response = BlockResponse::Redirect(ip("0.0.0.0"));
        let ab = AdvancedBlocking::build(&[g]);
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "blocked.test").map(|d| d.action),
            Some(Action::Redirect(ip("0.0.0.0")))
        );
    }

    #[test]
    fn disabled_group_is_skipped() {
        let mut g = group("off");
        g.enabled = false;
        g.block = vec!["blocked.test".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        assert!(ab.is_empty());
        assert!(ab.evaluate(ip("1.2.3.4"), "blocked.test").is_none());
    }

    #[test]
    fn invalid_regex_is_skipped_not_fatal() {
        let mut g = group("re");
        g.block_regex = vec!["(unclosed".to_string(), r"^bad\.".to_string()];
        let ab = AdvancedBlocking::build(&[g]);
        // The valid pattern still blocks; the invalid one is dropped.
        assert!(ab.evaluate(ip("1.2.3.4"), "bad.test").is_some());
    }
}
