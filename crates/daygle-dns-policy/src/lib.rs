//! # daygle-policy
//!
//! Plugin-style policy engine for Daygle DNS.
//!
//! The engine combines, in evaluation order:
//!
//! 1. **ACLs** - allow/deny client networks (`ipnet::IpNet`).
//! 2. **Blocklists** - exact and wildcard domain matches.
//! 3. **Per-client rules** - ordered rules that match a client network and an
//!    optional domain set, producing [`Action::Allow`], [`Action::Block`] or
//!    [`Action::Redirect`].
//! 4. **Plugins** - user-defined [`PolicyPlugin`]s evaluated last; the first
//!    plugin returning `Some(action)` wins.
//!
//! A [`Decision`] carries the action plus a human-readable reason, which the
//! dispatcher records in the logs.

mod acl;
mod advanced;
mod blocklist;
mod blocklist_source;
mod engine;
mod plugin;
mod rule;

pub use acl::Acl;
pub use advanced::{validate_regex, AdvancedBlocking};
pub use blocklist::Blocklist;
pub use blocklist_source::{parse_blocklist, BlocklistSourceManager, SourceStatus};
pub use engine::{Decision, PolicyEngine};
pub use plugin::{PolicyContext, PolicyPlugin, PluginRegistry};
pub use rule::PerClientRule;

use std::net::IpAddr;

use daygle_dns_core::config::{normalize_domains, PolicySettings};
use daygle_dns_core::error::{DaygleError, Result};

/// Outcome of policy evaluation for a single query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Let the query proceed normally.
    Allow,
    /// Refuse the query (map to REFUSED).
    Refused,
    /// Answer NXDOMAIN (used for blocklists).
    Block,
    /// Synthesize a redirect answer with the given address.
    Redirect(IpAddr),
    /// Answer with an empty NODATA response (NOERROR, no records). Used by the
    /// AAAA filter to force dual-stack clients onto IPv4.
    NoData,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Refused => "refused",
            Action::Block => "block",
            Action::Redirect(_) => "redirect",
            Action::NoData => "nodata",
        }
    }
}

impl std::str::FromStr for Action {
    type Err = DaygleError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(Action::Allow),
            "refused" | "refuse" | "deny" => Ok(Action::Refused),
            "block" | "nxdomain" => Ok(Action::Block),
            other => Err(DaygleError::InvalidPolicy(format!(
                "unknown action '{other}'"
            ))),
        }
    }
}

/// Build a [`PolicyEngine`] from [`PolicySettings`], loading blocklist files.
pub fn build_engine(settings: &PolicySettings) -> Result<PolicyEngine> {
    let mut engine = PolicyEngine::new(settings.enabled);

    // Blocklists: inline entries first, then files.
    let mut domains = normalize_domains(settings.blocklist.iter().cloned());
    for file in &settings.blocklist_files {
        let text = std::fs::read_to_string(file).map_err(|e| {
            DaygleError::Config(format!("cannot read blocklist {file}: {e}"))
        })?;
        domains.extend(normalize_domains(text.lines().map(|l| l.to_string())));
    }
    if !domains.is_empty() {
        engine.set_blocklist(Blocklist::from_set(domains));
    }

    // ACLs.
    let mut denied = Vec::new();
    let mut allowed = Vec::new();
    for net in &settings.denied_networks {
        denied.push(net.parse().map_err(|_| {
            DaygleError::InvalidPolicy(format!("bad denied network '{net}'"))
        })?);
    }
    for net in &settings.allowed_networks {
        allowed.push(net.parse().map_err(|_| {
            DaygleError::InvalidPolicy(format!("bad allowed network '{net}'"))
        })?);
    }
    engine.set_acl(Acl::new(denied, allowed));

    // Ordered per-client rules.
    for rule in &settings.rules {
        engine.add_rule(PerClientRule::from_config(rule)?);
    }

    // Filter AAAA (Technitium-style "Block AAAA"): answer AAAA with NODATA so
    // dual-stack clients fall back to IPv4. Names on the bypass list keep IPv6.
    if settings.filter_aaaa {
        let bypass = normalize_domains(settings.filter_aaaa_except.iter().cloned());
        let bypass = (!bypass.is_empty()).then(|| Blocklist::from_set(bypass));
        engine.set_filter_aaaa(true, bypass);
    }

    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actions() {
        assert_eq!("allow".parse::<Action>().unwrap(), Action::Allow);
        assert_eq!("BLOCK".parse::<Action>().unwrap(), Action::Block);
        assert_eq!("deny".parse::<Action>().unwrap(), Action::Refused);
        assert!("bogus".parse::<Action>().is_err());
    }
}
