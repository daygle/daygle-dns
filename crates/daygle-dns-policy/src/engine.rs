//! The policy engine: combines ACLs, blocklists, per-client rules and plugins.

use std::net::IpAddr;

use crate::{Acl, Action, Blocklist, PerClientRule, PluginRegistry};

/// A policy decision with a human-readable reason.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    /// The named policy group (e.g. an Advanced Blocking group) that produced
    /// this decision, when the source has one. Kept separate from `reason` so
    /// callers can show it as its own element instead of parsing it out.
    pub group: Option<String>,
    /// What decided, as one of the [`source`] names (`blocklist`,
    /// `blocklist_source`, `group`, `ai`, ...); empty when nothing did.
    pub source: &'static str,
    /// The entry, list, service or category that matched, when there is one
    /// (`*.ads.example`, `OISD`, `TikTok`, `malware`).
    pub matched: Option<String>,
}

/// The names [`Decision::source`] (and the query log) use for what blocked
/// or allowed a query.
pub mod source {
    /// A denied client network (Settings -> Clients).
    pub const DENIED_NETWORK: &str = "denied_network";
    /// The server-wide allowlist.
    pub const ALLOWLIST: &str = "allowlist";
    /// The server-wide blocklist (Domain Lists).
    pub const BLOCKLIST: &str = "blocklist";
    /// A blocklist source that applies to everyone (or the DoT listener).
    pub const BLOCKLIST_SOURCE: &str = "blocklist_source";
    /// A per-client rule from the configuration.
    pub const CLIENT_RULE: &str = "client_rule";
    /// Filter AAAA.
    pub const AAAA_FILTER: &str = "aaaa_filter";
    /// The AI scanner (Enforce mode).
    pub const AI: &str = "ai";
    /// Another policy plugin.
    pub const PLUGIN: &str = "plugin";
    /// A filtering group's own allow or block entries and patterns.
    pub const GROUP: &str = "group";
    /// A blocked service (TikTok, YouTube, ...) of a filtering group.
    pub const SERVICE: &str = "service";
    /// A blocklist source selected by a filtering group.
    pub const GROUP_BLOCKLIST: &str = "group_blocklist";
    /// A response policy zone.
    pub const RPZ: &str = "rpz";
    /// CNAME inspection: the answer led to a blocked name.
    pub const CNAME: &str = "cname";
    /// The client may not use the encrypted listener it asked on.
    pub const LISTENER: &str = "listener";
    /// Safe Search or YouTube Restricted Mode (a rewrite, not a block).
    pub const SAFE_SEARCH: &str = "safe_search";
}

impl Decision {
    pub fn new(reason: impl Into<String>, action: Action) -> Self {
        Self {
            action,
            reason: reason.into(),
            group: None,
            source: "",
            matched: None,
        }
    }

    /// Attach the name of the group that produced this decision.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Say what decided (a [`source`] name) and what in it matched.
    pub fn with_source(mut self, source: &'static str, matched: Option<String>) -> Self {
        self.source = source;
        self.matched = matched;
        self
    }

    pub fn allow() -> Self {
        Self::new("no policy matched", Action::Allow)
    }
}

/// The policy engine. Cheap to clone: it shares all of its state through
/// `Arc`s, so the dispatcher can hold one clone per task.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    enabled: bool,
    acl: Option<std::sync::Arc<Acl>>,
    /// Domains explicitly trusted by the operator. This takes precedence over
    /// all domain blocklists and rules, but not over client ACLs.
    allowlist: Option<std::sync::Arc<Blocklist>>,
    blocklist: Option<std::sync::Arc<Blocklist>>,
    /// Domains pulled from remote blocklist sources. Kept separate from
    /// `blocklist` (config + files) so the source refresher can swap just the
    /// remote set without touching user-configured entries.
    remote_blocklist: Option<std::sync::Arc<Blocklist>>,
    /// Domains pulled from remote blocklist sources scoped to the DoT
    /// listener. Applied only to clients whose query arrived on the DoT
    /// listener (`evaluate_dot`), so the plain-DNS LAN path is untouched.
    dot_blocklist: Option<std::sync::Arc<Blocklist>>,
    rules: std::sync::Arc<Vec<PerClientRule>>,
    plugins: std::sync::Arc<PluginRegistry>,
    /// When set, AAAA queries are answered with an empty NODATA response
    /// (Technitium-style "Filter AAAA") so dual-stack clients fall back to
    /// IPv4. Names matching `filter_aaaa_bypass` are exempt.
    filter_aaaa: bool,
    /// Names (and `*.suffix` wildcards) exempt from the AAAA filter, e.g.
    /// hosts that must remain reachable over IPv6.
    filter_aaaa_bypass: Option<std::sync::Arc<Blocklist>>,
    /// `policy.youtube_restricted`.
    youtube_restricted: bool,
    /// `policy.safe_search`.
    safe_search: bool,
    /// `policy.cname_inspection`.
    cname_inspection: bool,
    /// The per-source entries behind `remote_blocklist` and `dot_blocklist`,
    /// to name the source a block came from. Installed once at startup.
    source_lists: Option<std::sync::Arc<crate::GroupBlocklists>>,
}

/// One check of [`PolicyEngine::explain`] and
/// [`crate::AdvancedBlocking::explain`]: one thing that can block or allow a
/// query, and what it does with this one.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Check {
    /// What was checked, as a [`source`] name.
    pub source: &'static str,
    /// `block` (it blocks the query), `allow` (it lets the query through
    /// whatever later checks say), `rewrite` (Safe Search), `none` (it does
    /// not match), or `off` (it does not apply now).
    pub result: &'static str,
    /// What it found, in words.
    pub detail: String,
    /// The entry, list, service or category that matched.
    pub matched: Option<String>,
    /// The filtering group, for group checks.
    pub group: Option<String>,
    /// The answer it gives (`block` is NXDOMAIN, `refused`, `redirect`,
    /// `nodata`) when it blocks.
    pub action: Option<&'static str>,
}

impl Check {
    pub(crate) fn new(
        source: &'static str,
        result: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            source,
            result,
            detail: detail.into(),
            matched: None,
            group: None,
            action: None,
        }
    }

    pub(crate) fn from_decision(decision: &Decision) -> Self {
        let result = match decision.action {
            Action::Allow => "allow",
            _ => "block",
        };
        Self {
            source: if decision.source.is_empty() {
                source::PLUGIN
            } else {
                decision.source
            },
            result,
            detail: decision.reason.clone(),
            matched: decision.matched.clone(),
            group: decision.group.clone(),
            action: (result == "block").then(|| decision.action.as_str()),
        }
    }
}

impl PolicyEngine {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }

    pub fn set_acl(&mut self, acl: Acl) {
        self.acl = Some(std::sync::Arc::new(acl));
    }

    pub fn set_allowlist(&mut self, allowlist: Blocklist) {
        self.allowlist = Some(std::sync::Arc::new(allowlist));
    }

    pub fn allowlist_len(&self) -> usize {
        self.allowlist.as_ref().map(|l| l.len()).unwrap_or(0)
    }

    /// Whether a domain matches an explicitly trusted entry.
    pub fn is_allowlisted(&self, domain: &str) -> bool {
        self.allowlist.as_ref().is_some_and(|l| l.contains(domain))
    }

    /// Replace the configured blocklist.
    pub fn set_blocklist(&mut self, blocklist: Blocklist) {
        self.blocklist = Some(std::sync::Arc::new(blocklist));
    }

    /// Replace the remote blocklist (from URL sources). The static blocklist
    /// from configuration is left untouched, so refreshing sources never
    /// discards user-configured entries.
    pub fn set_remote_blocklist(&mut self, blocklist: Blocklist) {
        self.remote_blocklist = Some(std::sync::Arc::new(blocklist));
    }

    /// The number of domains currently blocked by remote sources (0 when
    /// none are configured or fetched yet).
    pub fn remote_blocklist_len(&self) -> usize {
        self.remote_blocklist.as_ref().map(|l| l.len()).unwrap_or(0)
    }

    /// The current remote blocklist, for comparison on refresh.
    pub fn remote_blocklist_snapshot(&self) -> Option<std::sync::Arc<Blocklist>> {
        self.remote_blocklist.clone()
    }

    /// Enable or disable the AAAA filter. When enabled, AAAA queries return an
    /// empty NODATA answer unless the name matches `bypass`.
    /// Set `policy.cname_inspection`.
    pub fn set_cname_inspection(&mut self, enabled: bool) {
        self.cname_inspection = enabled;
    }

    /// Whether `policy.cname_inspection` is on.
    pub fn cname_inspection(&self) -> bool {
        self.cname_inspection
    }

    /// Set `policy.safe_search`.
    pub fn set_safe_search(&mut self, enabled: bool) {
        self.safe_search = enabled;
    }

    /// Whether `policy.safe_search` is on.
    pub fn safe_search(&self) -> bool {
        self.safe_search
    }

    /// Set `policy.youtube_restricted`.
    pub fn set_youtube_restricted(&mut self, enabled: bool) {
        self.youtube_restricted = enabled;
    }

    /// Whether `policy.youtube_restricted` is on.
    pub fn youtube_restricted(&self) -> bool {
        self.youtube_restricted
    }

    pub fn set_filter_aaaa(&mut self, enabled: bool, bypass: Option<Blocklist>) {
        self.filter_aaaa = enabled;
        self.filter_aaaa_bypass = bypass.map(std::sync::Arc::new);
    }

    /// Replace the DoT-scoped remote blocklist. Kept separate from the
    /// server-wide sets so the source refresher can swap it independently.
    pub fn set_dot_blocklist(&mut self, blocklist: Blocklist) {
        self.dot_blocklist = Some(std::sync::Arc::new(blocklist));
    }

    /// Share what `other` holds that is not built from the configuration:
    /// the source-owned sets (the remote and DoT-scoped blocklists) and the
    /// plugins. A rebuild from configuration keeps what the source
    /// refresher fetched, at the cost of a few `Arc` clones rather than a
    /// copy of every domain.
    pub fn adopt_source_lists(&mut self, other: &PolicyEngine) {
        self.remote_blocklist = other.remote_blocklist.clone();
        self.dot_blocklist = other.dot_blocklist.clone();
        // Plugins (the AI auto-blocker) are installed once at startup, not
        // built from the config: a rebuild that dropped them silently
        // switched AI enforcement off until the next restart.
        self.plugins = other.plugins.clone();
        self.source_lists = other.source_lists.clone();
    }

    /// Name the blocklist source behind a remote block from the per-source
    /// entries `lists` keeps (the refresher fills it).
    pub fn set_source_attribution(&mut self, lists: std::sync::Arc<crate::GroupBlocklists>) {
        self.source_lists = Some(lists);
    }

    /// The blocklist sources (merged into the everyone list, or the DoT
    /// listener's with `dot`) that list `domain`, with their entries.
    fn sources_listing(&self, domain: &str, dot: bool) -> Vec<(String, String)> {
        self.source_lists
            .as_ref()
            .map(|l| l.sources_listing(domain, dot))
            .unwrap_or_default()
    }

    /// The decision for a remote-list block of `domain`, naming the first
    /// source that lists it.
    fn source_block(&self, domain: &str, dot: bool) -> Decision {
        let scope = if dot { " (DoT)" } else { "" };
        match self.sources_listing(domain, dot).into_iter().next() {
            Some((name, entry)) => Decision::new(
                format!("'{domain}' is on the blocklist source '{name}'{scope} (entry '{entry}')"),
                Action::Block,
            )
            .with_source(source::BLOCKLIST_SOURCE, Some(name)),
            None => Decision::new(
                format!("'{domain}' matched remote blocklist source{scope}"),
                Action::Block,
            )
            .with_source(source::BLOCKLIST_SOURCE, None),
        }
    }

    /// Replace both source-owned sets (`None` clears one).
    pub fn set_source_lists(
        &mut self,
        remote: Option<std::sync::Arc<Blocklist>>,
        dot: Option<std::sync::Arc<Blocklist>>,
    ) {
        self.remote_blocklist = remote;
        self.dot_blocklist = dot;
    }

    /// The current DoT-scoped remote blocklist, for comparison on refresh
    /// and for carrying over a policy-engine rebuild.
    pub fn dot_blocklist_snapshot(&self) -> Option<std::sync::Arc<Blocklist>> {
        self.dot_blocklist.clone()
    }

    /// The number of domains currently blocked by DoT-scoped sources (0 when
    /// none are configured or fetched yet).
    pub fn dot_blocklist_len(&self) -> usize {
        self.dot_blocklist.as_ref().map(|l| l.len()).unwrap_or(0)
    }

    /// Whether the AAAA filter would suppress a query for `query_name` of the
    /// given `record_type` (used by the dispatcher and tests).
    fn aaaa_filtered(&self, query_name: &str, record_type: &str) -> bool {
        self.filter_aaaa
            && record_type.eq_ignore_ascii_case("AAAA")
            && !self
                .filter_aaaa_bypass
                .as_ref()
                .is_some_and(|b| b.contains(query_name))
    }

    pub fn add_rule(&mut self, rule: PerClientRule) {
        std::sync::Arc::make_mut(&mut self.rules).push(rule);
    }

    pub fn add_plugin(&mut self, plugin: std::sync::Arc<dyn crate::PolicyPlugin>) {
        std::sync::Arc::make_mut(&mut self.plugins).register(plugin);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Evaluate policy for a query.
    ///
    /// `query_name` must already be normalized (lowercase, no trailing dot).
    /// Returns a [`Decision`]; `Action::Allow` means "no policy objected".
    pub async fn evaluate(&self, client: IpAddr, query_name: &str, record_type: &str) -> Decision {
        self.evaluate_on(client, query_name, record_type, None)
            .await
    }

    /// Evaluate policy for a query arriving on the DoT listener: the normal
    /// evaluation plus the DoT-scoped remote blocklist. All the shared
    /// rules (ACLs, allowlist, static/remote blocklists, per-client rules,
    /// AAAA filter, plugins) apply exactly as for plain DNS, so a DoT
    /// client never bypasses operator policy - it only faces the extra
    /// listener-scoped set on top.
    pub async fn evaluate_dot(
        &self,
        client: IpAddr,
        query_name: &str,
        record_type: &str,
    ) -> Decision {
        self.evaluate_on(client, query_name, record_type, Some("dot"))
            .await
    }

    /// Evaluate policy for a query that arrived on `listener` (`dot`, `doh`,
    /// `doq`; `None` for plain DNS). The DoT listener also faces the
    /// DoT-scoped sources, and plugins are told the listener.
    pub async fn evaluate_on(
        &self,
        client: IpAddr,
        query_name: &str,
        record_type: &str,
        listener: Option<&'static str>,
    ) -> Decision {
        if !self.enabled {
            return Decision::allow();
        }
        self.evaluate_with(client, query_name, record_type, listener)
            .await
    }

    async fn evaluate_with(
        &self,
        client: IpAddr,
        query_name: &str,
        record_type: &str,
        listener: Option<&'static str>,
    ) -> Decision {
        let dot_listener = listener == Some("dot");
        // 1. ACLs.
        if let Some(acl) = &self.acl {
            if !acl.is_allowed(client) {
                return Decision::new(
                    format!("client {client} is in a denied network"),
                    Action::Refused,
                )
                .with_source(source::DENIED_NETWORK, None);
            }
        }

        // 2. Explicit trusted domains override domain-based blocking. ACLs
        // above remain authoritative, so a denied client is never exempt.
        if let Some(list) = &self.allowlist {
            if let Some(entry) = list.matching_entry(query_name) {
                return Decision::new(
                    format!("'{query_name}' is on the allowlist (entry '{entry}')"),
                    Action::Allow,
                )
                .with_source(source::ALLOWLIST, Some(entry));
            }
        }

        // 3. Blocklists (static config + remote sources).
        if let Some(list) = &self.blocklist {
            if let Some(entry) = list.matching_entry(query_name) {
                return Decision::new(
                    format!("'{query_name}' is on the blocklist (entry '{entry}')"),
                    Action::Block,
                )
                .with_source(source::BLOCKLIST, Some(entry));
            }
        }
        if let Some(list) = &self.remote_blocklist {
            if list.contains(query_name) {
                return self.source_block(query_name, false);
            }
        }

        // 3b. DoT-scoped sources: apply only on the DoT listener.
        if dot_listener {
            if let Some(list) = &self.dot_blocklist {
                if list.contains(query_name) {
                    return self.source_block(query_name, true);
                }
            }
        }

        // 4. Ordered per-client rules.
        for rule in self.rules.iter() {
            if rule.matches_client(client) && rule.matches_domain(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched per-client rule"),
                    rule.action().clone(),
                )
                .with_source(source::CLIENT_RULE, None);
            }
        }

        // 5. Filter AAAA: after explicit blocklists/rules (so an outright
        // block still wins with NXDOMAIN) but before plugins, suppress IPv6
        // answers by returning NODATA, forcing dual-stack clients to IPv4.
        if self.aaaa_filtered(query_name, record_type) {
            return Decision::new(format!("AAAA filtered for '{query_name}'"), Action::NoData)
                .with_source(source::AAAA_FILTER, None);
        }

        // 6. Plugins.
        if !self.plugins.is_empty() {
            let ctx = crate::PolicyContext {
                client,
                query_name: query_name.to_string(),
                record_type: record_type.to_string(),
                listener,
            };
            if let Some(mut decision) = self.plugins.evaluate(&ctx).await {
                if decision.source.is_empty() {
                    decision.source = source::PLUGIN;
                }
                return decision;
            }
        }

        Decision::allow()
    }

    /// Every server-wide check, in the order queries meet them, and what
    /// each does with `query_name` for `client`, without stopping at the
    /// first that decides: for the console's "why is this blocked?". Only
    /// checks that are set up are listed.
    pub async fn explain(
        &self,
        client: IpAddr,
        query_name: &str,
        record_type: &str,
        listener: Option<&'static str>,
    ) -> Vec<Check> {
        if !self.enabled {
            return vec![Check::new(
                source::BLOCKLIST,
                "off",
                "Filtering is turned off, so no list or rule blocks anything",
            )];
        }
        let mut checks = Vec::new();
        if let Some(acl) = &self.acl {
            checks.push(if acl.is_allowed(client) {
                Check::new(
                    source::DENIED_NETWORK,
                    "none",
                    format!("{client} is not in a denied network"),
                )
            } else {
                Check {
                    action: Some(Action::Refused.as_str()),
                    ..Check::new(
                        source::DENIED_NETWORK,
                        "block",
                        format!("{client} is in a denied network: every query is refused"),
                    )
                }
            });
        }
        if let Some(list) = self.allowlist.as_ref().filter(|l| !l.is_empty()) {
            checks.push(match list.matching_entry(query_name) {
                Some(entry) => Check {
                    matched: Some(entry.clone()),
                    ..Check::new(
                        source::ALLOWLIST,
                        "allow",
                        format!("On the allowlist (entry '{entry}'): no blocklist, group or response policy zone blocks it"),
                    )
                },
                None => Check::new(source::ALLOWLIST, "none", "Not on the allowlist"),
            });
        }
        if let Some(list) = self.blocklist.as_ref().filter(|l| !l.is_empty()) {
            checks.push(match list.matching_entry(query_name) {
                Some(entry) => Check {
                    matched: Some(entry.clone()),
                    action: Some(Action::Block.as_str()),
                    ..Check::new(
                        source::BLOCKLIST,
                        "block",
                        format!("On the blocklist (entry '{entry}')"),
                    )
                },
                None => Check::new(source::BLOCKLIST, "none", "Not on the blocklist"),
            });
        }
        let mut source_checks = |list: &Option<std::sync::Arc<Blocklist>>, dot: bool| {
            let Some(list) = list.as_ref().filter(|l| !l.is_empty()) else {
                return;
            };
            let scope = if dot { " for the DoT listener" } else { "" };
            if !list.contains(query_name) {
                checks.push(Check::new(
                    source::BLOCKLIST_SOURCE,
                    "none",
                    format!("Not on any blocklist source{scope}"),
                ));
                return;
            }
            let listing = self.sources_listing(query_name, dot);
            if listing.is_empty() {
                checks.push(Check {
                    action: Some(Action::Block.as_str()),
                    ..Check::new(
                        source::BLOCKLIST_SOURCE,
                        "block",
                        format!("On a blocklist source{scope}"),
                    )
                });
            }
            for (name, entry) in listing {
                checks.push(Check {
                    matched: Some(name.clone()),
                    action: Some(Action::Block.as_str()),
                    ..Check::new(
                        source::BLOCKLIST_SOURCE,
                        "block",
                        format!("On the blocklist source '{name}'{scope} (entry '{entry}')"),
                    )
                });
            }
        };
        source_checks(&self.remote_blocklist, false);
        if listener == Some("dot") {
            source_checks(&self.dot_blocklist, true);
        }
        for rule in self.rules.iter() {
            if rule.matches_client(client) && rule.matches_domain(query_name) {
                let action = rule.action();
                checks.push(Check {
                    action: (*action != Action::Allow).then(|| action.as_str()),
                    ..Check::new(
                        source::CLIENT_RULE,
                        if *action == Action::Allow {
                            "allow"
                        } else {
                            "block"
                        },
                        "Matches a per-client rule in the configuration",
                    )
                });
            }
        }
        if self.filter_aaaa && record_type.eq_ignore_ascii_case("AAAA") {
            checks.push(if self.aaaa_filtered(query_name, record_type) {
                Check {
                    action: Some(Action::NoData.as_str()),
                    ..Check::new(
                        source::AAAA_FILTER,
                        "block",
                        "Filter AAAA answers IPv6 queries with no addresses",
                    )
                }
            } else {
                Check::new(source::AAAA_FILTER, "none", "Exempt from Filter AAAA")
            });
        }
        if !self.plugins.is_empty() {
            let ctx = crate::PolicyContext {
                client,
                query_name: query_name.to_string(),
                record_type: record_type.to_string(),
                listener,
            };
            if let Some(decision) = self.plugins.evaluate(&ctx).await {
                let mut check = Check::from_decision(&decision);
                if decision.source.is_empty() {
                    check.source = source::PLUGIN;
                }
                checks.push(check);
            } else {
                checks.push(Check::new(
                    source::AI,
                    "none",
                    "The AI scanner does not block it (no blocking verdict, Train mode, or the device's group has AI blocking off)",
                ));
            }
        }
        checks
    }
}

/// Publish `engine`, a rebuild from configuration, keeping the source-owned
/// sets of whatever engine is live at that moment. Read-modify-write through
/// `rcu`: a source refresh landing in between is kept, not overwritten.
pub fn publish_rebuilt(policy: &arc_swap::ArcSwap<PolicyEngine>, engine: PolicyEngine) {
    policy.rcu(|current| {
        let mut next = engine.clone();
        next.adopt_source_lists(current);
        next
    });
}

/// Publish new source-owned sets (`remote` for everyone, `dot` for the DoT
/// listener; `None` clears one) into the live engine, keeping everything
/// else. Read-modify-write through `rcu`, so a concurrent rebuild from
/// configuration is not lost. Returns whether anything changed.
pub fn publish_source_lists(
    policy: &arc_swap::ArcSwap<PolicyEngine>,
    remote: Option<std::sync::Arc<Blocklist>>,
    dot: Option<std::sync::Arc<Blocklist>>,
) -> bool {
    let same = |current: &Option<std::sync::Arc<Blocklist>>,
                new: &Option<std::sync::Arc<Blocklist>>| {
        let empty = |l: &Option<std::sync::Arc<Blocklist>>| l.as_ref().is_none_or(|l| l.is_empty());
        match (current, new) {
            (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b) || a == b,
            _ => empty(current) && empty(new),
        }
    };
    let live = policy.load();
    if same(&live.remote_blocklist, &remote) && same(&live.dot_blocklist, &dot) {
        return false;
    }
    drop(live);
    policy.rcu(|current| {
        let mut next = current.as_ref().clone();
        next.set_source_lists(remote.clone(), dot.clone());
        next
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        let mut e = PolicyEngine::new(true);
        e.set_blocklist(Blocklist::from_lines(["ads.example.com"]));
        e.set_acl(Acl::new(vec!["10.99.0.0/16".parse().unwrap()], vec![]));
        e.add_rule(PerClientRule::new(
            vec!["192.168.1.0/24".parse().unwrap()],
            Some(vec!["*.internal.test".to_string()]),
            Action::Redirect("0.0.0.0".parse().unwrap()),
        ));
        e
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Blocks one name, as the AI plugin would.
    struct BlockOne;

    #[async_trait::async_trait]
    impl crate::PolicyPlugin for BlockOne {
        fn name(&self) -> &str {
            "block-one"
        }

        async fn evaluate(&self, context: &crate::PolicyContext) -> Option<Decision> {
            (context.query_name == "plugin.example.com")
                .then(|| Decision::new("blocked by plugin", Action::Block))
        }
    }

    /// A rebuild from configuration (any filtering or network save) keeps
    /// the plugins installed at startup.
    #[tokio::test]
    async fn rebuilds_keep_plugins() {
        let mut live = engine();
        live.add_plugin(std::sync::Arc::new(BlockOne));
        let policy = arc_swap::ArcSwap::from_pointee(live);
        publish_rebuilt(&policy, engine());
        let d = policy
            .load()
            .evaluate(ip("1.1.1.1"), "plugin.example.com", "A")
            .await;
        assert_eq!(d.action, Action::Block);
    }

    #[tokio::test]
    async fn blocklist_matches() {
        let e = engine();
        let d = e.evaluate(ip("1.1.1.1"), "ads.example.com", "A").await;
        assert_eq!(d.action, Action::Block);
    }

    #[tokio::test]
    async fn acl_denies_client() {
        let e = engine();
        let d = e.evaluate(ip("10.99.1.1"), "example.org", "A").await;
        assert_eq!(d.action, Action::Refused);
    }

    #[tokio::test]
    async fn per_client_redirect() {
        let e = engine();
        let d = e.evaluate(ip("192.168.1.42"), "x.internal.test", "A").await;
        assert_eq!(d.action, Action::Redirect("0.0.0.0".parse().unwrap()));
    }

    #[tokio::test]
    async fn unmatched_is_allowed() {
        let e = engine();
        let d = e.evaluate(ip("8.8.8.8"), "example.org", "A").await;
        assert_eq!(d.action, Action::Allow);
    }

    #[tokio::test]
    async fn dot_scoped_blocklist_applies_only_to_dot_clients() {
        let mut e = PolicyEngine::new(true);
        e.set_dot_blocklist(Blocklist::from_lines(["public-ads.test"]));

        // A query on the DoT listener is blocked...
        assert_eq!(
            e.evaluate_dot(ip("203.0.113.7"), "public-ads.test", "A")
                .await
                .action,
            Action::Block
        );
        // ...an identical query from plain DNS is not.
        assert_eq!(
            e.evaluate(ip("192.168.1.10"), "public-ads.test", "A")
                .await
                .action,
            Action::Allow
        );
    }

    #[tokio::test]
    async fn dot_scoped_blocklist_never_overrides_shared_policy() {
        let mut e = PolicyEngine::new(true);
        e.set_allowlist(Blocklist::from_lines(["*.trusted.test"]));
        e.set_dot_blocklist(Blocklist::from_lines(["trusted.test", "blocked.test"]));

        // The operator allowlist still wins on the DoT listener...
        assert_eq!(
            e.evaluate_dot(ip("203.0.113.7"), "safe.trusted.test", "A")
                .await
                .action,
            Action::Allow
        );
        // ...and a name in both the global and DoT sets blocks either way.
        e.set_blocklist(Blocklist::from_lines(["blocked.test"]));
        assert_eq!(
            e.evaluate_dot(ip("203.0.113.7"), "blocked.test", "A")
                .await
                .action,
            Action::Block
        );
    }

    #[tokio::test]
    async fn disabled_engine_always_allows() {
        let mut e = engine();
        e.enabled = false;
        let d = e.evaluate(ip("10.99.1.1"), "ads.example.com", "A").await;
        assert_eq!(d.action, Action::Allow);
    }

    #[tokio::test]
    async fn filter_aaaa_returns_nodata_for_aaaa_only() {
        let mut e = PolicyEngine::new(true);
        e.set_filter_aaaa(true, None);
        // AAAA is filtered...
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "example.org", "AAAA")
                .await
                .action,
            Action::NoData
        );
        // ...but A (and other types) pass through untouched.
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "example.org", "A").await.action,
            Action::Allow
        );
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "example.org", "MX").await.action,
            Action::Allow
        );
    }

    #[tokio::test]
    async fn filter_aaaa_bypass_keeps_ipv6() {
        let mut e = PolicyEngine::new(true);
        e.set_filter_aaaa(
            true,
            Some(Blocklist::from_lines(["*.v6.test", "host.test"])),
        );
        // Bypassed names keep their AAAA answers (fall through to Allow).
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "a.v6.test", "AAAA").await.action,
            Action::Allow
        );
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "host.test", "AAAA").await.action,
            Action::Allow
        );
        // Everything else is still filtered.
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "other.test", "AAAA").await.action,
            Action::NoData
        );
    }

    #[tokio::test]
    async fn filter_aaaa_off_by_default() {
        let e = PolicyEngine::new(true);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "example.org", "AAAA")
                .await
                .action,
            Action::Allow
        );
    }

    #[tokio::test]
    async fn explicit_block_wins_over_aaaa_filter() {
        // A blocklisted name must still return NXDOMAIN for AAAA, not NODATA.
        let mut e = engine();
        e.set_filter_aaaa(true, None);
        assert_eq!(
            e.evaluate(ip("1.1.1.1"), "ads.example.com", "AAAA")
                .await
                .action,
            Action::Block
        );
    }

    #[tokio::test]
    async fn allowlist_overrides_static_and_remote_blocklists() {
        let mut e = PolicyEngine::new(true);
        e.set_allowlist(Blocklist::from_lines([
            "safe.example.com",
            "*.trusted.test",
        ]));
        e.set_blocklist(Blocklist::from_lines(["safe.example.com", "blocked.test"]));
        e.set_remote_blocklist(Blocklist::from_lines(["remote.test"]));

        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "safe.example.com", "A")
                .await
                .action,
            Action::Allow
        );
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "a.trusted.test", "A")
                .await
                .action,
            Action::Allow
        );
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), "remote.test", "A").await.action,
            Action::Block
        );
    }
}
