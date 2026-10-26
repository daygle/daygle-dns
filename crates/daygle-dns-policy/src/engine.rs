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
}

impl Decision {
    pub fn new(reason: impl Into<String>, action: Action) -> Self {
        Self {
            action,
            reason: reason.into(),
            group: None,
        }
    }

    /// Attach the name of the group that produced this decision.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
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
    /// `policy.cname_inspection`.
    cname_inspection: bool,
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
                return Decision::new(format!("client {client} denied by ACL"), Action::Refused);
            }
        }

        // 2. Explicit trusted domains override domain-based blocking. ACLs
        // above remain authoritative, so a denied client is never exempt.
        if let Some(list) = &self.allowlist {
            if list.contains(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched trusted domain allowlist"),
                    Action::Allow,
                );
            }
        }

        // 3. Blocklists (static config + remote sources).
        if let Some(list) = &self.blocklist {
            if list.contains(query_name) {
                return Decision::new(format!("'{query_name}' matched blocklist"), Action::Block);
            }
        }
        if let Some(list) = &self.remote_blocklist {
            if list.contains(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched remote blocklist source"),
                    Action::Block,
                );
            }
        }

        // 3b. DoT-scoped sources: apply only on the DoT listener.
        if dot_listener {
            if let Some(list) = &self.dot_blocklist {
                if list.contains(query_name) {
                    return Decision::new(
                        format!("'{query_name}' matched remote blocklist source (DoT)"),
                        Action::Block,
                    );
                }
            }
        }

        // 4. Ordered per-client rules.
        for rule in self.rules.iter() {
            if rule.matches_client(client) && rule.matches_domain(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched per-client rule"),
                    rule.action().clone(),
                );
            }
        }

        // 5. Filter AAAA: after explicit blocklists/rules (so an outright
        // block still wins with NXDOMAIN) but before plugins, suppress IPv6
        // answers by returning NODATA, forcing dual-stack clients to IPv4.
        if self.aaaa_filtered(query_name, record_type) {
            return Decision::new(format!("AAAA filtered for '{query_name}'"), Action::NoData);
        }

        // 6. Plugins.
        if !self.plugins.is_empty() {
            let ctx = crate::PolicyContext {
                client,
                query_name: query_name.to_string(),
                record_type: record_type.to_string(),
                listener,
            };
            if let Some(decision) = self.plugins.evaluate(&ctx).await {
                return decision;
            }
        }

        Decision::allow()
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
