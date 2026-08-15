//! The policy engine: combines ACLs, blocklists, per-client rules and plugins.

use std::net::IpAddr;

use crate::{Acl, Action, Blocklist, PerClientRule, PluginRegistry};

/// A policy decision with a human-readable reason.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
}

impl Decision {
    pub fn new(reason: impl Into<String>, action: Action) -> Self {
        Self {
            action,
            reason: reason.into(),
        }
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
    blocklist: Option<std::sync::Arc<Blocklist>>,
    rules: std::sync::Arc<Vec<PerClientRule>>,
    plugins: std::sync::Arc<PluginRegistry>,
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

    pub fn set_blocklist(&mut self, blocklist: Blocklist) {
        self.blocklist = Some(std::sync::Arc::new(blocklist));
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
    pub async fn evaluate(
        &self,
        client: IpAddr,
        query_name: &str,
        record_type: &str,
    ) -> Decision {
        if !self.enabled {
            return Decision::allow();
        }

        // 1. ACLs.
        if let Some(acl) = &self.acl {
            if !acl.is_allowed(client) {
                return Decision::new(
                    format!("client {client} denied by ACL"),
                    Action::Refused,
                );
            }
        }

        // 2. Blocklists.
        if let Some(list) = &self.blocklist {
            if list.contains(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched blocklist"),
                    Action::Block,
                );
            }
        }

        // 3. Ordered per-client rules.
        for rule in self.rules.iter() {
            if rule.matches_client(client) && rule.matches_domain(query_name) {
                return Decision::new(
                    format!("'{query_name}' matched per-client rule"),
                    rule.action().clone(),
                );
            }
        }

        // 4. Plugins.
        if !self.plugins.is_empty() {
            let ctx = crate::PolicyContext {
                client,
                query_name: query_name.to_string(),
                record_type: record_type.to_string(),
            };
            if let Some(decision) = self.plugins.evaluate(&ctx).await {
                return decision;
            }
        }

        Decision::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        let mut e = PolicyEngine::new(true);
        e.set_blocklist(Blocklist::from_lines(["ads.example.com"]));
        e.set_acl(Acl::new(
            vec!["10.99.0.0/16".parse().unwrap()],
            vec![],
        ));
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
        let d = e
            .evaluate(ip("192.168.1.42"), "x.internal.test", "A")
            .await;
        assert_eq!(d.action, Action::Redirect("0.0.0.0".parse().unwrap()));
    }

    #[tokio::test]
    async fn unmatched_is_allowed() {
        let e = engine();
        let d = e.evaluate(ip("8.8.8.8"), "example.org", "A").await;
        assert_eq!(d.action, Action::Allow);
    }

    #[tokio::test]
    async fn disabled_engine_always_allows() {
        let mut e = engine();
        e.enabled = false;
        let d = e.evaluate(ip("10.99.1.1"), "ads.example.com", "A").await;
        assert_eq!(d.action, Action::Allow);
    }
}
