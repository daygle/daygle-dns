//! Extension point for custom policy logic.
//!
//! A [`PolicyPlugin`] is a boxed async callback evaluated after ACLs,
//! blocklists and per-client rules. Plugins run in registration order; the
//! first plugin returning `Some(decision)` stops evaluation.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{Action, Decision};

/// Context passed to each plugin.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Source address of the DNS client.
    pub client: IpAddr,
    /// Normalized query name (lowercase, no trailing dot).
    pub query_name: String,
    /// Record type being queried, e.g. `"A"`.
    pub record_type: String,
}

/// A user-supplied policy plugin.
#[async_trait]
pub trait PolicyPlugin: Send + Sync {
    /// Unique name used in logs and metrics.
    fn name(&self) -> &str;

    /// Evaluate the plugin. Return `None` to defer to the next plugin or the
    /// default engine behaviour.
    async fn evaluate(&self, context: &PolicyContext) -> Option<Decision>;
}

/// Ordered collection of plugins.
#[derive(Default, Clone)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn PolicyPlugin>>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.plugins.iter().map(|p| p.name()).collect();
        f.debug_struct("PluginRegistry")
            .field("plugins", &names)
            .finish()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: Arc<dyn PolicyPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Evaluate plugins in order, returning the first non-`None` decision.
    pub async fn evaluate(&self, context: &PolicyContext) -> Option<Decision> {
        for plugin in &self.plugins {
            if let Some(decision) = plugin.evaluate(context).await {
                return Some(decision);
            }
        }
        None
    }
}

/// Convenience helper to build a [`Decision`] from a plugin.
#[allow(dead_code)]
pub fn decide(reason: impl Into<String>, action: Action) -> Decision {
    Decision::new(reason, action)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAllow;
    #[async_trait]
    impl PolicyPlugin for AlwaysAllow {
        fn name(&self) -> &str {
            "always-allow"
        }
        async fn evaluate(&self, _ctx: &PolicyContext) -> Option<Decision> {
            Some(decide("always allow", Action::Allow))
        }
    }

    struct BlockGoogle;
    #[async_trait]
    impl PolicyPlugin for BlockGoogle {
        fn name(&self) -> &str {
            "block-google"
        }
        async fn evaluate(&self, ctx: &PolicyContext) -> Option<Decision> {
            if ctx.query_name.ends_with("google.com") {
                Some(decide("blocked by plugin", Action::Block))
            } else {
                None
            }
        }
    }

    #[tokio::test]
    async fn first_plugin_wins() {
        let mut registry = PluginRegistry::new();
        registry.register(Arc::new(AlwaysAllow));
        registry.register(Arc::new(BlockGoogle));

        let ctx = PolicyContext {
            client: "1.2.3.4".parse().unwrap(),
            query_name: "www.google.com".to_string(),
            record_type: "A".to_string(),
        };
        let decision = registry.evaluate(&ctx).await.unwrap();
        assert_eq!(decision.action, Action::Allow);
    }

    #[tokio::test]
    async fn deferral_reaches_later_plugins() {
        let mut registry = PluginRegistry::new();
        registry.register(Arc::new(BlockGoogle));

        let ctx = PolicyContext {
            client: "1.2.3.4".parse().unwrap(),
            query_name: "www.google.com".to_string(),
            record_type: "A".to_string(),
        };
        assert_eq!(registry.evaluate(&ctx).await.unwrap().action, Action::Block);

        let other = PolicyContext {
            client: "1.2.3.4".parse().unwrap(),
            query_name: "example.com".to_string(),
            record_type: "A".to_string(),
        };
        assert!(registry.evaluate(&other).await.is_none());
    }
}
