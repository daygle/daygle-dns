//! The AI policy plugin: consults the scanner's block snapshot and returns
//! `Action::Block` for fresh, high-confidence threat verdicts in enforce
//! mode. In `train` mode it always defers (`None`) - verdicts are recorded,
//! nothing blocks.
//!
//! Placement in the engine's evaluation order does the safety work:
//!
//! 1. ACLs run first (unchanged).
//! 2. The user allowlist runs *before* plugins, so an explicitly trusted
//!    domain can never be auto-blocked by the AI.
//! 3. Static/remote blocklists and per-client rules run before plugins, so
//!    operator decisions always supersede AI verdicts.
//! 4. This plugin runs last.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_policy::{Action, Decision, PolicyContext, PolicyPlugin};

use crate::scanner::BlockSnapshot;

/// Longest suffix match against the snapshot: a verdict recorded on
/// `bad.example.com` also blocks `www.bad.example.com`, while a verdict on
/// `example.com` covers every subdomain. Anchor on label boundaries. The
/// returned domain is a snapshot key owned by the caller.
fn suffix_match(qname: &str, snapshot: &BlockSnapshot, now: i64) -> Option<String> {
    let mut candidate = qname.trim_end_matches('.').to_ascii_lowercase();
    loop {
        if let Some(block) = snapshot.get(&candidate) {
            if block.expires_at > now {
                return Some(candidate);
            }
        }
        candidate = candidate.split_once('.')?.1.to_string();
    }
}

/// The plugin installed into the [`daygle_dns_policy::PolicyEngine`].
pub struct AiBlockPlugin {
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    settings: Arc<ArcSwap<AiSettings>>,
}

impl AiBlockPlugin {
    pub fn new(
        snapshot: Arc<ArcSwap<BlockSnapshot>>,
        settings: Arc<ArcSwap<AiSettings>>,
    ) -> Arc<Self> {
        Arc::new(Self { snapshot, settings })
    }
}

impl std::fmt::Debug for AiBlockPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiBlockPlugin")
            .field("snapshot_len", &self.snapshot.load().len())
            .finish()
    }
}

#[async_trait]
impl PolicyPlugin for AiBlockPlugin {
    fn name(&self) -> &str {
        "ai"
    }

    async fn evaluate(&self, context: &PolicyContext) -> Option<Decision> {
        let settings = self.settings.load_full();
        if settings.mode != AiMode::Enforce || !settings.enabled {
            return None; // train mode: never block
        }
        let snapshot = self.snapshot.load_full();
        let now = Utc::now().timestamp();
        let key = suffix_match(&context.query_name, &snapshot, now)?;
        let block = snapshot.get(&key)?;
        Some(
            Decision::new(
                format!(
                    "'{}' auto-blocked by AI verdict (category '{}')",
                    context.query_name, block.category
                ),
                Action::Block,
            )
            .with_group("ai"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ActiveBlock;
    use daygle_dns_core::config::AiMode;

    fn plugin(mode: AiMode, snapshot: BlockSnapshot) -> Arc<AiBlockPlugin> {
        let settings = AiSettings {
            enabled: true,
            mode,
            ..AiSettings::default()
        };
        AiBlockPlugin::new(
            Arc::new(ArcSwap::from_pointee(snapshot)),
            Arc::new(ArcSwap::from_pointee(settings)),
        )
    }

    fn ctx(query_name: &str) -> PolicyContext {
        PolicyContext {
            client: "10.0.0.5".parse().unwrap(),
            query_name: query_name.to_string(),
            record_type: "A".to_string(),
        }
    }

    #[tokio::test]
    async fn train_mode_never_blocks() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "phishing".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Train, snapshot);
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());
    }

    #[tokio::test]
    async fn enforce_blocks_exact_and_subdomains() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Enforce, snapshot.clone());

        let d = p.evaluate(&ctx("bad.example.com")).await.unwrap();
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.group.as_deref(), Some("ai"));

        let d = p.evaluate(&ctx("www.bad.example.com")).await.unwrap();
        assert_eq!(d.action, Action::Block);

        // unmatched domain
        assert!(p.evaluate(&ctx("fine.example.org")).await.is_none());
        // does not match label-suffix collisions
        assert!(p.evaluate(&ctx("notbad.example.com")).await.is_none());
        snapshot.clear();
    }

    #[tokio::test]
    async fn expired_verdicts_stop_blocking() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "old.example.com".to_string(),
            ActiveBlock {
                category: "phishing".to_string(),
                expires_at: chrono::Utc::now().timestamp() - 1,
            },
        );
        let p = plugin(AiMode::Enforce, snapshot);
        assert!(p.evaluate(&ctx("old.example.com")).await.is_none());
    }

    #[tokio::test]
    async fn disabled_plugin_never_blocks() {
        let settings = AiSettings {
            enabled: false,
            mode: AiMode::Enforce,
            ..AiSettings::default()
        };
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = AiBlockPlugin::new(
            Arc::new(ArcSwap::from_pointee(snapshot)),
            Arc::new(ArcSwap::from_pointee(settings)),
        );
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());
    }
}
