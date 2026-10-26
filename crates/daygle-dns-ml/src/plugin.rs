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
//!
//! Client groups can turn AI blocking off for their clients
//! (`ai_blocking`): the first enabled group a client belongs to decides,
//! and clients in no group are covered.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_policy::{Action, AdvancedBlocking, Decision, PolicyContext, PolicyPlugin};

use crate::scanner::{ActiveBlock, BlockSnapshot};

/// Longest suffix match against the snapshot: a verdict recorded on
/// `bad.example.com` also blocks `www.bad.example.com`, while a verdict on
/// `example.com` covers every subdomain. Anchor on label boundaries. Walks
/// borrowed suffixes of one lowercased copy (no allocation per label).
fn suffix_match<'a>(qname: &str, snapshot: &'a BlockSnapshot, now: i64) -> Option<&'a ActiveBlock> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    let mut candidate = name.as_str();
    loop {
        if let Some(block) = snapshot.get(candidate) {
            if block.expires_at > now {
                return Some(block);
            }
        }
        candidate = candidate.split_once('.')?.1;
    }
}

/// The plugin installed into the [`daygle_dns_policy::PolicyEngine`].
pub struct AiBlockPlugin {
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    settings: Arc<ArcSwap<AiSettings>>,
    /// The live client groups, consulted for their `ai_blocking` switch
    /// (installed once the server has built them).
    groups: arc_swap::ArcSwapOption<ArcSwap<AdvancedBlocking>>,
}

impl AiBlockPlugin {
    pub fn new(
        snapshot: Arc<ArcSwap<BlockSnapshot>>,
        settings: Arc<ArcSwap<AiSettings>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot,
            settings,
            groups: arc_swap::ArcSwapOption::empty(),
        })
    }

    /// Let the client groups decide which clients AI blocking covers.
    pub fn set_client_groups(&self, groups: Arc<ArcSwap<AdvancedBlocking>>) {
        self.groups.store(Some(groups));
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
        let block = suffix_match(&context.query_name, &snapshot, now)?;
        if let Some(groups) = self.groups.load().as_deref() {
            if !groups
                .load()
                .ai_blocking(context.client, context.listener)
                .0
            {
                return None;
            }
        }
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
            listener: None,
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

    /// A client group with AI blocking off exempts its clients; others are
    /// still blocked.
    #[tokio::test]
    async fn client_groups_can_turn_ai_blocking_off() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Enforce, snapshot);
        let group = daygle_dns_core::blocking::BlockingGroup {
            id: "g".to_string(),
            name: "no ai".to_string(),
            enabled: true,
            clients: vec!["10.0.0.0/24".to_string()],
            allow: vec![],
            block: vec![],
            allow_regex: vec![],
            block_regex: vec![],
            blocklists: vec![],
            response: Default::default(),
            ai_blocking: false,
            position: 0,
            last_modified_at: None,
        };
        p.set_client_groups(Arc::new(ArcSwap::from_pointee(AdvancedBlocking::build(
            &[group],
            Arc::default(),
        ))));
        // ctx() queries from 10.0.0.5, inside the group.
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());
        let mut outside = ctx("bad.example.com");
        outside.client = "192.0.2.1".parse().unwrap();
        assert!(p.evaluate(&outside).await.is_some());
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
