//! The AI policy plugin: two independent jobs, one per channel.
//!
//! - **Threats** consult the block snapshot and return `Action::Block` for
//!   fresh, high-confidence threat verdicts in enforce mode. In `train` mode
//!   they defer: verdicts are recorded, nothing blocks.
//! - **Categories** consult the category snapshot and block a query whose
//!   domain (or a parent domain) is labelled with a category one of the
//!   client's groups blocks. This is the operator's rule, not the model's
//!   decision, so it applies in both modes; `ai.mode` only governs
//!   auto-blocking of detected threats. A threat label (malware, phishing,
//!   scam) is in that snapshot only for a threat verdict at or above
//!   `ai.block_threshold`, never on the categorizer's guess.
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
//! Client groups can override the enforcement mode for their clients
//! (`ai_mode`: inherit, enforce, record only): the first enabled group a
//! client belongs to decides, and clients in no group follow `ai.mode`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use daygle_dns_core::config::{AiMode, AiSettings};
use daygle_dns_policy::{Action, AdvancedBlocking, Decision, PolicyContext, PolicyPlugin};

use crate::scanner::{exempt, BlockSnapshot, CategorySnapshot, ExemptionSnapshot};

/// Longest suffix match against the snapshot: a verdict recorded on
/// `bad.example.com` also blocks `www.bad.example.com`, while a verdict on
/// `example.com` covers every subdomain. Anchor on label boundaries. Walks
/// borrowed suffixes of one lowercased copy (no allocation per label).
fn suffix_match<'a, T>(
    name: &str,
    snapshot: &'a std::collections::HashMap<String, T>,
    now: i64,
    expires_at: impl Fn(&T) -> i64,
) -> Option<&'a T> {
    let mut candidate = name;
    loop {
        if let Some(found) = snapshot.get(candidate) {
            if expires_at(found) > now {
                return Some(found);
            }
        }
        candidate = candidate.split_once('.')?.1;
    }
}

/// The plugin installed into the [`daygle_dns_policy::PolicyEngine`].
pub struct AiBlockPlugin {
    snapshot: Arc<ArcSwap<BlockSnapshot>>,
    categories: Arc<ArcSwap<CategorySnapshot>>,
    /// Operator exemptions. Snapshots already leave out exempt domains and
    /// their subdomains; this also covers a query for an exempt subdomain
    /// whose verdict sits on a parent domain.
    exemptions: Arc<ArcSwap<ExemptionSnapshot>>,
    settings: Arc<ArcSwap<AiSettings>>,
    /// The live client groups, consulted for their per-group enforcement mode
    /// (installed once the server has built them).
    groups: arc_swap::ArcSwapOption<ArcSwap<AdvancedBlocking>>,
}

impl AiBlockPlugin {
    pub fn new(
        snapshot: Arc<ArcSwap<BlockSnapshot>>,
        categories: Arc<ArcSwap<CategorySnapshot>>,
        exemptions: Arc<ArcSwap<ExemptionSnapshot>>,
        settings: Arc<ArcSwap<AiSettings>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot,
            categories,
            exemptions,
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
        // `load()` guards are cheaper than `load_full()` Arc clones, and
        // this runs once per DNS query.
        let settings = self.settings.load();
        if !settings.enabled {
            return None; // scanner off: no verdicts to act on
        }
        let now = Utc::now().timestamp();
        let groups = self.groups.load();
        let name = context
            .query_name
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // Checked only once something would block, so the common no-match
        // query pays nothing for it.
        let is_exempt = || exempt(&name, &self.exemptions.load());

        // 1. Detected threats: blocked where the effective mode is enforce.
        //    The global mode is the default; the first enabled group covering
        //    the client can replace it either way (enforce one group while
        //    the server records, or record for one while it enforces).
        let mode = groups.as_deref().map_or(settings.mode, |groups| {
            groups
                .load()
                .ai_mode(context.client, context.listener, settings.mode)
                .0
        });
        if mode == AiMode::Enforce {
            let snapshot = self.snapshot.load();
            if let Some(block) =
                suffix_match(&name, &snapshot, now, |b| b.expires_at).filter(|_| !is_exempt())
            {
                return Some(
                    Decision::new(
                        format!(
                            "'{}' auto-blocked by AI threat detection (category '{}')",
                            context.query_name, block.category
                        ),
                        Action::Block,
                    )
                    .with_group("ai")
                    .with_source(daygle_dns_policy::source::AI, Some(block.category.clone())),
                );
            }
        }

        // 2. Blocked categories (both modes: this is an operator policy).
        let groups = groups.as_deref()?.load();
        let (blocked, group_name) = groups.blocked_categories(context.client, context.listener);
        let blocked = blocked?;
        if blocked.is_empty() {
            return None;
        }
        let categories = self.categories.load();
        let labelled = suffix_match(&name, &categories, now, |c| c.expires_at)?;
        let category = labelled.category.as_str();
        if !blocked.iter().any(|c| c.eq_ignore_ascii_case(category)) || is_exempt() {
            return None;
        }
        Some(
            Decision::new(
                format!(
                    "'{}' blocked by category policy (category '{}', group '{}')",
                    context.query_name,
                    category,
                    group_name.unwrap_or("filtering group")
                ),
                Action::Block,
            )
            .with_group("ai")
            .with_source(daygle_dns_policy::source::AI, Some(category.to_string())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ActiveBlock;

    fn plugin(mode: AiMode, snapshot: BlockSnapshot) -> Arc<AiBlockPlugin> {
        plugin_with(mode, snapshot, CategorySnapshot::new())
    }

    fn plugin_with(
        mode: AiMode,
        snapshot: BlockSnapshot,
        categories: CategorySnapshot,
    ) -> Arc<AiBlockPlugin> {
        let settings = AiSettings {
            enabled: true,
            mode,
            ..AiSettings::default()
        };
        AiBlockPlugin::new(
            Arc::new(ArcSwap::from_pointee(snapshot)),
            Arc::new(ArcSwap::from_pointee(categories)),
            Arc::default(),
            Arc::new(ArcSwap::from_pointee(settings)),
        )
    }

    fn exempting(p: &AiBlockPlugin, domains: &[&str]) {
        p.exemptions
            .store(Arc::new(domains.iter().map(|d| d.to_string()).collect()));
    }

    fn category(domain: &str, category: &str) -> CategorySnapshot {
        let mut snapshot = CategorySnapshot::new();
        snapshot.insert(
            domain.to_string(),
            crate::scanner::ActiveCategory {
                category: category.to_string(),
                expires_at: i64::MAX,
            },
        );
        snapshot
    }

    /// A group covering 10.0.0.0/24 that blocks `categories`, with the given
    /// AI enforcement override (`None` follows the global mode).
    fn groups_blocking(
        categories: &[&str],
        ai_mode: Option<AiMode>,
    ) -> Arc<ArcSwap<AdvancedBlocking>> {
        let group = daygle_dns_core::blocking::BlockingGroup {
            id: "g".to_string(),
            name: "kids".to_string(),
            enabled: true,
            clients: vec!["10.0.0.0/24".to_string()],
            allow: vec![],
            block: vec![],
            allow_regex: vec![],
            block_regex: vec![],
            blocklists: vec![],
            response: Default::default(),
            ai_mode,
            safe_search: false,
            youtube_restricted: false,
            schedule: vec![],
            blocked_services: vec![],
            blocked_categories: categories.iter().map(|c| c.to_string()).collect(),
            blocked_security: vec![],
            blocked_tlds: vec![],
            block_local_addresses: false,
            limit_payloads: false,
            position: 0,
            last_modified_at: None,
        };
        Arc::new(ArcSwap::from_pointee(AdvancedBlocking::build(
            &[group],
            Arc::default(),
        )))
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
        let p = plugin(AiMode::Enforce, snapshot);

        let d = p.evaluate(&ctx("bad.example.com")).await.unwrap();
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.group.as_deref(), Some("ai"));

        let d = p.evaluate(&ctx("www.bad.example.com")).await.unwrap();
        assert_eq!(d.action, Action::Block);

        // unmatched domain
        assert!(p.evaluate(&ctx("fine.example.org")).await.is_none());
        // does not match label-suffix collisions
        assert!(p.evaluate(&ctx("notbad.example.com")).await.is_none());
    }

    /// A client group that records only exempts its clients; others are still
    /// blocked.
    #[tokio::test]
    async fn a_group_can_record_only_while_the_rest_enforce() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Enforce, snapshot);
        p.set_client_groups(groups_blocking(&[], Some(AiMode::Train)));
        // ctx() queries from 10.0.0.5, inside the group.
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());
        let mut outside = ctx("bad.example.com");
        outside.client = "192.0.2.1".parse().unwrap();
        assert!(p.evaluate(&outside).await.is_some());
    }

    /// The other direction: one group enforces while the global mode (and a
    /// client in no group) records only.
    #[tokio::test]
    async fn a_group_can_enforce_while_the_rest_record() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Train, snapshot);
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());

        p.set_client_groups(groups_blocking(&[], Some(AiMode::Enforce)));
        let d = p.evaluate(&ctx("bad.example.com")).await.unwrap();
        assert_eq!(d.action, Action::Block);
        let mut outside = ctx("bad.example.com");
        outside.client = "192.0.2.1".parse().unwrap();
        assert!(p.evaluate(&outside).await.is_none());
    }

    /// An exemption on a subdomain holds even though the verdict that
    /// matches the query is on its parent; the parent and its other
    /// subdomains stay blocked.
    #[tokio::test]
    async fn exempt_subdomain_of_a_blocked_parent_is_not_blocked() {
        let mut snapshot = BlockSnapshot::new();
        snapshot.insert(
            "bad.example.com".to_string(),
            ActiveBlock {
                category: "malware".to_string(),
                expires_at: i64::MAX,
            },
        );
        let p = plugin(AiMode::Enforce, snapshot);
        exempting(&p, &["www.bad.example.com"]);

        assert!(p.evaluate(&ctx("www.bad.example.com")).await.is_none());
        assert!(p.evaluate(&ctx("WWW.Bad.Example.com.")).await.is_none());
        assert!(p.evaluate(&ctx("cdn.www.bad.example.com")).await.is_none());
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_some());
        assert!(p.evaluate(&ctx("api.bad.example.com")).await.is_some());
    }

    /// The same for category blocking: an exempt subdomain of a labelled
    /// domain is not blocked for the group.
    #[tokio::test]
    async fn exempt_subdomain_escapes_category_blocking() {
        let p = plugin_with(
            AiMode::Train,
            BlockSnapshot::new(),
            category("casino.example", "gambling"),
        );
        p.set_client_groups(groups_blocking(&["gambling"], None));
        exempting(&p, &["help.casino.example"]);

        assert!(p.evaluate(&ctx("help.casino.example")).await.is_none());
        assert!(p.evaluate(&ctx("www.casino.example")).await.is_some());
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
            Arc::new(ArcSwap::from_pointee(CategorySnapshot::new())),
            Arc::default(),
            Arc::new(ArcSwap::from_pointee(settings)),
        );
        assert!(p.evaluate(&ctx("bad.example.com")).await.is_none());
    }

    /// A category the group blocks is blocked for its clients and nobody
    /// else, and in train mode too: this is the operator's rule, not a
    /// verdict the AI acted on.
    #[tokio::test]
    async fn blocked_category_blocks_group_clients_in_both_modes() {
        for mode in [AiMode::Train, AiMode::Enforce] {
            let p = plugin_with(
                mode,
                BlockSnapshot::new(),
                category("casino.example", "gambling"),
            );
            p.set_client_groups(groups_blocking(&["gambling"], None));

            let d = p.evaluate(&ctx("www.casino.example")).await.unwrap();
            assert_eq!(d.action, Action::Block);
            assert!(d.reason.contains("gambling"), "{}", d.reason);

            // A client outside the group is untouched.
            let mut outside = ctx("casino.example");
            outside.client = "192.0.2.1".parse().unwrap();
            assert!(p.evaluate(&outside).await.is_none());
        }
    }

    #[tokio::test]
    async fn unlisted_category_is_not_blocked() {
        let p = plugin_with(
            AiMode::Train,
            BlockSnapshot::new(),
            category("shop.example", "shopping"),
        );
        p.set_client_groups(groups_blocking(&["gambling"], None));
        assert!(p.evaluate(&ctx("shop.example")).await.is_none());
    }

    #[tokio::test]
    async fn clients_in_no_group_block_no_categories() {
        let p = plugin_with(
            AiMode::Train,
            BlockSnapshot::new(),
            category("casino.example", "gambling"),
        );
        // No client groups installed at all.
        assert!(p.evaluate(&ctx("casino.example")).await.is_none());
        // Installed, but this client belongs to none of them.
        p.set_client_groups(groups_blocking(&["gambling"], None));
        let mut outside = ctx("casino.example");
        outside.client = "192.0.2.1".parse().unwrap();
        assert!(p.evaluate(&outside).await.is_none());
    }
}
