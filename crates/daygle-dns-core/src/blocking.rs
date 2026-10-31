//! Data model for Advanced Blocking: named per-client-group allow/block
//! policies with domain lists, regex patterns and a configurable response.
//!
//! These are plain serializable structures shared by the storage layer
//! (`daygle-dns-authoritative`) and the matching engine
//! (`daygle-dns-policy`); neither the compiled regex nor any runtime state
//! lives here.

use serde::{Deserialize, Serialize};

use crate::schedule::ScheduleWindow;

/// What to answer when a query is blocked by an Advanced Blocking group.
///
/// Serialized adjacently-tagged so the API/DB round-trips as
/// `{"kind":"nx_domain"}` or `{"kind":"redirect","address":"0.0.0.0"}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "address", rename_all = "snake_case")]
pub enum BlockResponse {
    /// NXDOMAIN - the name does not exist.
    #[default]
    NxDomain,
    /// REFUSED.
    Refused,
    /// Empty NODATA (NOERROR, no records).
    NoData,
    /// Synthesize an address answer pointing at this IP (e.g. `0.0.0.0`).
    Redirect(std::net::IpAddr),
}

/// One Advanced Blocking group: a set of client networks and the allow/block
/// rules applied to their queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockingGroup {
    /// Primary key (UUID).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Whether the group is evaluated.
    pub enabled: bool,
    /// Client networks (CIDR) this group applies to. Empty means every client.
    pub clients: Vec<String>,
    /// Allowed domains (exact or `*.suffix`) - a whitelist that overrides the
    /// block rules for matching names.
    pub allow: Vec<String>,
    /// Blocked domains (exact or `*.suffix`).
    pub block: Vec<String>,
    /// Allow regex patterns - matched names are never blocked (override).
    pub allow_regex: Vec<String>,
    /// Block regex patterns.
    pub block_regex: Vec<String>,
    /// Names of the remote blocklist sources (scope `groups`) this group
    /// blocks with.
    #[serde(default)]
    pub blocklists: Vec<String>,
    /// Response returned for blocked queries.
    pub response: BlockResponse,
    /// Whether the AI scanner may auto-block these clients' queries (in
    /// enforce mode). The first enabled group a client belongs to decides;
    /// clients in no group are covered.
    #[serde(default = "default_true")]
    pub ai_blocking: bool,
    /// Force Safe Search on Google, Bing and DuckDuckGo for these clients.
    /// Like `ai_blocking`, the first enabled group a client belongs to
    /// decides (the global switch applies to everyone either way).
    #[serde(default)]
    pub safe_search: bool,
    /// Force YouTube Restricted Mode for these clients (same rule).
    #[serde(default)]
    pub youtube_restricted: bool,
    /// When the group applies; empty means always. Outside its windows the
    /// group is skipped as if it did not exist.
    #[serde(default)]
    pub schedule: Vec<ScheduleWindow>,
    /// Services (by id, e.g. `tiktok`) whose domains the group blocks.
    #[serde(default)]
    pub blocked_services: Vec<String>,
    /// AI content categories this group blocks (lowercase labels, e.g.
    /// `gambling`, `ads`). The scanner only *labels* a domain; blocking a
    /// label is an operator policy, scoped to these clients. Independent of
    /// `ai_blocking`, which governs auto-blocking of detected threats.
    #[serde(default)]
    pub blocked_categories: Vec<String>,
    /// Ordering position (lower groups are evaluated first).
    pub position: i64,
    /// When the group was last created or edited through the console or API,
    /// as RFC 3339. `null` for rows that predate this field and have not been
    /// edited since; reordering alone does not change it.
    #[serde(default)]
    pub last_modified_at: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Payload to create or update an Advanced Blocking group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingGroupInput {
    /// The group being edited: updated by id, so it can be renamed. Without
    /// one, a group with the same name is updated in place or a new one is
    /// created.
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub allow_regex: Vec<String>,
    #[serde(default)]
    pub block_regex: Vec<String>,
    #[serde(default)]
    pub blocklists: Vec<String>,
    #[serde(default)]
    pub response: BlockResponse,
    #[serde(default = "default_true")]
    pub ai_blocking: bool,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default)]
    pub youtube_restricted: bool,
    #[serde(default)]
    pub schedule: Vec<ScheduleWindow>,
    #[serde(default)]
    pub blocked_services: Vec<String>,
    #[serde(default)]
    pub blocked_categories: Vec<String>,
}

impl BlockingGroup {
    /// The input that saves this group back unchanged (by id).
    pub fn to_input(&self) -> BlockingGroupInput {
        BlockingGroupInput {
            id: Some(self.id.clone()),
            name: self.name.clone(),
            enabled: self.enabled,
            clients: self.clients.clone(),
            allow: self.allow.clone(),
            block: self.block.clone(),
            allow_regex: self.allow_regex.clone(),
            block_regex: self.block_regex.clone(),
            blocklists: self.blocklists.clone(),
            response: self.response.clone(),
            ai_blocking: self.ai_blocking,
            safe_search: self.safe_search,
            youtube_restricted: self.youtube_restricted,
            schedule: self.schedule.clone(),
            blocked_services: self.blocked_services.clone(),
            blocked_categories: self.blocked_categories.clone(),
        }
    }
}
