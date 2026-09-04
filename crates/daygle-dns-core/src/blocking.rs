//! Data model for Advanced Blocking: named per-client-group allow/block
//! policies with domain lists, regex patterns and a configurable response.
//!
//! These are plain serializable structures shared by the storage layer
//! (`daygle-dns-authoritative`) and the matching engine
//! (`daygle-dns-policy`); neither the compiled regex nor any runtime state
//! lives here.

use serde::{Deserialize, Serialize};

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
    /// Response returned for blocked queries.
    pub response: BlockResponse,
    /// Ordering position (lower groups are evaluated first).
    pub position: i64,
}

fn default_true() -> bool {
    true
}

/// Payload to create or update an Advanced Blocking group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingGroupInput {
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
    pub response: BlockResponse,
}
