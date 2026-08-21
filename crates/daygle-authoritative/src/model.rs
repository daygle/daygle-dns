//! Serializable zone and record data structures.

use serde::{Deserialize, Serialize};

/// A DNS zone, persisted in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Zone {
    /// Primary key (UUID).
    pub id: String,
    /// Zone apex, e.g. `example.com` (no trailing dot).
    pub name: String,
    /// SOA primary nameserver, e.g. `ns1.example.com.`.
    pub primary_ns: String,
    /// SOA administrator mailbox, e.g. `admin.example.com.`.
    pub admin_mailbox: String,
    /// SOA serial number.
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

/// Payload used to create a zone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneInput {
    pub name: String,
    #[serde(default)]
    pub primary_ns: Option<String>,
    #[serde(default)]
    pub admin_mailbox: Option<String>,
    #[serde(default)]
    pub serial: Option<u32>,
    #[serde(default)]
    pub refresh: Option<u32>,
    #[serde(default)]
    pub retry: Option<u32>,
    #[serde(default)]
    pub expire: Option<u32>,
    #[serde(default)]
    pub minimum: Option<u32>,
}

/// A DNS resource record, persisted in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub id: String,
    /// Owning zone id.
    pub zone_id: String,
    /// Owner name. Fully qualified, no trailing dot, e.g. `www.example.com`.
    pub name: String,
    /// Record type: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `PTR`, `CAA`.
    pub rtype: String,
    /// Full RDATA string as it would appear in a zone file, e.g. an MX
    /// stores `10 mail.example.com.` and a TXT stores `"hello world"`.
    pub content: String,
    pub ttl: u32,
    /// Priority for MX/SRV records (informational; the value is embedded in
    /// `content`).
    pub priority: u16,
    pub disabled: bool,
}

/// Payload used to upsert a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInput {
    /// Owner name. Relative (`www`) or fully qualified (`www.example.com.`).
    pub name: String,
    pub rtype: String,
    pub content: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub priority: u16,
    #[serde(default)]
    pub disabled: bool,
}

fn default_ttl() -> u32 {
    3600
}

/// The set of record types Daygle understands.
pub const KNOWN_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "CAA",
];

/// One deletion in an RFC 2136 dynamic update: an RRset (name + type), a
/// single RR (name + type + content), or everything at a name (type `None`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeleteSpec {
    /// Fully qualified owner name, no trailing dot.
    pub name: String,
    /// Record type to delete; `None` deletes every type at `name`.
    pub rtype: Option<String>,
    /// Exact RDATA (canonical content string) to delete; `None` deletes the
    /// whole RRset.
    pub content: Option<String>,
}

/// A new SOA to write when a dynamic update explicitly sets one.
#[derive(Debug, Clone, PartialEq)]
pub struct SoaUpdate {
    pub primary_ns: String,
    pub admin_mailbox: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// The parsed contents of an RFC 2136 UPDATE message, ready to be applied to
/// a zone in a single transaction.
#[derive(Debug, Clone, Default)]
pub struct DynamicUpdate {
    /// Records to add (class IN), with absolute owner names.
    pub adds: Vec<RecordInput>,
    /// Records/RRsets to delete.
    pub deletes: Vec<DeleteSpec>,
    /// Explicit SOA rewrite for the zone apex, if the update carried one.
    pub soa: Option<SoaUpdate>,
}

/// Secondary-zone metadata: which masters a zone replicates from and when the
/// last successful transfer happened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecondaryZone {
    /// Owning zone id.
    pub zone_id: String,
    /// Master addresses as configured (`IP`, `IP:port`, or `[IPv6]:port`).
    pub masters: Vec<String>,
    /// Refresh interval in seconds.
    pub refresh_secs: u64,
    /// RFC 3339 timestamp of the last successful transfer, if any.
    pub last_transfer: Option<String>,
}

/// A named client network group used by split-horizon views, e.g.
/// `LAN = ["192.168.20.0/24"]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitHorizonNetwork {
    /// Primary key (UUID).
    pub id: String,
    /// Human-readable network name, e.g. `LAN`.
    pub name: String,
    /// CIDR ranges belonging to this network, e.g. `192.168.20.0/24`.
    pub cidrs: Vec<String>,
}

/// Payload to create or update a split-horizon network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitHorizonNetworkInput {
    pub name: String,
    pub cidrs: Vec<String>,
}

/// One typed answer value for a split-horizon entry, in zone-file
/// presentation format: `A` → `10.0.0.5`, `AAAA` → `fd00::1`, `MX` →
/// `10 mail.example.com.`, `TXT` → `"hello world"` (quoted),
/// `CNAME` → `target.example.com.`, `SRV` → `0 5 5060 sip.example.com.`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitHorizonRecord {
    pub rtype: String,
    pub content: String,
}

/// Record types a split-horizon entry can synthesize.
pub const SPLIT_HORIZON_RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "CNAME", "SRV"];

/// One split-horizon view rule: clients in `networks` receive `records` for
/// `domain` instead of the normal answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitHorizonEntry {
    /// Primary key (UUID).
    pub id: String,
    /// Fully qualified domain name, no trailing dot, e.g. `www.example.com`.
    pub domain: String,
    /// Network names and/or literal CIDRs (e.g. `["LAN", "10.0.0.0/8"]`);
    /// empty means every client.
    pub networks: Vec<String>,
    /// IPv4/IPv6 addresses returned to matching clients. Kept for backward
    /// compatibility: it is always the A/AAAA subset of `records`.
    pub ips: Vec<String>,
    /// Typed answers (A, AAAA, MX, TXT, CNAME, SRV) served to matching
    /// clients for queries of the matching type.
    #[serde(default)]
    pub records: Vec<SplitHorizonRecord>,
    /// TTL of synthesized answers.
    pub ttl: u32,
    /// When true the entry is skipped (kept for later use).
    pub disabled: bool,
    /// Ordering for entries of the same domain (first match wins on ties).
    pub position: i64,
}

/// Payload to create or update a split-horizon entry.
///
/// `records` is the canonical form. For compatibility, `ips` alone still
/// works and is converted to A/AAAA records; when both are present `records`
/// wins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitHorizonEntryInput {
    pub domain: String,
    pub networks: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub records: Vec<SplitHorizonRecord>,
    #[serde(default = "default_split_horizon_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub disabled: bool,
}

fn default_split_horizon_ttl() -> u32 {
    60
}

/// Direction to move a split-horizon entry within its domain's ordering.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MoveDirection {
    /// Move earlier (higher precedence).
    Up,
    /// Move later (lower precedence).
    Down,
}
