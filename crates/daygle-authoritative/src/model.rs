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
