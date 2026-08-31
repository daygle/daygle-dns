//! The Daygle DNS configuration model, serialized from TOML.
//!
//! A single [`DaygleConfig`] describes every subsystem of the server. The
//! installer writes the example file to `/etc/daygle-dns/daygle-dns.toml`.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{DaygleError, Result};

/// Root configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DaygleConfig {
    /// Core DNS listeners (UDP/TCP on port 53).
    pub server: ServerSettings,
    /// Recursive resolution subsystem.
    pub recursive: RecursiveSettings,
    /// Authoritative zone storage.
    pub authoritative: AuthoritativeSettings,
    /// DNS over TLS listener.
    pub dot: DotSettings,
    /// DNS over HTTPS listener.
    pub doh: DohSettings,
    /// HTTP REST API + embedded web GUI.
    pub api: ApiSettings,
    /// Policy / filtering engine.
    pub policy: PolicySettings,
    /// Per-client and per-domain query rate limiting.
    pub rate_limit: RateLimitSettings,
    /// Logging.
    pub logging: LoggingSettings,
}

impl Default for DaygleConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            recursive: RecursiveSettings::default(),
            authoritative: AuthoritativeSettings::default(),
            dot: DotSettings::default(),
            doh: DohSettings::default(),
            api: ApiSettings::default(),
            policy: PolicySettings::default(),
            rate_limit: RateLimitSettings::default(),
            logging: LoggingSettings::default(),
        }
    }
}

impl DaygleConfig {
    /// Parse a TOML document into a validated configuration.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: DaygleConfig = toml::from_str(text)
            .map_err(|e| DaygleError::Config(format!("invalid TOML: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load and parse a configuration file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| {
            DaygleError::Config(format!("cannot read {}: {e}", path.display()))
        })?;
        Self::parse(&text)
    }

    /// Enforce cross-field invariants (ports, upstreams, etc.).
    pub fn validate(&self) -> Result<()> {
        for (name, port) in [
            ("server.port", self.server.port),
            ("dot.port", self.dot.port),
            ("doh.port", self.doh.port),
            ("api.port", self.api.port),
        ] {
            if port == 0 {
                return Err(DaygleError::Config(format!("{name} must not be 0")));
            }
        }
        if self.recursive.attempts == 0 {
            return Err(DaygleError::Config(
                "recursive.attempts must be >= 1".to_string(),
            ));
        }
        let dnssec = &self.authoritative;
        if dnssec.dnssec_sig_validity_days == 0 {
            return Err(DaygleError::Config(
                "authoritative.dnssec_sig_validity_days must be >= 1".to_string(),
            ));
        }
        if dnssec.dnssec_rollover_overlap_days == 0
            || dnssec.dnssec_rollover_retire_days == 0
        {
            return Err(DaygleError::Config(
                "authoritative.dnssec_rollover_{overlap,retire}_days must be >= 1".to_string(),
            ));
        }
        if dnssec.dnssec_maintenance_secs < 60 {
            return Err(DaygleError::Config(
                "authoritative.dnssec_maintenance_secs must be >= 60".to_string(),
            ));
        }
        let rl = &self.rate_limit;
        if rl.client_max_queries == 0 || rl.domain_max_queries == 0 {
            return Err(DaygleError::Config(
                "rate_limit.*_max_queries must be >= 1".to_string(),
            ));
        }
        if rl.client_window_secs == 0 || rl.domain_window_secs == 0 {
            return Err(DaygleError::Config(
                "rate_limit.*_window_secs must be >= 1".to_string(),
            ));
        }
        for upstream in &self.recursive.upstreams {
            if upstream.trim().is_empty() {
                return Err(DaygleError::Config(
                    "recursive.upstreams contains an empty entry".to_string(),
                ));
            }
        }
        for zone in &self.recursive.conditional_zones {
            if zone.name.trim().is_empty() {
                return Err(DaygleError::Config(
                    "recursive.conditional_zones contains a zone with an empty name".to_string(),
                ));
            }
            if zone.upstreams.is_empty() {
                return Err(DaygleError::Config(format!(
                    "conditional zone '{}' has no upstreams",
                    zone.name
                )));
            }
            for upstream in &zone.upstreams {
                if upstream.trim().is_empty() {
                    return Err(DaygleError::Config(format!(
                        "conditional zone '{}' contains an empty upstream",
                        zone.name
                    )));
                }
            }
        }
        if self.authoritative.notify_enabled && self.authoritative.notify_targets.is_empty() {
            return Err(DaygleError::Config(
                "authoritative.notify_enabled requires notify_targets".to_string(),
            ));
        }
        for target in &self.authoritative.notify_targets {
            if parse_master_addr(target).is_err() {
                return Err(DaygleError::Config(format!(
                    "authoritative.notify_targets contains invalid address '{target}'"
                )));
            }
        }
        if self.authoritative.notify_listen_enabled
            && self.authoritative.secondary_zones.is_empty()
        {
            return Err(DaygleError::Config(
                "authoritative.notify_listen_enabled requires secondary_zones".to_string(),
            ));
        }
        for (label, networks) in [
            ("policy.denied_networks", &self.policy.denied_networks),
            ("policy.allowed_networks", &self.policy.allowed_networks),
            ("authoritative.axfr_networks", &self.authoritative.axfr_networks),
            ("authoritative.update_networks", &self.authoritative.update_networks),
        ] {
            for net in networks {
                if net.parse::<ipnet::IpNet>().is_err() {
                    return Err(DaygleError::Config(format!(
                        "{label} contains invalid network '{net}'"
                    )));
                }
            }
        }
        for source in &self.policy.blocklist_sources {
            if source.name.trim().is_empty() {
                return Err(DaygleError::Config(
                    "policy.blocklist_sources contains a source with an empty name".to_string(),
                ));
            }
            url::Url::parse(&source.url).map_err(|e| {
                DaygleError::Config(format!(
                    "blocklist source '{}' has invalid URL '{}': {e}",
                    source.name, source.url
                ))
            })?;
            if source.refresh_secs == 0 {
                return Err(DaygleError::Config(format!(
                    "blocklist source '{}' has refresh_secs = 0",
                    source.name
                )));
            }
        }
        let tsig_names: std::collections::HashSet<String> = self
            .authoritative
            .tsig_keys
            .iter()
            .map(|k| k.name.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        if tsig_names.len() != self.authoritative.tsig_keys.len() {
            return Err(DaygleError::Config(
                "authoritative.tsig_keys contains duplicate names".to_string(),
            ));
        }
        for key in &self.authoritative.tsig_keys {
            if key.name.trim().is_empty() {
                return Err(DaygleError::Config(
                    "authoritative.tsig_keys contains a key with an empty name".to_string(),
                ));
            }
            let algorithm = key.algorithm.trim();
            if !matches!(algorithm, "hmac-sha256" | "hmac-sha384" | "hmac-sha512") {
                return Err(DaygleError::Config(format!(
                    "tsig key '{}' uses unsupported algorithm '{algorithm}' (supported: hmac-sha256, hmac-sha384, hmac-sha512)",
                    key.name
                )));
            }
            if key.secret.trim().is_empty() {
                return Err(DaygleError::Config(format!(
                    "tsig key '{}' has an empty secret",
                    key.name
                )));
            }
            if base64::engine::general_purpose::STANDARD.decode(key.secret.trim()).is_err() {
                return Err(DaygleError::Config(format!(
                    "tsig key '{}' secret is not valid base64",
                    key.name
                )));
            }
        }
        for binding in self
            .authoritative
            .tsig_transfer_zones
            .iter()
            .chain(&self.authoritative.tsig_update_zones)
        {
            let Some((_zone, key)) = binding.split_once('=') else {
                return Err(DaygleError::Config(format!(
                    "tsig zone binding '{binding}' must be 'zone=key-name'"
                )));
            };
            if !tsig_names.contains(key.trim_end_matches('.').to_ascii_lowercase().as_str()) {
                return Err(DaygleError::Config(format!(
                    "tsig zone binding '{binding}' references unknown key '{key}'"
                )));
            }
        }
        for zone in &self.authoritative.secondary_zones {
            if zone.name.trim().is_empty() {
                return Err(DaygleError::Config(
                    "authoritative.secondary_zones contains a zone with an empty name".to_string(),
                ));
            }
            if zone.masters.is_empty() {
                return Err(DaygleError::Config(format!(
                    "secondary zone '{}' has no masters",
                    zone.name
                )));
            }
            for master in &zone.masters {
                parse_master_addr(master).map_err(|e| {
                    DaygleError::Config(format!(
                        "secondary zone '{}' has invalid master '{master}': {e}",
                        zone.name
                    ))
                })?;
            }
        }
        Ok(())
    }
}

/// Parse a master address of the form `IP`, `IP:port`, or `[IPv6]:port`
/// (port defaults to 53).
pub fn parse_master_addr(entry: &str) -> std::result::Result<std::net::SocketAddr, String> {
    let entry = entry.trim();
    if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, 53));
    }
    entry
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("cannot parse as IP[:port]: {e}"))
}

/// Core UDP/TCP DNS listener settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Address the plaintext DNS listeners bind to.
    pub listen: String,
    /// UDP/TCP port (default 53).
    pub port: u16,
    /// Serve plaintext UDP.
    pub udp_enabled: bool,
    /// Serve plaintext TCP.
    pub tcp_enabled: bool,
    /// TCP idle timeout in milliseconds.
    pub tcp_timeout_ms: u64,
    /// Outbound response buffer size (bytes).
    pub response_buffer_size: usize,
    /// Watch the configuration file and apply policy, upstream and listener
    /// changes without restarting.
    pub reload_enabled: bool,
    /// How often the configuration file is polled for changes, in
    /// milliseconds.
    pub reload_interval_ms: u64,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_string(),
            port: 53,
            udp_enabled: true,
            tcp_enabled: true,
            tcp_timeout_ms: 5000,
            response_buffer_size: 4096,
            reload_enabled: true,
            reload_interval_ms: 2000,
        }
    }
}

/// Recursive resolution subsystem settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RecursiveSettings {
    /// Whether recursion is offered at all.
    pub enabled: bool,
    /// Upstream servers. Accepts `8.8.8.8`, `1.1.1.1:53`,
    /// `tls://1.1.1.1:853@cloudflare-dns.com` and `https://...` forms.
    ///
    /// When empty, the operating system's resolver configuration is used.
    pub upstreams: Vec<String>,
    /// Use `/etc/resolv.conf` (or the Windows registry) instead of `upstreams`.
    pub use_system_config: bool,
    /// Number of entries in the response cache (positive caching).
    pub cache_size: usize,
    /// Per-nameserver timeout in seconds.
    pub timeout_secs: u64,
    /// Number of attempts per nameserver (retry logic).
    pub attempts: usize,
    /// Validate DNSSEC responses (sets AD and rejects bogus chains).
    pub dnssec_validate: bool,
    /// Lower bound, in seconds, applied to cached TTLs.
    pub min_cache_ttl: u32,
    /// Upper bound, in seconds, for caching negative (NXDOMAIN/NODATA) answers.
    /// Hickory derives the authoritative TTL from the SOA; this caps it.
    pub negative_cache_ttl: u32,
    /// Conditional forwarding: queries for these zones are resolved by the
    /// zone's dedicated upstreams instead of the default ones. The most
    /// specific (deepest) matching zone wins.
    pub conditional_zones: Vec<ConditionalZoneConfig>,
    /// Refresh popular cached names in the background as their TTLs near
    /// expiry, so repeated lookups never wait on an upstream round trip.
    pub prefetch_enabled: bool,
    /// Refresh a popular cached name when its remaining TTL drops below this
    /// fraction of the original TTL (e.g. 10 refreshes when 10% is left).
    /// Requires `prefetch_enabled`.
    pub prefetch_ttl_fraction_pct: u32,
    /// Minimum number of queries for a name within the window before it
    /// counts as popular and becomes prefetch-eligible.
    pub prefetch_min_queries: u32,
    /// Sliding window in seconds used to count queries per name for
    /// prefetch popularity.
    pub prefetch_window_secs: u64,
    /// Serve expired cache entries for up to this many seconds when all
    /// upstreams fail, so popular domains keep resolving during upstream
    /// outages. 0 disables serve-stale.
    pub serve_stale_secs: u64,
}

impl Default for RecursiveSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            upstreams: vec![],
            use_system_config: true,
            cache_size: 8192,
            timeout_secs: 5,
            attempts: 3,
            dnssec_validate: true,
            min_cache_ttl: 0,
            negative_cache_ttl: 3600,
            conditional_zones: vec![],
            prefetch_enabled: true,
            prefetch_ttl_fraction_pct: 10,
            prefetch_min_queries: 5,
            prefetch_window_secs: 600,
            serve_stale_secs: 86400,
        }
    }
}

/// A conditional forwarding zone: `name` is resolved via `upstreams` instead
/// of the global `recursive.upstreams`. Accepts the same upstream forms
/// (plain IP, `tls://IP:port@hostname`, …).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ConditionalZoneConfig {
    /// Zone apex to forward, e.g. `corp.internal`.
    pub name: String,
    /// Dedicated upstreams for this zone (same forms as `recursive.upstreams`).
    pub upstreams: Vec<String>,
}

impl Default for ConditionalZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            upstreams: vec![],
        }
    }
}

/// Authoritative zone storage settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthoritativeSettings {
    /// Path to the SQLite database.
    pub database: String,
    /// Optional directory of BIND-style zone files imported at startup.
    pub zones_dir: Option<String>,
    /// Default SOA primary nameserver used when a zone is created.
    pub default_primary_ns: String,
    /// Default SOA contact mailbox used when a zone is created.
    pub default_admin_mailbox: String,
    /// Whether zones with signing keys are DNSSEC-signed on reload.
    pub dnssec_enabled: bool,
    /// RRSIG validity window in days. The DNSSEC maintenance task re-signs
    /// zones at half this age so signatures never expire in service.
    pub dnssec_sig_validity_days: u32,
    /// DNSSEC key lifetime in days before a rollover starts (0 disables
    /// rollover). During a rollover the zone is double-signed by the old and
    /// the new key while both DNSKEYs are published.
    pub dnssec_rollover_days: u32,
    /// How long (days) old and new keys are both active (double-signing)
    /// before the old key is retired.
    pub dnssec_rollover_overlap_days: u32,
    /// How long (days) a retired key stays published (its DNSKEY stays in the
    /// zone) after it stops signing, so validators with cached RRSIGs can
    /// still verify, before the key is removed entirely.
    pub dnssec_rollover_retire_days: u32,
    /// How often (seconds) the DNSSEC maintenance task checks signature age
    /// and key rollover state.
    pub dnssec_maintenance_secs: u64,
    /// Serve AXFR/IXFR zone transfers for hosted zones.
    pub axfr_enabled: bool,
    /// Client networks allowed to request zone transfers. When empty, any
    /// client may transfer (subject to `axfr_enabled`).
    pub axfr_networks: Vec<String>,
    /// Accept RFC 2136 dynamic updates (UPDATE messages) for primary zones.
    /// Updates are written through to SQLite and applied live.
    pub allow_dynamic_updates: bool,
    /// Client networks allowed to send dynamic updates. When empty, any
    /// client may update (subject to `allow_dynamic_updates`).
    pub update_networks: Vec<String>,
    /// Secondary zones replicated from remote masters via AXFR/IXFR.
    pub secondary_zones: Vec<SecondaryZoneConfig>,
    /// Send RFC 1996 NOTIFY to `notify_targets` when a primary zone changes.
    pub notify_enabled: bool,
    /// NOTIFY targets (secondaries), each `IP`, `IP:port`, or `[IPv6]:port`
    /// (port defaults to 53). Requires `notify_enabled`.
    pub notify_targets: Vec<String>,
    /// Accept inbound NOTIFY from masters for secondary zones and refresh
    /// immediately instead of waiting for the refresh interval.
    pub notify_listen_enabled: bool,
    /// TSIG keys (RFC 8945). Referenced by name from `tsig_transfer_zones`,
    /// `tsig_update_zones`, and secondary-zone master keys.
    pub tsig_keys: Vec<TsigKeyConfig>,
    /// Zones whose AXFR/IXFR responses must be TSIG-signed with the named
    /// key; requests from other clients are refused. Each entry is
    /// `zone=key-name`.
    pub tsig_transfer_zones: Vec<String>,
    /// Zones whose RFC 2136 updates must be TSIG-signed with the named key;
    /// unsigned updates are refused. Each entry is `zone=key-name`.
    pub tsig_update_zones: Vec<String>,
    /// When true, a TSIG-signed request must also carry a valid signature on
    /// our response (request MAC inclusion) per RFC 8945 §5. Always enabled
    /// for responses we sign.
    pub tsig_require_request_mac: bool,
}

impl Default for AuthoritativeSettings {
    fn default() -> Self {
        Self {
            database: "daygle-dns.db".to_string(),
            zones_dir: None,
            default_primary_ns: "ns1.daygle.test.".to_string(),
            default_admin_mailbox: "admin.daygle.test.".to_string(),
            dnssec_enabled: true,
            dnssec_sig_validity_days: 14,
            dnssec_rollover_days: 90,
            dnssec_rollover_overlap_days: 30,
            dnssec_rollover_retire_days: 14,
            dnssec_maintenance_secs: 3600,
            axfr_enabled: false,
            axfr_networks: vec![],
            allow_dynamic_updates: false,
            update_networks: vec![],
            secondary_zones: vec![],
            notify_enabled: false,
            notify_targets: vec![],
            notify_listen_enabled: false,
            tsig_keys: vec![],
            tsig_transfer_zones: vec![],
            tsig_update_zones: vec![],
            tsig_require_request_mac: true,
        }
    }
}

/// A TSIG shared secret (RFC 8945). The secret is base64 (standard
/// alphabet, padding optional), matching BIND's `secret` file format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TsigKeyConfig {
    /// Key name in DNS name syntax, e.g. `daygle-transfer.`. The remote peer
    /// must reference the same name.
    pub name: String,
    /// HMAC algorithm name (RFC 8945 §6): `hmac-sha256`, `hmac-sha384`, or
    /// `hmac-sha512`.
    pub algorithm: String,
    /// Shared secret, base64-encoded.
    pub secret: String,
}

impl Default for TsigKeyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            algorithm: "hmac-sha256".to_string(),
            secret: String::new(),
        }
    }
}

/// A secondary zone: a zone replicated from one or more masters via
/// AXFR/IXFR. The first reachable master is used; the zone's records and SOA
/// are refreshed from it on `refresh_secs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SecondaryZoneConfig {
    /// Zone apex, e.g. `example.com`.
    pub name: String,
    /// Master servers, each `IP`, `IP:port`, or `[IPv6]:port` (port 53 when
    /// omitted).
    pub masters: Vec<String>,
    /// How often to check the master for updates, in seconds.
    pub refresh_secs: u64,
    /// Whether this secondary zone is active.
    pub enabled: bool,
    /// TSIG key name (from `authoritative.tsig_keys`) used to sign transfer
    /// requests to this zone's masters. Empty disables TSIG for this zone.
    pub tsig_key: String,
}

impl Default for SecondaryZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            masters: vec![],
            refresh_secs: 3600,
            enabled: true,
            tsig_key: String::new(),
        }
    }
}

/// DNS over TLS settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DotSettings {
    /// Serve DNS over TLS.
    pub enabled: bool,
    /// Address the DoT listener binds to.
    pub listen: String,
    /// DoT port (default 853).
    pub port: u16,
    /// TLS certificate (PEM, certificate chain first).
    pub cert_path: String,
    /// TLS private key (PEM).
    pub key_path: String,
    /// When the certificate/key are absent, generate a self-signed one for
    /// this name and write it to `cert_path`/`key_path`.
    pub self_signed: bool,
    /// Subject name used for the generated self-signed certificate.
    pub server_name: String,
}

impl Default for DotSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "0.0.0.0".to_string(),
            port: 853,
            cert_path: "/etc/daygle-dns/certs/server.crt".to_string(),
            key_path: "/etc/daygle-dns/certs/server.key".to_string(),
            self_signed: true,
            server_name: "daygle.local".to_string(),
        }
    }
}

/// DNS over HTTPS settings (RFC 8484).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DohSettings {
    /// Serve DNS over HTTPS.
    pub enabled: bool,
    /// Address the DoH listener binds to.
    pub listen: String,
    /// DoH port (default 443).
    pub port: u16,
    /// TLS certificate (PEM, certificate chain first).
    pub cert_path: String,
    /// TLS private key (PEM).
    pub key_path: String,
    /// When the certificate/key are absent, generate a self-signed one for
    /// this name and write it to `cert_path`/`key_path`.
    pub self_signed: bool,
    /// Subject name used for the generated self-signed certificate.
    pub server_name: String,
    /// HTTP path that serves DNS messages, e.g. `/dns-query`.
    pub endpoint: String,
}

impl Default for DohSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0".to_string(),
            port: 443,
            cert_path: "/etc/daygle-dns/certs/server.crt".to_string(),
            key_path: "/etc/daygle-dns/certs/server.key".to_string(),
            self_signed: true,
            server_name: "daygle.local".to_string(),
            endpoint: "/dns-query".to_string(),
        }
    }
}

/// REST API and GUI settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ApiSettings {
    /// Serve the REST API and GUI.
    pub enabled: bool,
    /// Address the HTTP server binds to.
    pub listen: String,
    /// HTTP port (default 5380).
    pub port: u16,
    /// Bearer token required by mutating endpoints. Empty disables auth.
    pub api_token: String,
    /// Serve the embedded web GUI at `/`.
    pub gui_enabled: bool,
    /// Comma-separated list of allowed CORS origins.
    pub cors_origins: Vec<String>,
}

impl Default for ApiSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1".to_string(),
            port: 5380,
            api_token: String::new(),
            gui_enabled: true,
            cors_origins: vec![],
        }
    }
}

/// Policy / filtering engine settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicySettings {
    /// Enable policy evaluation.
    pub enabled: bool,
    /// Domains (or `*.suffix`) blocked outright.
    pub blocklist: Vec<String>,
    /// Files containing one domain per line, merged into the blocklist.
    pub blocklist_files: Vec<String>,
    /// Remote blocklist sources fetched over HTTP(S) and refreshed on a
    /// schedule, like Technitium's blocklist management. Domains from all
    /// sources are merged into the blocklist.
    pub blocklist_sources: Vec<BlocklistSourceConfig>,
    /// Client networks denied entirely (REFUSED).
    pub denied_networks: Vec<String>,
    /// Client networks allowed; when non-empty, all others are denied.
    pub allowed_networks: Vec<String>,
    /// Per-client / per-domain rules, evaluated in order.
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            blocklist: vec![],
            blocklist_files: vec![],
            blocklist_sources: vec![],
            denied_networks: vec![],
            allowed_networks: vec![],
            rules: vec![],
        }
    }
}

/// A remote blocklist source: a URL fetched over HTTP(S) whose contents are
/// merged into the blocklist and re-fetched every `refresh_secs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistSourceConfig {
    /// Human-readable name, used in logs and status output.
    pub name: String,
    /// HTTP(S) URL of the blocklist.
    pub url: String,
    /// Content format: `domains` (one domain per line), `hosts` (a hosts
    /// file, e.g. StevenBlack), or `adblock` (AdGuard/uBlock syntax).
    pub format: BlocklistFormat,
    /// How often to re-fetch the source, in seconds (default 24 h).
    pub refresh_secs: u64,
    /// Whether this source is fetched at all.
    pub enabled: bool,
}

impl Default for BlocklistSourceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            format: BlocklistFormat::Domains,
            refresh_secs: 86400,
            enabled: true,
        }
    }
}

/// The wire format of a remote blocklist source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// One domain per line; comments (`#`, `!`) are skipped.
    #[default]
    Domains,
    /// A hosts file: lines like `0.0.0.0 example.com`. The hostname column is
    /// used; localhost/loopback entries are ignored.
    Hosts,
    /// AdGuard/uBlock origin syntax: `||example.com^`, `@@` exceptions are
    /// ignored (treated as not-blocked).
    Adblock,
}

/// A single ordered policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyRule {
    /// Client networks this rule applies to (`0.0.0.0/0` matches everyone).
    pub clients: Vec<String>,
    /// Domains this rule applies to; empty means every domain.
    pub domains: Vec<String>,
    /// Action: `allow`, `block`, or `redirect`.
    pub action: String,
    /// IPv4/IPv6 address returned for `redirect` rules.
    pub redirect: Option<IpAddr>,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            clients: vec![],
            domains: vec![],
            action: "allow".to_string(),
            redirect: None,
        }
    }
}

/// Per-client and per-domain query rate limiting.
///
/// Limits are fixed windows: a client (source IP) or domain (query name) may
/// send at most `*_max_queries` requests per `*_window_secs`. Requests over
/// the limit receive SERVFAIL and are counted in the `rate_limited` metric.
/// Each counter is tracked independently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSettings {
    /// Enforce the limits below.
    pub enabled: bool,
    /// Max queries per client (source IP) per window.
    pub client_max_queries: u32,
    /// Per-client window length in seconds.
    pub client_window_secs: u64,
    /// Max queries per domain (query name) per window.
    pub domain_max_queries: u32,
    /// Per-domain window length in seconds.
    pub domain_window_secs: u64,
    /// Never rate-limit loopback clients (127.0.0.0/8, ::1).
    pub exempt_loopback: bool,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            client_max_queries: 100,
            client_window_secs: 60,
            domain_max_queries: 600,
            domain_window_secs: 60,
            exempt_loopback: true,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingSettings {
    /// `tracing` filter, e.g. `info`, `daygle=debug`.
    pub level: String,
    /// Keep at most this many entries in the in-memory log ring buffer
    /// (exposed through the API).
    pub ring_buffer: usize,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            ring_buffer: 2000,
        }
    }
}

/// Helper: expand a list of domain patterns into a normalized set.
pub fn normalize_domains(entries: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    entries
        .into_iter()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg = DaygleConfig::parse("").unwrap();
        assert_eq!(cfg.server.port, 53);
        assert_eq!(cfg.dot.port, 853);
        assert!(cfg.recursive.dnssec_validate);
    }

    #[test]
    fn parses_full_config() {
        let text = r#"
[server]
port = 5353

[recursive]
upstreams = ["1.1.1.1", "tls://8.8.8.8:853@dns.google"]
cache_size = 4096
timeout_secs = 3
attempts = 2
dnssec_validate = true

[authoritative]
database = "/tmp/daygle-dns.db"

[dot]
enabled = false

[api]
port = 5380
api_token = "secret"

[[policy.rules]]
clients = ["192.168.0.0/16"]
domains = ["*.ads.example.com"]
action = "block"
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(cfg.server.port, 5353);
        assert_eq!(cfg.recursive.upstreams.len(), 2);
        assert_eq!(cfg.recursive.attempts, 2);
        assert!(!cfg.dot.enabled);
        assert_eq!(cfg.api.api_token, "secret");
        assert_eq!(cfg.policy.rules.len(), 1);
        assert_eq!(cfg.policy.rules[0].action, "block");
    }

    #[test]
    fn rejects_bad_network() {
        let text = "[policy]\ndenied_networks = [\"not-a-network\"]\n";
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(DaygleConfig::parse("[server]\nport = 53\nbogus = 1\n").is_err());
    }

    #[test]
    fn parses_axfr_and_secondary_zones() {
        let text = r#"
[authoritative]
axfr_enabled = true
axfr_networks = ["192.0.2.0/24"]

[[authoritative.secondary_zones]]
name = "example.com"
masters = ["192.0.2.1", "192.0.2.2:5353"]
refresh_secs = 600
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert!(cfg.authoritative.axfr_enabled);
        assert_eq!(cfg.authoritative.axfr_networks.len(), 1);
        assert_eq!(cfg.authoritative.secondary_zones.len(), 1);
        let zone = &cfg.authoritative.secondary_zones[0];
        assert_eq!(zone.name, "example.com");
        assert_eq!(zone.masters.len(), 2);
        assert_eq!(zone.refresh_secs, 600);
    }

    #[test]
    fn parses_notify_settings() {
        let text = r#"
[authoritative]
notify_enabled = true
notify_targets = ["192.0.2.20", "192.0.2.21:5353", "[2001:db8::20]:53"]
notify_listen_enabled = true

[[authoritative.secondary_zones]]
name = "example.com"
masters = ["192.0.2.1"]
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert!(cfg.authoritative.notify_enabled);
        assert_eq!(cfg.authoritative.notify_targets.len(), 3);
        assert!(cfg.authoritative.notify_listen_enabled);

        // Disabled by default.
        let defaults = DaygleConfig::default().authoritative;
        assert!(!defaults.notify_enabled);
        assert!(defaults.notify_targets.is_empty());
        assert!(!defaults.notify_listen_enabled);

        // notify_enabled without targets is rejected.
        assert!(DaygleConfig::parse("[authoritative]\nnotify_enabled = true\n").is_err());
        // Bad target addresses are rejected.
        assert!(DaygleConfig::parse(
            "[authoritative]\nnotify_enabled = true\nnotify_targets = [\"nope\"]\n"
        )
        .is_err());
        // Inbound NOTIFY without any secondary zone is rejected.
        assert!(DaygleConfig::parse(
            "[authoritative]\nnotify_listen_enabled = true\n"
        )
        .is_err());
    }

    #[test]
    fn parses_dnssec_maintenance_settings() {
        let text = r#"
[authoritative]
dnssec_enabled = true
dnssec_sig_validity_days = 30
dnssec_rollover_days = 0
dnssec_rollover_overlap_days = 7
dnssec_rollover_retire_days = 3
dnssec_maintenance_secs = 600
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(cfg.authoritative.dnssec_sig_validity_days, 30);
        assert_eq!(cfg.authoritative.dnssec_rollover_days, 0);
        assert_eq!(cfg.authoritative.dnssec_rollover_overlap_days, 7);
        assert_eq!(cfg.authoritative.dnssec_rollover_retire_days, 3);
        assert_eq!(cfg.authoritative.dnssec_maintenance_secs, 600);

        // Sensible defaults: 14-day signatures, 90-day keys, 30d overlap,
        // 14d retirement, hourly maintenance.
        let defaults = DaygleConfig::default().authoritative;
        assert_eq!(defaults.dnssec_sig_validity_days, 14);
        assert_eq!(defaults.dnssec_rollover_days, 90);
        assert_eq!(defaults.dnssec_rollover_overlap_days, 30);
        assert_eq!(defaults.dnssec_rollover_retire_days, 14);
        assert_eq!(defaults.dnssec_maintenance_secs, 3600);

        // Nonsensical values are rejected.
        assert!(DaygleConfig::parse(
            "[authoritative]\ndnssec_sig_validity_days = 0\n"
        )
        .is_err());
        assert!(DaygleConfig::parse(
            "[authoritative]\ndnssec_rollover_overlap_days = 0\n"
        )
        .is_err());
        assert!(DaygleConfig::parse(
            "[authoritative]\ndnssec_maintenance_secs = 10\n"
        )
        .is_err());
    }

    #[test]
    fn parses_dynamic_update_settings() {
        let text = r#"
[authoritative]
allow_dynamic_updates = true
update_networks = ["192.0.2.0/24", "2001:db8::/32"]
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert!(cfg.authoritative.allow_dynamic_updates);
        assert_eq!(cfg.authoritative.update_networks.len(), 2);
        assert!(DaygleConfig::default()
            .authoritative
            .update_networks
            .is_empty());
        assert!(!DaygleConfig::default()
            .authoritative
            .allow_dynamic_updates);

        // Invalid networks are rejected like the other network lists.
        let bad = r#"
[authoritative]
allow_dynamic_updates = true
update_networks = ["nope"]
"#;
        assert!(DaygleConfig::parse(bad).is_err());
    }

    #[test]
    fn parses_rate_limit_settings() {
        let text = r#"
[rate_limit]
enabled = true
client_max_queries = 50
client_window_secs = 10
domain_max_queries = 2000
domain_window_secs = 30
exempt_loopback = false
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.client_max_queries, 50);
        assert_eq!(cfg.rate_limit.client_window_secs, 10);
        assert_eq!(cfg.rate_limit.domain_max_queries, 2000);
        assert_eq!(cfg.rate_limit.domain_window_secs, 30);
        assert!(!cfg.rate_limit.exempt_loopback);

        // Disabled by default, loopback exempt by default.
        assert!(!DaygleConfig::default().rate_limit.enabled);
        assert!(DaygleConfig::default().rate_limit.exempt_loopback);

        // Zero limits / windows are rejected.
        assert!(DaygleConfig::parse("[rate_limit]\nclient_max_queries = 0\n").is_err());
        assert!(DaygleConfig::parse("[rate_limit]\nclient_window_secs = 0\n").is_err());
    }

    #[test]
    fn parses_doh_section() {
        let text = r#"
[doh]
enabled = true
listen = "127.0.0.1"
port = 8443
endpoint = "/dns-query"
self_signed = true
server_name = "dns.example.com"
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert!(cfg.doh.enabled);
        assert_eq!(cfg.doh.port, 8443);
        assert_eq!(cfg.doh.endpoint, "/dns-query");
        assert_eq!(cfg.doh.server_name, "dns.example.com");
    }

    #[test]
    fn doh_defaults_to_disabled_on_port_443() {
        let cfg = DaygleConfig::parse("").unwrap();
        assert!(!cfg.doh.enabled);
        assert_eq!(cfg.doh.port, 443);
        assert_eq!(cfg.doh.endpoint, "/dns-query");
    }

    #[test]
    fn parses_blocklist_sources() {
        let text = r#"
[policy]

[[policy.blocklist_sources]]
name = "StevenBlack hosts"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
format = "hosts"
refresh_secs = 43200

[[policy.blocklist_sources]]
name = "AdGuard DNS filter"
url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
format = "adblock"
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(cfg.policy.blocklist_sources.len(), 2);
        assert_eq!(cfg.policy.blocklist_sources[0].format, BlocklistFormat::Hosts);
        assert_eq!(cfg.policy.blocklist_sources[0].refresh_secs, 43200);
        assert_eq!(cfg.policy.blocklist_sources[1].format, BlocklistFormat::Adblock);
        assert_eq!(cfg.policy.blocklist_sources[1].refresh_secs, 86400);
    }

    #[test]
    fn rejects_bad_blocklist_source_url() {
        let text = r#"
[[policy.blocklist_sources]]
name = "bad"
url = "not a url"
"#;
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_zero_refresh_blocklist_source() {
        let text = r#"
[[policy.blocklist_sources]]
name = "bad"
url = "https://example.com/list.txt"
refresh_secs = 0
"#;
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn parses_conditional_zones() {
        let text = r#"
[recursive]
upstreams = ["8.8.8.8"]

[[recursive.conditional_zones]]
name = "corp.internal"
upstreams = ["192.0.2.10", "tls://192.0.2.11:853@corp-dns.internal"]

[[recursive.conditional_zones]]
name = "lab.internal"
upstreams = ["192.0.2.20:5353"]
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(cfg.recursive.conditional_zones.len(), 2);
        assert_eq!(cfg.recursive.conditional_zones[0].name, "corp.internal");
        assert_eq!(cfg.recursive.conditional_zones[0].upstreams.len(), 2);
    }

    #[test]
    fn rejects_conditional_zone_without_upstreams() {
        let text = r#"
[[recursive.conditional_zones]]
name = "corp.internal"
upstreams = []
"#;
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_secondary_zone_without_masters() {
        let text = r#"
[[authoritative.secondary_zones]]
name = "example.com"
masters = []
"#;
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_bad_master_addr() {
        let text = r#"
[[authoritative.secondary_zones]]
name = "example.com"
masters = ["not-an-addr"]
"#;
        assert!(DaygleConfig::parse(text).is_err());
    }

    #[test]
    fn master_addr_defaults_to_port_53() {
        assert_eq!(
            parse_master_addr("192.0.2.1").unwrap(),
            "192.0.2.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_master_addr("[2001:db8::1]:5353").unwrap(),
            "[2001:db8::1]:5353".parse().unwrap()
        );
    }
}
