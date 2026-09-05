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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
    /// DNS over QUIC listener (RFC 9250).
    pub doq: DoqSettings,
    /// HTTP REST API + embedded web GUI.
    pub api: ApiSettings,
    /// Policy / filtering engine.
    pub policy: PolicySettings,
    /// Per-client and per-domain query rate limiting.
    pub rate_limit: RateLimitSettings,
    /// Logging.
    pub logging: LoggingSettings,
}

/// The runtime-tunable subset of the configuration that lives in the
/// database rather than the TOML file (everything the console's Settings,
/// Cache, and Domain Lists pages edit). The file keeps bootstrap-only
/// values: listeners, addresses, ports, paths, and certificates.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSettings {
    pub recursive: Option<RecursiveUpdate>,
    pub dot: Option<ListenerUpdate>,
    pub doh: Option<DohUpdate>,
    pub doq: Option<ListenerUpdate>,
    pub policy: Option<PolicyUpdate>,
}

/// Partial updates for the recursive resolver (matches the API's shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RecursiveUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnssec_validate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefetch_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefetch_ttl_fraction_pct: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefetch_min_queries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serve_stale_secs: Option<u64>,
}

/// Partial updates for TLS listeners (DoT and DoQ share the shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ListenerUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

/// Partial updates for DoH.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DohUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Partial updates for the policy engine (allow/block lists and Filter AAAA).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PolicyUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocklist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_aaaa: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_aaaa_except: Option<Vec<String>>,
}

impl RuntimeSettings {
    /// Whether anything in this overlay would change `config`.
    pub fn is_empty(&self) -> bool {
        self.recursive.is_none()
            && self.dot.is_none()
            && self.doh.is_none()
            && self.doq.is_none()
            && self.policy.is_none()
    }

    /// Apply the overlay to `config` in place. `None` fields are untouched.
    pub fn apply_to(&self, config: &mut DaygleConfig) {
        if let Some(r) = &self.recursive {
            if let Some(v) = r.enabled { config.recursive.enabled = v; }
            if let Some(v) = r.cache_size { config.recursive.cache_size = v; }
            if let Some(v) = &r.upstreams { config.recursive.upstreams = v.clone(); }
            if let Some(v) = r.dnssec_validate { config.recursive.dnssec_validate = v; }
            if let Some(v) = r.prefetch_enabled { config.recursive.prefetch_enabled = v; }
            if let Some(v) = r.prefetch_ttl_fraction_pct { config.recursive.prefetch_ttl_fraction_pct = v; }
            if let Some(v) = r.prefetch_min_queries { config.recursive.prefetch_min_queries = v; }
            if let Some(v) = r.serve_stale_secs { config.recursive.serve_stale_secs = v; }
        }
        if let Some(d) = &self.dot {
            if let Some(v) = d.enabled { config.dot.enabled = v; }
            if let Some(v) = d.port { config.dot.port = v; }
            if let Some(v) = d.self_signed { config.dot.self_signed = v; }
            if let Some(v) = &d.server_name { config.dot.server_name = v.clone(); }
        }
        if let Some(d) = &self.doh {
            if let Some(v) = d.enabled { config.doh.enabled = v; }
            if let Some(v) = d.port { config.doh.port = v; }
            if let Some(v) = d.self_signed { config.doh.self_signed = v; }
            if let Some(v) = &d.server_name { config.doh.server_name = v.clone(); }
            if let Some(v) = &d.endpoint { config.doh.endpoint = v.clone(); }
        }
        if let Some(d) = &self.doq {
            if let Some(v) = d.enabled { config.doq.enabled = v; }
            if let Some(v) = d.port { config.doq.port = v; }
            if let Some(v) = d.self_signed { config.doq.self_signed = v; }
            if let Some(v) = &d.server_name { config.doq.server_name = v.clone(); }
        }
        if let Some(p) = &self.policy {
            if let Some(v) = &p.allowlist { config.policy.allowlist = v.clone(); }
            if let Some(v) = &p.blocklist { config.policy.blocklist = v.clone(); }
            if let Some(v) = p.filter_aaaa { config.policy.filter_aaaa = v; }
            if let Some(v) = &p.filter_aaaa_except { config.policy.filter_aaaa_except = v.clone(); }
        }
    }

    /// Capture the DB-owned fields of `config` as a full overlay, so a save
    /// replaces the whole stored overlay (removed values revert to defaults,
    /// and a later default change in the app is picked up on next boot).
    pub fn capture(config: &DaygleConfig) -> Self {
        Self {
            recursive: Some(RecursiveUpdate {
                enabled: Some(config.recursive.enabled),
                cache_size: Some(config.recursive.cache_size),
                upstreams: Some(config.recursive.upstreams.clone()),
                dnssec_validate: Some(config.recursive.dnssec_validate),
                prefetch_enabled: Some(config.recursive.prefetch_enabled),
                prefetch_ttl_fraction_pct: Some(config.recursive.prefetch_ttl_fraction_pct),
                prefetch_min_queries: Some(config.recursive.prefetch_min_queries),
                serve_stale_secs: Some(config.recursive.serve_stale_secs),
            }),
            dot: Some(ListenerUpdate {
                enabled: Some(config.dot.enabled),
                port: Some(config.dot.port),
                self_signed: Some(config.dot.self_signed),
                server_name: Some(config.dot.server_name.clone()),
            }),
            doh: Some(DohUpdate {
                enabled: Some(config.doh.enabled),
                port: Some(config.doh.port),
                self_signed: Some(config.doh.self_signed),
                server_name: Some(config.doh.server_name.clone()),
                endpoint: Some(config.doh.endpoint.clone()),
            }),
            doq: Some(ListenerUpdate {
                enabled: Some(config.doq.enabled),
                port: Some(config.doq.port),
                self_signed: Some(config.doq.self_signed),
                server_name: Some(config.doq.server_name.clone()),
            }),
            policy: Some(PolicyUpdate {
                allowlist: Some(config.policy.allowlist.clone()),
                blocklist: Some(config.policy.blocklist.clone()),
                filter_aaaa: Some(config.policy.filter_aaaa),
                filter_aaaa_except: Some(config.policy.filter_aaaa_except.clone()),
            }),
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

    /// Serialize this configuration to a TOML document.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| DaygleError::Config(format!("cannot serialize config: {e}")))
    }

    /// Enforce cross-field invariants (ports, upstreams, etc.).
    pub fn validate(&self) -> Result<()> {
        // Only *enabled* listeners need a concrete port; a disabled service
        // may keep port 0 (e.g. ephemeral test setups).
        for (name, port, enabled) in [
            ("server.port", self.server.port, self.server.udp_enabled || self.server.tcp_enabled),
            ("dot.port", self.dot.port, self.dot.enabled),
            ("doh.port", self.doh.port, self.doh.enabled),
            ("doq.port", self.doq.port, self.doq.enabled),
            ("api.port", self.api.port, self.api.enabled),
        ] {
            if enabled && port == 0 {
                return Err(DaygleError::Config(format!("{name} must not be 0")));
            }
        }
        if self.doq.enabled && self.doq.idle_timeout_secs < 30 {
            return Err(DaygleError::Config(
                "doq.idle_timeout_secs must be >= 30 (RFC 9250 recommends 600)".to_string(),
            ));
        }
        let rec = &self.recursive;
        if rec.cache_size == 0 {
            return Err(DaygleError::Config(
                "recursive.cache_size must be >= 1".to_string(),
            ));
        }
        if rec.prefetch_enabled {
            if rec.prefetch_ttl_fraction_pct == 0 || rec.prefetch_ttl_fraction_pct > 100 {
                return Err(DaygleError::Config(
                    "recursive.prefetch_ttl_fraction_pct must be 1..=100".to_string(),
                ));
            }
            if rec.prefetch_min_queries == 0 {
                return Err(DaygleError::Config(
                    "recursive.prefetch_min_queries must be >= 1".to_string(),
                ));
            }
            if rec.prefetch_window_secs == 0 {
                return Err(DaygleError::Config(
                    "recursive.prefetch_window_secs must be >= 1".to_string(),
                ));
            }
        }
        if rec.serve_stale_secs > 7 * 24 * 3600 {
            return Err(DaygleError::Config(
                "recursive.serve_stale_secs must be <= 604800 (7 days)".to_string(),
            ));
        }
        if !self.api.users.is_empty() {
            for user in &self.api.users {
                if user.username.trim().is_empty() {
                    return Err(DaygleError::Config(
                        "api.users[].username must not be empty".to_string(),
                    ));
                }
                if !crate::auth::is_valid_password_hash(&user.password_hash) {
                    return Err(DaygleError::Config(format!(
                        "api.users[{}].password_hash is not a valid pbkdf2-sha256 hash \
                         (generate one with `daygle-dns hash-password`)",
                        user.username
                    )));
                }
            }
            let mut names: Vec<&str> = self.api.users.iter().map(|u| u.username.as_str()).collect();
            names.sort_unstable();
            if names.windows(2).any(|w| w[0] == w[1]) {
                return Err(DaygleError::Config(
                    "api.users contains duplicate usernames".to_string(),
                ));
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
        for (label, domains) in [
            ("policy.allowlist", &self.policy.allowlist),
            ("policy.blocklist", &self.policy.blocklist),
            ("policy.filter_aaaa_except", &self.policy.filter_aaaa_except),
        ] {
            for domain in domains {
                validate_domain_pattern(domain).map_err(|e| {
                    DaygleError::Config(format!("{label} contains invalid domain '{domain}': {e}"))
                })?;
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
        for zone in &self.authoritative.stub_zones {
            if zone.name.trim().is_empty() {
                return Err(DaygleError::Config(
                    "authoritative.stub_zones contains a zone with an empty name".to_string(),
                ));
            }
            if zone.nss.is_empty() && zone.enabled {
                return Err(DaygleError::Config(format!(
                    "stub zone '{}' has no nameservers (learn them with the DNS client tool or set them manually)",
                    zone.name
                )));
            }
        }
        let log = &self.logging;
        if log.query_log_enabled {
            if log.query_log_dir.trim().is_empty() {
                return Err(DaygleError::Config(
                    "logging.query_log_dir must not be empty when query_log_enabled".to_string(),
                ));
            }
            if log.query_log_retention_days > 3650 {
                return Err(DaygleError::Config(
                    "logging.query_log_retention_days must be <= 3650".to_string(),
                ));
            }
        }
        if log.query_db_max_rows != 0 && log.query_db_max_rows < 100 {
            return Err(DaygleError::Config(
                "logging.query_db_max_rows must be 0 (unlimited) or >= 100".to_string(),
            ));
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ConditionalZoneConfig {
    /// Zone apex to forward, e.g. `corp.internal`.
    pub name: String,
    /// Dedicated upstreams for this zone (same forms as `recursive.upstreams`).
    pub upstreams: Vec<String>,
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
    /// Stub zones: zones whose nameservers we track and forward to directly
    /// (see [`StubZoneConfig`]). Managed at runtime through the API as well;
    /// entries here are merged with the database list at startup.
    pub stub_zones: Vec<StubZoneConfig>,
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
            stub_zones: vec![],
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
            enabled: false,
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

/// Console role: what a logged-in user may do.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full access: reads *and* mutations (zone edits, settings, cache ops).
    #[default]
    Admin,
    /// Read-only: every mutating endpoint is rejected with `403 Forbidden`.
    Viewer,
}

impl Role {
    /// Lowercase name used in JSON responses and the config file.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

/// A console user credential. Passwords are stored as PBKDF2-HMAC-SHA256
/// hashes (`pbkdf2-sha256$<iterations>$<salt>$<hash>`, base64); see
/// [`hash_password`](crate::auth::hash_password) or
/// `daygle-dns hash-password` to generate one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiUser {
    /// Login username.
    pub username: String,
    /// PBKDF2 password hash (never a plaintext password).
    pub password_hash: String,
    /// What the account may do. Defaults to `admin` for compatibility with
    /// configuration files written before roles existed.
    #[serde(default)]
    pub role: Role,
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
    /// Ignored when `users` are configured (username/password login takes
    /// over, including read endpoints).
    pub api_token: String,
    /// Console user accounts. When non-empty, the GUI shows a login screen
    /// and *every* API call requires a session token issued by
    /// `POST /api/auth/login`.
    pub users: Vec<ApiUser>,
    /// Require login on the console. On by default: with no `users`
    /// configured, the first GUI visit offers a one-time "create admin
    /// account" setup and every API call requires a session from then on.
    /// Set to `false` to serve the console fully open (development only).
    /// Note: an `api_token` keeps its legacy GETs-open/mutations-tokened
    /// behavior regardless of this flag, and configured `users` always
    /// enforce login.
    pub auth_required: bool,
    /// Session token lifetime for login sessions, in seconds (default 12h).
    pub session_ttl_secs: u64,
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
            users: vec![],
            auth_required: true,
            session_ttl_secs: 43_200,
            gui_enabled: true,
            cors_origins: vec![],
        }
    }
}

/// DNS over QUIC settings (RFC 9250).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DoqSettings {
    /// Serve DNS over QUIC.
    pub enabled: bool,
    /// Address the DoQ listener binds to.
    pub listen: String,
    /// DoQ port (default 853, per RFC 9250).
    pub port: u16,
    /// TLS certificate (PEM, certificate chain first). Defaults to the DoT
    /// certificate paths so one cert serves both.
    pub cert_path: String,
    /// TLS private key (PEM).
    pub key_path: String,
    /// When the certificate/key are absent, generate a self-signed one for
    /// this name and write it to `cert_path`/`key_path`.
    pub self_signed: bool,
    /// Subject name used for the generated self-signed certificate.
    pub server_name: String,
    /// QUIC idle timeout in seconds. RFC 9250 recommends 600 or larger.
    pub idle_timeout_secs: u64,
}

impl Default for DoqSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0".to_string(),
            port: 853,
            cert_path: "/etc/daygle-dns/certs/server.crt".to_string(),
            key_path: "/etc/daygle-dns/certs/server.key".to_string(),
            self_signed: true,
            server_name: "daygle.local".to_string(),
            idle_timeout_secs: 600,
        }
    }
}

/// Policy / filtering engine settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicySettings {
    /// Enable policy evaluation.
    pub enabled: bool,
    /// Domains (or `*.suffix`) always allowed, even when another policy would block them.
    /// The GUI presents these as trusted domains.
    pub allowlist: Vec<String>,
    /// Domains (or `*.suffix`) blocked outright.
    /// The GUI presents these as blocked domains.
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
    /// Filter AAAA (IPv6) answers: when true, AAAA queries are answered with an
    /// empty NODATA response so dual-stack clients fall back to IPv4 (the
    /// equivalent of Technitium's "Block AAAA" app).
    pub filter_aaaa: bool,
    /// Names (or `*.suffix` wildcards) exempt from `filter_aaaa`, i.e. hosts
    /// that must stay reachable over IPv6.
    pub filter_aaaa_except: Vec<String>,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            allowlist: vec![],
            blocklist: vec![],
            blocklist_files: vec![],
            blocklist_sources: vec![],
            denied_networks: vec![],
            allowed_networks: vec![],
            rules: vec![],
            filter_aaaa: false,
            filter_aaaa_except: vec![],
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
    /// Persist every served query to a daily JSON-lines file under
    /// `query_log_dir` (like Technitium's query logs).
    pub query_log_enabled: bool,
    /// Directory for the daily query-log files
    /// (`queries-YYYY-MM-DD.log`, one JSON object per line).
    pub query_log_dir: String,
    /// Delete query-log files older than this many days at rotation
    /// (0 keeps every file).
    pub query_log_retention_days: u32,
    /// Record every served query into the SQLite database so the console's
    /// Query Logs view can search, filter and export them.
    pub query_db_enabled: bool,
    /// Retention cap for the database query log: at most this many rows are
    /// kept (the oldest are deleted opportunistically). 0 keeps everything.
    pub query_db_max_rows: usize,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            ring_buffer: 2000,
            query_log_enabled: false,
            query_log_dir: "/var/log/daygle-dns".to_string(),
            query_log_retention_days: 30,
            query_db_enabled: true,
            query_db_max_rows: 200_000,
        }
    }
}

/// A stub zone: keep track of another zone's nameservers without hosting it.
///
/// Queries for names inside a stub zone are resolved directly against the
/// zone's NS servers (learned from the zone's SOA/NS records when the stub is
/// created or refreshed), instead of walking the root → TLD → authoritative
/// chain. This is the lightweight equivalent of BIND's stub zones and
/// Technitium's stub zones: useful when you know a sibling nameserver hosts
/// `internal.example.com` and want queries for it to go straight there.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StubZoneConfig {
    /// Zone apex the stub covers, e.g. `branch.example.com`.
    pub name: String,
    /// The zone's nameservers. Bare IPs are used as-is; hostnames are
    /// resolved through the default upstreams when the stub refreshes.
    pub nss: Vec<String>,
    /// How often to re-check the zone's SOA/NS on its nameservers, in
    /// seconds, so newly added nameservers are picked up.
    pub refresh_secs: u64,
    /// Whether this stub zone is active.
    pub enabled: bool,
}

impl Default for StubZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            nss: vec![],
            refresh_secs: 3600,
            enabled: true,
        }
    }
}

/// Validate an exact domain or a strict-subdomain wildcard (`*.example.com`).
///
/// This deliberately accepts ordinary DNS hostnames only. Keeping manually
/// entered policy lists to DNS label syntax prevents a typo such as a URL or a
/// hosts-file line from silently becoming a policy entry.
pub fn validate_domain_pattern(pattern: &str) -> std::result::Result<(), String> {
    let value = pattern.trim().trim_end_matches('.');
    let value = value.strip_prefix("*.").unwrap_or(value);
    if value.is_empty() {
        return Err("domain must not be empty".to_string());
    }
    if value.contains('*') || value.starts_with('.') || value.len() > 253 {
        return Err("expected a DNS name or *.suffix wildcard".to_string());
    }
    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("DNS labels must contain 1 to 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS labels must not start or end with '-'".to_string());
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("DNS labels may contain only letters, numbers and '-'".to_string());
        }
    }
    Ok(())
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
        assert!(cfg.policy.allowlist.is_empty());
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
    fn validates_domain_policy_patterns() {
        assert!(DaygleConfig::parse(
            "[policy]\nallowlist = [\"Example.COM.\", \"*.trusted.test\"]\n"
        )
        .is_ok());
        assert!(DaygleConfig::parse("[policy]\nallowlist = [\"https://example.com\"]\n").is_err());
        assert!(DaygleConfig::parse("[policy]\nblocklist = [\"*.\"]\n").is_err());
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
