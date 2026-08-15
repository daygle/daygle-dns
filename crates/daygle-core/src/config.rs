//! The Daygle DNS configuration model, serialized from TOML.
//!
//! A single [`DaygleConfig`] describes every subsystem of the server. The
//! installer writes the example file to `/etc/daygle/daygle.toml`.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

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
    /// HTTP REST API + embedded web GUI.
    pub api: ApiSettings,
    /// Policy / filtering engine.
    pub policy: PolicySettings,
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
            api: ApiSettings::default(),
            policy: PolicySettings::default(),
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
        for upstream in &self.recursive.upstreams {
            if upstream.trim().is_empty() {
                return Err(DaygleError::Config(
                    "recursive.upstreams contains an empty entry".to_string(),
                ));
            }
        }
        for (label, networks) in [
            ("policy.denied_networks", &self.policy.denied_networks),
            ("policy.allowed_networks", &self.policy.allowed_networks),
        ] {
            for net in networks {
                if net.parse::<ipnet::IpNet>().is_err() {
                    return Err(DaygleError::Config(format!(
                        "{label} contains invalid network '{net}'"
                    )));
                }
            }
        }
        Ok(())
    }
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
}

impl Default for AuthoritativeSettings {
    fn default() -> Self {
        Self {
            database: "daygle.db".to_string(),
            zones_dir: None,
            default_primary_ns: "ns1.daygle.test.".to_string(),
            default_admin_mailbox: "admin.daygle.test.".to_string(),
            dnssec_enabled: true,
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
            cert_path: "/etc/daygle/certs/server.crt".to_string(),
            key_path: "/etc/daygle/certs/server.key".to_string(),
            self_signed: true,
            server_name: "daygle.local".to_string(),
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
            denied_networks: vec![],
            allowed_networks: vec![],
            rules: vec![],
        }
    }
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
database = "/tmp/daygle.db"

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
}
