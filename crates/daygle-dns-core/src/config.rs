//! The Daygle DNS configuration model, serialized from TOML.
//!
//! A single [`DaygleConfig`] describes every subsystem of the server. The
//! installer writes the example file to `/etc/daygle-dns/daygle-dns.toml`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// AI scanner: background classification of observed domains.
    pub ai: AiSettings,
    /// Console defaults for showing dates and times.
    pub display: DisplaySettings,
    /// How the web console and API are reached: HTTP and/or HTTPS.
    pub web: WebSettings,
    /// Periodic (or disabled) checks for a newer Daygle DNS release.
    pub updates: UpdateCheckSettings,
    /// Sending logs to a syslog server.
    pub syslog: SyslogSettings,
    /// DNS64 (RFC 6147): AAAA answers made from A records for IPv6-only
    /// clients behind NAT64.
    pub dns64: Dns64Settings,
    /// EDNS Client Subnet (RFC 7871) sent to forwarding upstreams.
    pub ecs: EcsSettings,
    /// Named networks (`[[networks]]`), e.g. `LAN` = `192.168.1.0/24`, that
    /// network settings can name instead of repeating the addresses.
    pub networks: Vec<NamedNetwork>,
}

/// EDNS Client Subnet (RFC 7871): tell forwarding upstreams which network a
/// query comes from, so CDNs that pick servers by location answer with ones
/// near the client rather than near this server. Edited in Settings ->
/// Resolver and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EcsSettings {
    pub enabled: bool,
    /// Send this network for every query (e.g. this site's public
    /// `203.0.113.0/24`). Empty: send each client's own network, cut to
    /// `ipv4_prefix` / `ipv6_prefix` bits (private addresses are not sent).
    pub subnet: String,
    /// How much of a client's IPv4 address is sent (RFC 7871 advises 24).
    pub ipv4_prefix: u8,
    /// How much of a client's IPv6 address is sent (RFC 7871 advises 56).
    pub ipv6_prefix: u8,
}

impl Default for EcsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            subnet: String::new(),
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    }
}

/// [`EcsSettings`], parsed.
#[derive(Debug, Clone)]
pub struct Ecs {
    fixed: Option<ipnet::IpNet>,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
}

impl EcsSettings {
    /// Parse the settings (`None` when ECS is off).
    pub fn compile(&self) -> std::result::Result<Option<Ecs>, String> {
        if !(1..=32).contains(&self.ipv4_prefix) {
            return Err("ipv4_prefix must be 1 to 32".to_string());
        }
        if !(1..=128).contains(&self.ipv6_prefix) {
            return Err("ipv6_prefix must be 1 to 128".to_string());
        }
        let subnet = self.subnet.trim();
        let fixed = if subnet.is_empty() {
            None
        } else {
            Some(
                parse_network(subnet)
                    .ok_or_else(|| format!("'{subnet}' is not a network or address"))?
                    .trunc(),
            )
        };
        Ok(self.enabled.then_some(Ecs {
            fixed,
            ipv4_prefix: self.ipv4_prefix,
            ipv6_prefix: self.ipv6_prefix,
        }))
    }
}

impl Ecs {
    /// The subnet to send for `client`: the fixed one, else the client's
    /// network when its address is public.
    pub fn subnet_for(&self, client: IpAddr) -> Option<ipnet::IpNet> {
        if let Some(fixed) = self.fixed {
            return Some(fixed);
        }
        let net = match client.to_canonical() {
            IpAddr::V4(v4) if is_global_v4(v4) => {
                ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, self.ipv4_prefix).ok()?)
            }
            IpAddr::V6(v6) if is_global_v6(v6) => {
                ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, self.ipv6_prefix).ok()?)
            }
            _ => return None,
        };
        Some(net.trunc())
    }
}

/// Whether `ip` is a global unicast address (not loopback, unspecified,
/// unique-local, link-local, multicast or documentation).
fn is_global_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first == 0x2001 && ip.segments()[1] == 0x0db8)
        || ip.to_ipv4_mapped().is_some())
}

/// DNS64 (RFC 6147): when a recursive AAAA query finds no IPv6 address, the
/// name's IPv4 addresses are returned as AAAA records inside a NAT64 prefix
/// (RFC 6052), so IPv6-only clients can reach IPv4-only hosts through a
/// NAT64 gateway. Edited in Settings -> Recursive and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Dns64Settings {
    pub enabled: bool,
    /// The NAT64 prefix: a /32, /40, /48, /56, /64 or /96. The well-known
    /// `64:ff9b::/96` by default.
    pub prefix: String,
    /// Client networks that get synthesized answers (CIDRs or addresses);
    /// empty means every client.
    pub clients: Vec<String>,
}

impl Default for Dns64Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: "64:ff9b::/96".to_string(),
            clients: vec![],
        }
    }
}

/// [`Dns64Settings`], parsed.
#[derive(Debug, Clone)]
pub struct Dns64 {
    prefix: ipnet::Ipv6Net,
    clients: Vec<ipnet::IpNet>,
}

/// The well-known NAT64 prefix (RFC 6052 §2.1).
const DNS64_WELL_KNOWN: Ipv6Addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);

impl Dns64Settings {
    /// Parse the settings (`None` when DNS64 is off). `networks` resolves
    /// the network names in `clients`.
    pub fn compile(&self, networks: &[NamedNetwork]) -> std::result::Result<Option<Dns64>, String> {
        let prefix: ipnet::Ipv6Net = self
            .prefix
            .trim()
            .parse()
            .map_err(|_| format!("'{}' is not an IPv6 prefix", self.prefix.trim()))?;
        if ![32, 40, 48, 56, 64, 96].contains(&prefix.prefix_len()) {
            return Err(format!(
                "the prefix must be a /32, /40, /48, /56, /64 or /96 (RFC 6052), not /{}",
                prefix.prefix_len()
            ));
        }
        let prefix = prefix.trunc();
        if prefix.addr().octets()[8] != 0 {
            return Err("bits 64 to 71 of the prefix must be zero (RFC 6052)".to_string());
        }
        let mut clients = Vec::new();
        for entry in resolve_network_list(networks, &self.clients) {
            let net = parse_network(&entry).ok_or_else(|| {
                format!("'{entry}' is not a network, an address or a network name")
            })?;
            clients.push(net);
        }
        Ok(self.enabled.then_some(Dns64 { prefix, clients }))
    }
}

impl Dns64 {
    /// Whether `client` gets synthesized answers.
    pub fn applies_to(&self, client: IpAddr) -> bool {
        let client = client.to_canonical();
        self.clients.is_empty() || self.clients.iter().any(|n| n.contains(&client))
    }

    /// The IPv6 address for `v4` (RFC 6052 §2.2), or `None` for an address
    /// the well-known prefix must not carry (non-global ones, §3.1).
    pub fn synthesize(&self, v4: Ipv4Addr) -> Option<Ipv6Addr> {
        if self.prefix.addr() == DNS64_WELL_KNOWN && !is_global_v4(v4) {
            return None;
        }
        let mut octets = self.prefix.addr().octets();
        let mut at = usize::from(self.prefix.prefix_len() / 8);
        for byte in v4.octets() {
            // Octet 8 (bits 64-71) is the reserved "u" octet.
            if at == 8 {
                at += 1;
            }
            octets[at] = byte;
            at += 1;
        }
        Some(Ipv6Addr::from(octets))
    }
}

/// Whether `ip` is globally reachable (not private, shared, loopback,
/// link-local, documentation, benchmarking, reserved or multicast).
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b))
        || a >= 240)
}

/// Remote logging: send the server log (and optionally every query) to a
/// syslog server, RFC 5424 format, over UDP or TCP. Edited in Settings ->
/// General and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogSettings {
    pub enabled: bool,
    /// `host`, `host:port`, `udp://host:port` or `tcp://host:port`; UDP and
    /// port 514 by default. The host may be a name or an address.
    pub server: String,
    /// Syslog facility: `daemon`, `user` or `local0`..`local7`.
    pub facility: String,
    /// Lowest server-log level sent: `error`, `warn` or `info`.
    pub level: String,
    /// Also send a line for every query answered.
    pub queries: bool,
}

impl Default for SyslogSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            facility: "daemon".to_string(),
            level: "info".to_string(),
            queries: false,
        }
    }
}

/// Where syslog lines go, parsed from [`SyslogSettings::server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogTarget {
    pub tcp: bool,
    pub host: String,
    pub port: u16,
}

impl SyslogSettings {
    /// The facility code (RFC 5424 §6.2.1).
    pub fn facility_code(&self) -> Option<u8> {
        match self.facility.trim() {
            "" | "daemon" => Some(3),
            "user" => Some(1),
            f => f
                .strip_prefix("local")
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|n| *n <= 7)
                .map(|n| 16 + n),
        }
    }

    /// The lowest level sent, as a rank (error 3, warn 2, info 1).
    pub fn level_rank(&self) -> Option<u8> {
        match self.level.trim() {
            "error" => Some(3),
            "warn" => Some(2),
            "" | "info" => Some(1),
            _ => None,
        }
    }

    pub fn target(&self) -> std::result::Result<SyslogTarget, String> {
        let text = self.server.trim();
        let (tcp, rest) = if let Some(rest) = text.strip_prefix("tcp://") {
            (true, rest)
        } else {
            (false, text.strip_prefix("udp://").unwrap_or(text))
        };
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| format!("'{text}': unbalanced '['"))?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("'{text}': bad port"))?,
                None if tail.is_empty() => 514,
                None => return Err(format!("'{text}' is not host:port")),
            };
            (host.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (
                    host.to_string(),
                    port.parse().map_err(|_| format!("'{text}': bad port"))?,
                ),
                _ => (rest.to_string(), 514),
            }
        };
        if host.is_empty() || host.contains(char::is_whitespace) || port == 0 {
            return Err(format!(
                "'{text}' is not a syslog server (host or host:port)"
            ));
        }
        Ok(SyslogTarget { tcp, host, port })
    }

    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        if self.facility_code().is_none() {
            return Err(format!(
                "unknown facility '{}': use daemon, user or local0-local7",
                self.facility
            ));
        }
        if self.level_rank().is_none() {
            return Err(format!(
                "unknown level '{}': use error, warn or info",
                self.level
            ));
        }
        if self.enabled {
            self.target()?;
        }
        Ok(())
    }
}

/// How the web console and REST API are served. Edited in Settings ->
/// General and stored in the database like other runtime settings; the
/// `daygle-dns reset-web-access` command puts it back to plain HTTP on
/// `api.port` if a change locks you out. Listen address, CORS and whether
/// the GUI is served at all stay in `[api]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WebSettings {
    /// Serve over plain HTTP.
    pub http_enabled: bool,
    /// HTTP port; 0 means `api.port` from the config file.
    pub http_port: u16,
    /// Serve over HTTPS.
    pub https_enabled: bool,
    /// HTTPS port.
    pub https_port: u16,
    /// Managed certificate (Certificates page) presented over HTTPS.
    pub https_certificate: String,
    /// With both enabled, answer HTTP requests with a redirect to HTTPS.
    pub redirect_http: bool,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            http_enabled: true,
            http_port: 0,
            https_enabled: false,
            https_port: 5443,
            https_certificate: String::new(),
            redirect_http: false,
        }
    }
}

/// The managed certificate created for HTTPS when none is chosen.
pub const WEB_SELF_SIGNED_CERT: &str = "web-console";

/// How often (and whether at all) this server checks GitHub for a newer
/// Daygle DNS release. The check runs in the background away from DNS
/// traffic; GitHub's unauthenticated API allows only 60 requests per hour
/// per client IP, shared with everything else using that address, so the
/// interval has a floor (see [`MIN_UPDATE_CHECK_INTERVAL_SECS`]) and can be
/// switched off entirely. Edited in Settings -> General as "Update Checks".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateCheckSettings {
    /// Whether automatic checks (and the dashboard's update banner) run.
    /// Off: nothing probes GitHub; "Update Now" and the manual update
    /// command keep working.
    pub enabled: bool,
    /// Seconds between background checks.
    pub check_interval_secs: u64,
    /// When a release ships a *different* AI models bundle than the one
    /// installed, download and install it automatically at the check
    /// cadence (the same verified checksum + rollback-protected apply path
    /// the console's "Update AI Models" button uses; each install restarts
    /// the service, a brief DNS pause). Default off: automatic model
    /// writes and restarts are an explicit operator choice, compared here
    /// by content hashes - a release that ships unchanged models causes
    /// no run.
    #[serde(default)]
    pub auto_refresh_models: bool,
}

impl Default for UpdateCheckSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            // Hourly: one API request per hour, far inside the shared
            // unauthenticated budget, and a fresh release is still noticed
            // within an hour of publication.
            check_interval_secs: 3600,
            auto_refresh_models: false,
        }
    }
}

/// Floor for `updates.check_interval_secs`, enforced by validate() and by
/// the background warmer: 10 minutes = at most 6 API requests per hour for
/// this server, leaving room for other GitHub users behind the same
/// address. (Every update.sh / install.sh run uses additional one-off calls
/// on top of these.)
pub const MIN_UPDATE_CHECK_INTERVAL_SECS: u64 = 600;

impl WebSettings {
    /// Check the settings a console user can change. `api_port` is the
    /// config file's port, which an `http_port` of 0 stands for.
    pub fn check(&self, api_port: u16) -> std::result::Result<(), String> {
        if !self.http_enabled && !self.https_enabled {
            return Err("enable HTTP, HTTPS or both, or the console cannot be reached".into());
        }
        let http_port = self.effective_http_port(api_port);
        if self.https_enabled && self.https_port == 0 {
            return Err("choose an HTTPS port".into());
        }
        if self.http_enabled && self.https_enabled && http_port == self.https_port && http_port != 0
        {
            return Err(format!("HTTP and HTTPS cannot share port {http_port}"));
        }
        if self.redirect_http && !(self.http_enabled && self.https_enabled) {
            return Err("redirecting HTTP to HTTPS needs both enabled".into());
        }
        Ok(())
    }

    /// The HTTP port actually used.
    pub fn effective_http_port(&self, api_port: u16) -> u16 {
        if self.http_port == 0 {
            api_port
        } else {
            self.http_port
        }
    }
}

/// How the console shows dates and times to users who have not chosen their
/// own (each console account can override these in its preferences).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DisplaySettings {
    /// `system` (the viewer's own device), `UTC`, or an IANA zone name such
    /// as `Europe/London`.
    pub time_zone: String,
    /// `system` (the browser's locale), `dmy`, `mdy`, `ymd` or `d_mon_y`.
    pub date_format: String,
    /// `system` (the browser's locale), `24h` or `12h`.
    pub time_format: String,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            time_zone: "system".to_string(),
            date_format: "system".to_string(),
            time_format: "system".to_string(),
        }
    }
}

/// Accepted `date_format` values.
pub const DATE_FORMATS: &[&str] = &["system", "dmy", "mdy", "ymd", "d_mon_y"];
/// Accepted `time_format` values.
pub const TIME_FORMATS: &[&str] = &["system", "24h", "12h"];

/// Check a display time zone: `system`, `UTC`, or something shaped like an
/// IANA zone name (`Area/Location`, letters, digits, `_`, `-`, `+`). The
/// browser does the real lookup and falls back to the device zone for a
/// name it does not know.
pub fn validate_time_zone(tz: &str) -> std::result::Result<(), String> {
    if tz == "system" || tz.eq_ignore_ascii_case("utc") {
        return Ok(());
    }
    let shaped = !tz.is_empty()
        && tz.len() <= 64
        && !tz.starts_with('/')
        && !tz.ends_with('/')
        && !tz.contains("//")
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'));
    if shaped {
        Ok(())
    } else {
        Err(format!("'{tz}' is not a time zone name"))
    }
}

impl DisplaySettings {
    /// Check every field; `allow_empty` accepts `""` as "not set" (a user's
    /// preferences, where empty means use the server default).
    pub fn check(&self, allow_empty: bool) -> std::result::Result<(), String> {
        let unset = |v: &str| allow_empty && v.is_empty();
        if !unset(&self.time_zone) {
            validate_time_zone(&self.time_zone)?;
        }
        if !unset(&self.date_format) && !DATE_FORMATS.contains(&self.date_format.as_str()) {
            return Err(format!("unknown date format '{}'", self.date_format));
        }
        if !unset(&self.time_format) && !TIME_FORMATS.contains(&self.time_format.as_str()) {
            return Err(format!("unknown time format '{}'", self.time_format));
        }
        Ok(())
    }
}

/// How AI scanner verdicts are applied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AiMode {
    /// Record verdicts only (train/observe mode); nothing is blocked.
    #[default]
    Train,
    /// High-confidence threat verdicts additionally auto-block.
    Enforce,
}

/// AI scanner subsystem settings: a small CPU-only classifier runs in the
/// background over domains observed in the query log and records verdicts
/// (category, confidence, TTL). In `enforce` mode, fresh high-confidence
/// threat verdicts auto-block, while manual allowlist/overrides always win.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AiSettings {
    /// Run the background scanner at all.
    pub enabled: bool,
    /// Train (record-only) or enforce (auto-block) mode.
    pub mode: AiMode,
    /// SQLite database for AI verdicts; empty uses `ai.db` next to the
    /// authoritative zone database.
    pub database: String,
    /// fastText supervised model (.bin) used for classification; empty uses
    /// the built-in heuristic keyword backend.
    pub model_path: String,
    /// Background classification workers (off the DNS path).
    pub workers: u32,
    /// How often the scanner harvests unseen query-log domains, in seconds.
    pub scan_interval_secs: u64,
    /// How often expired verdicts are checked and re-queued, in seconds.
    pub expire_check_secs: u64,
    /// Domains per scan cycle (older ones are picked up on later cycles).
    pub max_domains_per_scan: u32,
    /// Categories eligible to auto-block in `enforce` mode (lowercase,
    /// e.g. `malware`, `phishing`). Other categories only feed the console.
    pub auto_block_categories: Vec<String>,
    /// Minimum confidence for a threat verdict to auto-block.
    pub block_threshold: f32,
    /// Verdicts below this confidence are skipped entirely.
    pub confidence_floor: f32,
    /// Freshness window for ordinary content-category verdicts, in seconds.
    pub category_ttl_secs: u64,
    /// Freshness window for threat verdicts, in seconds (re-scanned when expired).
    pub threat_ttl_secs: u64,
    /// Optional MiniLM/ONNX verifier model (.onnx). Empty disables the
    /// verifying second pass; threat verdicts from the primary classifier
    /// are then taken at face value. File-owned (not editable via the
    /// console's settings overlay).
    pub verifier_model_path: String,
    /// Optional centroid reference path for the verifier; empty looks for
    /// `minilm-centroids.json` beside the ONNX model.
    pub verifier_reference_path: String,
    /// Minimum embedding cosine for the verifier to assert a category.
    pub verifier_threshold: f32,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: AiMode::Train,
            database: String::new(),
            model_path: String::new(),
            workers: 2,
            scan_interval_secs: 300,
            expire_check_secs: 3600,
            max_domains_per_scan: 5120,
            auto_block_categories: vec!["malware".to_string(), "phishing".to_string()],
            block_threshold: 0.99,
            confidence_floor: 0.2,
            category_ttl_secs: 30 * 86400,
            threat_ttl_secs: 7 * 86400,
            verifier_model_path: String::new(),
            verifier_reference_path: String::new(),
            verifier_threshold: 0.35,
        }
    }
}

impl AiSettings {
    /// Whether `category` is eligible to auto-block in enforce mode.
    pub fn is_auto_block_category(&self, category: &str) -> bool {
        self.auto_block_categories
            .iter()
            .any(|c| c.eq_ignore_ascii_case(category))
    }

    /// Whether this verdict would auto-block in enforce mode.
    pub fn would_block(&self, category: &str, confidence: f32) -> bool {
        self.is_auto_block_category(category) && confidence >= self.block_threshold
    }
}

/// The runtime-tunable subset of the configuration that lives in the
/// database rather than the TOML file (everything the console's Settings,
/// Cache, and Domain Lists pages edit). The file keeps bootstrap-only
/// values: listeners, addresses, ports, paths, and certificates.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<WebSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syslog: Option<SyslogSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<UpdateCheckSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns64: Option<Dns64Settings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs: Option<EcsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<NamedNetwork>>,
    pub recursive: Option<RecursiveUpdate>,
    pub dot: Option<ListenerUpdate>,
    pub doh: Option<DohUpdate>,
    pub doq: Option<ListenerUpdate>,
    pub policy: Option<PolicyUpdate>,
    pub authoritative: Option<AuthoritativeUpdate>,
    pub ai: Option<AiUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<DisplaySettings>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cache_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_cache_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negative_cache_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_system_config: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_cache_ttl: Option<u32>,
    /// Conditional forwarder zones (the whole list; see
    /// [`ConditionalZoneConfig`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditional_zones: Option<Vec<ConditionalZoneConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ResolutionMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_access: Option<RecursionAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_networks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_hints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_randomization: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebinding_protection: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_root: Option<LocalRootSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opportunistic_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_ip_versions: Option<IpVersions>,
    /// Client resolution policies (the whole list; see
    /// [`ClientPolicyConfig`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_policies: Option<Vec<ClientPolicyConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_lookups: Option<usize>,
}

impl RecursiveUpdate {
    /// Apply the resolution-mode and recursion-access fields (shared by the
    /// DB overlay and the settings API).
    pub fn apply_resolution(&self, settings: &mut RecursiveSettings) {
        if let Some(v) = self.mode {
            settings.mode = Some(v);
        }
        if let Some(v) = self.recursion_access {
            settings.recursion_access = v;
        }
        if let Some(v) = &self.recursion_networks {
            settings.recursion_networks = trim_list(v);
        }
        if let Some(v) = &self.root_hints {
            settings.root_hints = trim_list(v);
        }
        if let Some(v) = self.case_randomization {
            settings.case_randomization = v;
        }
        if let Some(v) = self.rebinding_protection {
            settings.rebinding_protection = v;
        }
        if let Some(v) = self.opportunistic_encryption {
            settings.opportunistic_encryption = v;
        }
        if let Some(v) = self.outbound_ip_versions {
            settings.outbound_ip_versions = v;
        }
        if let Some(v) = self.min_cache_ttl {
            settings.min_cache_ttl = v;
        }
        if let Some(v) = self.negative_cache_ttl {
            settings.negative_cache_ttl = v;
        }
        if let Some(v) = self.use_system_config {
            settings.use_system_config = v;
        }
        if let Some(v) = &self.client_policies {
            settings.client_policies = v
                .iter()
                .map(|p| ClientPolicyConfig {
                    name: p.name.trim().to_string(),
                    enabled: p.enabled,
                    clients: trim_list(&p.clients),
                    action: p.action,
                    upstreams: trim_list(&p.upstreams),
                    modified_at: p.modified_at.clone(),
                })
                .collect();
        }
        if let Some(v) = &self.local_root {
            settings.local_root = LocalRootSettings {
                enabled: v.enabled,
                sources: trim_list(&v.sources),
                // Never set from the API or the database.
                test_trust_anchor: settings.local_root.test_trust_anchor.clone(),
                outbound_ip_versions: settings.local_root.outbound_ip_versions,
            };
        }
    }

    /// Trim conditional zones: names lose surrounding whitespace and a
    /// trailing dot and are lowercased; blank upstream entries are dropped.
    pub fn normalize_conditional_zones(
        zones: &[ConditionalZoneConfig],
    ) -> Vec<ConditionalZoneConfig> {
        zones
            .iter()
            .map(|z| ConditionalZoneConfig {
                name: normalize_zone_name(&z.name),
                upstreams: z
                    .upstreams
                    .iter()
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty())
                    .collect(),
            })
            .collect()
    }
}

/// Trim every entry and drop the blank ones.
fn trim_list(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
        .collect()
}

/// A named set of networks (Settings -> Networks), e.g. `LAN` =
/// `192.168.1.0/24`. Network settings can list the name instead of the
/// addresses; changing the network changes every setting that names it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NamedNetwork {
    /// Unique name (case-insensitive), e.g. `LAN`.
    pub name: String,
    /// CIDR networks or single addresses.
    pub cidrs: Vec<String>,
    /// Optional note shown in the console.
    pub description: String,
}

/// The networks every server has, which can be named but not changed.
pub fn builtin_networks() -> Vec<NamedNetwork> {
    builtin_network_list().to_vec()
}

/// The built-in networks, built once.
fn builtin_network_list() -> &'static [NamedNetwork] {
    static LIST: std::sync::OnceLock<Vec<NamedNetwork>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            NamedNetwork {
                name: "Private".to_string(),
                cidrs: PRIVATE_NETWORKS.iter().map(|n| n.to_string()).collect(),
                description: "Private, shared, link-local and loopback addresses".to_string(),
            },
            NamedNetwork {
                name: "This Server".to_string(),
                cidrs: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
                description: "Loopback: queries from this machine".to_string(),
            },
        ]
    })
}

impl DaygleConfig {
    /// The built-in networks followed by the configured ones.
    pub fn all_networks(&self) -> Vec<NamedNetwork> {
        let mut all = builtin_networks();
        all.extend(self.networks.iter().cloned());
        all
    }

    /// The network called `name` (any case), built-in or configured.
    pub fn find_network(&self, name: &str) -> Option<NamedNetwork> {
        self.named_network(name).cloned()
    }

    /// Like [`Self::find_network`], without copying: for per-query lookups.
    pub fn named_network(&self, name: &str) -> Option<&NamedNetwork> {
        let name = name.trim();
        builtin_network_list()
            .iter()
            .chain(&self.networks)
            .find(|n| n.name.eq_ignore_ascii_case(name))
    }

    /// Resolve a network list whose entries are CIDRs, single addresses or
    /// network names into networks. An unknown name is an error, never
    /// skipped: dropping it could turn an allow list into "nobody".
    pub fn resolve_networks(
        &self,
        entries: &[String],
    ) -> std::result::Result<Vec<ipnet::IpNet>, String> {
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(net) = parse_network(entry) {
                out.push(net);
            } else if let Some(network) = self.find_network(entry) {
                out.extend(network.cidrs.iter().filter_map(|c| parse_network(c)));
            } else {
                return Err(format!(
                    "'{entry}' is not a network, an address or a network name"
                ));
            }
        }
        Ok(out)
    }

    /// Whether `entry` is an address, a CIDR network or the name of a
    /// network (built-in or configured).
    pub fn is_network_entry(&self, entry: &str) -> bool {
        parse_network(entry).is_some() || self.find_network(entry).is_some()
    }

    /// A copy of the config in which every network name in the lists that
    /// may name networks is replaced by the addresses it stands for. Runtime
    /// components are built from this copy. The stored config keeps the
    /// names, so a change to a network reaches every setting that names it.
    pub fn with_networks_resolved(&self) -> DaygleConfig {
        let networks = self.all_networks();
        let mut resolved = self.clone();
        for list in resolved.network_lists_mut() {
            let expanded = resolve_network_list(&networks, list);
            *list = expanded;
        }
        resolved
    }

    /// The Advanced Blocking groups with the network names in their client
    /// lists resolved to addresses. Groups are stored in the database, so
    /// they are resolved here rather than through [`Self::with_networks_resolved`].
    pub fn resolve_blocking_groups(
        &self,
        groups: Vec<crate::blocking::BlockingGroup>,
    ) -> Vec<crate::blocking::BlockingGroup> {
        let networks = self.all_networks();
        groups
            .into_iter()
            .map(|mut group| {
                group.clients = resolve_network_list(&networks, &group.clients);
                group
            })
            .collect()
    }

    /// Every network list in the config that may name networks, labelled
    /// for "used by" in the console.
    pub fn network_lists(&self) -> Vec<(String, &Vec<String>)> {
        let mut lists = vec![
            (
                "Recursion access".to_string(),
                &self.recursive.recursion_networks,
            ),
            ("Denied networks".to_string(), &self.policy.denied_networks),
            (
                "Allowed networks".to_string(),
                &self.policy.allowed_networks,
            ),
            ("DNS64".to_string(), &self.dns64.clients),
            (
                "Zone transfers".to_string(),
                &self.authoritative.axfr_networks,
            ),
            (
                "Dynamic updates".to_string(),
                &self.authoritative.update_networks,
            ),
            ("PROXY protocol".to_string(), &self.server.proxy_protocol),
            (
                "DoT allowed networks".to_string(),
                &self.dot.allowed_networks,
            ),
            (
                "DoH allowed networks".to_string(),
                &self.doh.allowed_networks,
            ),
            (
                "DoQ allowed networks".to_string(),
                &self.doq.allowed_networks,
            ),
        ];
        for p in &self.recursive.client_policies {
            lists.push((format!("Client policy '{}'", p.name), &p.clients));
        }
        for (i, r) in self.policy.rules.iter().enumerate() {
            lists.push((format!("Policy rule {}", i + 1), &r.clients));
        }
        lists
    }

    /// Mutable form of [`Self::network_lists`] (for renames).
    fn network_lists_mut(&mut self) -> Vec<&mut Vec<String>> {
        let mut lists = vec![
            &mut self.recursive.recursion_networks,
            &mut self.policy.denied_networks,
            &mut self.policy.allowed_networks,
            &mut self.dns64.clients,
            &mut self.authoritative.axfr_networks,
            &mut self.authoritative.update_networks,
            &mut self.server.proxy_protocol,
            &mut self.dot.allowed_networks,
            &mut self.doh.allowed_networks,
            &mut self.doq.allowed_networks,
        ];
        for p in &mut self.recursive.client_policies {
            lists.push(&mut p.clients);
        }
        for r in &mut self.policy.rules {
            lists.push(&mut r.clients);
        }
        lists
    }

    /// The config settings that name the network `name` (any case).
    pub fn network_users(&self, name: &str) -> Vec<String> {
        self.network_lists()
            .into_iter()
            .filter(|(_, list)| {
                list.iter()
                    .any(|e| e.trim().eq_ignore_ascii_case(name.trim()))
            })
            .map(|(label, _)| label)
            .collect()
    }

    /// Rename every reference to the network `old` (any case) to `new`.
    pub fn rename_network_refs(&mut self, old: &str, new: &str) {
        for list in self.network_lists_mut() {
            for entry in list.iter_mut() {
                if entry.trim().eq_ignore_ascii_case(old.trim()) {
                    *entry = new.to_string();
                }
            }
        }
    }
}

/// Check a named network's name and addresses.
pub fn validate_named_network(network: &NamedNetwork) -> std::result::Result<(), String> {
    let name = network.name.trim();
    if name.is_empty() {
        return Err("a network needs a name".to_string());
    }
    if name.len() > 64 {
        return Err(format!(
            "network name '{name}' is longer than 64 characters"
        ));
    }
    if parse_network(name).is_some() || name.contains('/') || name.contains(',') {
        return Err(format!(
            "'{name}' looks like an address; give the network a name such as LAN"
        ));
    }
    if network.cidrs.iter().all(|c| c.trim().is_empty()) {
        return Err(format!("network '{name}' has no addresses"));
    }
    for cidr in &network.cidrs {
        if !cidr.trim().is_empty() && parse_network(cidr).is_none() {
            return Err(format!(
                "network '{name}': '{}' is not a network or address",
                cidr.trim()
            ));
        }
    }
    Ok(())
}

/// Expand the names in a network list into the addresses they stand for,
/// keeping addresses as they are. An unknown name is kept unchanged: the
/// config check refuses it, so it never reaches a running server.
pub fn resolve_network_list(networks: &[NamedNetwork], entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if parse_network(entry).is_some() {
            out.push(entry.to_string());
            continue;
        }
        match networks
            .iter()
            .find(|n| n.name.trim().eq_ignore_ascii_case(entry))
        {
            Some(network) => out.extend(
                network
                    .cidrs
                    .iter()
                    .map(|c| c.trim())
                    .filter(|c| parse_network(c).is_some())
                    .map(str::to_string),
            ),
            None => out.push(entry.to_string()),
        }
    }
    out
}

/// Parse a CIDR network, or a bare IP address as a single-host network.
pub fn parse_network(text: &str) -> Option<ipnet::IpNet> {
    let text = text.trim();
    text.parse::<ipnet::IpNet>()
        .ok()
        .or_else(|| text.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
}

/// Normalize a zone apex for storage: trim, drop one trailing dot, lowercase.
pub fn normalize_zone_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Partial updates for authoritative-zone defaults (the runtime-tunable
/// subset of [`AuthoritativeSettings`], matching the API's shape).
///
/// AXFR and dynamic-update gates are read from the live catalog per request,
/// so these apply immediately. NOTIFY sender/listener hooks are built at
/// startup: `notify_*` fields are persisted and validated but take effect on
/// the next restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthoritativeUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_record_ttl: Option<u32>,
    /// Default SOA contact mailbox used when a zone is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_admin_mailbox: Option<String>,
    /// Default SOA primary nameserver (MNAME) used when a zone is created
    /// without one; typically this server's own hostname (e.g.
    /// "ns1.example.com."). Exposed in the console's Settings page as "DNS
    /// Server Domain" instead of guessing "ns1.<zone>".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_primary_ns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axfr_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axfr_networks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_dynamic_updates: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_networks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_targets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_listen_enabled: Option<bool>,
    /// Stub zones (the whole list; see [`StubZoneConfig`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stub_zones: Option<Vec<StubZoneConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_zone: Option<String>,
    /// Consumed catalog zones (the whole list).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_consumers: Option<Vec<CatalogConsumerConfig>>,
}

impl AuthoritativeUpdate {
    /// Trim stub zones: names are normalized like conditional zones and blank
    /// nameserver entries are dropped.
    pub fn normalize_stub_zones(zones: &[StubZoneConfig]) -> Vec<StubZoneConfig> {
        zones
            .iter()
            .map(|z| StubZoneConfig {
                name: normalize_zone_name(&z.name),
                nss: z
                    .nss
                    .iter()
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty())
                    .collect(),
                ..z.clone()
            })
            .collect()
    }

    /// Trim consumed catalogs: names normalized like zone names, blank
    /// master entries dropped.
    pub fn normalize_catalog_consumers(
        consumers: &[CatalogConsumerConfig],
    ) -> Vec<CatalogConsumerConfig> {
        consumers
            .iter()
            .map(|c| CatalogConsumerConfig {
                name: normalize_zone_name(&c.name),
                masters: c
                    .masters
                    .iter()
                    .map(|m| m.trim().to_string())
                    .filter(|m| !m.is_empty())
                    .collect(),
                ..c.clone()
            })
            .collect()
    }

    /// Normalize user-supplied network lists (trim entries, drop empties).
    fn normalize_networks(items: Vec<String>) -> Vec<String> {
        items
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// DoQ-only: QUIC connection idle timeout in seconds. Ignored for DoT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
    /// DoT-only: TLS handshake timeout in seconds. Ignored for DoQ (QUIC
    /// governs its own handshake).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
    /// Maximum active connections for this listener (DoT/DoQ).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,
    /// DoQ maximum concurrent DNS streams per listener.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_streams: Option<usize>,
    /// Client networks allowed to use this listener (addresses or network
    /// names); empty or absent means everyone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_networks: Option<Vec<String>>,
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
    pub cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// TLS handshake timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
    /// DoH-only maximum active TLS connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,
    /// Client networks allowed to use this listener (addresses or network
    /// names); empty or absent means everyone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_networks: Option<Vec<String>>,
}

/// Partial updates for the policy engine (allow/block lists and Filter AAAA).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PolicyUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<String>>,
    /// Client networks always refused (addresses or network names).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_networks: Option<Vec<String>>,
    /// Client networks that bypass the denied list (addresses or network names).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_networks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocklist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_aaaa: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_aaaa_except: Option<Vec<String>>,
    /// The remote blocklist sources (Filtering -> Blocklists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocklist_sources: Option<Vec<BlocklistSourceConfig>>,
}

/// Partial update for the AI scanner (matches the API's shape): the fields
/// of [`AiSettings`] the console edits.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AiUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<AiMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_interval_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_check_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_domains_per_scan: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_block_categories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_threshold: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_floor: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_ttl_secs: Option<u64>,
}

impl AiUpdate {
    /// The full-field overlay captured from an [`AiSettings`] (this is the
    /// single capture used by [`RuntimeSettings::capture`], so callers that
    /// must reason about "what the first boot would have stored" reuse it).
    pub fn capture_ai(settings: &AiSettings) -> Self {
        Self {
            enabled: Some(settings.enabled),
            mode: Some(settings.mode),
            database: Some(settings.database.clone()),
            model_path: Some(settings.model_path.clone()),
            workers: Some(settings.workers),
            scan_interval_secs: Some(settings.scan_interval_secs),
            expire_check_secs: Some(settings.expire_check_secs),
            max_domains_per_scan: Some(settings.max_domains_per_scan),
            auto_block_categories: Some(settings.auto_block_categories.clone()),
            block_threshold: Some(settings.block_threshold),
            confidence_floor: Some(settings.confidence_floor),
            category_ttl_secs: Some(settings.category_ttl_secs),
            threat_ttl_secs: Some(settings.threat_ttl_secs),
        }
    }

    /// Normalize a category list: trim, lowercase, drop empties and
    /// duplicates. Matching ignores case, so this is cosmetic but keeps the
    /// stored value canonical.
    pub fn normalize_categories(categories: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut normalized = Vec::new();
        for category in categories {
            let category = category.trim().trim_matches(',').to_ascii_lowercase();
            if !category.is_empty() && seen.insert(category.clone()) {
                normalized.push(category);
            }
        }
        normalized
    }
}

impl RuntimeSettings {
    /// Whether anything in this overlay would change `config`.
    pub fn is_empty(&self) -> bool {
        self.recursive.is_none()
            && self.dot.is_none()
            && self.doh.is_none()
            && self.doq.is_none()
            && self.policy.is_none()
            && self.authoritative.is_none()
            && self.ai.is_none()
            && self.display.is_none()
            && self.web.is_none()
            && self.syslog.is_none()
            && self.updates.is_none()
            && self.dns64.is_none()
            && self.ecs.is_none()
            && self.networks.is_none()
    }

    /// Apply the overlay to `config` in place. `None` fields are untouched.
    pub fn apply_to(&self, config: &mut DaygleConfig) {
        if let Some(r) = &self.recursive {
            if let Some(v) = r.enabled {
                config.recursive.enabled = v;
            }
            if let Some(v) = r.cache_size {
                config.recursive.cache_size = v;
            }
            if let Some(v) = &r.upstreams {
                config.recursive.upstreams = v.clone();
            }
            if let Some(v) = r.dnssec_validate {
                config.recursive.dnssec_validate = v;
            }
            if let Some(v) = r.prefetch_enabled {
                config.recursive.prefetch_enabled = v;
            }
            if let Some(v) = r.prefetch_ttl_fraction_pct {
                config.recursive.prefetch_ttl_fraction_pct = v;
            }
            if let Some(v) = r.prefetch_min_queries {
                config.recursive.prefetch_min_queries = v;
            }
            if let Some(v) = r.serve_stale_secs {
                config.recursive.serve_stale_secs = v;
            }
            if let Some(v) = r.max_cache_ttl {
                config.recursive.max_cache_ttl = v;
            }
            if let Some(v) = r.failure_cache_ttl {
                config.recursive.failure_cache_ttl = v;
            }
            if let Some(v) = r.max_concurrent_lookups {
                config.recursive.max_concurrent_lookups = v;
            }
            if let Some(v) = &r.conditional_zones {
                config.recursive.conditional_zones =
                    RecursiveUpdate::normalize_conditional_zones(v);
            }
            r.apply_resolution(&mut config.recursive);
        }
        if let Some(d) = &self.dot {
            if let Some(v) = d.enabled {
                config.dot.enabled = v;
            }
            if let Some(v) = d.port {
                config.dot.port = v;
            }
            if let Some(v) = d.self_signed {
                config.dot.self_signed = v;
            }
            if let Some(v) = &d.server_name {
                config.dot.server_name = v.clone();
            }
            if let Some(v) = &d.cert_path {
                config.dot.cert_path = v.clone();
            }
            if let Some(v) = &d.key_path {
                config.dot.key_path = v.clone();
            }
            if let Some(v) = &d.certificate {
                config.dot.certificate = v.clone();
            }
            if let Some(v) = d.handshake_timeout_secs {
                config.dot.handshake_timeout_secs = v;
            }
            if let Some(v) = d.max_connections {
                config.dot.max_connections = v;
            }
            if let Some(v) = &d.allowed_networks {
                config.dot.allowed_networks = trim_list(v);
            }
        }
        if let Some(d) = &self.doh {
            if let Some(v) = d.enabled {
                config.doh.enabled = v;
            }
            if let Some(v) = d.port {
                config.doh.port = v;
            }
            if let Some(v) = d.self_signed {
                config.doh.self_signed = v;
            }
            if let Some(v) = &d.server_name {
                config.doh.server_name = v.clone();
            }
            if let Some(v) = &d.cert_path {
                config.doh.cert_path = v.clone();
            }
            if let Some(v) = &d.key_path {
                config.doh.key_path = v.clone();
            }
            if let Some(v) = &d.endpoint {
                config.doh.endpoint = v.clone();
            }
            if let Some(v) = &d.certificate {
                config.doh.certificate = v.clone();
            }
            if let Some(v) = d.handshake_timeout_secs {
                config.doh.handshake_timeout_secs = v;
            }
            if let Some(v) = d.max_connections {
                config.doh.max_connections = v;
            }
            if let Some(v) = &d.allowed_networks {
                config.doh.allowed_networks = trim_list(v);
            }
        }
        if let Some(d) = &self.doq {
            if let Some(v) = d.enabled {
                config.doq.enabled = v;
            }
            if let Some(v) = d.port {
                config.doq.port = v;
            }
            if let Some(v) = d.self_signed {
                config.doq.self_signed = v;
            }
            if let Some(v) = &d.server_name {
                config.doq.server_name = v.clone();
            }
            if let Some(v) = &d.cert_path {
                config.doq.cert_path = v.clone();
            }
            if let Some(v) = &d.key_path {
                config.doq.key_path = v.clone();
            }
            if let Some(v) = &d.certificate {
                config.doq.certificate = v.clone();
            }
            if let Some(v) = d.idle_timeout_secs {
                config.doq.idle_timeout_secs = v;
            }
            if let Some(v) = d.max_connections {
                config.doq.max_connections = v;
            }
            if let Some(v) = d.max_concurrent_streams {
                config.doq.max_concurrent_streams = v;
            }
            if let Some(v) = &d.allowed_networks {
                config.doq.allowed_networks = trim_list(v);
            }
        }
        if let Some(p) = &self.policy {
            if let Some(v) = &p.allowlist {
                config.policy.allowlist = v.clone();
            }
            if let Some(v) = &p.blocklist {
                config.policy.blocklist = v.clone();
            }
            if let Some(v) = p.filter_aaaa {
                config.policy.filter_aaaa = v;
            }
            if let Some(v) = &p.filter_aaaa_except {
                config.policy.filter_aaaa_except = v.clone();
            }
            if let Some(v) = &p.blocklist_sources {
                config.policy.blocklist_sources = v.clone();
            }
        }
        if let Some(d) = &self.display {
            config.display = d.clone();
        }
        if let Some(d) = &self.dns64 {
            config.dns64 = d.clone();
        }
        if let Some(e) = &self.ecs {
            config.ecs = e.clone();
        }
        if let Some(n) = &self.networks {
            config.networks = n.clone();
        }
        if let Some(s) = &self.syslog {
            config.syslog = s.clone();
        }
        if let Some(w) = &self.web {
            config.web = w.clone();
        }
        if let Some(u) = &self.updates {
            config.updates = u.clone();
        }
        if let Some(a) = &self.ai {
            if let Some(v) = a.enabled {
                config.ai.enabled = v;
            }
            if let Some(v) = a.mode {
                config.ai.mode = v;
            }
            if let Some(v) = &a.database {
                config.ai.database = v.trim().to_string();
            }
            if let Some(v) = &a.model_path {
                config.ai.model_path = v.trim().to_string();
            }
            if let Some(v) = a.workers {
                config.ai.workers = v;
            }
            if let Some(v) = a.scan_interval_secs {
                config.ai.scan_interval_secs = v;
            }
            if let Some(v) = a.expire_check_secs {
                config.ai.expire_check_secs = v;
            }
            if let Some(v) = a.max_domains_per_scan {
                config.ai.max_domains_per_scan = v;
            }
            if let Some(v) = &a.auto_block_categories {
                config.ai.auto_block_categories = AiUpdate::normalize_categories(v.clone());
            }
            if let Some(v) = a.block_threshold {
                config.ai.block_threshold = v;
            }
            if let Some(v) = a.confidence_floor {
                config.ai.confidence_floor = v;
            }
            if let Some(v) = a.category_ttl_secs {
                config.ai.category_ttl_secs = v;
            }
            if let Some(v) = a.threat_ttl_secs {
                config.ai.threat_ttl_secs = v;
            }
        }
        if let Some(a) = &self.authoritative {
            if let Some(v) = a.default_record_ttl {
                config.authoritative.default_record_ttl = v;
            }
            if let Some(v) = a.axfr_enabled {
                config.authoritative.axfr_enabled = v;
            }
            if let Some(v) = &a.axfr_networks {
                config.authoritative.axfr_networks =
                    AuthoritativeUpdate::normalize_networks(v.clone());
            }
            if let Some(v) = a.allow_dynamic_updates {
                config.authoritative.allow_dynamic_updates = v;
            }
            if let Some(v) = &a.update_networks {
                config.authoritative.update_networks =
                    AuthoritativeUpdate::normalize_networks(v.clone());
            }
            if let Some(v) = a.notify_enabled {
                config.authoritative.notify_enabled = v;
            }
            if let Some(v) = &a.notify_targets {
                config.authoritative.notify_targets =
                    AuthoritativeUpdate::normalize_networks(v.clone());
            }
            if let Some(v) = a.notify_listen_enabled {
                config.authoritative.notify_listen_enabled = v;
            }
            if let Some(v) = &a.stub_zones {
                config.authoritative.stub_zones = AuthoritativeUpdate::normalize_stub_zones(v);
            }
            if let Some(v) = &a.catalog_zone {
                config.authoritative.catalog_zone = normalize_zone_name(v);
            }
            if let Some(v) = &a.catalog_consumers {
                config.authoritative.catalog_consumers =
                    AuthoritativeUpdate::normalize_catalog_consumers(v);
            }
            if let Some(v) = &a.default_admin_mailbox {
                config.authoritative.default_admin_mailbox = v.clone();
            }
            if let Some(v) = &a.default_primary_ns {
                let v = v.trim();
                if !v.is_empty() {
                    // SOA MNAME is conventionally fully qualified; store the
                    // trailing dot even when the user omitted it. Blank input
                    // keeps the current value.
                    config.authoritative.default_primary_ns = if v.ends_with('.') {
                        v.to_string()
                    } else {
                        format!("{v}.")
                    };
                }
            }
        }
        // Placeholders stored by earlier versions count as unset.
        config.authoritative.clear_legacy_placeholders();
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
                max_cache_ttl: Some(config.recursive.max_cache_ttl),
                min_cache_ttl: Some(config.recursive.min_cache_ttl),
                negative_cache_ttl: Some(config.recursive.negative_cache_ttl),
                use_system_config: Some(config.recursive.use_system_config),
                failure_cache_ttl: Some(config.recursive.failure_cache_ttl),
                max_concurrent_lookups: Some(config.recursive.max_concurrent_lookups),
                conditional_zones: Some(config.recursive.conditional_zones.clone()),
                // Store the effective mode so a later upstreams change cannot
                // silently flip an install between recursive and forwarding.
                mode: Some(config.recursive.effective_mode()),
                recursion_access: Some(config.recursive.recursion_access),
                recursion_networks: Some(config.recursive.recursion_networks.clone()),
                root_hints: Some(config.recursive.root_hints.clone()),
                case_randomization: Some(config.recursive.case_randomization),
                rebinding_protection: Some(config.recursive.rebinding_protection),
                local_root: Some(config.recursive.local_root.clone()),
                opportunistic_encryption: Some(config.recursive.opportunistic_encryption),
                outbound_ip_versions: Some(config.recursive.outbound_ip_versions),
                client_policies: Some(config.recursive.client_policies.clone()),
            }),
            dot: Some(ListenerUpdate {
                enabled: Some(config.dot.enabled),
                port: Some(config.dot.port),
                self_signed: Some(config.dot.self_signed),
                server_name: Some(config.dot.server_name.clone()),
                cert_path: Some(config.dot.cert_path.clone()),
                key_path: Some(config.dot.key_path.clone()),
                certificate: (!config.dot.certificate.is_empty())
                    .then(|| config.dot.certificate.clone()),
                idle_timeout_secs: None,
                handshake_timeout_secs: Some(config.dot.handshake_timeout_secs),
                max_connections: Some(config.dot.max_connections),
                max_concurrent_streams: None,
                allowed_networks: Some(config.dot.allowed_networks.clone()),
            }),
            doh: Some(DohUpdate {
                enabled: Some(config.doh.enabled),
                port: Some(config.doh.port),
                self_signed: Some(config.doh.self_signed),
                server_name: Some(config.doh.server_name.clone()),
                cert_path: Some(config.doh.cert_path.clone()),
                key_path: Some(config.doh.key_path.clone()),
                endpoint: Some(config.doh.endpoint.clone()),
                certificate: (!config.doh.certificate.is_empty())
                    .then(|| config.doh.certificate.clone()),
                handshake_timeout_secs: Some(config.doh.handshake_timeout_secs),
                max_connections: Some(config.doh.max_connections),
                allowed_networks: Some(config.doh.allowed_networks.clone()),
            }),
            doq: Some(ListenerUpdate {
                enabled: Some(config.doq.enabled),
                port: Some(config.doq.port),
                self_signed: Some(config.doq.self_signed),
                server_name: Some(config.doq.server_name.clone()),
                cert_path: Some(config.doq.cert_path.clone()),
                key_path: Some(config.doq.key_path.clone()),
                certificate: (!config.doq.certificate.is_empty())
                    .then(|| config.doq.certificate.clone()),
                idle_timeout_secs: Some(config.doq.idle_timeout_secs),
                handshake_timeout_secs: None,
                max_connections: Some(config.doq.max_connections),
                max_concurrent_streams: Some(config.doq.max_concurrent_streams),
                allowed_networks: Some(config.doq.allowed_networks.clone()),
            }),
            policy: Some(PolicyUpdate {
                allowlist: Some(config.policy.allowlist.clone()),
                denied_networks: Some(config.policy.denied_networks.clone()),
                allowed_networks: Some(config.policy.allowed_networks.clone()),
                blocklist: Some(config.policy.blocklist.clone()),
                filter_aaaa: Some(config.policy.filter_aaaa),
                filter_aaaa_except: Some(config.policy.filter_aaaa_except.clone()),
                blocklist_sources: Some(config.policy.blocklist_sources.clone()),
            }),
            authoritative: Some(AuthoritativeUpdate {
                default_record_ttl: Some(config.authoritative.default_record_ttl),
                default_admin_mailbox: Some(config.authoritative.default_admin_mailbox.clone()),
                default_primary_ns: Some(config.authoritative.default_primary_ns.clone()),
                axfr_enabled: Some(config.authoritative.axfr_enabled),
                axfr_networks: Some(config.authoritative.axfr_networks.clone()),
                allow_dynamic_updates: Some(config.authoritative.allow_dynamic_updates),
                update_networks: Some(config.authoritative.update_networks.clone()),
                notify_enabled: Some(config.authoritative.notify_enabled),
                notify_targets: Some(config.authoritative.notify_targets.clone()),
                notify_listen_enabled: Some(config.authoritative.notify_listen_enabled),
                stub_zones: Some(config.authoritative.stub_zones.clone()),
                catalog_zone: Some(config.authoritative.catalog_zone.clone()),
                catalog_consumers: Some(config.authoritative.catalog_consumers.clone()),
            }),
            ai: Some(AiUpdate::capture_ai(&config.ai)),
            display: Some(config.display.clone()),
            web: Some(config.web.clone()),
            updates: Some(config.updates.clone()),
            syslog: Some(config.syslog.clone()),
            dns64: Some(config.dns64.clone()),
            ecs: Some(config.ecs.clone()),
            networks: Some(config.networks.clone()),
        }
    }
}

/// Join a listen setting and a port. The setting is one address or several
/// separated by commas, IPv4 or IPv6, with or without brackets: `0.0.0.0`
/// (every IPv4 address), `::` or `[::]` (every IPv6 address, and every IPv4
/// one too unless the list also names IPv4 addresses or `server.ipv6_only`
/// is set), `192.168.1.2`, `fd00::53`, `192.168.1.2, fd00::53`.
///
/// Repeats, and an address a wildcard in the list already covers, are
/// refused: the second socket could not be bound.
pub fn listen_socket_addrs(
    listen: &str,
    port: u16,
) -> std::result::Result<Vec<std::net::SocketAddr>, String> {
    let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
    for entry in listen.split(',') {
        let addr = listen_socket_addr(entry, port)?;
        if addrs.iter().any(|a| a.ip() == addr.ip()) {
            return Err(format!("{} is listed twice", addr.ip()));
        }
        addrs.push(addr);
    }
    for (wildcard, family) in [
        (IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED), "IPv4"),
        (IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED), "IPv6"),
    ] {
        if addrs.iter().any(|a| a.ip() == wildcard)
            && addrs
                .iter()
                .any(|a| a.ip() != wildcard && a.is_ipv4() == wildcard.is_ipv4())
        {
            return Err(format!(
                "{wildcard} already covers every {family} address: list it alone, or list specific addresses instead"
            ));
        }
    }
    Ok(addrs)
}

/// Accept a listen setting written as a string or, in the config file, as
/// an array of addresses (kept as the comma-separated form).
fn listen_list<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Listen {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Listen::deserialize(d)? {
        Listen::One(s) => s,
        Listen::Many(v) => v.join(", "),
    })
}

/// One listen address and a port (see [`listen_socket_addrs`]).
fn listen_socket_addr(
    listen: &str,
    port: u16,
) -> std::result::Result<std::net::SocketAddr, String> {
    let text = listen.trim();
    let bare = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    bare.parse::<IpAddr>()
        .map(|ip| std::net::SocketAddr::new(ip, port))
        .map_err(|_| {
            format!(
                "'{text}' is not an IP address (use 0.0.0.0 for every IPv4 address, or :: for every IPv4 and IPv6 address)"
            )
        })
}

/// Placeholder SOA defaults that earlier versions shipped (and stored in
/// the database on the first settings save). They name no real server or
/// person, so they are treated as unset: the server's own name and the
/// first administrator's email are used instead.
const LEGACY_PLACEHOLDER_PRIMARY_NS: &str = "ns1.daygle.test.";
const LEGACY_PLACEHOLDER_ADMIN_MAILBOX: &str = "admin.daygle.test.";

impl AuthoritativeSettings {
    /// Clear the legacy placeholder SOA defaults (see above).
    pub fn clear_legacy_placeholders(&mut self) {
        if self.default_primary_ns.trim() == LEGACY_PLACEHOLDER_PRIMARY_NS {
            self.default_primary_ns.clear();
        }
        if self.default_admin_mailbox.trim() == LEGACY_PLACEHOLDER_ADMIN_MAILBOX {
            self.default_admin_mailbox.clear();
        }
    }
}

/// Turn a mailbox as people write it into the SOA RNAME form:
/// `jane.doe@example.com` becomes `jane\.doe.example.com.` (dots in the
/// local part are escaped, the `@` becomes a dot). Input already in RNAME
/// form gets its trailing dot. Empty stays empty.
pub fn mailbox_to_rname(input: &str) -> std::result::Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(String::new());
    }
    if input.chars().any(|c| c.is_whitespace() || c.is_control()) || input.len() > 254 {
        return Err(format!("'{input}' is not a mailbox"));
    }
    let rname = match input.split_once('@') {
        Some((local, domain)) => {
            let domain = domain.trim_end_matches('.');
            if local.is_empty()
                || domain.is_empty()
                || domain.contains('@')
                || domain.starts_with('.')
            {
                return Err(format!("'{input}' is not an email address"));
            }
            let local = local.replace('\\', "\\\\").replace('.', "\\.");
            format!("{local}.{domain}.")
        }
        None if input.ends_with('.') => input.to_string(),
        None => format!("{input}."),
    };
    if rname.starts_with('.') || rname.contains("..") {
        return Err(format!("'{input}' is not a mailbox"));
    }
    Ok(rname.to_ascii_lowercase())
}

/// The inverse of [`mailbox_to_rname`] for display, when the first label
/// is clearly the local part: `jane\.doe.example.com.` becomes
/// `jane.doe@example.com`. Returns `None` for names with fewer than three
/// labels (the split would be a guess).
pub fn rname_to_email(rname: &str) -> Option<String> {
    let rname = rname.trim().trim_end_matches('.');
    let mut local = String::new();
    let mut chars = rname.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => local.push(chars.next()?),
            '.' => {
                let domain: String = chars.collect();
                return (domain.contains('.') && !local.is_empty())
                    .then(|| format!("{local}@{domain}"));
            }
            c => local.push(c),
        }
    }
    None
}

/// This server's host name as a fully qualified, absolute DNS name (e.g.
/// `dns1.example.lan.`), for the SOA primary nameserver of new zones when no
/// DNS Server Domain is set. A bare host name gets the resolver's `domain`
/// (or first `search`) suffix from /etc/resolv.conf. `None` when the name
/// cannot be read.
pub fn detect_server_name() -> Option<String> {
    let host = ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::env::var("HOSTNAME").ok())?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = |name: &str| {
        !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
    };
    if !valid(&host) || host == "localhost" {
        return None;
    }
    if host.contains('.') {
        return Some(format!("{host}."));
    }
    let suffix = std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|text| resolv_conf_domain(&text));
    Some(match suffix {
        Some(domain) if valid(&domain) => format!("{host}.{domain}."),
        _ => format!("{host}."),
    })
}

/// The `domain` entry of a resolv.conf, else the first `search` entry.
fn resolv_conf_domain(text: &str) -> Option<String> {
    let mut search = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("domain"), Some(d)) => return Some(d.trim_end_matches('.').to_ascii_lowercase()),
            (Some("search"), Some(d)) if search.is_none() => {
                search = Some(d.trim_end_matches('.').to_ascii_lowercase())
            }
            _ => {}
        }
    }
    search
}

impl DaygleConfig {
    /// Parse a TOML document into a validated configuration.
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: DaygleConfig =
            toml::from_str(text).map_err(|e| DaygleError::Config(format!("invalid TOML: {e}")))?;
        cfg.authoritative.clear_legacy_placeholders();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load and parse a configuration file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| DaygleError::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Serialize this configuration to a TOML document.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| DaygleError::Config(format!("cannot serialize config: {e}")))
    }

    /// Enforce cross-field invariants (ports, upstreams, etc.).
    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::new();
        for network in &self.networks {
            validate_named_network(network).map_err(DaygleError::Config)?;
            let key = network.name.trim().to_ascii_lowercase();
            if builtin_networks()
                .iter()
                .any(|b| b.name.eq_ignore_ascii_case(&key))
            {
                return Err(DaygleError::Config(format!(
                    "'{}' is a built-in network name",
                    network.name.trim()
                )));
            }
            if !names.insert(key) {
                return Err(DaygleError::Config(format!(
                    "two networks are named '{}'",
                    network.name.trim()
                )));
            }
        }
        // Only *enabled* listeners need a concrete port; a disabled service
        // may keep port 0 (e.g. ephemeral test setups).
        for (name, port, enabled) in [
            (
                "server.port",
                self.server.port,
                self.server.udp_enabled || self.server.tcp_enabled,
            ),
            ("dot.port", self.dot.port, self.dot.enabled),
            ("doh.port", self.doh.port, self.doh.enabled),
            ("doq.port", self.doq.port, self.doq.enabled),
            ("api.port", self.api.port, self.api.enabled),
        ] {
            if enabled && port == 0 {
                return Err(DaygleError::Config(format!("{name} must not be 0")));
            }
        }
        if !(1..=65_536).contains(&self.server.proxy_protocol_max_connections) {
            return Err(DaygleError::Config(
                "server.proxy_protocol_max_connections must be in 1..=65536".to_string(),
            ));
        }
        for (name, value, enabled) in [
            (
                "dot.max_connections",
                self.dot.max_connections,
                self.dot.enabled,
            ),
            (
                "doh.max_connections",
                self.doh.max_connections,
                self.doh.enabled,
            ),
            (
                "doq.max_connections",
                self.doq.max_connections,
                self.doq.enabled,
            ),
        ] {
            if enabled && !(1..=65_536).contains(&value) {
                return Err(DaygleError::Config(format!("{name} must be in 1..=65536")));
            }
        }
        if self.doq.enabled && !(1..=65_536).contains(&self.doq.max_concurrent_streams) {
            return Err(DaygleError::Config(
                "doq.max_concurrent_streams must be in 1..=65536".to_string(),
            ));
        }
        if self.doq.enabled && self.doq.idle_timeout_secs < 30 {
            return Err(DaygleError::Config(
                "doq.idle_timeout_secs must be >= 30 (RFC 9250 recommends 600)".to_string(),
            ));
        }
        // TLS handshake timeout for the DoT/DoH listeners: a client cannot
        // start sending DNS messages until the handshake completes, so 0
        // drops every connection and an over-large one pins connections for
        // minutes. Same validation style as doq.idle_timeout_secs above:
        // only *enabled* listeners need a concrete value.
        for (name, secs, enabled) in [
            (
                "dot.handshake_timeout_secs",
                self.dot.handshake_timeout_secs,
                self.dot.enabled,
            ),
            (
                "doh.handshake_timeout_secs",
                self.doh.handshake_timeout_secs,
                self.doh.enabled,
            ),
        ] {
            if enabled && !(1..=600).contains(&secs) {
                return Err(DaygleError::Config(format!(
                    "{name} must be in 1..=600 (default 10)"
                )));
            }
        }
        if !(1000..=10_000).contains(&self.server.client_timeout_ms) {
            return Err(DaygleError::Config(
                "server.client_timeout_ms must be in 1000..=10000".to_string(),
            ));
        }
        if !(8..=65_536).contains(&self.server.udp_send_buffer_kb) {
            return Err(DaygleError::Config(
                "server.udp_send_buffer_kb must be in 8..=65536 (KiB)".to_string(),
            ));
        }
        if !(8..=65_536).contains(&self.server.udp_recv_buffer_kb) {
            return Err(DaygleError::Config(
                "server.udp_recv_buffer_kb must be in 8..=65536 (KiB)".to_string(),
            ));
        }
        let rec = &self.recursive;
        if rec.cache_size == 0 {
            return Err(DaygleError::Config(
                "recursive.cache_size must be >= 1".to_string(),
            ));
        }
        if !(1..=65_536).contains(&rec.max_concurrent_lookups) {
            return Err(DaygleError::Config(
                "recursive.max_concurrent_lookups must be in 1..=65536".to_string(),
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
        if rec.max_cache_ttl > 0 && rec.max_cache_ttl < rec.min_cache_ttl {
            return Err(DaygleError::Config(
                "recursive.max_cache_ttl must be >= recursive.min_cache_ttl when both are set"
                    .to_string(),
            ));
        }
        if rec.failure_cache_ttl > 7 * 24 * 3600 {
            return Err(DaygleError::Config(
                "recursive.failure_cache_ttl must be <= 604800 (7 days)".to_string(),
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
        if dnssec.default_record_ttl == 0 {
            return Err(DaygleError::Config(
                "authoritative.default_record_ttl must be >= 1".to_string(),
            ));
        }
        if dnssec.dnssec_sig_validity_days == 0 {
            return Err(DaygleError::Config(
                "authoritative.dnssec_sig_validity_days must be >= 1".to_string(),
            ));
        }
        if dnssec.dnssec_rollover_overlap_days == 0 || dnssec.dnssec_rollover_retire_days == 0 {
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
        if !(1..=128).contains(&rl.client_ipv6_prefix) {
            return Err(DaygleError::Config(
                "rate_limit.client_ipv6_prefix must be 1-128".to_string(),
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
        let mut policy_names = std::collections::HashSet::new();
        for policy in &self.recursive.client_policies {
            let name = policy.name.trim();
            if name.is_empty() {
                return Err(DaygleError::Config(
                    "recursive.client_policies contains a policy with an empty name".to_string(),
                ));
            }
            if !policy_names.insert(name.to_ascii_lowercase()) {
                return Err(DaygleError::Config(format!(
                    "client policy '{name}' is defined more than once"
                )));
            }
            if policy.clients.is_empty() {
                return Err(DaygleError::Config(format!(
                    "client policy '{name}' has no client networks"
                )));
            }
            for network in &policy.clients {
                if !self.is_network_entry(network) {
                    return Err(DaygleError::Config(format!(
                        "client policy '{name}' contains invalid network '{network}'"
                    )));
                }
            }
            if policy.action == ClientPolicyAction::Forward
                && policy.upstreams.iter().all(|u| u.trim().is_empty())
            {
                return Err(DaygleError::Config(format!(
                    "client policy '{name}' forwards but has no upstreams"
                )));
            }
        }
        for network in &self.recursive.recursion_networks {
            if !self.is_network_entry(network) {
                return Err(DaygleError::Config(format!(
                    "recursive.recursion_networks contains invalid network '{network}'"
                )));
            }
        }
        for (section, networks) in [
            ("dot", &self.dot.allowed_networks),
            ("doh", &self.doh.allowed_networks),
            ("doq", &self.doq.allowed_networks),
        ] {
            for network in networks {
                if !self.is_network_entry(network) {
                    return Err(DaygleError::Config(format!(
                        "{section}.allowed_networks contains invalid network '{network}'"
                    )));
                }
            }
        }
        if self.recursive.recursion_access == RecursionAccess::Custom
            && self.recursive.recursion_networks.is_empty()
        {
            return Err(DaygleError::Config(
                "recursive.recursion_access = \"custom\" requires recursion_networks".to_string(),
            ));
        }
        for source in &self.recursive.local_root.sources {
            parse_master_addr(source).map_err(|e| {
                DaygleError::Config(format!(
                    "recursive.local_root.sources contains invalid server '{source}': {e}"
                ))
            })?;
        }
        for hint in &self.recursive.root_hints {
            if hint.trim().parse::<IpAddr>().is_err() {
                return Err(DaygleError::Config(format!(
                    "recursive.root_hints contains invalid IP address '{hint}'"
                )));
            }
        }
        let versions = self.recursive.outbound_ip_versions;
        if !self.recursive.root_hints.is_empty()
            && !self
                .recursive
                .root_hints
                .iter()
                .filter_map(|h| h.trim().parse::<IpAddr>().ok())
                .any(|ip| versions.allows(ip))
        {
            return Err(DaygleError::Config(format!(
                "recursive.root_hints has no {} address, and outbound_ip_versions allows only {}",
                versions.label(),
                versions.label()
            )));
        }
        if self.recursive.local_root.enabled
            && self
                .recursive
                .local_root_in_effect()
                .effective_sources()
                .is_empty()
        {
            return Err(DaygleError::Config(format!(
                "recursive.local_root.sources has no {} server, and outbound_ip_versions allows only {}",
                versions.label(),
                versions.label()
            )));
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
        for (label, networks) in [
            ("policy.denied_networks", &self.policy.denied_networks),
            ("policy.allowed_networks", &self.policy.allowed_networks),
            (
                "authoritative.axfr_networks",
                &self.authoritative.axfr_networks,
            ),
            (
                "authoritative.update_networks",
                &self.authoritative.update_networks,
            ),
        ] {
            for net in networks {
                if !self.is_network_entry(net) {
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
            if base64::engine::general_purpose::STANDARD
                .decode(key.secret.trim())
                .is_err()
            {
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
        let catalog = self.authoritative.catalog_zone.trim();
        for entry in &self.server.proxy_protocol {
            if !self.is_network_entry(entry) {
                return Err(DaygleError::Config(format!(
                    "server.proxy_protocol: '{entry}' is not a network or address"
                )));
            }
        }
        for (i, rule) in self.policy.rules.iter().enumerate() {
            for network in &rule.clients {
                if !self.is_network_entry(network) {
                    return Err(DaygleError::Config(format!(
                        "policy rule {} contains invalid network '{network}'",
                        i + 1
                    )));
                }
            }
        }
        let not_a_name = |n: &str| n.contains('*') || validate_domain_pattern(n).is_err();
        if !catalog.is_empty() && not_a_name(catalog) {
            return Err(DaygleError::Config(format!(
                "authoritative.catalog_zone '{catalog}' is not a domain name"
            )));
        }
        for consumer in &self.authoritative.catalog_consumers {
            if not_a_name(&consumer.name) {
                return Err(DaygleError::Config(format!(
                    "catalog zone '{}' is not a domain name",
                    consumer.name
                )));
            }
            if consumer.masters.is_empty() {
                return Err(DaygleError::Config(format!(
                    "catalog zone '{}' has no masters",
                    consumer.name
                )));
            }
            for master in &consumer.masters {
                parse_master_addr(master).map_err(|e| {
                    DaygleError::Config(format!(
                        "catalog zone '{}' has invalid master '{master}': {e}",
                        consumer.name
                    ))
                })?;
            }
            if consumer.refresh_secs < 30 {
                return Err(DaygleError::Config(format!(
                    "catalog zone '{}': refresh_secs must be at least 30",
                    consumer.name
                )));
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
                    "stub zone '{}' has no nameservers (set them in nss)",
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
        let ai = &self.ai;
        if !(1..=32).contains(&ai.workers) {
            return Err(DaygleError::Config(
                "ai.workers must be in 1..=32".to_string(),
            ));
        }
        if ai.enabled {
            if ai.scan_interval_secs < 10 {
                return Err(DaygleError::Config(
                    "ai.scan_interval_secs must be >= 10".to_string(),
                ));
            }
            if ai.expire_check_secs < 10 {
                return Err(DaygleError::Config(
                    "ai.expire_check_secs must be >= 10".to_string(),
                ));
            }
        }
        if ai.max_domains_per_scan < 1 {
            return Err(DaygleError::Config(
                "ai.max_domains_per_scan must be >= 1".to_string(),
            ));
        }
        if !(0.5..=1.0).contains(&ai.block_threshold) {
            return Err(DaygleError::Config(
                "ai.block_threshold must be in 0.5..=1.0".to_string(),
            ));
        }
        if !(0.0..ai.block_threshold).contains(&ai.confidence_floor) {
            return Err(DaygleError::Config(
                "ai.confidence_floor must be < ai.block_threshold".to_string(),
            ));
        }
        if ai.category_ttl_secs < 60 {
            return Err(DaygleError::Config(
                "ai.category_ttl_secs must be >= 60".to_string(),
            ));
        }
        if ai.threat_ttl_secs < 60 {
            return Err(DaygleError::Config(
                "ai.threat_ttl_secs must be >= 60".to_string(),
            ));
        }
        for category in &ai.auto_block_categories {
            if category.trim().is_empty() {
                return Err(DaygleError::Config(
                    "ai.auto_block_categories contains an empty category".to_string(),
                ));
            }
        }
        self.display
            .check(false)
            .map_err(|e| DaygleError::Config(format!("display: {e}")))?;
        for (name, listen, enabled) in [
            ("server.listen", &self.server.listen, true),
            ("api.listen", &self.api.listen, self.api.enabled),
            ("dot.listen", &self.dot.listen, self.dot.enabled),
            ("doh.listen", &self.doh.listen, self.doh.enabled),
            ("doq.listen", &self.doq.listen, self.doq.enabled),
        ] {
            if enabled {
                listen_socket_addrs(listen, 0)
                    .map_err(|e| DaygleError::Config(format!("{name}: {e}")))?;
            }
        }
        if self.api.enabled {
            self.web
                .check(self.api.port)
                .map_err(|e| DaygleError::Config(format!("web: {e}")))?;
        }
        self.syslog
            .check()
            .map_err(|e| DaygleError::Config(format!("syslog: {e}")))?;
        self.dns64
            .compile(&self.all_networks())
            .map_err(|e| DaygleError::Config(format!("dns64: {e}")))?;
        self.ecs
            .compile()
            .map_err(|e| DaygleError::Config(format!("ecs: {e}")))?;
        if self.updates.enabled && self.updates.check_interval_secs < MIN_UPDATE_CHECK_INTERVAL_SECS
        {
            return Err(DaygleError::Config(format!(
                "updates.check_interval_secs must be >= {} seconds: GitHub's unauthenticated API allows 60 requests per hour per address, which everything else on this network shares",
                MIN_UPDATE_CHECK_INTERVAL_SECS
            )));
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
    #[serde(deserialize_with = "listen_list")]
    pub listen: String,
    /// With a listen address of `::` (here or in `[api]`, `[dot]`, `[doh]`
    /// or `[doq]`), accept IPv6 clients only. Off by default: `::` accepts
    /// IPv4 clients too.
    pub ipv6_only: bool,
    /// DNS cookies (RFC 7873): answer clients that send a cookie with a
    /// server cookie, and give clients whose server cookie checks out ten
    /// times the per-client rate limit. On by default.
    pub dns_cookies: bool,
    /// PROXY protocol (v1/v2): networks of trusted load balancers. A TCP,
    /// DoT or DoH connection from one of them must start with a PROXY
    /// header, and the client it names is treated as the real client.
    /// Empty (the default) turns it off.
    pub proxy_protocol: Vec<String>,
    /// Maximum active connections admitted by each PROXY-protocol TCP front.
    pub proxy_protocol_max_connections: usize,
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
    /// Client Timeout (milliseconds): how long the server waits for an answer
    /// before replying SERVFAIL. Applied to the recursive path; valid range
    /// 1000-10000 (Technitium-style Client Timeout, default 2000).
    pub client_timeout_ms: u64,
    /// Plaintext UDP listener socket send buffer size, in KiB. The kernel may
    /// round or double the requested value. Valid range 8-65536 (default
    /// 2048). Does not apply to DoQ/QUIC sockets.
    pub udp_send_buffer_kb: u32,
    /// Plaintext UDP listener socket receive buffer size, in KiB. The kernel
    /// may round or double the requested value. Valid range 8-65536 (default
    /// 2048). Does not apply to DoQ/QUIC sockets.
    pub udp_recv_buffer_kb: u32,
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
            ipv6_only: false,
            dns_cookies: true,
            proxy_protocol: vec![],
            proxy_protocol_max_connections: 1024,
            port: 53,
            udp_enabled: true,
            tcp_enabled: true,
            tcp_timeout_ms: 5000,
            response_buffer_size: 4096,
            client_timeout_ms: 2000,
            udp_send_buffer_kb: 2048,
            udp_recv_buffer_kb: 2048,
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
    /// How non-authoritative queries are resolved: `recursive` walks root ->
    /// TLD -> authoritative itself, `forwarding` sends them to `upstreams`.
    /// Unset means: forwarding when `upstreams` is non-empty, otherwise
    /// recursive (see [`RecursiveSettings::effective_mode`]).
    pub mode: Option<ResolutionMode>,
    /// Upstream servers (forwarding mode). Accepts `8.8.8.8`, `1.1.1.1:53`,
    /// `tls://1.1.1.1:853@cloudflare-dns.com` and `https://...` forms.
    ///
    /// In forwarding mode with no upstreams, the operating system's resolver
    /// configuration is used.
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
    /// Lower bound, in seconds, applied to cached *positive* TTLs.
    /// A record whose authoritative TTL is below this is kept in cache for at
    /// least this long so very-short-TTL answers are not churned out of the
    /// cache immediately.
    pub min_cache_ttl: u32,
    /// Upper bound, in seconds, for caching *negative* (NXDOMAIN/NODATA)
    /// answers. Hickory derives the authoritative negative TTL from the SOA;
    /// this caps it.
    pub negative_cache_ttl: u32,
    /// Upper bound, in seconds, applied to cached *positive* TTLs at insert
    /// time. Records whose TTL exceeds this are clamped down so tracking-heavy
    /// domains cannot pin themselves in cache for weeks.
    pub max_cache_ttl: u32,
    /// TTL, in seconds, for caching *failure responses* (SERVFAIL and, when the
    /// upstream returns an explicit code, NXDOMAIN/NODATA that arrives as an
    /// error). A cached failure blocks repeated lookups to a broken upstream
    /// for this long; 0 disables failure caching.
    pub failure_cache_ttl: u32,
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
    /// Maximum concurrent client recursive lookups. Timed-out work retains its slot until complete.
    pub max_concurrent_lookups: usize,
    /// Which clients may use recursion (both modes). Authoritative zones are
    /// answered for every client regardless.
    pub recursion_access: RecursionAccess,
    /// Client networks (CIDRs or bare IPs) allowed when `recursion_access` is
    /// `custom`.
    pub recursion_networks: Vec<String>,
    /// Root server addresses for recursive mode. Empty uses the built-in IANA
    /// root servers.
    pub root_hints: Vec<String>,
    /// Randomize query-name case (0x20) on outgoing UDP queries in recursive
    /// mode and require answers to echo it, making spoofed answers harder to
    /// inject. Off by default: a few authoritative servers do not preserve
    /// case and would fail to resolve.
    pub case_randomization: bool,
    /// DNS rebinding protection (recursive mode): drop private, loopback and
    /// link-local addresses from public answers. Names served by local
    /// zones, conditional forwarders and stub zones are not affected.
    pub rebinding_protection: bool,
    /// Local root zone (RFC 8806): keep a verified copy of the root zone and
    /// answer root queries from it instead of asking the root servers.
    pub local_root: LocalRootSettings,
    /// Opportunistic encryption (RFC 9539, recursive mode): probe
    /// nameservers for DNS over TLS / QUIC in the background and use it where
    /// it works, falling back to plain DNS. Off by default: it is
    /// experimental and adds connection overhead.
    pub opportunistic_encryption: bool,
    /// Which IP versions the resolver uses for its own queries: to root and
    /// domain name servers, forwarders, stub zone name servers and local
    /// root zone sources. Zone transfers and NOTIFY go to the addresses
    /// configured for them regardless.
    pub outbound_ip_versions: IpVersions,
    /// Client resolution policies: clients in a policy's networks are
    /// resolved its way (forwarded to its own upstreams, resolved from the
    /// root servers, or refused) instead of by the default mode. The first
    /// enabled matching policy wins; conditional forwarders and stub zones
    /// still take precedence for their names.
    pub client_policies: Vec<ClientPolicyConfig>,
    /// Testing only: send recursive-mode queries to this port instead of 53
    /// and allow private/loopback nameservers, so tests can run a fake
    /// root -> TLD -> authoritative hierarchy without privileged ports.
    #[serde(skip)]
    pub test_outbound_port: Option<u16>,
}

/// How non-authoritative queries are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    /// Resolve iteratively from the root servers.
    Recursive,
    /// Send queries to the configured upstreams (or the system resolver).
    Forwarding,
}

/// Which clients may use recursion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursionAccess {
    /// Every client.
    Allow,
    /// Loopback, RFC 1918, CGNAT (100.64.0.0/10), link-local and IPv6 ULA
    /// clients only.
    #[default]
    PrivateNetworks,
    /// The networks in `recursion_networks`.
    Custom,
    /// Nobody: only authoritative zones are answered.
    Deny,
}

/// Which IP versions outgoing queries use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersions {
    /// IPv4 and IPv6.
    #[default]
    Both,
    /// IPv4 only, e.g. on a host whose IPv6 does not reach the internet.
    Ipv4,
    /// IPv6 only.
    Ipv6,
}

impl IpVersions {
    /// Whether `ip` may be used (IPv4-mapped IPv6 counts as IPv4).
    pub fn allows(self, ip: IpAddr) -> bool {
        match (self, ip.to_canonical()) {
            (Self::Both, _) => true,
            (Self::Ipv4, ip) => ip.is_ipv4(),
            (Self::Ipv6, ip) => ip.is_ipv6(),
        }
    }

    /// How the setting reads in error messages ("IPv4", "IPv6").
    pub fn label(self) -> &'static str {
        match self {
            Self::Both => "IPv4 or IPv6",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

/// Local root zone settings (RFC 8806, "Secondary ROOT Zone" in the
/// console). The zone is transferred from `sources`, accepted only when its
/// ZONEMD digest (RFC 8976) matches and is signed by a key chaining to the
/// built-in root trust anchor, and kept in memory (and on disk next to the
/// database). In recursive mode root queries are answered from it; in
/// forwarding mode names under top-level domains that do not exist are
/// answered NXDOMAIN without asking the upstreams.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LocalRootSettings {
    /// Keep a local copy of the root zone.
    pub enabled: bool,
    /// Servers to transfer the root zone from (AXFR over TCP), as `IP`,
    /// `IP:port` or `[IPv6]:port`, tried in order. Empty uses
    /// [`LOCAL_ROOT_SOURCES`].
    pub sources: Vec<String>,
    /// Testing only: trust this DNSKEY public key (wire format) instead of
    /// the built-in root trust anchor, so tests can sign a fake root zone.
    #[serde(skip)]
    pub test_trust_anchor: Option<Vec<u8>>,
    /// Copied from `recursive.outbound_ip_versions` (see
    /// [`RecursiveSettings::local_root_in_effect`]): sources of other IP
    /// versions are skipped.
    #[serde(skip)]
    pub outbound_ip_versions: IpVersions,
}

/// Servers that allow root zone transfers (RFC 8806 Appendix A): ICANN's
/// transfer servers and the root servers that permit AXFR.
pub const LOCAL_ROOT_SOURCES: &[&str] = &[
    "192.0.32.132",  // lax.xfr.dns.icann.org
    "192.0.47.132",  // iad.xfr.dns.icann.org
    "170.247.170.2", // b.root-servers.net
    "192.33.4.12",   // c.root-servers.net
    "199.7.91.13",   // d.root-servers.net
    "192.5.5.241",   // f.root-servers.net
    "192.112.36.4",  // g.root-servers.net
    "193.0.14.129",  // k.root-servers.net
    "2620:0:2d0:202::132",
    "2620:0:2830:202::132",
    "2801:1b8:10::b",
    "2001:500:2::c",
    "2001:500:2d::d",
    "2001:500:2f::f",
    "2001:500:12::d0d",
    "2001:7fd::1",
];

impl LocalRootSettings {
    /// The transfer sources in effect (the configured list or the defaults).
    /// Sources of an IP version the resolver does not use are left out.
    pub fn effective_sources(&self) -> Vec<String> {
        let sources: Vec<String> = if self.sources.is_empty() {
            LOCAL_ROOT_SOURCES.iter().map(|s| s.to_string()).collect()
        } else {
            self.sources.clone()
        };
        sources
            .into_iter()
            .filter(|s| {
                parse_master_addr(s)
                    .map(|a| self.outbound_ip_versions.allows(a.ip()))
                    .unwrap_or(true)
            })
            .collect()
    }
}

/// One client resolution policy (see `RecursiveSettings::client_policies`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientPolicyConfig {
    /// Display name, unique among the policies.
    pub name: String,
    pub enabled: bool,
    /// Client networks (CIDRs or bare IPs) the policy applies to.
    pub clients: Vec<String>,
    pub action: ClientPolicyAction,
    /// Upstreams for [`ClientPolicyAction::Forward`] (same forms as
    /// `recursive.upstreams`).
    pub upstreams: Vec<String>,
    /// When the policy last changed (RFC 3339). Stamped by the server when
    /// the list is saved - never taken from a request - and shown as "Last
    /// Modified" in the console.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
}

impl Default for ClientPolicyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            clients: vec![],
            action: ClientPolicyAction::Forward,
            upstreams: vec![],
            modified_at: None,
        }
    }
}

/// How a client resolution policy resolves its clients' queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientPolicyAction {
    /// Send queries to the policy's own upstreams.
    #[default]
    Forward,
    /// Resolve from the root servers, whatever the default mode.
    Recursive,
    /// Refuse recursion (local zones are still answered).
    Refuse,
}

/// Answers rebinding protection drops from public names: the private
/// networks plus the "this host" ranges and IPv4-mapped IPv6, which would
/// otherwise carry a private IPv4 address inside an AAAA record
/// (`::ffff:192.168.1.1`).
pub const REBINDING_DENY_NETWORKS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "::1/128",
    "::/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
];

/// The global IPv6 networks this host has addresses in (read from
/// /proc/net/if_inet6 on Linux; empty elsewhere). Most LANs number their
/// IPv6 devices from the ISP's global prefix rather than ULA, so "private
/// networks" access also covers these. Cached for a minute, so a prefix the
/// ISP renumbers is picked up without a restart.
pub fn on_link_ipv6_networks() -> Vec<ipnet::IpNet> {
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    /// When the networks were last read, and what they were.
    type Cached = Option<(Instant, Vec<ipnet::IpNet>)>;
    static CACHE: OnceLock<parking_lot::Mutex<Cached>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| parking_lot::Mutex::new(None));
    let mut guard = cache.lock();
    if let Some((at, nets)) = guard.as_ref() {
        if at.elapsed() < Duration::from_secs(60) {
            return nets.clone();
        }
    }
    let nets = std::fs::read_to_string("/proc/net/if_inet6")
        .map(|text| parse_if_inet6(&text))
        .unwrap_or_default();
    *guard = Some((Instant::now(), nets.clone()));
    nets
}

/// Parse /proc/net/if_inet6 lines (`address ifindex prefixlen scope flags
/// name`, hex) into the global-scope networks.
fn parse_if_inet6(text: &str) -> Vec<ipnet::IpNet> {
    let mut nets: Vec<ipnet::IpNet> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (hex, prefix, scope) = (fields.first()?, fields.get(2)?, fields.get(3)?);
            if *scope != "00" || hex.len() != 32 {
                return None;
            }
            let bits = u128::from_str_radix(hex, 16).ok()?;
            let prefix = u8::from_str_radix(prefix, 16).ok()?;
            let addr = std::net::Ipv6Addr::from(bits);
            ipnet::Ipv6Net::new(addr, prefix)
                .ok()
                .map(|n| ipnet::IpNet::V6(n.trunc()))
        })
        .collect();
    nets.sort();
    nets.dedup();
    nets
}

/// Client networks treated as private for [`RecursionAccess::PrivateNetworks`]
/// (plus this host's own global IPv6 networks; see
/// [`on_link_ipv6_networks`]).
pub const PRIVATE_NETWORKS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

impl RecursiveSettings {
    /// The local root zone settings with the outbound IP versions applied.
    pub fn local_root_in_effect(&self) -> LocalRootSettings {
        LocalRootSettings {
            outbound_ip_versions: self.outbound_ip_versions,
            ..self.local_root.clone()
        }
    }

    /// The resolution mode in effect: the explicit `mode`, otherwise
    /// forwarding when upstreams are configured and recursive when not.
    pub fn effective_mode(&self) -> ResolutionMode {
        self.mode.unwrap_or(if self.upstreams.is_empty() {
            ResolutionMode::Recursive
        } else {
            ResolutionMode::Forwarding
        })
    }
}

impl Default for RecursiveSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: None,
            upstreams: vec![],
            use_system_config: true,
            cache_size: 8192,
            timeout_secs: 5,
            attempts: 3,
            dnssec_validate: true,
            min_cache_ttl: 0,
            negative_cache_ttl: 3600,
            max_cache_ttl: 0,
            failure_cache_ttl: 10,
            conditional_zones: vec![],
            prefetch_enabled: true,
            prefetch_ttl_fraction_pct: 10,
            prefetch_min_queries: 5,
            prefetch_window_secs: 600,
            serve_stale_secs: 86400,
            max_concurrent_lookups: 256,
            recursion_access: RecursionAccess::PrivateNetworks,
            recursion_networks: vec![],
            root_hints: vec![],
            case_randomization: false,
            rebinding_protection: false,
            local_root: LocalRootSettings::default(),
            opportunistic_encryption: false,
            outbound_ip_versions: IpVersions::Both,
            client_policies: vec![],
            test_outbound_port: None,
        }
    }
}

/// A conditional forwarding zone: `name` is resolved via `upstreams` instead
/// of the global `recursive.upstreams`. Accepts the same upstream forms
/// (plain IP, `tls://IP:port@hostname`, ...).
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
    /// Default SOA primary nameserver used when a zone is created. Empty
    /// means this server's own host name (see [`detect_server_name`]).
    pub default_primary_ns: String,
    /// Default SOA contact mailbox used when a zone is created. Empty means
    /// the first administrator's email address.
    pub default_admin_mailbox: String,
    /// Default TTL (seconds) used for records that do not specify one (e.g.
    /// the console's Records page pre-fills this value for new records).
    pub default_record_ttl: u32,
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
    /// Client networks allowed to send dynamic updates. When empty, only
    /// zones bound to a TSIG key (`tsig_update_zones`) accept updates, and
    /// only signed ones; an unauthenticated update from anywhere is never
    /// accepted.
    pub update_networks: Vec<String>,
    /// Secondary zones replicated from remote masters via AXFR/IXFR.
    pub secondary_zones: Vec<SecondaryZoneConfig>,
    /// Publish a catalog zone (RFC 9432) of this name listing every primary
    /// zone, so secondaries that consume it pick up new and deleted zones
    /// on their own. Empty turns it off.
    pub catalog_zone: String,
    /// Catalog zones (RFC 9432) to consume: each is transferred from its
    /// masters, and every zone it lists is served here as a secondary zone
    /// from the same masters (zones it drops are removed).
    pub catalog_consumers: Vec<CatalogConsumerConfig>,
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
    /// Stub zones: queries for names inside these zones are resolved
    /// directly against the zone's own nameservers (see [`StubZoneConfig`]).
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
            default_primary_ns: String::new(),
            default_admin_mailbox: String::new(),
            default_record_ttl: 3600,
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
            catalog_zone: String::new(),
            catalog_consumers: vec![],
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

/// A catalog zone (RFC 9432) consumed from remote masters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CatalogConsumerConfig {
    /// The catalog zone's name, e.g. `catalog.example.com`.
    pub name: String,
    /// The servers to transfer the catalog, and its member zones, from:
    /// each `IP`, `IP:port`, or `[IPv6]:port` (port 53 when omitted).
    pub masters: Vec<String>,
    /// How often to check the catalog, and its members, for changes.
    pub refresh_secs: u64,
    /// Whether the catalog is followed. A disabled catalog keeps the zones
    /// it already added, but stops adding and removing them.
    pub enabled: bool,
}

impl Default for CatalogConsumerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            masters: vec![],
            refresh_secs: 3600,
            enabled: true,
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
    #[serde(deserialize_with = "listen_list")]
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
    /// Name of a console-managed certificate (stored in the database) to use.
    /// When set it takes precedence over `self_signed` and the file paths.
    #[serde(default)]
    pub certificate: String,
    /// Maximum active TCP connections (including TLS handshakes). One client
    /// (an IPv4 address or IPv6 /64) may hold an eighth of them, at least 4.
    pub max_connections: usize,
    /// TLS handshake timeout in seconds: how long a client may take to
    /// complete the TLS handshake before the connection is dropped. It is
    /// also the read-inactivity timeout of an established DoT session, so an
    /// idle keep-alive connection is closed once it expires (1..=600,
    /// default 20).
    pub handshake_timeout_secs: u64,
    /// Client networks allowed to use this listener (addresses or network
    /// names). Empty means everyone; clients outside the list get REFUSED
    /// and, on this listener only, are treated as allowed for recursion.
    pub allowed_networks: Vec<String>,
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
            certificate: String::new(),
            max_connections: 1024,
            handshake_timeout_secs: 20,
            allowed_networks: vec![],
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
    #[serde(deserialize_with = "listen_list")]
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
    /// Name of a console-managed certificate (stored in the database) to use.
    #[serde(default)]
    pub certificate: String,
    /// TLS handshake timeout in seconds: how long a client may take to
    /// complete the TLS handshake before the connection is dropped
    /// (1..=600, default 10).
    pub handshake_timeout_secs: u64,
    /// Maximum active TCP connections including TLS handshakes.
    pub max_connections: usize,
    /// Client networks allowed to use this listener (addresses or network
    /// names). Empty means everyone; clients outside the list get REFUSED
    /// and, on this listener only, are treated as allowed for recursion.
    pub allowed_networks: Vec<String>,
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
            certificate: String::new(),
            handshake_timeout_secs: 10,
            max_connections: 1024,
            allowed_networks: vec![],
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
    #[serde(deserialize_with = "listen_list")]
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
    #[serde(deserialize_with = "listen_list")]
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
    /// Maximum active QUIC connections, including handshakes.
    pub max_connections: usize,
    /// Maximum concurrent DNS query streams per DoQ listener.
    pub max_concurrent_streams: usize,
    /// Name of a console-managed certificate (stored in the database) to use.
    #[serde(default)]
    pub certificate: String,
    /// Client networks allowed to use this listener (addresses or network
    /// names). Empty means everyone; clients outside the list get REFUSED
    /// and, on this listener only, are treated as allowed for recursion.
    pub allowed_networks: Vec<String>,
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
            max_connections: 1024,
            max_concurrent_streams: 256,
            certificate: String::new(),
            allowed_networks: vec![],
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
    /// Content format: `domains` (one domain per line), `wildcard` (one
    /// domain per line, each covering its subdomains), `hosts` (a hosts
    /// file, e.g. StevenBlack), `adblock` (AdGuard/uBlock syntax), or `rpz`
    /// (a Response Policy Zone file).
    pub format: BlocklistFormat,
    /// How often to re-fetch the source, in seconds (default 24 h).
    pub refresh_secs: u64,
    /// Whether this source is fetched at all.
    pub enabled: bool,
    /// Who the source blocks for: `everyone` (the default), or only the
    /// client groups that select it (`groups`). `dot` remains accepted for
    /// compatibility with previously saved sources.
    pub scope: BlocklistScope,
}

impl Default for BlocklistSourceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            format: BlocklistFormat::Domains,
            refresh_secs: 86400,
            enabled: true,
            scope: BlocklistScope::Everyone,
        }
    }
}

/// Who a remote blocklist source applies to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistScope {
    /// Every client (merged into the server-wide blocklist).
    #[default]
    Everyone,
    /// Only clients in a client group that selects this source.
    Groups,
    /// Legacy compatibility: only queries arriving on the DoT listener.
    #[serde(rename = "dot")]
    Dot,
}

/// The wire format of a remote blocklist source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistFormat {
    /// One domain per line; comments (`#`, `!`) are skipped.
    #[default]
    Domains,
    /// One domain per line, each also covering its subdomains (oisd's
    /// `domainswild2`): `example.com` blocks `example.com` and
    /// `ads.example.com`.
    Wildcard,
    /// A hosts file: lines like `0.0.0.0 example.com`. The hostname column is
    /// used; localhost/loopback entries are ignored.
    Hosts,
    /// AdGuard/uBlock origin syntax: `||example.com^`, `@@` exceptions are
    /// ignored (treated as not-blocked).
    Adblock,
    /// A Response Policy Zone (RPZ) in zone-file form: every QNAME trigger is
    /// blocked, except `rpz-passthru.` exceptions; IP and NSDNAME triggers
    /// are ignored.
    Rpz,
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
    /// IPv6 clients are counted per prefix of this length: one host or
    /// network normally holds a whole /64 or more, so counting single
    /// addresses would let a client rotate past the limit. 56 matches
    /// BIND's response rate limiting; 128 counts single addresses.
    pub client_ipv6_prefix: u8,
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
            client_ipv6_prefix: 56,
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
    /// The zone's nameservers. Bare IPs (and `IP:port`) are used as-is;
    /// hostnames are resolved once through the system resolver at startup
    /// and on live reload. Entries that cannot be resolved are skipped.
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
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
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
    fn resource_limits_validate_and_survive_runtime_settings_overlay() {
        let mut config = DaygleConfig::default();
        config.recursive.max_concurrent_lookups = 17;
        config.dot.max_connections = 18;
        config.doh.max_connections = 19;
        config.doq.max_connections = 20;
        config.doq.max_concurrent_streams = 21;

        let overlay = RuntimeSettings::capture(&config);
        let mut restored = DaygleConfig::default();
        overlay.apply_to(&mut restored);
        assert_eq!(restored.recursive.max_concurrent_lookups, 17);
        assert_eq!(restored.dot.max_connections, 18);
        assert_eq!(restored.doh.max_connections, 19);
        assert_eq!(restored.doq.max_connections, 20);
        assert_eq!(restored.doq.max_concurrent_streams, 21);
        restored.validate().unwrap();

        let mut invalid = DaygleConfig::default();
        invalid.recursive.max_concurrent_lookups = 0;
        assert!(invalid.validate().is_err());
        invalid.recursive.max_concurrent_lookups = 1;
        invalid.dot.enabled = true;
        invalid.dot.max_connections = 0;
        assert!(invalid.validate().is_err());
        invalid.dot.max_connections = 1;
        invalid.doq.enabled = true;
        invalid.doq.max_concurrent_streams = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn update_check_settings_parse_and_floor() {
        // Defaults: hourly checks on.
        let cfg = DaygleConfig::parse("").unwrap();
        assert!(cfg.updates.enabled);
        assert_eq!(cfg.updates.check_interval_secs, 3600);
        // Explicitly parsed section; unknown keys rejected.
        let cfg = DaygleConfig::parse("[updates]\nenabled = false\ncheck_interval_secs = 86400\n")
            .unwrap();
        assert!(!cfg.updates.enabled);
        assert_eq!(cfg.updates.check_interval_secs, 86400);
        assert!(DaygleConfig::parse("[updates]\nnope = 1\n").is_err());
        // The interval floor applies only while checks are enabled.
        let mut cfg = DaygleConfig::parse("").unwrap();
        cfg.updates.check_interval_secs = 60;
        assert!(cfg.validate().is_err());
        cfg.updates.enabled = false;
        assert!(cfg.validate().is_ok());
        cfg.updates.enabled = true;
        cfg.updates.check_interval_secs = 600;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rebinding_deny_list_covers_ipv6_forms_of_private_addresses() {
        let nets: Vec<ipnet::IpNet> = REBINDING_DENY_NETWORKS
            .iter()
            .map(|n| n.parse().unwrap())
            .collect();
        let denied = |ip: &str| {
            let ip: IpAddr = ip.parse().unwrap();
            nets.iter().any(|n| n.contains(&ip))
        };
        // A private IPv4 address smuggled inside an AAAA answer.
        assert!(denied("::ffff:192.168.1.1"));
        assert!(denied("::ffff:127.0.0.1"));
        assert!(denied("fd12:3456::1"));
        assert!(denied("fe80::1"));
        assert!(denied("::1"));
        assert!(denied("::"));
        assert!(denied("0.0.0.0"));
        // Public addresses pass.
        assert!(!denied("2606:4700:4700::1111"));
        assert!(!denied("1.1.1.1"));
    }

    #[test]
    fn reads_global_ipv6_networks_from_if_inet6() {
        let text = "\
00000000000000000000000000000001 01 80 10 80       lo
2a0204ab12340001021122fffe334455 02 40 00 00     eth0
fe80000000000000021122fffe334455 02 40 20 80     eth0
fd0000000000000000000000000000aa 02 40 00 80     eth0
2a0204ab123400010000000000000053 02 80 00 80     eth0
";
        let nets: Vec<String> = parse_if_inet6(text).iter().map(|n| n.to_string()).collect();
        // Global scope only (loopback and link-local skipped), as networks.
        assert_eq!(
            nets,
            [
                "2a02:4ab:1234:1::/64",
                "2a02:4ab:1234:1::53/128",
                "fd00::/64"
            ]
        );
    }

    #[test]
    fn outbound_ip_versions_limit_root_hints_and_sources() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(IpVersions::Both.allows(ip("2001:db8::1")));
        assert!(IpVersions::Ipv4.allows(ip("192.0.2.1")));
        assert!(IpVersions::Ipv4.allows(ip("::ffff:192.0.2.1")));
        assert!(!IpVersions::Ipv4.allows(ip("2001:db8::1")));
        assert!(!IpVersions::Ipv6.allows(ip("192.0.2.1")));

        let cfg = DaygleConfig::parse(
            "[server]\nipv6_only = true\n[recursive]\noutbound_ip_versions = \"ipv4\"\n",
        )
        .unwrap();
        assert!(cfg.server.ipv6_only);
        assert_eq!(cfg.recursive.outbound_ip_versions, IpVersions::Ipv4);
        // The default local root sources narrow to IPv4.
        let sources = cfg.recursive.local_root_in_effect().effective_sources();
        assert!(!sources.is_empty());
        assert!(sources.iter().all(|s| !s.contains(':')), "{sources:?}");

        // Root hints and local root sources must keep an allowed server.
        let mut cfg = DaygleConfig::default();
        cfg.recursive.outbound_ip_versions = IpVersions::Ipv6;
        cfg.recursive.root_hints = vec!["198.41.0.4".into()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("root_hints"));
        cfg.recursive.root_hints = vec!["198.41.0.4".into(), "2001:503:ba3e::2:30".into()];
        cfg.validate().unwrap();
        cfg.recursive.local_root.enabled = true;
        cfg.recursive.local_root.sources = vec!["192.0.32.132".into()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("local_root.sources"));
        // The setting survives the database overlay.
        let overlay = RuntimeSettings::capture(&cfg);
        let mut restored = DaygleConfig::default();
        overlay.apply_to(&mut restored);
        assert_eq!(restored.recursive.outbound_ip_versions, IpVersions::Ipv6);
    }

    #[test]
    fn listen_addresses_take_ipv4_and_ipv6() {
        let addr = |s: &str| listen_socket_addr(s, 53).map(|a| a.to_string());
        assert_eq!(addr("0.0.0.0").unwrap(), "0.0.0.0:53");
        assert_eq!(addr("::").unwrap(), "[::]:53");
        assert_eq!(addr("[::]").unwrap(), "[::]:53");
        assert_eq!(addr(" fd00::53 ").unwrap(), "[fd00::53]:53");
        assert_eq!(addr("192.168.1.2").unwrap(), "192.168.1.2:53");
        assert!(addr("dns.example.com").is_err());
        assert!(addr("[::").is_err());
        // Before this, "::" was joined into ":::53", which does not parse.
        let mut cfg = DaygleConfig::default();
        cfg.server.listen = "::".into();
        cfg.api.listen = "[::1]".into();
        cfg.validate().unwrap();
        cfg.server.listen = "not-an-ip".into();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("server.listen"));
    }

    #[test]
    fn dns64_embeds_addresses_per_rfc_6052() {
        let dns64 = |prefix: &str| {
            Dns64Settings {
                enabled: true,
                prefix: prefix.to_string(),
                clients: vec![],
            }
            .compile(&[])
            .unwrap()
            .unwrap()
        };
        let v4: Ipv4Addr = "192.0.2.33".parse().unwrap();
        // RFC 6052 §2.4's examples.
        for (prefix, expected) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::c000:221"),
        ] {
            assert_eq!(
                dns64(prefix).synthesize(v4),
                Some(expected.parse().unwrap()),
                "{prefix}"
            );
        }
        // The well-known prefix carries global addresses only.
        let wkp = dns64("64:ff9b::/96");
        assert_eq!(
            wkp.synthesize("198.51.100.1".parse().unwrap()),
            None,
            "documentation range"
        );
        assert_eq!(wkp.synthesize("10.1.2.3".parse().unwrap()), None);
        assert_eq!(
            wkp.synthesize("93.184.216.34".parse().unwrap()),
            Some("64:ff9b::5db8:d822".parse().unwrap())
        );
        // A network-specific prefix carries any.
        assert!(dns64("2001:db8:64::/96")
            .synthesize("10.1.2.3".parse().unwrap())
            .is_some());

        // Checks.
        let bad = |prefix: &str, clients: Vec<&str>| {
            Dns64Settings {
                enabled: true,
                prefix: prefix.to_string(),
                clients: clients.into_iter().map(String::from).collect(),
            }
            .compile(&[])
            .is_err()
        };
        assert!(bad("64:ff9b::/80", vec![]));
        assert!(bad("10.0.0.0/8", vec![]));
        assert!(bad("2001:db8:0:0:ff00::/96", vec![]), "u octet set");
        assert!(bad("64:ff9b::/96", vec!["nope"]));
        assert!(Dns64Settings::default().compile(&[]).unwrap().is_none());

        let only = Dns64Settings {
            enabled: true,
            clients: vec!["2001:db8:1::/48".into()],
            ..Default::default()
        }
        .compile(&[])
        .unwrap()
        .unwrap();
        assert!(only.applies_to("2001:db8:1::5".parse().unwrap()));
        assert!(!only.applies_to("2001:db8:2::5".parse().unwrap()));
    }

    #[test]
    fn ecs_subnets_are_cut_and_private_ones_kept_back() {
        let ecs = |subnet: &str| {
            EcsSettings {
                enabled: true,
                subnet: subnet.to_string(),
                ..Default::default()
            }
            .compile()
            .unwrap()
            .unwrap()
        };
        let per_client = ecs("");
        let at = |ip: &str| {
            per_client
                .subnet_for(ip.parse().unwrap())
                .map(|n| n.to_string())
        };
        assert_eq!(at("93.184.216.34").as_deref(), Some("93.184.216.0/24"));
        assert_eq!(
            at("::ffff:93.184.216.34").as_deref(),
            Some("93.184.216.0/24")
        );
        assert_eq!(
            at("2a00:1450:4001:82a::200e").as_deref(),
            Some("2a00:1450:4001:800::/56")
        );
        for private in [
            "192.168.1.5",
            "10.0.0.1",
            "127.0.0.1",
            "100.64.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert_eq!(at(private), None, "{private}");
        }
        // A fixed subnet is sent for everyone, host bits cleared.
        let fixed = ecs("203.0.113.77/24");
        assert_eq!(
            fixed
                .subnet_for("192.168.1.5".parse().unwrap())
                .map(|n| n.to_string())
                .as_deref(),
            Some("203.0.113.0/24")
        );
        assert!(EcsSettings::default().compile().unwrap().is_none());
        for bad in [
            EcsSettings {
                enabled: true,
                ipv4_prefix: 0,
                ..Default::default()
            },
            EcsSettings {
                enabled: true,
                ipv6_prefix: 129,
                ..Default::default()
            },
            EcsSettings {
                enabled: true,
                subnet: "nope".into(),
                ..Default::default()
            },
        ] {
            assert!(bad.compile().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn syslog_targets_and_checks() {
        let target = |server: &str| {
            SyslogSettings {
                enabled: true,
                server: server.into(),
                ..Default::default()
            }
            .target()
        };
        assert_eq!(
            target("logs.example.com").unwrap(),
            SyslogTarget {
                tcp: false,
                host: "logs.example.com".into(),
                port: 514
            }
        );
        assert_eq!(target("tcp://10.0.0.5:6514").unwrap().port, 6514);
        assert!(target("tcp://10.0.0.5:6514").unwrap().tcp);
        assert_eq!(
            target("udp://[2001:db8::1]:1514").unwrap().host,
            "2001:db8::1"
        );
        assert_eq!(target("2001:db8::1").unwrap().port, 514);
        assert!(target("").is_err());
        assert!(target("host:notaport").is_err());
        let mut s = SyslogSettings::default();
        assert!(s.check().is_ok(), "off and empty is fine");
        assert_eq!(s.facility_code(), Some(3));
        s.facility = "local7".into();
        assert_eq!(s.facility_code(), Some(23));
        s.facility = "local8".into();
        assert!(s.check().is_err());
        s.facility = "daemon".into();
        s.level = "debug".into();
        assert!(s.check().is_err());
        s.level = "warn".into();
        s.enabled = true;
        assert!(s.check().is_err(), "enabled needs a server");
    }

    #[test]
    fn listen_settings_take_several_addresses() {
        let addrs = |s: &str| {
            listen_socket_addrs(s, 53).map(|v| v.iter().map(|a| a.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(addrs("0.0.0.0").unwrap(), ["0.0.0.0:53"]);
        assert_eq!(
            addrs("192.168.1.2, [fd00::53]").unwrap(),
            ["192.168.1.2:53", "[fd00::53]:53"]
        );
        // Every IPv6 address plus one IPv4 address, and both wildcards.
        assert_eq!(
            addrs("::,192.168.1.2").unwrap(),
            ["[::]:53", "192.168.1.2:53"]
        );
        assert_eq!(addrs("0.0.0.0, ::").unwrap().len(), 2);
        // A wildcard already covers its family; repeats cannot both bind.
        assert!(addrs("0.0.0.0, 192.168.1.2")
            .unwrap_err()
            .contains("0.0.0.0 already covers"));
        assert!(addrs(":: , fd00::53")
            .unwrap_err()
            .contains(":: already covers"));
        assert!(addrs("192.168.1.2, 192.168.1.2")
            .unwrap_err()
            .contains("twice"));
        assert!(addrs("192.168.1.2,").is_err());

        // The file may use an array.
        let cfg = DaygleConfig::parse(
            "[server]\nlisten = [\"127.0.0.1\", \"::1\"]\n[api]\nlisten = \"127.0.0.1, ::1\"\n",
        )
        .unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1, ::1");
        assert_eq!(cfg.api.listen, "127.0.0.1, ::1");
        let mut cfg = DaygleConfig::default();
        cfg.dot.enabled = true;
        cfg.dot.listen = "0.0.0.0, 10.0.0.1".into();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("dot.listen"));
    }

    #[test]
    fn mailboxes_convert_between_email_and_soa_form() {
        assert_eq!(
            mailbox_to_rname("Glen@Example.com").unwrap(),
            "glen.example.com."
        );
        assert_eq!(
            mailbox_to_rname("jane.doe@example.com").unwrap(),
            "jane\\.doe.example.com."
        );
        assert_eq!(
            mailbox_to_rname("hostmaster.example.com").unwrap(),
            "hostmaster.example.com."
        );
        assert_eq!(
            mailbox_to_rname("hostmaster.example.com.").unwrap(),
            "hostmaster.example.com."
        );
        assert_eq!(mailbox_to_rname("  ").unwrap(), "");
        for bad in [
            "@example.com",
            "jane@",
            "a b@example.com",
            "jane@@example.com",
            "jane@.example.com",
        ] {
            assert!(mailbox_to_rname(bad).is_err(), "{bad}");
        }
        assert_eq!(
            rname_to_email("jane\\.doe.example.com.").as_deref(),
            Some("jane.doe@example.com")
        );
        assert_eq!(
            rname_to_email("glen.example.com.").as_deref(),
            Some("glen@example.com")
        );
        // Too short to tell the local part from the domain.
        assert_eq!(rname_to_email("admin.lan."), None);
    }

    #[test]
    fn resolv_conf_supplies_the_domain_suffix() {
        assert_eq!(
            resolv_conf_domain("domain example.lan\nsearch other.lan").as_deref(),
            Some("example.lan")
        );
        assert_eq!(
            resolv_conf_domain("# x\nsearch home.arpa corp.lan\nnameserver 1.1.1.1").as_deref(),
            Some("home.arpa")
        );
        assert_eq!(resolv_conf_domain("nameserver 1.1.1.1"), None);
    }

    #[test]
    fn legacy_placeholder_soa_defaults_count_as_unset() {
        let cfg = DaygleConfig::parse(
            "[authoritative]\ndefault_primary_ns = \"ns1.daygle.test.\"\ndefault_admin_mailbox = \"admin.daygle.test.\"\n",
        )
        .unwrap();
        assert_eq!(cfg.authoritative.default_primary_ns, "");
        assert_eq!(cfg.authoritative.default_admin_mailbox, "");
        // Real values are kept.
        let cfg =
            DaygleConfig::parse("[authoritative]\ndefault_primary_ns = \"ns1.example.com.\"\n")
                .unwrap();
        assert_eq!(cfg.authoritative.default_primary_ns, "ns1.example.com.");
        // A stored overlay from before is cleared the same way.
        let mut cfg = DaygleConfig::default();
        RuntimeSettings {
            authoritative: Some(AuthoritativeUpdate {
                default_primary_ns: Some("ns1.daygle.test.".into()),
                default_admin_mailbox: Some("admin.daygle.test.".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
        .apply_to(&mut cfg);
        assert_eq!(cfg.authoritative.default_primary_ns, "");
        assert_eq!(cfg.authoritative.default_admin_mailbox, "");
    }

    #[test]
    fn display_settings_are_validated() {
        let ok = |tz: &str, d: &str, t: &str| {
            DisplaySettings {
                time_zone: tz.into(),
                date_format: d.into(),
                time_format: t.into(),
            }
            .check(false)
        };
        assert!(ok("system", "system", "system").is_ok());
        assert!(ok("UTC", "dmy", "24h").is_ok());
        assert!(ok("America/Argentina/Buenos_Aires", "d_mon_y", "12h").is_ok());
        assert!(ok("Etc/GMT+10", "ymd", "system").is_ok());
        assert!(ok("Not A Zone", "dmy", "24h").is_err());
        assert!(ok("/etc/passwd", "dmy", "24h").is_err());
        assert!(ok("", "dmy", "24h").is_err());
        assert!(ok("UTC", "yyyy", "24h").is_err());
        assert!(ok("UTC", "dmy", "25h").is_err());
        // A user's preferences may leave fields empty (server default).
        assert!(DisplaySettings {
            time_zone: String::new(),
            date_format: String::new(),
            time_format: "12h".into(),
        }
        .check(true)
        .is_ok());
        // A config without [display] gets the defaults.
        let cfg: DaygleConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.display, DisplaySettings::default());
    }

    #[test]
    fn example_config_file_parses() {
        // The shipped example must stay valid for the real parser so users
        // who copy it as-is (the installer does exactly that) get a working
        // configuration.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../daygle-dns.toml.example");
        let text = std::fs::read_to_string(&path).expect("daygle-dns.toml.example is readable");
        DaygleConfig::parse(&text).expect("daygle-dns.toml.example must parse and validate");
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
        // Inbound NOTIFY needs no secondary zone in the file: they can also
        // be added in the console or by a followed catalog zone.
        assert!(DaygleConfig::parse("[authoritative]\nnotify_listen_enabled = true\n").is_ok());
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
        assert!(DaygleConfig::parse("[authoritative]\ndnssec_sig_validity_days = 0\n").is_err());
        assert!(
            DaygleConfig::parse("[authoritative]\ndnssec_rollover_overlap_days = 0\n").is_err()
        );
        assert!(DaygleConfig::parse("[authoritative]\ndnssec_maintenance_secs = 10\n").is_err());
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
        assert!(!DaygleConfig::default().authoritative.allow_dynamic_updates);

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
    fn parses_dot_doh_handshake_timeout() {
        let text = r#"
[dot]
enabled = true
handshake_timeout_secs = 30

[doh]
enabled = true
handshake_timeout_secs = 60
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(cfg.dot.handshake_timeout_secs, 30);
        assert_eq!(cfg.doh.handshake_timeout_secs, 60);

        // DoT default is 20 s: real clients on mobile or high-latency links
        // can take longer than 10 s to finish the handshake.
        assert_eq!(DaygleConfig::default().dot.handshake_timeout_secs, 20);
        assert_eq!(DaygleConfig::default().doh.handshake_timeout_secs, 10);

        // Out-of-range values are rejected for enabled listeners (same
        // validation style as doq.idle_timeout_secs).
        assert!(
            DaygleConfig::parse("[dot]\nenabled = true\nhandshake_timeout_secs = 0\n").is_err()
        );
        assert!(
            DaygleConfig::parse("[dot]\nenabled = true\nhandshake_timeout_secs = 601\n").is_err()
        );
        assert!(
            DaygleConfig::parse("[doh]\nenabled = true\nhandshake_timeout_secs = 0\n").is_err()
        );

        // Disabled listeners may keep a placeholder value.
        assert!(DaygleConfig::parse("[dot]\nhandshake_timeout_secs = 0\n").is_ok());
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
        assert_eq!(
            cfg.policy.blocklist_sources[0].format,
            BlocklistFormat::Hosts
        );
        assert_eq!(cfg.policy.blocklist_sources[0].refresh_secs, 43200);
        assert_eq!(
            cfg.policy.blocklist_sources[1].format,
            BlocklistFormat::Adblock
        );
        assert_eq!(cfg.policy.blocklist_sources[1].refresh_secs, 86400);
    }

    #[test]
    fn parses_blocklist_source_scopes_including_legacy_dot_scope() {
        let text = r#"
[policy]

[[policy.blocklist_sources]]
name = "global"
url = "https://example.com/a"

[[policy.blocklist_sources]]
name = "dot only"
url = "https://example.com/b"
scope = "dot"

[[policy.blocklist_sources]]
name = "group only"
url = "https://example.com/c"
scope = "groups"
"#;
        let cfg = DaygleConfig::parse(text).unwrap();
        assert_eq!(
            cfg.policy.blocklist_sources[0].scope,
            BlocklistScope::Everyone
        );
        assert_eq!(cfg.policy.blocklist_sources[1].scope, BlocklistScope::Dot);
        let legacy_json = serde_json::to_value(&cfg.policy.blocklist_sources[1]).unwrap();
        assert_eq!(legacy_json["scope"], "dot");
        assert_eq!(
            cfg.policy.blocklist_sources[2].scope,
            BlocklistScope::Groups
        );
    }

    #[test]
    fn ai_overlay_capture_matches_runtime_capture() {
        // capture() and AiUpdate::capture_ai must stay in lockstep: the
        // installer's seed-ai-settings step compares a stored overlay against
        // capture_ai(default) to decide whether the console ever edited the
        // AI settings.
        let mut cfg = DaygleConfig::default();
        assert_eq!(
            RuntimeSettings::capture(&cfg).ai,
            Some(AiUpdate::capture_ai(&cfg.ai))
        );

        cfg.ai = AiSettings {
            enabled: true,
            model_path: "/etc/daygle-dns/models/daygle-starter.bin".to_string(),
            ..AiSettings::default()
        };
        assert_eq!(
            RuntimeSettings::capture(&cfg).ai,
            Some(AiUpdate::capture_ai(&cfg.ai))
        );

        // A never-edited (default) overlay matches the "untouched" baseline;
        // an overlay with the bundled model enabled does not.
        assert_eq!(
            Some(AiUpdate::capture_ai(&AiSettings::default())),
            RuntimeSettings::capture(&DaygleConfig::default()).ai
        );
        assert_ne!(
            Some(AiUpdate::capture_ai(&cfg.ai)),
            RuntimeSettings::capture(&DaygleConfig::default()).ai
        );
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
    fn resolution_mode_defaults_to_recursive_unless_upstreams_are_set() {
        // New installs: no upstreams -> recursive.
        let cfg = DaygleConfig::parse("[recursive]\n").unwrap();
        assert_eq!(cfg.recursive.effective_mode(), ResolutionMode::Recursive);
        // Existing installs with upstreams keep forwarding.
        let cfg = DaygleConfig::parse("[recursive]\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        assert_eq!(cfg.recursive.effective_mode(), ResolutionMode::Forwarding);
        // An explicit mode wins either way.
        let cfg =
            DaygleConfig::parse("[recursive]\nmode = \"recursive\"\nupstreams = [\"1.1.1.1\"]\n")
                .unwrap();
        assert_eq!(cfg.recursive.effective_mode(), ResolutionMode::Recursive);
        // Saving settings pins the effective mode, so a later upstreams edit
        // cannot silently flip it.
        let captured = RuntimeSettings::capture(&cfg);
        assert_eq!(
            captured.recursive.unwrap().mode,
            Some(ResolutionMode::Recursive)
        );
    }

    #[test]
    fn recursion_access_defaults_to_private_networks_and_validates() {
        let cfg = DaygleConfig::default();
        assert_eq!(
            cfg.recursive.recursion_access,
            RecursionAccess::PrivateNetworks
        );

        let err = DaygleConfig::parse("[recursive]\nrecursion_access = \"custom\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires recursion_networks"), "{err}");
        let err = DaygleConfig::parse(
            "[recursive]\nrecursion_access = \"custom\"\nrecursion_networks = [\"not-a-net\"]\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid network"), "{err}");
        // Bare IPs count as single-host networks.
        DaygleConfig::parse(
            "[recursive]\nrecursion_access = \"custom\"\nrecursion_networks = [\"203.0.113.5\", \"10.0.0.0/8\"]\n",
        )
        .unwrap();
        let err = DaygleConfig::parse("[recursive]\nroot_hints = [\"a.root-servers.net\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("root_hints"), "{err}");
    }

    #[test]
    fn client_policies_validate() {
        let ok = "[[recursive.client_policies]]\nname = \"kids\"\nclients = [\"192.168.1.0/24\"]\nupstreams = [\"1.1.1.3\"]\n";
        let cfg = DaygleConfig::parse(ok).unwrap();
        let policy = &cfg.recursive.client_policies[0];
        assert!(policy.enabled);
        assert_eq!(policy.action, ClientPolicyAction::Forward);

        let cases = [
            ("[[recursive.client_policies]]\nname = \"x\"\nupstreams = [\"1.1.1.3\"]\n", "no client networks"),
            ("[[recursive.client_policies]]\nname = \"x\"\nclients = [\"nope\"]\naction = \"refuse\"\n", "invalid network"),
            ("[[recursive.client_policies]]\nname = \"x\"\nclients = [\"10.0.0.1\"]\n", "no upstreams"),
            ("[[recursive.client_policies]]\nclients = [\"10.0.0.1\"]\naction = \"refuse\"\n", "empty name"),
            (
                "[[recursive.client_policies]]\nname = \"x\"\nclients = [\"10.0.0.1\"]\naction = \"refuse\"\n[[recursive.client_policies]]\nname = \"X\"\nclients = [\"10.0.0.2\"]\naction = \"recursive\"\n",
                "more than once",
            ),
        ];
        for (text, expected) in cases {
            let err = DaygleConfig::parse(text).unwrap_err().to_string();
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn local_root_settings_validate_and_survive_the_overlay() {
        assert!(!DaygleConfig::default().recursive.local_root.enabled);
        assert_eq!(
            LocalRootSettings::default().effective_sources().len(),
            LOCAL_ROOT_SOURCES.len()
        );
        let cfg = DaygleConfig::parse(
            "[recursive.local_root]\nenabled = true\nsources = [\"192.0.32.132\", \"[2620:0:2d0:202::132]:53\"]\n",
        )
        .unwrap();
        assert!(cfg.recursive.local_root.enabled);
        assert_eq!(cfg.recursive.local_root.effective_sources().len(), 2);

        let err = DaygleConfig::parse("[recursive.local_root]\nsources = [\"xfr.example\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("local_root.sources"), "{err}");

        // Stored in the database overlay like the other resolver settings.
        let mut restored = DaygleConfig::default();
        RuntimeSettings::capture(&cfg).apply_to(&mut restored);
        assert_eq!(restored.recursive.local_root, cfg.recursive.local_root);
    }

    #[test]
    fn listener_allowed_networks_validate_and_resolve() {
        // A literal address or CIDR parses on its own...
        DaygleConfig::parse("[dot]\nallowed_networks = [\"10.0.0.0/8\"]\n").unwrap();
        // ...and so does the name of a configured network.
        let cfg = DaygleConfig::parse(
            r#"
[[networks]]
name = "LAN"
cidrs = ["192.168.30.0/24"]

[dot]
allowed_networks = ["lan"]

[doh]
allowed_networks = ["192.168.31.0/24"]

[doq]
allowed_networks = ["LAN"]
"#,
        )
        .unwrap();
        let resolved = cfg.with_networks_resolved();
        assert_eq!(resolved.dot.allowed_networks, ["192.168.30.0/24"]);
        assert_eq!(resolved.doh.allowed_networks, ["192.168.31.0/24"]);
        assert_eq!(resolved.doq.allowed_networks, ["192.168.30.0/24"]);
        // The stored config keeps the names.
        assert_eq!(cfg.dot.allowed_networks, ["lan"]);

        // Unknown names are refused, labelled with their section.
        for section in ["dot", "doh", "doq"] {
            let text = format!("[{section}]\nallowed_networks = [\"Office\"]\n");
            let err = DaygleConfig::parse(&text).unwrap_err().to_string();
            assert!(
                err.contains(&format!("{section}.allowed_networks")),
                "{err}"
            );
        }
    }

    #[test]
    fn listener_allowed_networks_capture_apply_round_trip() {
        let mut cfg = DaygleConfig::default();
        cfg.dot.allowed_networks = vec!["LAN".to_string()];
        cfg.doh.allowed_networks = vec!["10.0.0.0/8".to_string(), "  ".to_string()];
        cfg.doq.allowed_networks = vec!["VPN".to_string()];

        let overlay = RuntimeSettings::capture(&cfg);
        assert_eq!(
            overlay.dot.as_ref().unwrap().allowed_networks.as_deref(),
            Some(cfg.dot.allowed_networks.as_slice())
        );

        let mut restored = DaygleConfig::default();
        overlay.apply_to(&mut restored);
        assert_eq!(restored.dot.allowed_networks, ["LAN"]);
        // Blank entries are dropped on apply.
        assert_eq!(restored.doh.allowed_networks, ["10.0.0.0/8"]);
        assert_eq!(restored.doq.allowed_networks, ["VPN"]);
    }

    #[test]
    fn network_names_resolve_to_addresses_in_every_list() {
        let cfg = DaygleConfig::parse(
            r#"
[[networks]]
name = "LAN"
cidrs = ["192.168.20.0/24"]

[recursive]
recursion_access = "custom"
recursion_networks = ["lan", "10.9.0.0/16"]

[dns64]
enabled = true
clients = ["LAN"]

[[recursive.client_policies]]
name = "lab"
clients = ["Private"]
action = "refuse"

[[policy.rules]]
clients = ["LAN"]
action = "block"
"#,
        )
        .unwrap();

        let resolved = cfg.with_networks_resolved();
        assert_eq!(
            resolved.recursive.recursion_networks,
            ["192.168.20.0/24", "10.9.0.0/16"]
        );
        assert_eq!(resolved.dns64.clients, ["192.168.20.0/24"]);
        let proxy = DaygleConfig::parse(
            "[[networks]]\nname = \"LAN\"\ncidrs = [\"127.0.0.0/8\"]\n\n[server]\nproxy_protocol = [\"lan\"]\n",
        )
        .unwrap();
        assert_eq!(
            proxy.with_networks_resolved().server.proxy_protocol,
            ["127.0.0.0/8"]
        );
        assert_eq!(resolved.policy.rules[0].clients, ["192.168.20.0/24"]);
        assert_eq!(
            resolved.recursive.client_policies[0].clients,
            builtin_networks()[0].cidrs
        );
        // The stored config keeps the names.
        assert_eq!(cfg.recursive.recursion_networks, ["lan", "10.9.0.0/16"]);
        assert_eq!(cfg.dns64.clients, ["LAN"]);

        // DNS64 compiles its names only with the networks to resolve them.
        let dns64 = cfg.dns64.compile(&cfg.all_networks()).unwrap().unwrap();
        assert!(dns64.applies_to("192.168.20.7".parse().unwrap()));
        assert!(!dns64.applies_to("10.1.2.3".parse().unwrap()));
        assert!(cfg.dns64.compile(&[]).is_err());
    }

    #[test]
    fn unknown_network_names_are_refused_in_every_list() {
        let refused = |text: &str| DaygleConfig::parse(text).unwrap_err().to_string();
        assert!(
            refused("[recursive]\nrecursion_networks = [\"Office\"]\n").contains("invalid network")
        );
        assert!(refused("[policy]\ndenied_networks = [\"Office\"]\n").contains("invalid network"));
        assert!(refused("[dns64]\nenabled = true\nclients = [\"Office\"]\n").contains("dns64"));
        assert!(refused("[server]\nproxy_protocol = [\"Office\"]\n").contains("proxy_protocol"));
        assert!(
            refused("[[policy.rules]]\nclients = [\"Office\"]\naction = \"block\"\n")
                .contains("policy rule 1")
        );
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

    #[test]
    fn named_networks_resolve_and_validate() {
        let mut cfg = DaygleConfig {
            networks: vec![NamedNetwork {
                name: "LAN".to_string(),
                cidrs: vec!["192.168.1.0/24".to_string(), "10.0.0.5".to_string()],
                description: String::new(),
            }],
            ..Default::default()
        };
        cfg.validate().unwrap();
        let nets = cfg
            .resolve_networks(&["lan".to_string(), "172.16.0.0/12".to_string()])
            .unwrap();
        assert_eq!(nets.len(), 3);
        assert!(
            cfg.resolve_networks(&["This Server".to_string()]).unwrap()[0]
                .contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
        );
        let err = cfg.resolve_networks(&["Office".to_string()]).unwrap_err();
        assert!(err.contains("Office"), "{err}");

        // References follow a rename and are reported as users.
        cfg.dns64.clients = vec!["LAN".to_string()];
        assert_eq!(cfg.network_users("lan"), vec!["DNS64".to_string()]);
        cfg.rename_network_refs("lan", "Home");
        assert_eq!(cfg.dns64.clients, vec!["Home".to_string()]);

        for bad in [
            NamedNetwork {
                name: "".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            NamedNetwork {
                name: "10.0.0.0/8".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            NamedNetwork {
                name: "X".into(),
                cidrs: vec![],
                ..Default::default()
            },
            NamedNetwork {
                name: "X".into(),
                cidrs: vec!["nope".into()],
                ..Default::default()
            },
        ] {
            assert!(validate_named_network(&bad).is_err(), "{bad:?}");
        }
        let mut dup = cfg.clone();
        dup.networks.push(NamedNetwork {
            name: "lan".into(),
            ..cfg.networks[0].clone()
        });
        assert!(dup.validate().is_err());
        let mut builtin = cfg.clone();
        builtin.networks[0].name = "private".to_string();
        assert!(builtin.validate().is_err());
    }
}
