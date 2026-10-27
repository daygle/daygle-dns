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
    /// Sending every query, as JSON, to an HTTP endpoint (a log collector).
    pub log_export: LogExportSettings,
    /// DNS64 (RFC 6147): AAAA answers made from A records for IPv6-only
    /// clients behind NAT64.
    pub dns64: Dns64Settings,
    /// EDNS Client Subnet (RFC 7871) sent to forwarding upstreams.
    pub ecs: EcsSettings,
    /// Named networks (`[[networks]]`), e.g. `LAN` = `192.168.1.0/24`, that
    /// network settings can name instead of repeating the addresses.
    pub networks: Vec<NamedNetwork>,
    /// Alerts by email and/or webhook when something needs attention.
    pub alerts: AlertSettings,
    /// Response rate limiting (RRL): caps identical responses to one network,
    /// against reflection and amplification attacks over UDP.
    pub rrl: RrlSettings,
    /// Response policy zones (`[[rpz]]`), checked in order.
    pub rpz: Vec<RpzZoneConfig>,
    /// A web page that tells people a site was blocked.
    pub block_page: BlockPageSettings,
    /// Discovery of Designated Resolvers (RFC 9462).
    pub ddr: DdrSettings,
    /// A scheduled summary sent to the alert destinations.
    pub reports: ReportSettings,
    /// The DHCP service (DHCPv4 and DHCPv6).
    pub dhcp: crate::dhcp::DhcpSettings,
}

/// A scheduled report: a summary of the query log (queries, blocks, top
/// domains and devices) sent daily or weekly to the alert destinations
/// (Settings -> Alerts). Stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ReportSettings {
    pub enabled: bool,
    /// `daily` (the last 24 hours) or `weekly` (the last 7 days).
    pub frequency: String,
    /// `weekly`: the day it goes out (`mon`..`sun`).
    pub weekday: String,
    /// The hour it goes out (0-23), in the display time zone.
    pub hour: u8,
    /// How many domains and devices each list shows.
    pub top: usize,
}

impl Default for ReportSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            frequency: "weekly".to_string(),
            weekday: "mon".to_string(),
            hour: 8,
            top: 10,
        }
    }
}

impl ReportSettings {
    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        if !matches!(self.frequency.as_str(), "daily" | "weekly") {
            return Err(format!(
                "unknown frequency '{}': use daily or weekly",
                self.frequency
            ));
        }
        if self.weekday_index().is_none() {
            return Err(format!("'{}' is not a day of the week", self.weekday));
        }
        if self.hour > 23 {
            return Err("the hour must be 0 to 23".to_string());
        }
        if !(1..=50).contains(&self.top) {
            return Err("each list shows 1 to 50 entries".to_string());
        }
        Ok(())
    }

    /// The report day as 0 = Monday.
    pub fn weekday_index(&self) -> Option<u32> {
        crate::schedule::DAYS
            .iter()
            .position(|d| self.weekday.trim().eq_ignore_ascii_case(d))
            .map(|i| i as u32)
    }

    /// How far back a report looks.
    pub fn period(&self) -> std::time::Duration {
        let days = if self.frequency == "daily" { 1 } else { 7 };
        std::time::Duration::from_secs(days * 86_400)
    }
}

/// Discovery of Designated Resolvers (DDR, RFC 9462): answer the
/// `_dns.resolver.arpa` SVCB query with this server's encrypted listeners
/// (DoH, DoT, DoQ), so devices that support it (Windows 11, Apple, Android)
/// switch from plain DNS to encrypted DNS by themselves. Edited in
/// Settings -> Encrypted DNS and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DdrSettings {
    pub enabled: bool,
    /// The name devices connect to (it must be in the listeners'
    /// certificate). Empty: each listener's own server name.
    pub name: String,
}

impl Default for DdrSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            name: String::new(),
        }
    }
}

impl DdrSettings {
    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        let name = self.name.trim();
        if !name.is_empty() && (name.starts_with("*.") || validate_domain_pattern(name).is_err()) {
            return Err(format!("'{name}' is not a host name"));
        }
        Ok(())
    }
}

/// The block page: blocked names (that would get NXDOMAIN) are answered
/// with this server's address instead, and a small web server here shows
/// a page saying what was blocked and why. Edited in Filtering -> Response
/// Filters and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BlockPageSettings {
    pub enabled: bool,
    /// The address blocked names resolve to (A queries): this server's
    /// address as clients reach it. Empty: A queries get NXDOMAIN as usual.
    pub ipv4: String,
    /// The same for AAAA queries; empty: no IPv6 answer (NODATA).
    pub ipv6: String,
    /// Where the page's web server listens (addresses, comma-separated).
    #[serde(deserialize_with = "listen_list")]
    pub listen: String,
    /// The page's HTTP port (80, so plain `http://` links reach it).
    pub port: u16,
    /// Extra text shown on the page (e.g. who to ask for access).
    pub message: String,
}

impl Default for BlockPageSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4: String::new(),
            ipv6: String::new(),
            listen: "0.0.0.0".to_string(),
            port: 80,
            message: String::new(),
        }
    }
}

impl BlockPageSettings {
    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        if !self.ipv4.trim().is_empty() && self.ipv4.trim().parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("'{}' is not an IPv4 address", self.ipv4.trim()));
        }
        if !self.ipv6.trim().is_empty() && self.ipv6.trim().parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!("'{}' is not an IPv6 address", self.ipv6.trim()));
        }
        if self.enabled {
            if self.ipv4.trim().is_empty() && self.ipv6.trim().is_empty() {
                return Err("enter the address blocked names should point to".to_string());
            }
            if self.port == 0 {
                return Err("the port cannot be 0".to_string());
            }
            listen_socket_addrs(&self.listen, self.port)?;
        }
        if self.message.len() > 2000 {
            return Err("the message is too long (2000 characters at most)".to_string());
        }
        Ok(())
    }
}

/// Where a response policy zone's rules come from.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RpzSource {
    /// Rules typed into the console (`rules`).
    #[default]
    Local,
    /// A zone file fetched over HTTP(S) (`url`).
    Url,
    /// A zone transfer (AXFR) from the feed's servers (`primaries`), as most
    /// commercial and community RPZ feeds are delivered.
    Transfer,
}

/// Overrides the actions written in a response policy zone (BIND's
/// `policy` option).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpzPolicy {
    /// The action each rule gives.
    #[default]
    Given,
    /// Match and count, but act on nothing (to try a zone out).
    Disabled,
    Nxdomain,
    Nodata,
    Passthru,
    Drop,
    TcpOnly,
    /// Answer with a CNAME to `cname_target` (a walled garden).
    Cname,
}

/// One response policy zone (RPZ).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RpzZoneConfig {
    /// The zone's name (e.g. `rpz.example.com`): what is transferred, and
    /// the suffix stripped from the rules' owner names.
    pub name: String,
    pub enabled: bool,
    pub source: RpzSource,
    /// `transfer`: the servers to transfer from (`IP`, `IP:port`).
    pub primaries: Vec<String>,
    /// `transfer`: the TSIG key (from `authoritative.tsig_keys`) that signs
    /// the transfer; empty for none.
    pub tsig_key: String,
    /// `url`: where the zone file is fetched from.
    pub url: String,
    /// `local`: the rules, in zone-file form (`bad.example CNAME .`).
    pub rules: String,
    /// `url` and `transfer`: how often to check for changes, in seconds.
    pub refresh_secs: u64,
    pub policy: RpzPolicy,
    /// The walled-garden name for `policy = "cname"`.
    pub cname_target: String,
}

impl Default for RpzZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            source: RpzSource::Local,
            primaries: Vec::new(),
            tsig_key: String::new(),
            url: String::new(),
            rules: String::new(),
            refresh_secs: 3600,
            policy: RpzPolicy::Given,
            cname_target: String::new(),
        }
    }
}

/// Longest `rules` text accepted for a local zone.
pub const RPZ_MAX_LOCAL_RULES: usize = 2 * 1024 * 1024;

impl RpzZoneConfig {
    /// Problems that stop the zone being used (`tsig_keys`: the configured
    /// key names).
    pub fn check(&self, tsig_keys: &[TsigKeyConfig]) -> std::result::Result<(), String> {
        let name = self.name.trim();
        validate_domain_pattern(name)
            .ok()
            .filter(|_| !name.starts_with("*."))
            .ok_or_else(|| format!("'{name}' is not a zone name"))?;
        match self.source {
            RpzSource::Local => {
                if self.rules.len() > RPZ_MAX_LOCAL_RULES {
                    return Err("the rules are too long (2 MB at most)".to_string());
                }
            }
            RpzSource::Url => {
                let url = url::Url::parse(self.url.trim())
                    .map_err(|_| format!("'{}' is not a URL", self.url.trim()))?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(format!("'{}' is not an http(s) URL", self.url.trim()));
                }
            }
            RpzSource::Transfer => {
                if self.primaries.is_empty() {
                    return Err("add the servers to transfer the zone from".to_string());
                }
                for primary in &self.primaries {
                    parse_master_addr(primary).map_err(|e| format!("'{primary}': {e}"))?;
                }
                let key = self.tsig_key.trim();
                if !key.is_empty()
                    && !tsig_keys.iter().any(|k| {
                        k.name
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(key.trim_end_matches('.'))
                    })
                {
                    return Err(format!("there is no TSIG key named '{key}'"));
                }
            }
        }
        if self.source != RpzSource::Local && self.refresh_secs < 60 {
            return Err("check for changes every 60 seconds at most often".to_string());
        }
        if self.policy == RpzPolicy::Cname {
            let target = self.cname_target.trim();
            validate_domain_pattern(target)
                .map_err(|_| format!("'{target}' is not a walled-garden name"))?;
        }
        Ok(())
    }
}

/// Check a list of response policy zones: each one, and that no name is
/// used twice.
pub fn check_rpz_zones(
    zones: &[RpzZoneConfig],
    tsig_keys: &[TsigKeyConfig],
) -> std::result::Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for zone in zones {
        zone.check(tsig_keys)
            .map_err(|e| format!("zone '{}': {e}", zone.name.trim()))?;
        let key = zone.name.trim().trim_end_matches('.').to_ascii_lowercase();
        if !seen.insert(key) {
            return Err(format!("there are two zones named '{}'", zone.name.trim()));
        }
    }
    Ok(())
}

/// Response rate limiting (RRL), as in BIND and Knot: each client network
/// gets at most so many identical responses per second over UDP. Past the
/// limit, responses are dropped, and every `slip`-th one is sent truncated
/// (TC) instead so a real client retries over TCP, which cannot be spoofed.
/// Edited in Settings -> Rate Limiting and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RrlSettings {
    pub enabled: bool,
    /// Identical answers (same name and type) per second per network.
    pub responses_per_second: u32,
    /// NXDOMAIN answers per second per network and parent domain (a flood
    /// of random names under one domain shares the limit).
    pub nxdomains_per_second: u32,
    /// Error answers (SERVFAIL, REFUSED, FORMERR...) per second per network.
    pub errors_per_second: u32,
    /// How many seconds of excess a network's account remembers: a flood
    /// stays limited until it has been quiet (or within the rate) this long.
    pub window_secs: u32,
    /// Send every `slip`-th limited response truncated instead of dropping
    /// it (0: drop them all; 1: truncate them all).
    pub slip: u32,
    /// Clients are grouped into networks of this size (BIND: /24 and /56).
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
    /// Networks never limited (addresses, CIDRs or network names).
    pub exempt: Vec<String>,
    /// Count what would be limited without limiting anything (to size the
    /// rates before enforcing them).
    pub log_only: bool,
}

impl Default for RrlSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            responses_per_second: 10,
            nxdomains_per_second: 10,
            errors_per_second: 10,
            window_secs: 15,
            slip: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
            exempt: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            log_only: false,
        }
    }
}

impl RrlSettings {
    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        for (name, rate) in [
            ("responses per second", self.responses_per_second),
            ("NXDOMAIN per second", self.nxdomains_per_second),
            ("errors per second", self.errors_per_second),
        ] {
            if rate > 10_000 {
                return Err(format!("{name} must be at most 10000 (0: no limit)"));
            }
        }
        if !(1..=3600).contains(&self.window_secs) {
            return Err("the window must be 1 to 3600 seconds".to_string());
        }
        if self.slip > 10 {
            return Err("slip must be 0 to 10".to_string());
        }
        if !(8..=32).contains(&self.ipv4_prefix) {
            return Err("the IPv4 prefix must be 8 to 32".to_string());
        }
        if !(16..=128).contains(&self.ipv6_prefix) {
            return Err("the IPv6 prefix must be 16 to 128".to_string());
        }
        Ok(())
    }
}

/// Alerts: tell the operator by email (SMTP) and/or a webhook when
/// something needs attention. Edited in Settings -> Alerts and stored in
/// the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AlertSettings {
    pub enabled: bool,
    /// URL that receives each alert as a JSON `POST` (empty: no webhook).
    pub webhook_url: String,
    /// SMTP server host name (empty: no email).
    pub smtp_server: String,
    pub smtp_port: u16,
    /// `starttls` (usually port 587), `tls` (usually 465) or `none`.
    pub smtp_security: String,
    /// SMTP sign-in; empty for a server that needs none.
    pub smtp_username: String,
    pub smtp_password: String,
    /// Sender address.
    pub email_from: String,
    /// Recipient addresses.
    pub email_to: Vec<String>,
    /// A remote blocklist cannot be downloaded.
    pub blocklist_failures: bool,
    /// A secondary zone cannot be refreshed from its primary.
    pub zone_transfer_failures: bool,
    /// A console-managed certificate expires within 14 days, or its
    /// automatic renewal failed.
    pub certificate_expiry: bool,
    /// DNSSEC: a key rollover started (the parent DS needs updating) or
    /// signing failed.
    pub dnssec: bool,
    /// A newer Daygle DNS release is available.
    pub update_available: bool,
    /// The AI scanner (in Enforce mode) started blocking new domains.
    pub ai_blocks: bool,
}

impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            smtp_server: String::new(),
            smtp_port: 587,
            smtp_security: "starttls".to_string(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            email_from: String::new(),
            email_to: Vec::new(),
            blocklist_failures: true,
            zone_transfer_failures: true,
            certificate_expiry: true,
            dnssec: true,
            update_available: true,
            ai_blocks: false,
        }
    }
}

impl AlertSettings {
    /// Whether email is configured.
    pub fn email_configured(&self) -> bool {
        !self.smtp_server.trim().is_empty() && !self.email_to.is_empty()
    }

    /// Whether the event `kind` is switched on.
    pub fn wants(&self, kind: crate::alerts::AlertKind) -> bool {
        use crate::alerts::AlertKind as K;
        match kind {
            K::BlocklistFailure => self.blocklist_failures,
            K::ZoneTransferFailure => self.zone_transfer_failures,
            K::CertificateExpiry => self.certificate_expiry,
            K::Dnssec => self.dnssec,
            K::UpdateAvailable => self.update_available,
            K::AiBlocks => self.ai_blocks,
            K::Test | K::Report => true,
        }
    }

    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        let webhook = self.webhook_url.trim();
        if !webhook.is_empty() {
            let url = url::Url::parse(webhook)
                .map_err(|_| format!("'{webhook}' is not a webhook URL"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(format!("'{webhook}' is not an http(s) URL"));
            }
        }
        if !matches!(self.smtp_security.as_str(), "starttls" | "tls" | "none") {
            return Err(format!(
                "unknown SMTP security '{}': use starttls, tls or none",
                self.smtp_security
            ));
        }
        let server = self.smtp_server.trim();
        if server.contains(char::is_whitespace) || server.contains('/') {
            return Err(format!("'{server}' is not an SMTP server name"));
        }
        if !server.is_empty() && self.smtp_port == 0 {
            return Err("the SMTP port cannot be 0".to_string());
        }
        let is_address = |a: &str| {
            let a = a.trim();
            a.split_once('@').is_some_and(|(user, host)| {
                !user.is_empty() && host.contains('.') && !a.contains(char::is_whitespace)
            })
        };
        if !server.is_empty() {
            if !is_address(&self.email_from) {
                return Err(format!("'{}' is not an email address", self.email_from));
            }
            if self.email_to.is_empty() {
                return Err("add at least one recipient".to_string());
            }
        }
        if let Some(bad) = self.email_to.iter().find(|a| !is_address(a)) {
            return Err(format!("'{bad}' is not an email address"));
        }
        if self.enabled && webhook.is_empty() && !self.email_configured() {
            return Err("set a webhook URL or an SMTP server to send alerts to".to_string());
        }
        Ok(())
    }
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

/// Query export: every answered query, as JSON, posted in batches to an
/// HTTP(S) endpoint such as Vector, Fluent Bit, Logstash, Splunk HEC or a
/// webhook. Edited in Settings -> Logging and stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LogExportSettings {
    pub enabled: bool,
    /// `http://` or `https://` URL each batch is POSTed to.
    pub url: String,
    /// `ndjson` (one JSON object per line) or `json` (one JSON array).
    pub format: String,
    /// Sent as the `Authorization` header when set, e.g. `Bearer abc123`
    /// or `Splunk <token>`. Write-only: the API never shows it.
    pub authorization: String,
    /// Most queries in one POST.
    pub batch_size: u32,
    /// Longest wait, in seconds, before a part-filled batch is sent.
    pub flush_secs: u32,
}

impl Default for LogExportSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            format: "ndjson".to_string(),
            authorization: String::new(),
            batch_size: 500,
            flush_secs: 5,
        }
    }
}

impl LogExportSettings {
    /// Whether batches are sent as a JSON array (else NDJSON).
    pub fn json_array(&self) -> bool {
        self.format.trim() == "json"
    }

    /// Problems that stop the settings being used.
    pub fn check(&self) -> std::result::Result<(), String> {
        if !matches!(self.format.trim(), "" | "ndjson" | "json") {
            return Err(format!(
                "unknown format '{}': use ndjson or json",
                self.format
            ));
        }
        if !(1..=10_000).contains(&self.batch_size) {
            return Err("batch_size must be 1 to 10000".to_string());
        }
        if !(1..=300).contains(&self.flush_secs) {
            return Err("flush_secs must be 1 to 300".to_string());
        }
        if self.authorization.contains(['\r', '\n']) {
            return Err("authorization must be one line".to_string());
        }
        let url = self.url.trim();
        if self.enabled || !url.is_empty() {
            let parsed = url::Url::parse(url).map_err(|_| format!("'{url}' is not a URL"))?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(format!("'{url}' is not an http:// or https:// URL"));
            }
        }
        Ok(())
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

/// How the console shows dates, times and colours to users who have not
/// chosen their own (each console account can override these in its
/// preferences).
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
    /// The console's colours: `system` (follow the device's light or dark
    /// setting), `light` or `dark`.
    pub theme: String,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            time_zone: "system".to_string(),
            date_format: "system".to_string(),
            time_format: "system".to_string(),
            theme: "dark".to_string(),
        }
    }
}

/// Accepted `date_format` values.
pub const DATE_FORMATS: &[&str] = &["system", "dmy", "mdy", "ymd", "d_mon_y"];
/// Accepted `time_format` values.
pub const TIME_FORMATS: &[&str] = &["system", "24h", "12h"];
/// Accepted `theme` values.
pub const THEMES: &[&str] = &["system", "light", "dark"];

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
        if !unset(&self.theme) && !THEMES.contains(&self.theme.as_str()) {
            return Err(format!("unknown theme '{}'", self.theme));
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
    pub log_export: Option<LogExportSettings>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alerts: Option<AlertSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrl: Option<RrlSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpz: Option<Vec<RpzZoneConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_page: Option<BlockPageSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddr: Option<DdrSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<ReportSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<crate::dhcp::DhcpSettings>,
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
    /// `server.client_timeout_ms`: kept with the resolver settings because
    /// it only applies to recursive lookups (the console shows it beside
    /// the serve-stale window).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_timeout_ms: Option<u64>,
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

    /// The block page needs its own TCP port: not one the web console, the
    /// API or a DoH/DoT listener holds.
    pub fn check_block_page_port(&self) -> std::result::Result<(), String> {
        if !self.block_page.enabled {
            return Ok(());
        }
        for (name, port, used) in [
            (
                "the web console (HTTP)",
                self.web.http_port,
                self.web.http_enabled,
            ),
            (
                "the web console (HTTPS)",
                self.web.https_port,
                self.web.https_enabled,
            ),
            ("the API", self.api.port, self.api.enabled),
            ("DNS over HTTPS", self.doh.port, self.doh.enabled),
            ("DNS over TLS", self.dot.port, self.dot.enabled),
        ] {
            if used && port == self.block_page.port {
                return Err(format!("port {port} is already used by {name}"));
            }
        }
        Ok(())
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
            (
                "Response rate limiting exemptions".to_string(),
                &self.rrl.exempt,
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
            &mut self.rrl.exempt,
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
    /// Also serve DoH over HTTP/3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http3: Option<bool>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_inspection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub youtube_restricted: Option<bool>,
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
            && self.log_export.is_none()
            && self.updates.is_none()
            && self.dns64.is_none()
            && self.ecs.is_none()
            && self.networks.is_none()
            && self.alerts.is_none()
            && self.rrl.is_none()
            && self.rpz.is_none()
            && self.block_page.is_none()
            && self.ddr.is_none()
            && self.reports.is_none()
            && self.dhcp.is_none()
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
            if let Some(v) = r.client_timeout_ms {
                config.server.client_timeout_ms = v;
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
            if let Some(v) = d.http3 {
                config.doh.http3 = v;
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
            if let Some(v) = p.cname_inspection {
                config.policy.cname_inspection = v;
            }
            if let Some(v) = p.safe_search {
                config.policy.safe_search = v;
            }
            if let Some(v) = p.youtube_restricted {
                config.policy.youtube_restricted = v;
            }
            // Captured on every save but never applied: a console-made
            // client deny/allow list reverted to the config file's at the
            // next start or file reload.
            if let Some(v) = &p.denied_networks {
                config.policy.denied_networks = trim_list(v);
            }
            if let Some(v) = &p.allowed_networks {
                config.policy.allowed_networks = trim_list(v);
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
        if let Some(e) = &self.log_export {
            config.log_export = e.clone();
        }
        if let Some(a) = &self.alerts {
            config.alerts = a.clone();
        }
        if let Some(r) = &self.rrl {
            config.rrl = r.clone();
        }
        if let Some(r) = &self.rpz {
            config.rpz = r.clone();
        }
        if let Some(b) = &self.block_page {
            config.block_page = b.clone();
        }
        if let Some(d) = &self.ddr {
            config.ddr = d.clone();
        }
        if let Some(r) = &self.reports {
            config.reports = r.clone();
        }
        if let Some(d) = &self.dhcp {
            config.dhcp = d.clone();
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
                // SOA MNAME is conventionally fully qualified; store the
                // trailing dot even when the user omitted it. Blank clears it
                // (new zones then use this server's name), as the console
                // save does; it used to keep the file's value instead, so a
                // cleared name came back at the next start.
                let v = v.trim();
                config.authoritative.default_primary_ns = if v.is_empty() || v.ends_with('.') {
                    v.to_string()
                } else {
                    format!("{v}.")
                };
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
                client_timeout_ms: Some(config.server.client_timeout_ms),
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
                http3: Some(config.doh.http3),
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
                cname_inspection: Some(config.policy.cname_inspection),
                safe_search: Some(config.policy.safe_search),
                youtube_restricted: Some(config.policy.youtube_restricted),
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
            log_export: Some(config.log_export.clone()),
            dns64: Some(config.dns64.clone()),
            ecs: Some(config.ecs.clone()),
            networks: Some(config.networks.clone()),
            alerts: Some(config.alerts.clone()),
            rrl: Some(config.rrl.clone()),
            rpz: Some(config.rpz.clone()),
            block_page: Some(config.block_page.clone()),
            ddr: Some(config.ddr.clone()),
            reports: Some(config.reports.clone()),
            dhcp: Some(config.dhcp.clone()),
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
        // DoH over HTTP/3 and DoQ both listen on UDP.
        if self.doh.enabled && self.doh.http3 && self.doq.enabled && self.doh.port == self.doq.port
        {
            return Err(DaygleError::Config(format!(
                "DoH over HTTP/3 and DoQ cannot share UDP port {}",
                self.doh.port
            )));
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
        for entry in &self.rrl.exempt {
            if !self.is_network_entry(entry) {
                return Err(DaygleError::Config(format!(
                    "rrl.exempt: '{entry}' is not a network, an address or a network name"
                )));
            }
        }
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
        if log.query_db_retention_days > 3650 {
            return Err(DaygleError::Config(
                "logging.query_db_retention_days must be <= 3650".to_string(),
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
        self.log_export
            .check()
            .map_err(|e| DaygleError::Config(format!("log_export: {e}")))?;
        self.alerts
            .check()
            .map_err(|e| DaygleError::Config(format!("alerts: {e}")))?;
        self.rrl
            .check()
            .map_err(|e| DaygleError::Config(format!("rrl: {e}")))?;
        check_rpz_zones(&self.rpz, &self.authoritative.tsig_keys)
            .map_err(|e| DaygleError::Config(format!("rpz: {e}")))?;
        self.block_page
            .check()
            .map_err(|e| DaygleError::Config(format!("block_page: {e}")))?;
        self.check_block_page_port()
            .map_err(|e| DaygleError::Config(format!("block_page: {e}")))?;
        self.ddr
            .check()
            .map_err(|e| DaygleError::Config(format!("ddr: {e}")))?;
        self.reports
            .check()
            .map_err(|e| DaygleError::Config(format!("reports: {e}")))?;
        self.dhcp
            .check()
            .map_err(|e| DaygleError::Config(format!("dhcp: {e}")))?;
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
    /// Also serve DoH over HTTP/3 (QUIC, UDP) on the same addresses and
    /// port, with the same certificate, endpoint and allowed networks.
    #[serde(default)]
    pub http3: bool,
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
            http3: false,
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
    /// Block a query whose answer leads, through a CNAME, to a blocked name
    /// (trackers hidden behind a CNAME on an allowed domain).
    pub cname_inspection: bool,
    /// Force Safe Search on Google, Bing and DuckDuckGo for every client.
    pub safe_search: bool,
    /// Force YouTube Restricted Mode for every client.
    pub youtube_restricted: bool,
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
            cname_inspection: true,
            safe_search: false,
            youtube_restricted: false,
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
            client_max_queries: 1000,
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
    /// Also delete database query-log rows older than this many days (0:
    /// no age limit, only `query_db_max_rows`).
    pub query_db_retention_days: u32,
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
            query_db_retention_days: 0,
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
    use std::collections::BTreeMap;

    /// Every setting the console saves into the database overlay must come
    /// back from it on the next start (and on a config-file reload, which
    /// re-applies the overlay): change each owned field, store the overlay
    /// the way the database does (JSON), apply it to a fresh config and
    /// compare. A field captured but not applied (or the reverse) silently
    /// reverts a console change at restart.
    #[test]
    fn every_console_setting_survives_the_database_overlay() {
        let mut c = DaygleConfig::default();
        let s = |v: &str| v.to_string();

        let r = &mut c.recursive;
        r.enabled = !r.enabled;
        r.cache_size += 1;
        r.upstreams = vec![s("192.0.2.53")];
        r.dnssec_validate = !r.dnssec_validate;
        r.prefetch_enabled = !r.prefetch_enabled;
        r.prefetch_ttl_fraction_pct += 1;
        r.prefetch_min_queries += 1;
        r.serve_stale_secs += 1;
        r.max_cache_ttl += 1;
        r.min_cache_ttl += 1;
        r.negative_cache_ttl += 1;
        r.use_system_config = !r.use_system_config;
        r.failure_cache_ttl += 1;
        r.max_concurrent_lookups += 1;
        c.server.client_timeout_ms += 1;
        let r = &mut c.recursive;
        r.conditional_zones = vec![ConditionalZoneConfig {
            name: s("corp.example"),
            upstreams: vec![s("192.0.2.1")],
        }];
        r.mode = Some(ResolutionMode::Forwarding);
        r.recursion_access = RecursionAccess::Custom;
        r.recursion_networks = vec![s("192.0.2.0/24")];
        r.root_hints = vec![s("192.0.2.2")];
        r.case_randomization = !r.case_randomization;
        r.rebinding_protection = !r.rebinding_protection;
        r.local_root.enabled = !r.local_root.enabled;
        r.local_root.sources = vec![s("https://www.internic.net/domain/root.zone")];
        r.opportunistic_encryption = !r.opportunistic_encryption;
        r.outbound_ip_versions = IpVersions::Ipv4;
        r.client_policies = vec![ClientPolicyConfig {
            name: s("kids"),
            enabled: true,
            clients: vec![s("192.0.2.64/26")],
            action: ClientPolicyAction::Refuse,
            upstreams: vec![],
            modified_at: Some(s("2026-01-01T00:00:00Z")),
        }];

        for (enabled, port, self_signed, name, cert, key, certificate, networks) in [
            (
                &mut c.dot.enabled,
                &mut c.dot.port,
                &mut c.dot.self_signed,
                &mut c.dot.server_name,
                &mut c.dot.cert_path,
                &mut c.dot.key_path,
                &mut c.dot.certificate,
                &mut c.dot.allowed_networks,
            ),
            (
                &mut c.doh.enabled,
                &mut c.doh.port,
                &mut c.doh.self_signed,
                &mut c.doh.server_name,
                &mut c.doh.cert_path,
                &mut c.doh.key_path,
                &mut c.doh.certificate,
                &mut c.doh.allowed_networks,
            ),
            (
                &mut c.doq.enabled,
                &mut c.doq.port,
                &mut c.doq.self_signed,
                &mut c.doq.server_name,
                &mut c.doq.cert_path,
                &mut c.doq.key_path,
                &mut c.doq.certificate,
                &mut c.doq.allowed_networks,
            ),
        ] {
            *enabled = !*enabled;
            *port += 1;
            *self_signed = !*self_signed;
            *name = s("dns.example");
            *cert = s("/srv/cert.pem");
            *key = s("/srv/key.pem");
            *certificate = s("managed");
            *networks = vec![s("0.0.0.0/0")];
        }
        c.dot.handshake_timeout_secs += 1;
        c.dot.max_connections += 1;
        c.doh.handshake_timeout_secs += 1;
        c.doh.max_connections += 1;
        c.doh.endpoint = s("/q");
        c.doq.idle_timeout_secs += 1;
        c.doq.max_connections += 1;
        c.doq.max_concurrent_streams += 1;

        let p = &mut c.policy;
        p.allowlist = vec![s("ok.example")];
        p.blocklist = vec![s("ads.example")];
        p.denied_networks = vec![s("198.51.100.0/24")];
        p.allowed_networks = vec![s("192.0.2.0/24")];
        p.filter_aaaa = !p.filter_aaaa;
        p.filter_aaaa_except = vec![s("v6.example")];
        p.cname_inspection = !p.cname_inspection;
        p.safe_search = !p.safe_search;
        p.youtube_restricted = !p.youtube_restricted;
        p.blocklist_sources = vec![BlocklistSourceConfig {
            name: s("list"),
            url: s("https://lists.example/hosts"),
            format: BlocklistFormat::Hosts,
            refresh_secs: 7200,
            enabled: true,
            scope: BlocklistScope::Groups,
        }];

        let a = &mut c.authoritative;
        a.default_record_ttl += 1;
        a.default_admin_mailbox = s("hostmaster.example.com.");
        a.default_primary_ns = s("ns1.example.com.");
        a.axfr_enabled = !a.axfr_enabled;
        a.axfr_networks = vec![s("192.0.2.10")];
        a.allow_dynamic_updates = !a.allow_dynamic_updates;
        a.update_networks = vec![s("192.0.2.11")];
        a.notify_enabled = !a.notify_enabled;
        a.notify_targets = vec![s("192.0.2.12")];
        a.notify_listen_enabled = !a.notify_listen_enabled;
        a.stub_zones = vec![StubZoneConfig {
            name: s("stub.example"),
            nss: vec![s("192.0.2.13")],
            refresh_secs: 600,
            enabled: true,
        }];
        a.catalog_zone = s("catalog.example");
        a.catalog_consumers = vec![CatalogConsumerConfig {
            name: s("their-catalog.example"),
            masters: vec![s("192.0.2.14")],
            refresh_secs: 900,
            enabled: true,
        }];

        let ai = &mut c.ai;
        ai.enabled = !ai.enabled;
        ai.mode = AiMode::Enforce;
        ai.database = s("/srv/ai.db");
        ai.model_path = s("/srv/model.bin");
        ai.workers += 1;
        ai.scan_interval_secs += 1;
        ai.expire_check_secs += 1;
        ai.max_domains_per_scan += 1;
        ai.auto_block_categories = vec![s("malware")];
        ai.block_threshold = 0.42;
        ai.confidence_floor = 0.21;
        ai.category_ttl_secs += 1;
        ai.threat_ttl_secs += 1;

        c.display = DisplaySettings {
            time_zone: s("UTC"),
            date_format: s("ymd"),
            time_format: s("24h"),
            theme: s("light"),
        };
        c.web.http_port = 8080;
        c.web.https_enabled = true;
        c.web.https_port = 8443;
        c.web.https_certificate = s("managed");
        c.web.redirect_http = true;
        c.updates.enabled = !c.updates.enabled;
        c.updates.check_interval_secs += 1;
        c.updates.auto_refresh_models = !c.updates.auto_refresh_models;
        c.syslog.enabled = true;
        c.syslog.server = s("192.0.2.15:514");
        c.syslog.queries = true;
        c.log_export.enabled = true;
        c.log_export.url = s("https://logs.example/ingest");
        c.log_export.format = s("json");
        c.log_export.authorization = s("Bearer abc");
        c.dns64.enabled = true;
        c.dns64.prefix = s("64:ff9b::/96");
        c.dns64.clients = vec![s("2001:db8::/64")];
        c.ecs.enabled = true;
        c.ecs.subnet = s("198.51.100.0/24");
        c.alerts.enabled = true;
        c.alerts.webhook_url = s("https://hooks.example/daygle");
        c.alerts.smtp_password = s("secret");
        c.alerts.ai_blocks = true;
        c.rrl.enabled = true;
        c.rrl.slip = 0;
        c.rrl.exempt = vec![s("LAN")];
        c.rpz = vec![RpzZoneConfig {
            name: s("rpz.local"),
            rules: s("bad.example CNAME ."),
            policy: RpzPolicy::Nodata,
            ..Default::default()
        }];
        c.networks = vec![NamedNetwork {
            name: s("LAN"),
            cidrs: vec![s("192.168.1.0/24")],
            description: s("home"),
        }];

        c.doh.http3 = true;
        c.block_page.enabled = true;
        c.block_page.ipv4 = s("192.168.1.2");
        c.block_page.message = s("Ask Sam");
        c.ddr.enabled = false;
        c.ddr.name = s("dns.example.com");
        c.reports.enabled = true;
        c.reports.frequency = s("daily");
        c.reports.hour = 7;
        c.dhcp.enabled = true;
        c.dhcp.dns_zone = s("home.arpa");
        c.dhcp.scopes.push(crate::dhcp::DhcpScope {
            name: s("LAN"),
            subnet: s("192.168.1.0/24"),
            range_start: s("192.168.1.100"),
            range_end: s("192.168.1.199"),
            ..Default::default()
        });
        let stored = serde_json::to_string(&RuntimeSettings::capture(&c)).unwrap();
        let overlay: RuntimeSettings = serde_json::from_str(&stored).unwrap();
        let mut restored = DaygleConfig::default();
        overlay.apply_to(&mut restored);

        assert_eq!(restored.recursive, c.recursive, "recursive");
        assert_eq!(
            restored.server.client_timeout_ms, c.server.client_timeout_ms,
            "server.client_timeout_ms"
        );
        assert_eq!(restored.dot, c.dot, "dot");
        assert_eq!(restored.doh, c.doh, "doh");
        assert_eq!(restored.doq, c.doq, "doq");
        assert_eq!(restored.policy, c.policy, "policy");
        assert_eq!(restored.authoritative, c.authoritative, "authoritative");
        assert_eq!(restored.ai, c.ai, "ai");
        assert_eq!(restored.display, c.display, "display");
        assert_eq!(restored.web, c.web, "web");
        assert_eq!(restored.updates, c.updates, "updates");
        assert_eq!(restored.syslog, c.syslog, "syslog");
        assert_eq!(restored.log_export, c.log_export, "log_export");
        assert_eq!(restored.dns64, c.dns64, "dns64");
        assert_eq!(restored.ecs, c.ecs, "ecs");
        assert_eq!(restored.networks, c.networks, "networks");
        assert_eq!(restored.alerts, c.alerts, "alerts");
        assert_eq!(restored.rrl, c.rrl, "rrl");
        assert_eq!(restored.rpz, c.rpz, "rpz");
        assert_eq!(restored.block_page, c.block_page, "block_page");
        assert_eq!(restored.ddr, c.ddr, "ddr");
        assert_eq!(restored.reports, c.reports, "reports");
        assert_eq!(restored.dhcp, c.dhcp, "dhcp");

        // Clearing a value in the console must stay cleared after a restart,
        // even when the config file sets it.
        let mut cleared = c.clone();
        cleared.authoritative.default_primary_ns = String::new();
        let overlay = RuntimeSettings::capture(&cleared);
        let mut from_file = c.clone();
        overlay.apply_to(&mut from_file);
        assert_eq!(from_file.authoritative.default_primary_ns, "");
    }

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

        let mut timeout = DaygleConfig::default();
        timeout.server.client_timeout_ms = 3000;
        let mut restored = DaygleConfig::default();
        RuntimeSettings::capture(&timeout).apply_to(&mut restored);
        assert_eq!(restored.server.client_timeout_ms, 3000);
        for bad in [999, 10_001] {
            timeout.server.client_timeout_ms = bad;
            assert!(timeout.validate().is_err(), "{bad} ms accepted");
        }

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
    fn block_page_needs_an_address_and_its_own_port() {
        let mut c = DaygleConfig::default();
        c.block_page.enabled = true;
        assert!(c.block_page.check().is_err(), "no address");
        c.block_page.ipv4 = "192.168.1.2".to_string();
        assert!(c.block_page.check().is_ok());
        c.block_page.ipv6 = "not-an-address".to_string();
        assert!(c.block_page.check().is_err());
        c.block_page.ipv6 = String::new();
        c.web.http_enabled = true;
        c.web.http_port = 80;
        c.block_page.port = 80;
        assert!(c
            .check_block_page_port()
            .unwrap_err()
            .contains("web console"));
        c.block_page.port = 8081;
        assert!(c.check_block_page_port().is_ok());
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
    fn log_export_checks() {
        let mut e = LogExportSettings::default();
        assert!(e.check().is_ok(), "off and empty is fine");
        e.enabled = true;
        assert!(e.check().is_err(), "enabled needs a URL");
        e.url = "ftp://logs.example".into();
        assert!(e.check().is_err(), "only http(s)");
        e.url = "https://logs.example:8088/services/collector/raw".into();
        assert!(e.check().is_ok());
        assert!(!e.json_array());
        e.format = "json".into();
        assert!(e.json_array());
        e.format = "xml".into();
        assert!(e.check().is_err());
        e.format = "ndjson".into();
        e.batch_size = 0;
        assert!(e.check().is_err());
        e.batch_size = 100;
        e.flush_secs = 301;
        assert!(e.check().is_err());
        e.flush_secs = 2;
        e.authorization = "Bearer a\nX-Evil: 1".into();
        assert!(e.check().is_err(), "no header injection");
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
                theme: "system".into(),
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
        assert!(DisplaySettings {
            theme: "purple".into(),
            ..Default::default()
        }
        .check(false)
        .is_err());
        // A user's preferences may leave fields empty (server default).
        assert!(DisplaySettings {
            time_zone: String::new(),
            date_format: String::new(),
            time_format: "12h".into(),
            theme: String::new(),
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
    fn installer_firewall_ranges_match_private_networks() {
        // install.sh opens its firewall rules to the networks "Private
        // Networks Only" trusts; loopback is never firewalled.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
        let script = std::fs::read_to_string(&path).expect("install.sh is readable");
        let mut opened: Vec<&str> = script
            .lines()
            .filter_map(|line| {
                line.strip_prefix("LAN_NETS_V4=\"")
                    .or_else(|| line.strip_prefix("LAN_NETS_V6=\""))
            })
            .flat_map(|list| list.trim_end_matches('"').split_whitespace())
            .collect();
        let mut private: Vec<&str> = PRIVATE_NETWORKS
            .iter()
            .copied()
            .filter(|net| *net != "127.0.0.0/8" && *net != "::1/128")
            .collect();
        opened.sort_unstable();
        private.sort_unstable();
        assert_eq!(opened, private);
    }

    #[test]
    fn example_config_matches_defaults() {
        // The installer copies the example as the live config, so any value
        // it pins overrides the built-in default on every new install. Only
        // the keys below may differ: install paths, the bundled AI models
        // and placeholders the operator is expected to edit.
        const INTENDED: &[&str] = &[
            "ai.enabled",
            "ai.model_path",
            "ai.verifier_model_path",
            "authoritative.database",
            "authoritative.zones_dir",
            "doh.server_name",
            "doq.server_name",
            "dot.server_name",
            "recursive.mode",
        ];
        fn flatten(prefix: &str, value: &toml::Value, out: &mut BTreeMap<String, String>) {
            match value {
                toml::Value::Table(table) => {
                    for (key, value) in table {
                        let path = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        };
                        flatten(&path, value, out);
                    }
                }
                other => {
                    out.insert(prefix.to_string(), other.to_string());
                }
            }
        }
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../daygle-dns.toml.example");
        let text = std::fs::read_to_string(&path).expect("daygle-dns.toml.example is readable");
        let (mut example, mut defaults) = (BTreeMap::new(), BTreeMap::new());
        flatten(
            "",
            &toml::Value::try_from(DaygleConfig::parse(&text).unwrap()).unwrap(),
            &mut example,
        );
        flatten(
            "",
            &toml::Value::try_from(DaygleConfig::default()).unwrap(),
            &mut defaults,
        );
        let keys: BTreeSet<&String> = example.keys().chain(defaults.keys()).collect();
        let drift: Vec<String> = keys
            .into_iter()
            .filter(|key| !INTENDED.contains(&key.as_str()))
            .filter(|key| example.get(*key) != defaults.get(*key))
            .map(|key| {
                format!(
                    "{key}: example {:?}, default {:?}",
                    example.get(key),
                    defaults.get(key)
                )
            })
            .collect();
        assert!(
            drift.is_empty(),
            "example differs from defaults:\n{}",
            drift.join("\n")
        );
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
