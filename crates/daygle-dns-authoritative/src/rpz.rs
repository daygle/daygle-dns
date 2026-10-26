//! Response policy zones (RPZ): DNS firewall rules published as a zone.
//!
//! Each rule is a set of records at a *trigger* name inside the zone, and
//! what those records are gives the *action*:
//!
//! | Trigger owner (relative to the zone) | Matches |
//! |---|---|
//! | `bad.example`, `*.bad.example` | the query name (QNAME), or a name in its CNAME chain |
//! | `32.1.2.0.192.rpz-client-ip` | the client's address (`192.0.2.1/32`) |
//! | `24.0.2.0.192.rpz-ip` | an address in the answer (`192.0.2.0/24`) |
//!
//! | Records | Action |
//! |---|---|
//! | `CNAME .` | NXDOMAIN |
//! | `CNAME *.` | NODATA |
//! | `CNAME rpz-passthru.` | exempt from the rest of the RPZ rules |
//! | `CNAME rpz-drop.` | no answer at all |
//! | `CNAME rpz-tcp-only.` | over UDP, a truncated answer (retry over TCP) |
//! | anything else (`A`, `CNAME garden.example.`, `TXT`...) | answered with these records (local data) |
//!
//! Zones are checked in order and the first that matches decides; within
//! a zone, client-IP triggers come before QNAME triggers, an exact QNAME
//! before a wildcard, and the longest wildcard or address prefix wins.
//! NSDNAME and NSIP triggers are not supported (counted and skipped).
//!
//! [`RpzManager`] keeps the zones' rules: typed into the console, fetched
//! over HTTP(S), or transferred (AXFR, optionally TSIG-signed) from a feed,
//! and refreshed in the background. It publishes the compiled set in an
//! [`ArcSwap`] the dispatcher reads per query.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use daygle_dns_core::config::{RpzPolicy, RpzSource, RpzZoneConfig};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Serialize;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::catalog::AuthorityCatalog;
use crate::transfer::XfrClient;

/// Largest zone file fetched over HTTP(S).
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// How long to wait before retrying a zone that failed to load.
const RETRY_AFTER: Duration = Duration::from_secs(300);

/// What an RPZ rule does.
#[derive(Debug, Clone, PartialEq)]
pub enum RpzAction {
    NxDomain,
    NoData,
    /// Exempt from the remaining RPZ rules.
    Passthru,
    /// Send no answer.
    Drop,
    /// Over UDP, answer truncated so the client retries over TCP.
    TcpOnly,
    /// Answer with these records (owner: the query name). A CNAME target
    /// starting with `*.` has the `*` replaced by the query name.
    Local(Arc<Vec<LocalRecord>>),
}

impl RpzAction {
    /// A short name for logs and the console.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NxDomain => "NXDOMAIN",
            Self::NoData => "NODATA",
            Self::Passthru => "PASSTHRU",
            Self::Drop => "DROP",
            Self::TcpOnly => "TCP-only",
            Self::Local(_) => "local data",
        }
    }
}

/// One record of a local-data action.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalRecord {
    pub rtype: RecordType,
    pub ttl: u32,
    pub rdata: RData,
}

/// What matched, and what to do.
#[derive(Debug, Clone)]
pub struct RpzHit {
    /// The zone that matched.
    pub zone: String,
    /// The trigger, for logs (`QNAME *.bad.example`).
    pub trigger: String,
    pub action: RpzAction,
}

/// Address triggers grouped by prefix length, longest first, so a lookup
/// masks the address once per length present.
#[derive(Debug, Default)]
struct IpTriggers {
    v4: BTreeMap<std::cmp::Reverse<u8>, HashMap<u32, RpzAction>>,
    v6: BTreeMap<std::cmp::Reverse<u8>, HashMap<u128, RpzAction>>,
}

impl IpTriggers {
    fn insert(&mut self, net: ipnet::IpNet, action: RpzAction) {
        match net {
            ipnet::IpNet::V4(n) => {
                self.v4
                    .entry(std::cmp::Reverse(n.prefix_len()))
                    .or_default()
                    .insert(u32::from(n.network()), action);
            }
            ipnet::IpNet::V6(n) => {
                self.v6
                    .entry(std::cmp::Reverse(n.prefix_len()))
                    .or_default()
                    .insert(u128::from(n.network()), action);
            }
        }
    }

    /// The longest-prefix trigger containing `ip`, with its prefix length.
    fn find(&self, ip: IpAddr) -> Option<(u8, &RpzAction)> {
        match ip.to_canonical() {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().find_map(|(len, nets)| {
                    let mask = if len.0 == 0 {
                        0
                    } else {
                        u32::MAX << (32 - len.0)
                    };
                    nets.get(&(a & mask)).map(|act| (len.0, act))
                })
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().find_map(|(len, nets)| {
                    let mask = if len.0 == 0 {
                        0
                    } else {
                        u128::MAX << (128 - len.0)
                    };
                    nets.get(&(a & mask)).map(|act| (len.0, act))
                })
            }
        }
    }

    fn len(&self) -> usize {
        self.v4.values().map(HashMap::len).sum::<usize>()
            + self.v6.values().map(HashMap::len).sum::<usize>()
    }
}

/// How many rules of each kind a zone has.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RuleCounts {
    pub qname: usize,
    pub wildcard: usize,
    pub client_ip: usize,
    pub response_ip: usize,
    /// NSDNAME/NSIP triggers and unparsable owners, which are skipped.
    pub unsupported: usize,
}

/// A zone's rules, compiled for lookup.
#[derive(Debug, Default)]
pub struct CompiledZone {
    exact: HashMap<String, RpzAction>,
    /// `*.suffix` rules, keyed by `suffix`.
    wildcard: HashMap<String, RpzAction>,
    client_ip: IpTriggers,
    response_ip: IpTriggers,
    unsupported: usize,
    /// The zone's SOA serial, when it had one.
    pub serial: Option<u32>,
}

impl CompiledZone {
    /// Rule counts, for the console.
    pub fn counts(&self) -> RuleCounts {
        RuleCounts {
            qname: self.exact.len(),
            wildcard: self.wildcard.len(),
            client_ip: self.client_ip.len(),
            response_ip: self.response_ip.len(),
            unsupported: self.unsupported,
        }
    }

    /// The rule for the name `qname` (lowercase, no trailing dot): exact,
    /// else the closest wildcard.
    fn qname(&self, qname: &str) -> Option<(String, &RpzAction)> {
        if let Some(action) = self.exact.get(qname) {
            return Some((qname.to_string(), action));
        }
        if self.wildcard.is_empty() {
            return None;
        }
        let mut rest = qname;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(action) = self.wildcard.get(parent) {
                return Some((format!("*.{parent}"), action));
            }
            rest = parent;
        }
        None
    }

    /// Compile a zone from its records. `owner` is the record's owner name
    /// (lowercase, no trailing dot), absolute or relative to `zone`.
    pub fn from_records(
        zone: &str,
        records: impl IntoIterator<Item = (String, LocalRecord)>,
    ) -> Self {
        let zone = zone.trim_end_matches('.').to_ascii_lowercase();
        let suffix = format!(".{zone}");
        // Records grouped by trigger, in the order they first appear.
        let mut grouped: HashMap<String, Vec<LocalRecord>> = HashMap::new();
        let mut compiled = CompiledZone::default();
        for (owner, record) in records {
            let owner = owner.trim_end_matches('.').to_ascii_lowercase();
            if owner == zone || owner.is_empty() || owner == "@" {
                // The apex: SOA and NS only.
                if let RData::SOA(soa) = &record.rdata {
                    compiled.serial = Some(soa.serial);
                }
                continue;
            }
            let relative = owner.strip_suffix(&suffix).unwrap_or(&owner).to_string();
            if matches!(record.rtype, RecordType::SOA | RecordType::NS) {
                continue;
            }
            grouped.entry(relative).or_default().push(record);
        }
        for (trigger, records) in grouped {
            let action = action_of(&trigger, &zone, records);
            if let Some(ip) = trigger.strip_suffix(".rpz-client-ip") {
                match parse_ip_trigger(ip) {
                    Some(net) => compiled.client_ip.insert(net, action),
                    None => compiled.unsupported += 1,
                }
            } else if let Some(ip) = trigger.strip_suffix(".rpz-ip") {
                match parse_ip_trigger(ip) {
                    Some(net) => compiled.response_ip.insert(net, action),
                    None => compiled.unsupported += 1,
                }
            } else if trigger
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.starts_with("rpz-"))
            {
                // NSDNAME, NSIP, and anything newer.
                compiled.unsupported += 1;
            } else if let Some(suffix) = trigger.strip_prefix("*.") {
                compiled.wildcard.insert(suffix.to_string(), action);
            } else if trigger == "*" {
                compiled.unsupported += 1;
            } else {
                compiled.exact.insert(trigger, action);
            }
        }
        compiled
    }

    /// Compile zone-file text (as typed into the console, or fetched). A
    /// record that does not parse is reported with its line.
    pub fn from_text(zone: &str, text: &str) -> Result<Self, String> {
        let inputs = crate::parse::parse_zone_file(text).map_err(|e| e.to_string())?;
        let mut records = Vec::with_capacity(inputs.len());
        for input in inputs {
            let rtype = RecordType::from_str(&input.rtype)
                .map_err(|_| format!("unknown record type '{}'", input.rtype))?;
            let rdata = RData::try_from_str(rtype, &input.content)
                .map_err(|e| format!("'{} {} {}': {e}", input.name, input.rtype, input.content))?;
            records.push((
                input.name,
                LocalRecord {
                    rtype,
                    ttl: input.ttl,
                    rdata,
                },
            ));
        }
        Ok(Self::from_records(zone, records))
    }

    /// Compile a zone transfer's records.
    pub fn from_transfer(zone: &str, records: &[Record]) -> Self {
        Self::from_records(
            zone,
            records.iter().map(|r| {
                (
                    r.name.to_ascii(),
                    LocalRecord {
                        rtype: r.record_type(),
                        ttl: r.ttl,
                        rdata: r.data.clone(),
                    },
                )
            }),
        )
    }
}

/// The action the records at a trigger give.
fn action_of(trigger: &str, zone: &str, records: Vec<LocalRecord>) -> RpzAction {
    let cname = records.iter().find_map(|r| match &r.rdata {
        RData::CNAME(target) => Some(target.0.to_ascii().to_ascii_lowercase()),
        _ => None,
    });
    match cname.as_deref() {
        Some(".") => RpzAction::NxDomain,
        Some("*.") => RpzAction::NoData,
        Some("rpz-passthru.") => RpzAction::Passthru,
        Some("rpz-drop.") => RpzAction::Drop,
        Some("rpz-tcp-only.") => RpzAction::TcpOnly,
        // The old way to write PASSTHRU: a CNAME to the trigger itself.
        Some(target)
            if target.trim_end_matches('.') == trigger
                || target.trim_end_matches('.') == format!("{trigger}.{zone}") =>
        {
            RpzAction::Passthru
        }
        _ => RpzAction::Local(Arc::new(records)),
    }
}

/// Parse the address part of an IP trigger owner: the prefix length, then
/// the address with its labels reversed (`24.0.2.0.192` is `192.0.2.0/24`;
/// IPv6 words are reversed too, with `zz` for `::`).
fn parse_ip_trigger(text: &str) -> Option<ipnet::IpNet> {
    let mut labels = text.split('.');
    let prefix: u8 = labels.next()?.parse().ok()?;
    let mut parts: Vec<&str> = labels.collect();
    parts.reverse();
    let ip: IpAddr = if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        parts.join(".").parse().ok()?
    } else {
        let text = parts
            .iter()
            .map(|p| if *p == "zz" { "" } else { p })
            .collect::<Vec<_>>()
            .join(":");
        // `zz` at either end stands for a `::` there.
        let text = if text.starts_with(':') {
            format!(":{text}")
        } else {
            text
        };
        let text = if text.ends_with(':') {
            format!("{text}:")
        } else {
            text
        };
        text.parse().ok()?
    };
    let net = ipnet::IpNet::new(ip, prefix).ok()?;
    // The address must be the network itself (no host bits set).
    (net.network() == ip).then_some(net)
}

/// One zone in force, with its policy override applied at match time.
#[derive(Debug)]
struct ActiveZone {
    name: String,
    policy: RpzPolicy,
    cname_target: Option<Name>,
    data: Arc<CompiledZone>,
    hits: Arc<AtomicU64>,
}

impl ActiveZone {
    /// `action` with the zone's policy override; `None` when the zone only
    /// counts (policy `disabled`).
    fn apply(&self, action: &RpzAction) -> Option<RpzAction> {
        Some(match self.policy {
            RpzPolicy::Given => action.clone(),
            RpzPolicy::Disabled => return None,
            RpzPolicy::Nxdomain => RpzAction::NxDomain,
            RpzPolicy::Nodata => RpzAction::NoData,
            RpzPolicy::Passthru => RpzAction::Passthru,
            RpzPolicy::Drop => RpzAction::Drop,
            RpzPolicy::TcpOnly => RpzAction::TcpOnly,
            RpzPolicy::Cname => match &self.cname_target {
                Some(target) => RpzAction::Local(Arc::new(vec![LocalRecord {
                    rtype: RecordType::CNAME,
                    ttl: 300,
                    rdata: RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                }])),
                None => RpzAction::NxDomain,
            },
        })
    }
}

/// One match, for the console's tester.
#[derive(Debug, Clone, Serialize)]
pub struct RpzMatch {
    pub zone: String,
    pub trigger: String,
    /// The action after the zone's policy override.
    pub action: &'static str,
    /// The zone only counts matches (policy `disabled`).
    pub log_only: bool,
}

/// The zones in force, compiled; swapped whole when anything changes.
#[derive(Debug, Default)]
pub struct RpzSet {
    zones: Vec<ActiveZone>,
}

impl RpzSet {
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// The first zone that acts on a query for `qname` (lowercase, no
    /// trailing dot) from `client`: client-IP, then QNAME triggers. A
    /// PASSTHRU hit is returned too (the caller skips the rest of RPZ).
    pub fn check_query(&self, client: IpAddr, qname: &str) -> Option<RpzHit> {
        for zone in &self.zones {
            let found = zone
                .data
                .client_ip
                .find(client)
                .map(|(len, action)| (format!("client IP {client}/{len}"), action))
                .or_else(|| {
                    zone.data
                        .qname(qname)
                        .map(|(trigger, action)| (format!("QNAME {trigger}"), action))
                });
            if let Some(hit) = found.and_then(|(trigger, action)| self.hit(zone, trigger, action)) {
                return Some(hit);
            }
        }
        None
    }

    /// The first zone that acts on an answer: a name in its CNAME chain
    /// (`names`) matching a QNAME trigger, or an address in it (`ips`)
    /// matching an IP trigger.
    pub fn check_answer(&self, names: &[String], ips: &[IpAddr]) -> Option<RpzHit> {
        for zone in &self.zones {
            let found = names
                .iter()
                .find_map(|name| {
                    zone.data.qname(name).map(|(trigger, action)| {
                        (format!("QNAME {trigger} (CNAME target)"), action)
                    })
                })
                .or_else(|| {
                    ips.iter().find_map(|ip| {
                        zone.data
                            .response_ip
                            .find(*ip)
                            .map(|(len, action)| (format!("answer IP {ip}/{len}"), action))
                    })
                });
            if let Some(hit) = found.and_then(|(trigger, action)| self.hit(zone, trigger, action)) {
                return Some(hit);
            }
        }
        None
    }

    /// Whether any zone has answer (CNAME-target or IP) triggers worth
    /// checking an answer against.
    pub fn checks_answers(&self) -> bool {
        self.zones.iter().any(|z| {
            !z.data.exact.is_empty() || !z.data.wildcard.is_empty() || z.data.response_ip.len() > 0
        })
    }

    /// Count a match; `None` when the zone only counts.
    fn hit(&self, zone: &ActiveZone, trigger: String, action: &RpzAction) -> Option<RpzHit> {
        zone.hits.fetch_add(1, Ordering::Relaxed);
        zone.apply(action).map(|action| RpzHit {
            zone: zone.name.clone(),
            trigger,
            action,
        })
    }

    /// Every zone that matches a query (for the console's tester), in
    /// order; the first that is not log-only is the one that acts.
    pub fn explain(&self, client: IpAddr, qname: &str) -> Vec<RpzMatch> {
        let mut out = Vec::new();
        for zone in &self.zones {
            let found = zone
                .data
                .client_ip
                .find(client)
                .map(|(len, action)| (format!("client IP {client}/{len}"), action))
                .or_else(|| {
                    zone.data
                        .qname(qname)
                        .map(|(trigger, action)| (format!("QNAME {trigger}"), action))
                });
            if let Some((trigger, action)) = found {
                let applied = zone.apply(action);
                out.push(RpzMatch {
                    zone: zone.name.clone(),
                    trigger,
                    action: applied.as_ref().unwrap_or(action).label(),
                    log_only: applied.is_none(),
                });
            }
        }
        out
    }
}

/// A zone's state, for the console.
#[derive(Debug, Clone, Serialize)]
pub struct RpzZoneStatus {
    pub name: String,
    pub enabled: bool,
    pub source: RpzSource,
    pub policy: RpzPolicy,
    /// Whether rules are loaded (a zone that never loaded has none).
    pub loaded: bool,
    pub rules: RuleCounts,
    pub serial: Option<u32>,
    /// When the rules were last loaded (RFC 3339).
    pub last_loaded: Option<String>,
    /// When the source was last checked, changed or not (RFC 3339).
    pub last_checked: Option<String>,
    /// Why the last load failed (the previous rules stay in force).
    pub last_error: Option<String>,
    /// Matches since start (including those of a `disabled` zone).
    pub hits: u64,
}

struct ZoneState {
    config: RpzZoneConfig,
    data: Option<Arc<CompiledZone>>,
    last_loaded: Option<chrono::DateTime<chrono::Utc>>,
    last_checked: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
    next_due: Instant,
    hits: Arc<AtomicU64>,
}

/// Keeps the response policy zones loaded and publishes them.
pub struct RpzManager {
    set: Arc<ArcSwap<RpzSet>>,
    zones: Mutex<Vec<ZoneState>>,
    catalog: Arc<AuthorityCatalog>,
    wake: Notify,
    xfr: XfrClient,
    http: reqwest::Client,
    /// Serializes refresh rounds (the loop and a console "refresh now").
    refreshing: tokio::sync::Mutex<()>,
}

impl RpzManager {
    /// A manager publishing into `set` (shared with the dispatcher).
    pub fn new(set: Arc<ArcSwap<RpzSet>>, catalog: Arc<AuthorityCatalog>) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Arc::new(Self {
            set,
            zones: Mutex::new(Vec::new()),
            catalog,
            wake: Notify::new(),
            xfr: XfrClient::new(Duration::from_secs(30)),
            http,
            refreshing: tokio::sync::Mutex::new(()),
        })
    }

    /// The compiled set the dispatcher reads.
    pub fn set(&self) -> Arc<ArcSwap<RpzSet>> {
        Arc::clone(&self.set)
    }

    /// Take a new list of zones. A zone whose source did not change keeps
    /// its loaded rules (and its hit count); local zones compile at once,
    /// the others load in the background.
    pub fn set_zones(&self, configs: &[RpzZoneConfig]) {
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        let mut old: Vec<ZoneState> = std::mem::take(&mut *zones);
        for config in configs {
            let key = config
                .name
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let previous = old
                .iter()
                .position(|z| {
                    z.config
                        .name
                        .trim()
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(&key)
                })
                .map(|i| old.remove(i));
            let same_source = previous
                .as_ref()
                .is_some_and(|p| same_source(&p.config, config));
            let mut state = match previous {
                Some(mut p) if same_source => {
                    p.config = config.clone();
                    p
                }
                previous => ZoneState {
                    config: config.clone(),
                    data: None,
                    last_loaded: None,
                    last_checked: None,
                    last_error: None,
                    next_due: Instant::now(),
                    hits: previous.map(|p| p.hits).unwrap_or_default(),
                },
            };
            if state.config.source == RpzSource::Local && (!same_source || state.data.is_none()) {
                let now = chrono::Utc::now();
                state.last_checked = Some(now);
                match CompiledZone::from_text(&state.config.name, &state.config.rules) {
                    Ok(data) => {
                        state.data = Some(Arc::new(data));
                        state.last_loaded = Some(now);
                        state.last_error = None;
                    }
                    Err(e) => state.last_error = Some(e),
                }
            }
            zones.push(state);
        }
        self.publish(&zones);
        drop(zones);
        self.wake.notify_one();
    }

    /// Publish the loaded, enabled zones in order.
    fn publish(&self, zones: &[ZoneState]) {
        let active = zones
            .iter()
            .filter(|z| z.config.enabled)
            .filter_map(|z| {
                Some(ActiveZone {
                    name: z
                        .config
                        .name
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                    policy: z.config.policy,
                    cname_target: Name::from_ascii(format!(
                        "{}.",
                        z.config.cname_target.trim().trim_end_matches('.')
                    ))
                    .ok()
                    .filter(|_| !z.config.cname_target.trim().is_empty()),
                    data: z.data.clone()?,
                    hits: Arc::clone(&z.hits),
                })
            })
            .collect();
        self.set.store(Arc::new(RpzSet { zones: active }));
    }

    /// Each zone's state.
    pub fn status(&self) -> Vec<RpzZoneStatus> {
        let zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        zones
            .iter()
            .map(|z| RpzZoneStatus {
                name: z.config.name.clone(),
                enabled: z.config.enabled,
                source: z.config.source,
                policy: z.config.policy,
                loaded: z.data.is_some(),
                rules: z.data.as_ref().map(|d| d.counts()).unwrap_or_default(),
                serial: z.data.as_ref().and_then(|d| d.serial),
                last_loaded: z.last_loaded.map(|t| t.to_rfc3339()),
                last_checked: z.last_checked.map(|t| t.to_rfc3339()),
                last_error: z.last_error.clone(),
                hits: z.hits.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Mark every remote zone due and wake the loop.
    pub fn refresh_now(&self) {
        let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
        for zone in zones.iter_mut() {
            zone.next_due = Instant::now();
        }
        drop(zones);
        self.wake.notify_one();
    }

    /// Load every remote zone that is due. Returns how many were loaded.
    pub async fn refresh_due(&self) -> usize {
        let _round = self.refreshing.lock().await;
        let due: Vec<(RpzZoneConfig, Option<u32>)> = {
            let zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            zones
                .iter()
                .filter(|z| z.config.enabled && z.config.source != RpzSource::Local)
                .filter(|z| z.next_due <= now)
                .map(|z| (z.config.clone(), z.data.as_ref().and_then(|d| d.serial)))
                .collect()
        };
        let mut loaded = 0;
        for (config, serial) in due {
            let result = self.load(&config, serial).await;
            let mut zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
            let Some(state) = zones.iter_mut().find(|z| same_source(&z.config, &config)) else {
                continue; // removed or changed meanwhile
            };
            let now = chrono::Utc::now();
            state.last_checked = Some(now);
            let key = format!("rpz:{}", config.name);
            match result {
                Ok(Some(data)) => {
                    info!(zone = %config.name, rules = ?data.counts(), "response policy zone loaded");
                    state.data = Some(Arc::new(data));
                    state.last_loaded = Some(now);
                    state.last_error = None;
                    state.next_due =
                        Instant::now() + Duration::from_secs(config.refresh_secs.max(60));
                    loaded += 1;
                    daygle_dns_core::alerts::resolve(&key);
                }
                Ok(None) => {
                    // Unchanged (same serial).
                    state.last_error = None;
                    state.next_due =
                        Instant::now() + Duration::from_secs(config.refresh_secs.max(60));
                    daygle_dns_core::alerts::resolve(&key);
                }
                Err(e) => {
                    warn!(zone = %config.name, error = %e, "response policy zone cannot be loaded");
                    state.last_error = Some(e.clone());
                    state.next_due = Instant::now()
                        + RETRY_AFTER.min(Duration::from_secs(config.refresh_secs.max(60)));
                    let kind = if config.source == RpzSource::Transfer {
                        daygle_dns_core::alerts::AlertKind::ZoneTransferFailure
                    } else {
                        daygle_dns_core::alerts::AlertKind::BlocklistFailure
                    };
                    daygle_dns_core::alerts::raise(
                        kind,
                        key,
                        format!("Response policy zone '{}' cannot be loaded", config.name),
                        format!(
                            "Loading the response policy zone '{}' failed: {e}. Its last loaded \
                             rules (if any) stay in force.",
                            config.name
                        ),
                    );
                }
            }
            self.publish(&zones);
        }
        loaded
    }

    /// Load one remote zone: `None` when a transfer source reports the
    /// serial already loaded.
    async fn load(
        &self,
        config: &RpzZoneConfig,
        serial: Option<u32>,
    ) -> Result<Option<CompiledZone>, String> {
        match config.source {
            RpzSource::Local => CompiledZone::from_text(&config.name, &config.rules).map(Some),
            RpzSource::Url => {
                let text = self.fetch(config.url.trim()).await?;
                CompiledZone::from_text(&config.name, &text).map(Some)
            }
            RpzSource::Transfer => self.transfer(config, serial).await,
        }
    }

    async fn fetch(&self, url: &str) -> Result<String, String> {
        let mut response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("GET {url} returned {}", response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("reading {url}: {e}"))?
        {
            if bytes.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(format!("{url} is larger than {MAX_BODY_BYTES} bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn transfer(
        &self,
        config: &RpzZoneConfig,
        serial: Option<u32>,
    ) -> Result<Option<CompiledZone>, String> {
        let zone = Name::from_ascii(format!("{}.", config.name.trim().trim_end_matches('.')))
            .map_err(|e| format!("'{}': {e}", config.name))?;
        let key = match config.tsig_key.trim() {
            "" => None,
            name => Some(
                self.catalog
                    .tsig_key_ring()
                    .get_by_config_name(name)
                    .cloned()
                    .ok_or_else(|| format!("there is no TSIG key named '{name}'"))?,
            ),
        };
        let mut errors = Vec::new();
        for primary in &config.primaries {
            let addr = match daygle_dns_core::config::parse_master_addr(primary) {
                Ok(addr) => addr,
                Err(e) => {
                    errors.push(format!("{primary}: {e}"));
                    continue;
                }
            };
            // An unchanged serial means nothing to transfer.
            if let Some(current) = serial {
                if let Ok(Some(soa)) = self.xfr.query_soa_signed(addr, &zone, key.as_ref()).await {
                    if let RData::SOA(soa) = &soa.data {
                        if !crate::secondary::serial_newer(soa.serial, current) {
                            return Ok(None);
                        }
                    }
                }
            }
            match self.xfr.axfr_signed(addr, &zone, key.as_ref()).await {
                Ok(records) => {
                    let complete = records.len() >= 2
                        && records.first().map(Record::record_type) == Some(RecordType::SOA)
                        && records.last().map(Record::record_type) == Some(RecordType::SOA);
                    if !complete {
                        errors.push(format!("{primary}: the transfer was incomplete"));
                        continue;
                    }
                    return Ok(Some(CompiledZone::from_transfer(
                        &config.name,
                        &records[..records.len() - 1],
                    )));
                }
                Err(e) => errors.push(format!("{primary}: {e}")),
            }
        }
        Err(errors.join("; "))
    }

    /// Load zones as they fall due until `shutdown`.
    pub async fn run_forever(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            self.refresh_due().await;
            let wait = {
                let zones = self.zones.lock().unwrap_or_else(|e| e.into_inner());
                zones
                    .iter()
                    .filter(|z| z.config.enabled && z.config.source != RpzSource::Local)
                    .map(|z| z.next_due.saturating_duration_since(Instant::now()))
                    .min()
                    .unwrap_or(Duration::from_secs(3600))
                    .max(Duration::from_secs(1))
            };
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// Whether two configurations load the same rules.
fn same_source(a: &RpzZoneConfig, b: &RpzZoneConfig) -> bool {
    a.name
        .trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(b.name.trim().trim_end_matches('.'))
        && a.source == b.source
        && match a.source {
            RpzSource::Local => a.rules == b.rules,
            RpzSource::Url => a.url.trim() == b.url.trim(),
            RpzSource::Transfer => a.primaries == b.primaries && a.tsig_key == b.tsig_key,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "\
$TTL 300
@                       SOA ns.rpz.local. admin.rpz.local. 7 3600 600 86400 60
                        NS  ns.rpz.local.
bad.example             CNAME .
*.ads.example           CNAME .
empty.example           CNAME *.
ok.ads.example          CNAME rpz-passthru.
quiet.example           CNAME rpz-drop.
tcp.example             CNAME rpz-tcp-only.
garden.example          CNAME walled.garden.test.
local.example           A 192.0.2.80
local.example           TXT \"blocked by policy\"
32.7.2.0.192.rpz-client-ip CNAME rpz-drop.
24.0.113.0.203.rpz-ip   CNAME .
48.zz.8b.db8.2001.rpz-ip CNAME *.
ns.evil.rpz-nsdname     CNAME .
";

    fn zone() -> CompiledZone {
        let mut text = String::from("$ORIGIN rpz.local.\n");
        text.push_str(ZONE);
        CompiledZone::from_text("rpz.local", &text).unwrap()
    }

    fn set(policy: RpzPolicy) -> RpzSet {
        RpzSet {
            zones: vec![ActiveZone {
                name: "rpz.local".to_string(),
                policy,
                cname_target: Name::from_ascii("garden.test.").ok(),
                data: Arc::new(zone()),
                hits: Arc::default(),
            }],
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn action(set: &RpzSet, client: &str, qname: &str) -> Option<&'static str> {
        set.check_query(ip(client), qname).map(|h| h.action.label())
    }

    #[test]
    fn triggers_and_actions_are_parsed() {
        let z = zone();
        assert_eq!(z.serial, Some(7));
        assert_eq!(
            z.counts(),
            RuleCounts {
                qname: 7,
                wildcard: 1,
                client_ip: 1,
                response_ip: 2,
                unsupported: 1,
            }
        );
        let s = set(RpzPolicy::Given);
        assert_eq!(action(&s, "10.0.0.1", "bad.example"), Some("NXDOMAIN"));
        assert_eq!(action(&s, "10.0.0.1", "x.y.ads.example"), Some("NXDOMAIN"));
        // The wildcard does not cover the name itself; the exact rule beats it.
        assert_eq!(action(&s, "10.0.0.1", "ads.example"), None);
        assert_eq!(action(&s, "10.0.0.1", "ok.ads.example"), Some("PASSTHRU"));
        assert_eq!(action(&s, "10.0.0.1", "empty.example"), Some("NODATA"));
        assert_eq!(action(&s, "10.0.0.1", "quiet.example"), Some("DROP"));
        assert_eq!(action(&s, "10.0.0.1", "tcp.example"), Some("TCP-only"));
        assert_eq!(action(&s, "10.0.0.1", "garden.example"), Some("local data"));
        assert_eq!(action(&s, "10.0.0.1", "fine.example"), None);
        // Client-IP triggers come first.
        assert_eq!(action(&s, "192.0.2.7", "fine.example"), Some("DROP"));

        let Some(RpzHit {
            action: RpzAction::Local(records),
            ..
        }) = s.check_query(ip("10.0.0.1"), "local.example")
        else {
            panic!("local data expected");
        };
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn answers_are_checked_by_address_and_cname_target() {
        let s = set(RpzPolicy::Given);
        let hit = s.check_answer(&[], &[ip("203.0.113.9")]).unwrap();
        assert_eq!(hit.action, RpzAction::NxDomain);
        assert!(hit.trigger.contains("203.0.113.9/24"), "{}", hit.trigger);
        let hit = s.check_answer(&[], &[ip("2001:db8:8b::1")]).unwrap();
        assert_eq!(hit.action, RpzAction::NoData);
        assert!(s.check_answer(&[], &[ip("198.51.100.1")]).is_none());
        let hit = s.check_answer(&["t.ads.example".to_string()], &[]).unwrap();
        assert_eq!(hit.action, RpzAction::NxDomain);
    }

    #[test]
    fn zone_policy_overrides_the_given_action() {
        let s = set(RpzPolicy::Nodata);
        assert_eq!(action(&s, "10.0.0.1", "bad.example"), Some("NODATA"));
        let s = set(RpzPolicy::Cname);
        let Some(RpzHit {
            action: RpzAction::Local(records),
            ..
        }) = s.check_query(ip("10.0.0.1"), "bad.example")
        else {
            panic!("walled garden expected");
        };
        assert_eq!(records[0].rtype, RecordType::CNAME);
        // Disabled: counted, never acted on, and explained as log-only.
        let s = set(RpzPolicy::Disabled);
        assert!(s.check_query(ip("10.0.0.1"), "bad.example").is_none());
        assert_eq!(s.zones[0].hits.load(Ordering::Relaxed), 1);
        let explained = s.explain(ip("10.0.0.1"), "bad.example");
        assert_eq!(explained.len(), 1);
        assert!(explained[0].log_only);
        assert_eq!(explained[0].action, "NXDOMAIN");
    }

    #[test]
    fn ip_triggers_parse_both_families() {
        assert_eq!(
            parse_ip_trigger("24.0.2.0.192"),
            Some("192.0.2.0/24".parse().unwrap())
        );
        assert_eq!(
            parse_ip_trigger("128.1.zz.db8.2001"),
            Some("2001:db8::1/128".parse().unwrap())
        );
        assert_eq!(
            parse_ip_trigger("64.zz.db8.2001"),
            Some("2001:db8::/64".parse().unwrap())
        );
        // Host bits set, bad prefix: rejected.
        assert_eq!(parse_ip_trigger("24.7.2.0.192"), None);
        assert_eq!(parse_ip_trigger("33.0.2.0.192"), None);
    }

    #[test]
    fn owners_may_be_absolute_or_relative() {
        let z = CompiledZone::from_text(
            "rpz.local",
            "a.example.rpz.local. CNAME .\nb.example CNAME .\n",
        )
        .unwrap();
        assert_eq!(z.counts().qname, 2);
        assert!(z.qname("a.example").is_some());
        assert!(z.qname("b.example").is_some());
    }
}
