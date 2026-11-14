//! Advanced Blocking: per-client-group allow/block policies.
//!
//! Each [`BlockingGroup`] targets a set of client networks and carries its own
//! allow list, block list, allow/block regex patterns and a response to return
//! when it blocks. Groups are evaluated in `position` order; within a matching
//! group the allow rules (domain list or regex) win over the block rules, so an
//! allowed name short-circuits and is never blocked by a later group.
//!
//! A group can also block with remote blocklist sources scoped to groups.
//! Those are looked up by name in the shared [`GroupBlocklists`], which the
//! refresh loop updates as the sources are fetched, so a refreshed list takes
//! effect without rebuilding the groups.
//!
//! The compiled form here (parsed CIDRs and [`RegexSet`]s) is rebuilt whenever
//! the stored groups change; the hot path only does lookups.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use regex::{RegexSet, RegexSetBuilder};
use tracing::warn;

use daygle_dns_core::blocking::{BlockResponse, BlockingGroup};
use daygle_dns_core::config::{normalize_domains, AiMode};
use daygle_dns_core::schedule::{self, CompiledWindow, WeekTime};

use crate::engine::{source, Check};
use crate::feeds::FeedLists;
use crate::security::{Detector, SecurityCategory};
use crate::{Action, Blocklist, Decision, GroupBlocklists};

/// Client-list keywords that match by listener instead of by address.
/// Case-insensitive; a group's client list may mix them with networks
/// (e.g. `DOT` alongside `192.168.1.0/24`). This is how a group targets
/// public/remote encrypted-DNS users, whose addresses cannot be expressed
/// as networks ("everything except my private ranges" is not a CIDR set).
pub const LISTENER_KEYWORDS: [&str; 3] = ["dot", "doh", "doq"];

/// The client-list entry prefix that names a DNS account
/// (`account:<name>`, the name case-insensitive).
pub const ACCOUNT_PREFIX: &str = "account:";

/// The account an `account:<name>` client-list entry names.
pub fn account_entry(entry: &str) -> Option<&str> {
    let entry = entry.trim();
    let prefix = entry.get(..ACCOUNT_PREFIX.len())?;
    prefix
        .eq_ignore_ascii_case(ACCOUNT_PREFIX)
        .then(|| entry[ACCOUNT_PREFIX.len()..].trim())
        .filter(|name| !name.is_empty())
}

/// Whether `entry` names an encrypted listener in a client list.
pub fn is_listener_keyword(entry: &str) -> bool {
    listener_keyword(entry).is_some()
}

/// A single blocking group compiled for evaluation.
struct CompiledGroup {
    name: String,
    /// Whether the group's client list is empty, so it covers every
    /// client. Decided from the list as stored, not from what compiled: a
    /// group whose only entries are unusable (a network name no longer
    /// configured) covers no one, never everyone.
    everyone: bool,
    /// Client networks this group applies to.
    clients: Vec<IpNet>,
    /// Encrypted listeners (lowercased `dot`/`doh`/`doq`) this group applies
    /// to, from the special client-list entries; empty means no listener
    /// matches.
    listeners: Vec<&'static str>,
    /// DNS accounts (lowercased names) this group applies to, from
    /// `account:<name>` client-list entries.
    accounts: Vec<String>,
    allow: Blocklist,
    block: Blocklist,
    allow_regex: RegexSet,
    block_regex: RegexSet,
    /// The group-scoped sources this group blocks with: (lower-cased lookup
    /// key, name as written).
    blocklists: Vec<(String, String)>,
    /// Response returned when this group blocks a query.
    action: Action,
    /// This group's AI enforcement override: `None` follows the global
    /// `ai.mode`, `Some` replaces it for this group's clients.
    ai_mode: Option<AiMode>,
    /// Whether this group's clients get forced Safe Search.
    safe_search: bool,
    /// Whether this group's clients get YouTube Restricted Mode.
    youtube_restricted: bool,
    /// When the group applies; empty means always.
    schedule: Vec<CompiledWindow>,
    /// Blocked services: (display name, their domains and subdomains).
    services: Vec<(&'static str, Blocklist)>,
    /// Blocked security and privacy categories. List categories are looked
    /// up in their downloaded feed ([`crate::feeds`]); detectors are judged
    /// by the dispatcher after resolution.
    security: Vec<&'static SecurityCategory>,
    /// Blocked top-level domains (`*.tld` entries).
    tlds: Blocklist,
    /// Block answers with local network addresses for public names.
    block_local_addresses: bool,
    /// Block answers with oversized payloads.
    limit_payloads: bool,
    /// AI content categories this group blocks (lower-cased labels).
    blocked_categories: Vec<String>,
}

impl CompiledGroup {
    /// Whether a query from `client` on encrypted listener `listener`
    /// (`Some("dot"/"doh"/"doq") when the query arrived over one of them,
    /// `None` for plain DNS) matches the group: it does when the group has
    /// no client customers at all (every client), when a listed network
    /// contains the address, when the query arrived over a listed
    /// listener, or when it came from a listed DNS account (read from the
    /// query's [`identity`](crate::identity)).
    fn matches_client(&self, client: IpAddr, listener: Option<&str>) -> bool {
        if self.everyone {
            return true;
        }
        self.clients.iter().any(|net| net.contains(&client))
            || matches!(listener, Some(l) if self.listeners.contains(&l))
            || (!self.accounts.is_empty()
                && crate::identity::current_account().is_some_and(|account| {
                    // Unicode lowercase, as the entries were stored, without
                    // allocating a lowered copy per group per query.
                    self.accounts
                        .iter()
                        .any(|a| account.chars().flat_map(char::to_lowercase).eq(a.chars()))
                }))
    }

    /// Whether the group covers this query now: the client matches and the
    /// group's schedule (if any) is active. `now` is read once per query,
    /// and only when a group has a schedule.
    fn applies(&self, client: IpAddr, listener: Option<&str>, now: &mut Clock) -> bool {
        self.matches_client(client, listener)
            && (self.schedule.is_empty() || schedule::active(&self.schedule, now.get()))
    }

    /// The list category whose downloaded feed lists `qname`, if any.
    fn security_match(&self, qname: &str, feeds: &FeedLists) -> Option<&'static SecurityCategory> {
        self.security.iter().copied().find(|c| {
            c.detector.is_none() && feeds.get(c.id).is_some_and(|list| list.contains(qname))
        })
    }

    /// Whether the group blocks with `detector`.
    fn uses(&self, detector: Detector) -> bool {
        self.security.iter().any(|c| c.detector == Some(detector))
    }

    fn allows(&self, qname: &str) -> bool {
        self.allow.contains(qname) || self.allow_regex.is_match(qname)
    }

    /// The allow entry or pattern that lets `qname` through, if any.
    fn allow_match(&self, qname: &str) -> Option<String> {
        self.allow
            .matching_entry(qname)
            .or_else(|| first_pattern(&self.allow_regex, qname))
    }

    /// The block entry or pattern that blocks `qname`, if any.
    fn block_match(&self, qname: &str) -> Option<String> {
        self.block
            .matching_entry(qname)
            .or_else(|| first_pattern(&self.block_regex, qname))
    }
}

/// The first pattern of `set` that matches `qname`, written as `/pattern/`.
fn first_pattern(set: &RegexSet, qname: &str) -> Option<String> {
    set.matches(qname)
        .iter()
        .next()
        .map(|i| format!("/{}/", set.patterns()[i]))
}

/// The time of the week a query is evaluated at, read on first use.
struct Clock(Option<WeekTime>);

impl Clock {
    fn get(&mut self) -> WeekTime {
        *self.0.get_or_insert_with(schedule::now)
    }
}

/// The compiled set of Advanced Blocking groups.
#[derive(Default)]
pub struct AdvancedBlocking {
    groups: Vec<CompiledGroup>,
    lists: Arc<GroupBlocklists>,
    /// A fixed time to evaluate schedules at instead of the clock (tests).
    fixed_time: Option<WeekTime>,
}

impl AdvancedBlocking {
    /// Compile the enabled groups. Invalid CIDRs and regex patterns are
    /// skipped with a warning rather than failing the whole build, so one bad
    /// entry can never disable blocking for every group.
    pub fn build(groups: &[BlockingGroup], lists: Arc<GroupBlocklists>) -> Self {
        let mut compiled = Vec::new();
        for g in groups {
            if !g.enabled {
                continue;
            }
            let accounts: Vec<String> = g
                .clients
                .iter()
                .filter_map(|c| account_entry(c))
                .map(str::to_lowercase)
                .collect();
            let (networks, listener_entries): (Vec<String>, Vec<String>) = g
                .clients
                .iter()
                .filter(|c| account_entry(c).is_none())
                .cloned()
                .partition(|c| !is_listener_keyword(c));
            let listeners = listener_entries
                .iter()
                .filter_map(|e| listener_keyword(e))
                .collect::<Vec<_>>();
            let clients = parse_networks(&networks, &g.name);
            let everyone = g.clients.iter().all(|c| c.trim().is_empty());
            if !everyone && clients.is_empty() && listeners.is_empty() && accounts.is_empty() {
                warn!(
                    group = %g.name,
                    "no usable client entry; the group covers no client until its clients are fixed"
                );
            }
            compiled.push(CompiledGroup {
                everyone,
                listeners,
                accounts,
                clients,
                allow: Blocklist::from_set(normalize_domains(g.allow.iter().cloned())),
                block: Blocklist::from_set(normalize_domains(g.block.iter().cloned())),
                allow_regex: compile_regex(&g.allow_regex, &g.name),
                block_regex: compile_regex(&g.block_regex, &g.name),
                blocklists: g
                    .blocklists
                    .iter()
                    .map(|n| (n.to_ascii_lowercase(), n.clone()))
                    .collect(),
                action: response_to_action(&g.response),
                ai_mode: g.ai_mode,
                blocked_categories: g
                    .blocked_categories
                    .iter()
                    .map(|c| c.trim().to_ascii_lowercase())
                    .filter(|c| !c.is_empty())
                    .collect(),
                schedule: g
                    .schedule
                    .iter()
                    .filter_map(|w| match CompiledWindow::parse(w) {
                        Ok(window) => Some(window),
                        Err(e) => {
                            warn!(group = %g.name, error = %e, "skipping invalid schedule window");
                            None
                        }
                    })
                    .collect(),
                services: g
                    .blocked_services
                    .iter()
                    .filter_map(|id| {
                        let found = crate::services::find(id);
                        if found.is_none() {
                            warn!(group = %g.name, service = %id, "skipping unknown blocked service");
                        }
                        found
                    })
                    .map(|s| {
                        let domains = s
                            .domains
                            .iter()
                            .flat_map(|d| [d.to_string(), format!("*.{d}")]);
                        (s.name, Blocklist::from_set(normalize_domains(domains)))
                    })
                    .collect(),
                security: g
                    .blocked_security
                    .iter()
                    .filter_map(|id| {
                        let found = crate::security::find(id);
                        if found.is_none() && !crate::security::is_retired(id) {
                            warn!(group = %g.name, category = %id, "skipping unknown security category");
                        }
                        found
                    })
                    .collect(),
                tlds: Blocklist::from_set(
                    g.blocked_tlds
                        .iter()
                        .filter_map(|t| {
                            let tld = crate::security::normalize_tld(t);
                            if tld.is_none() {
                                warn!(group = %g.name, tld = %t, "skipping invalid TLD");
                            }
                            tld
                        })
                        .map(|t| format!("*.{t}"))
                        .collect(),
                ),
                block_local_addresses: g.block_local_addresses,
                limit_payloads: g.limit_payloads,
                safe_search: g.safe_search,
                youtube_restricted: g.youtube_restricted,
                name: g.name.clone(),
            });
        }
        Self {
            groups: compiled,
            lists,
            fixed_time: None,
        }
    }

    /// Evaluate schedules at `time` instead of the current time.
    pub fn at_time(mut self, time: WeekTime) -> Self {
        self.fixed_time = Some(time);
        self
    }

    fn clock(&self) -> Clock {
        Clock(self.fixed_time)
    }

    /// The first enabled group covering `client` on `listener` right now.
    fn first_group(&self, client: IpAddr, listener: Option<&str>) -> Option<&CompiledGroup> {
        let mut now = self.clock();
        self.groups
            .iter()
            .find(|g| g.applies(client, listener, &mut now))
    }

    /// The enabled groups that cover `client` on `listener` but are
    /// outside their schedule right now.
    pub fn scheduled_off(&self, client: IpAddr, listener: Option<&str>) -> Vec<&str> {
        let mut now = self.clock();
        self.groups
            .iter()
            .filter(|g| {
                g.matches_client(client, listener)
                    && !g.schedule.is_empty()
                    && !schedule::active(&g.schedule, now.get())
            })
            .map(|g| g.name.as_str())
            .collect()
    }

    /// The group-scoped sources the groups look their blocklists up in.
    pub fn lists(&self) -> Arc<GroupBlocklists> {
        Arc::clone(&self.lists)
    }

    /// Whether any enabled group is configured.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of compiled (enabled) groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// How AI threat blocking applies to a query from `client` on `listener`:
    /// the first enabled group the client belongs to may override `default`
    /// (the global `ai.mode`); otherwise the default stands, clients in no
    /// group included. Returns the deciding group's name when one matched
    /// (`None` when no group did), so a caller can explain the answer.
    pub fn ai_mode(
        &self,
        client: IpAddr,
        listener: Option<&str>,
        default: AiMode,
    ) -> (AiMode, Option<&str>) {
        self.first_group(client, listener)
            .map_or((default, None), |g| {
                (g.ai_mode.unwrap_or(default), Some(g.name.as_str()))
            })
    }

    /// The AI content categories the first enabled group `client` on
    /// `listener` belongs to blocks, plus that group's name. Clients in no
    /// group block no categories; an empty slice means this group blocks none.
    pub fn blocked_categories(
        &self,
        client: IpAddr,
        listener: Option<&str>,
    ) -> (Option<&[String]>, Option<&str>) {
        self.first_group(client, listener)
            .map_or((None, None), |g| {
                (Some(g.blocked_categories.as_slice()), Some(g.name.as_str()))
            })
    }

    /// Whether some enabled group blocks the AI category `category`.
    pub fn blocks_category(&self, category: &str) -> bool {
        self.groups.iter().any(|g| {
            g.blocked_categories
                .iter()
                .any(|c| c.eq_ignore_ascii_case(category))
        })
    }

    /// The Safe Search and YouTube Restricted Mode switches of the first
    /// enabled group `client` on `listener` belongs to (both off for clients
    /// in no group), with that group's name.
    pub fn safe_search(
        &self,
        client: IpAddr,
        listener: Option<&str>,
    ) -> (bool, bool, Option<&str>) {
        self.first_group(client, listener)
            .map_or((false, false, None), |g| {
                (g.safe_search, g.youtube_restricted, Some(g.name.as_str()))
            })
    }

    /// The ids of the feed-backed categories some enabled group uses, so
    /// the feed loop downloads only those.
    pub fn feed_categories(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .groups
            .iter()
            .flat_map(|g| g.security.iter())
            .filter(|c| c.feed.is_some())
            .map(|c| c.id.to_string())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// The response filters that apply to an answer for `qname` sent to
    /// `client` on `listener`: like [`Self::evaluate`], only the first
    /// enabled group covering the client decides, and none apply when its
    /// allow rules let `qname` through.
    pub fn response_filters(
        &self,
        client: IpAddr,
        qname: &str,
        listener: Option<&str>,
    ) -> ResponseFilters<'_> {
        let Some(group) = self
            .first_group(client, listener)
            .filter(|g| !g.allows(qname))
        else {
            return ResponseFilters::default();
        };
        let name = Some(group.name.as_str());
        let on = |enabled: bool| if enabled { name } else { None };
        ResponseFilters {
            local_addresses: on(group.block_local_addresses),
            payloads: on(group.limit_payloads),
            newly_registered: on(group.uses(Detector::NewlyRegistered)),
            safe_browsing: on(group.uses(Detector::SafeBrowsing)),
            cname_trackers: on(group.uses(Detector::CnameTracker)),
        }
    }

    /// Evaluate `qname` (already normalized: lowercase, no trailing dot) for
    /// `client`. Only the first enabled group covering the client right now
    /// decides, as it does for Safe Search and the AI mode: a client placed
    /// in a group above a broader one (a device above its LAN) gets that
    /// group's rules alone, never the broader group's as well. Returns
    /// `Some(Decision)` when that group blocks the query, or `None` when it
    /// allows the name, nothing in it matches, or no group covers the client.
    pub fn evaluate(
        &self,
        client: IpAddr,
        qname: &str,
        listener: Option<&'static str>,
    ) -> Option<Decision> {
        // Loaded at most once per query, and only when a group needs it.
        let mut lists = None;
        let mut now = self.clock();
        for group in &self.groups {
            if !group.applies(client, listener, &mut now) {
                continue;
            }
            // Whitelist wins: an allowed name is never blocked.
            if group.allows(qname) {
                return None;
            }
            let service = || {
                group
                    .services
                    .iter()
                    .find(|(_, domains)| domains.contains(qname))
                    .map(|(name, _)| *name)
            };
            let found = if let Some(entry) = group.block_match(qname) {
                Some((
                    format!(
                        "'{qname}' blocked by group '{}' (entry '{entry}')",
                        group.name
                    ),
                    source::GROUP,
                    entry,
                ))
            } else if let Some(service) = service() {
                Some((
                    format!(
                        "'{qname}' blocked as part of {service} by group '{}'",
                        group.name
                    ),
                    source::SERVICE,
                    service.to_string(),
                ))
            } else if let Some(category) = group.security_match(qname, self.lists.feeds()) {
                Some((
                    format!(
                        "'{qname}' blocked as {} by group '{}'",
                        category.name, group.name
                    ),
                    category_source(category.name),
                    category.name.to_string(),
                ))
            } else if let Some(entry) = group.tlds.matching_entry(qname) {
                Some((
                    format!(
                        "'{qname}' blocked by group '{}' (TLD '{}')",
                        group.name,
                        tld_of(&entry)
                    ),
                    source::TLD,
                    entry,
                ))
            } else if group.blocklists.is_empty() {
                None
            } else {
                let lists = lists.get_or_insert_with(|| self.lists.snapshot());
                group
                    .blocklists
                    .iter()
                    .find(|(key, _)| lists.get(key).is_some_and(|l| l.contains(qname)))
                    .map(|(_, name)| {
                        (
                            format!(
                                "'{qname}' blocked by blocklist '{name}' in group '{}'",
                                group.name
                            ),
                            source::GROUP_BLOCKLIST,
                            name.clone(),
                        )
                    })
            };
            // The first covering group decides alone: later groups are not
            // consulted, whether this one blocks the name or not.
            return found.map(|(reason, kind, matched)| {
                Decision::new(reason, group.action.clone())
                    .with_group(group.name.clone())
                    .with_source(kind, Some(matched))
            });
        }
        None
    }

    /// What the group deciding for `client` on `listener` does with
    /// `qname`: every rule in it that matches, not only the first. Groups
    /// above it that cover the client but are outside their schedule are
    /// listed as off; groups below it are not consulted, as in
    /// [`Self::evaluate`].
    pub fn explain(
        &self,
        client: IpAddr,
        qname: &str,
        listener: Option<&'static str>,
    ) -> Vec<Check> {
        let lists = self.lists.snapshot();
        let mut now = self.clock();
        let mut checks = Vec::new();
        for group in &self.groups {
            if !group.matches_client(client, listener) {
                continue;
            }
            let in_group = |result: &'static str, kind: &'static str, detail: String| Check {
                group: Some(group.name.clone()),
                action: (result == "block").then(|| group.action.as_str()),
                ..Check::new(kind, result, detail)
            };
            if !group.applies(client, listener, &mut now) {
                checks.push(in_group(
                    "off",
                    source::GROUP,
                    format!(
                        "Group '{}' covers this device but is outside its schedule now",
                        group.name
                    ),
                ));
                continue;
            }
            let before = checks.len();
            if let Some(entry) = group.allow_match(qname) {
                checks.push(Check {
                    matched: Some(entry.clone()),
                    ..in_group(
                        "allow",
                        source::GROUP,
                        format!("Allowed by group '{}' (entry '{entry}')", group.name),
                    )
                });
            }
            if let Some(entry) = group.block_match(qname) {
                checks.push(Check {
                    matched: Some(entry.clone()),
                    ..in_group(
                        "block",
                        source::GROUP,
                        format!("Blocked by group '{}' (entry '{entry}')", group.name),
                    )
                });
            }
            for (service, domains) in &group.services {
                if domains.contains(qname) {
                    checks.push(Check {
                        matched: Some(service.to_string()),
                        ..in_group(
                            "block",
                            source::SERVICE,
                            format!("Part of {service}, blocked by group '{}'", group.name),
                        )
                    });
                }
            }
            for category in &group.security {
                let name = category.name;
                if category.detector.is_some() {
                    checks.push(in_group(
                        "none",
                        category_source(name),
                        format!(
                            "{name}: group '{}' checks the domain once it resolves",
                            group.name
                        ),
                    ));
                    continue;
                }
                match self.lists.feeds().get(category.id) {
                    None => checks.push(in_group(
                        "none",
                        category_source(name),
                        format!(
                            "{name}: its list has not been downloaded yet, so it blocks nothing"
                        ),
                    )),
                    Some(list) => {
                        if let Some(entry) = list.matching_entry(qname) {
                            checks.push(Check {
                                matched: Some(name.to_string()),
                                ..in_group(
                                    "block",
                                    category_source(name),
                                    format!(
                                        "{name} (entry '{entry}'), blocked by group '{}'",
                                        group.name
                                    ),
                                )
                            });
                        }
                    }
                }
            }
            if let Some(entry) = group.tlds.matching_entry(qname) {
                checks.push(Check {
                    matched: Some(entry.clone()),
                    ..in_group(
                        "block",
                        source::TLD,
                        format!(
                            "In the TLD '{}', blocked by group '{}'",
                            tld_of(&entry),
                            group.name
                        ),
                    )
                });
            }
            for (key, name) in &group.blocklists {
                if let Some(entry) = lists.get(key).and_then(|l| l.matching_entry(qname)) {
                    checks.push(Check {
                        matched: Some(name.clone()),
                        ..in_group(
                            "block",
                            source::GROUP_BLOCKLIST,
                            format!(
                                "On the blocklist '{name}' (entry '{entry}'), selected by group '{}'",
                                group.name
                            ),
                        )
                    });
                }
            }
            if checks.len() == before {
                checks.push(in_group(
                    "none",
                    source::GROUP,
                    format!(
                        "Group '{}' covers this device; nothing in it matches",
                        group.name
                    ),
                ));
            }
            // The first covering group decides; later groups do not apply.
            break;
        }
        checks
    }
}

/// The response filters the group deciding a query turns on: each names
/// that group, or is `None` when it does not ask for the filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseFilters<'a> {
    /// Block answers with local network addresses for public names.
    pub local_addresses: Option<&'a str>,
    /// Block answers with oversized payloads.
    pub payloads: Option<&'a str>,
    /// Block newly registered domains (judged by their registration date).
    pub newly_registered: Option<&'a str>,
    /// Block names on Google Safe Browsing's lists.
    pub safe_browsing: Option<&'a str>,
    /// Block answers that cloak a third-party tracker behind a CNAME.
    pub cname_trackers: Option<&'a str>,
}

/// The block source of the category named `name`: `privacy` for the
/// console's privacy categories (native tracking), `security` otherwise.
fn category_source(name: &str) -> &'static str {
    let privacy = crate::security::SECURITY_CATEGORIES
        .iter()
        .any(|c| c.name == name && c.section == crate::security::Section::Privacy);
    if privacy {
        source::PRIVACY
    } else {
        source::SECURITY
    }
}

/// The TLD a `*.tld` entry of a group's TLD list names.
fn tld_of(entry: &str) -> &str {
    entry.strip_prefix("*.").unwrap_or(entry)
}

/// The listener keyword (`dot`, `doh` or `doq`) a client-list entry names,
/// in the static lowercase form queries are tagged with.
pub fn listener_keyword(entry: &str) -> Option<&'static str> {
    let entry = entry.trim();
    LISTENER_KEYWORDS
        .into_iter()
        .find(|k| entry.eq_ignore_ascii_case(k))
}

/// Parse CIDR strings, logging and skipping any that are invalid.
fn parse_networks(cidrs: &[String], group: &str) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|c| match c.trim().parse::<IpNet>() {
            Ok(net) => Some(net),
            Err(_) => {
                // A bare IP is a valid /32 or /128 network.
                match c.trim().parse::<IpAddr>() {
                    Ok(ip) => Some(ip.into()),
                    Err(_) => {
                        warn!(group, cidr = %c, "skipping invalid client network");
                        None
                    }
                }
            }
        })
        .collect()
}

/// Build a [`RegexSet`] the way groups match: case-insensitively, since
/// query names are lowercased before they are matched (a pattern written
/// `Ads\.` would otherwise never match anything).
fn regex_set<I, S>(patterns: I) -> std::result::Result<RegexSet, regex::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .build()
}

/// Compile a list of regex patterns into a [`RegexSet`], dropping (with a
/// warning) any that do not compile on their own. Should the valid ones
/// together exceed the size limit, the set keeps as many as fit, in order,
/// rather than none: an empty set would silently turn every rule off.
fn compile_regex(patterns: &[String], group: &str) -> RegexSet {
    let valid: Vec<&str> = patterns
        .iter()
        .map(String::as_str)
        .filter(|p| match regex_set([p]) {
            Ok(_) => true,
            Err(e) => {
                warn!(group, pattern = %p, error = %e, "skipping invalid block/allow regex");
                false
            }
        })
        .collect();
    if let Ok(set) = regex_set(&valid) {
        return set;
    }
    // The longest prefix that fits (a prefix's size only grows with it).
    let (mut fits, mut too_big) = (0, valid.len());
    while too_big - fits > 1 {
        let mid = (fits + too_big) / 2;
        if regex_set(&valid[..mid]).is_ok() {
            fits = mid;
        } else {
            too_big = mid;
        }
    }
    warn!(
        group,
        dropped = valid.len() - fits,
        "regex patterns exceed the size limit together; skipping the last ones"
    );
    regex_set(&valid[..fits]).unwrap_or_else(|_| RegexSet::empty())
}

/// Validate a single regex pattern, returning the compile error as a string.
fn validate_regex(pattern: &str) -> std::result::Result<(), String> {
    regex_set([pattern]).map(|_| ()).map_err(|e| e.to_string())
}

/// Validate a group's patterns of one kind (allow or block) together:
/// each must compile, and they must fit in one set, as the group matches
/// them. Returns the first error as a string.
pub fn validate_regexes(patterns: &[String]) -> std::result::Result<(), String> {
    for pattern in patterns {
        validate_regex(pattern).map_err(|e| format!("invalid regex '{pattern}': {e}"))?;
    }
    regex_set(patterns).map(|_| ()).map_err(|e| {
        format!("the patterns are too large to match together; use fewer or simpler ones ({e})")
    })
}

/// Map a stored [`BlockResponse`] to the engine [`Action`] the dispatcher
/// already knows how to serve.
fn response_to_action(response: &BlockResponse) -> Action {
    match response {
        BlockResponse::NxDomain => Action::Block,
        BlockResponse::Refused => Action::Refused,
        BlockResponse::NoData => Action::NoData,
        BlockResponse::Redirect(ip) => Action::Redirect(*ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> BlockingGroup {
        BlockingGroup {
            id: name.to_string(),
            name: name.to_string(),
            enabled: true,
            clients: vec![],
            allow: vec![],
            block: vec![],
            allow_regex: vec![],
            block_regex: vec![],
            blocklists: vec![],
            response: BlockResponse::NxDomain,
            ai_mode: None,
            safe_search: false,
            youtube_restricted: false,
            schedule: vec![],
            blocked_services: vec![],
            blocked_categories: vec![],
            blocked_security: vec![],
            blocked_tlds: vec![],
            block_local_addresses: false,
            limit_payloads: false,
            position: 0,
            last_modified_at: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The first enabled group a client belongs to can override the global
    /// enforcement mode; listener groups match by listener, and clients in no
    /// group follow the global mode.
    #[test]
    fn first_matching_group_decides_ai_mode() {
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        let mut public = group("public dot");
        public.clients = vec!["DoT".to_string()];
        public.ai_mode = Some(AiMode::Train);
        let mut everyone = group("everyone");
        everyone.ai_mode = Some(AiMode::Train);
        let ab = AdvancedBlocking::build(&[kids, public], Arc::default());
        // Kids inherits whatever the global mode is.
        assert_eq!(
            ab.ai_mode(ip("192.168.50.7"), None, AiMode::Enforce),
            (AiMode::Enforce, Some("kids"))
        );
        assert_eq!(
            ab.ai_mode(ip("192.168.50.7"), None, AiMode::Train),
            (AiMode::Train, Some("kids"))
        );
        assert_eq!(
            ab.ai_mode(ip("203.0.113.9"), Some("dot"), AiMode::Enforce),
            (AiMode::Train, Some("public dot"))
        );
        assert_eq!(
            ab.ai_mode(ip("203.0.113.9"), None, AiMode::Enforce),
            (AiMode::Enforce, None)
        );

        // Enforce for one group while the server records only, and the
        // catch-all group at the bottom records only for everyone else.
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        kids.ai_mode = Some(AiMode::Enforce);
        let ab = AdvancedBlocking::build(&[kids, everyone], Arc::default());
        assert_eq!(
            ab.ai_mode(ip("192.168.50.7"), None, AiMode::Train).0,
            AiMode::Enforce
        );
        assert_eq!(
            ab.ai_mode(ip("10.0.0.2"), None, AiMode::Train),
            (AiMode::Train, Some("everyone"))
        );
    }

    #[test]
    fn first_matching_group_decides_safe_search() {
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        kids.safe_search = true;
        kids.youtube_restricted = true;
        let mut everyone = group("everyone");
        everyone.safe_search = true;
        let ab = AdvancedBlocking::build(&[kids, everyone], Arc::default());
        assert_eq!(
            ab.safe_search(ip("192.168.50.7"), None),
            (true, true, Some("kids"))
        );
        assert_eq!(
            ab.safe_search(ip("10.0.0.2"), None),
            (true, false, Some("everyone"))
        );
        assert_eq!(
            AdvancedBlocking::default().safe_search(ip("10.0.0.2"), None),
            (false, false, None)
        );
    }

    /// Outside its schedule a group is skipped entirely: it neither blocks
    /// nor decides AI blocking or Safe Search.
    #[test]
    fn scheduled_group_applies_only_inside_its_windows() {
        let mut kids = group("kids");
        kids.block = vec!["games.test".to_string()];
        kids.safe_search = true;
        kids.ai_mode = Some(AiMode::Train);
        kids.schedule = vec![daygle_dns_core::schedule::ScheduleWindow {
            days: vec!["mon".to_string(), "tue".to_string()],
            start: "21:00".to_string(),
            end: "07:00".to_string(),
        }];
        let groups = [kids];
        let at = |day, minute| {
            AdvancedBlocking::build(&groups, Arc::default()).at_time(WeekTime { day, minute })
        };
        // Monday 22:00 and Tuesday 06:00: inside.
        for ab in [at(0, 22 * 60), at(1, 6 * 60)] {
            assert!(ab.evaluate(ip("1.2.3.4"), "games.test", None).is_some());
            assert!(ab.safe_search(ip("1.2.3.4"), None).0);
            assert_eq!(
                ab.ai_mode(ip("1.2.3.4"), None, AiMode::Enforce).0,
                AiMode::Train
            );
            assert!(ab.scheduled_off(ip("1.2.3.4"), None).is_empty());
        }
        // Monday noon and Thursday 06:00: outside.
        for ab in [at(0, 12 * 60), at(3, 6 * 60)] {
            assert!(ab.evaluate(ip("1.2.3.4"), "games.test", None).is_none());
            assert_eq!(ab.safe_search(ip("1.2.3.4"), None), (false, false, None));
            assert_eq!(
                ab.ai_mode(ip("1.2.3.4"), None, AiMode::Enforce),
                (AiMode::Enforce, None)
            );
            assert_eq!(ab.scheduled_off(ip("1.2.3.4"), None), vec!["kids"]);
        }
    }

    #[test]
    fn blocked_services_block_their_domains_and_subdomains() {
        let mut kids = group("kids");
        kids.blocked_services = vec!["tiktok".to_string(), "unknown".to_string()];
        kids.allow = vec!["ok.tiktok.com".to_string()];
        let ab = AdvancedBlocking::build(&[kids], Arc::default());
        let d = ab.evaluate(ip("1.2.3.4"), "tiktok.com", None).unwrap();
        assert!(d.reason.contains("TikTok"), "{}", d.reason);
        assert!(ab
            .evaluate(ip("1.2.3.4"), "v16.tiktokcdn.com", None)
            .is_some());
        // The group's allow list still wins.
        assert!(ab.evaluate(ip("1.2.3.4"), "ok.tiktok.com", None).is_none());
        assert!(ab.evaluate(ip("1.2.3.4"), "example.com", None).is_none());
    }

    #[test]
    fn security_categories_and_tlds_block_with_their_own_source() {
        let mut g = group("secure");
        g.blocked_security = vec![
            "dynamic_dns".to_string(),
            "native_apple".to_string(),
            "unknown".to_string(),
            "dga_domains".to_string(),
        ];
        g.blocked_tlds = vec![".ZIP".to_string(), "not.valid".to_string()];
        g.allow = vec!["home.duckdns.org".to_string()];
        let lists = Arc::new(GroupBlocklists::default());
        let ab = AdvancedBlocking::build(&[g], Arc::clone(&lists));
        assert_eq!(ab.feed_categories(), vec!["dynamic_dns", "native_apple"]);

        // Nothing is blocked by a list that has not been downloaded.
        assert!(ab
            .evaluate(ip("1.2.3.4"), "phish.duckdns.org", None)
            .is_none());
        let checks = ab.explain(ip("1.2.3.4"), "phish.duckdns.org", None);
        assert!(
            checks
                .iter()
                .any(|c| c.detail.contains("not been downloaded")),
            "{checks:?}"
        );

        lists.feeds().set(
            "dynamic_dns",
            Blocklist::from_lines(["duckdns.org", "*.duckdns.org"]),
        );
        lists.feeds().set(
            "native_apple",
            Blocklist::from_lines(["metrics.icloud.com"]),
        );
        let d = ab
            .evaluate(ip("1.2.3.4"), "phish.duckdns.org", None)
            .unwrap();
        assert!(d.reason.contains("Dynamic DNS"), "{}", d.reason);
        assert_eq!(d.source, source::SECURITY);
        let d = ab
            .evaluate(ip("1.2.3.4"), "metrics.icloud.com", None)
            .unwrap();
        assert_eq!(d.source, source::PRIVACY);
        // The group's allow list still wins.
        assert!(ab
            .evaluate(ip("1.2.3.4"), "home.duckdns.org", None)
            .is_none());

        let d = ab.evaluate(ip("1.2.3.4"), "update.zip", None).unwrap();
        assert_eq!(d.source, source::TLD);
        assert_eq!(d.matched.as_deref(), Some("*.zip"));
        assert!(ab.evaluate(ip("1.2.3.4"), "example.com", None).is_none());

        let checks = ab.explain(ip("1.2.3.4"), "a.b.zip", None);
        assert!(checks
            .iter()
            .any(|c| c.source == source::TLD && c.result == "block"));
    }

    #[test]
    fn response_filters_follow_group_order_and_allow_rules() {
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        kids.allow = vec!["plex.direct".to_string(), "*.plex.direct".to_string()];
        kids.limit_payloads = true;
        let mut everyone = group("everyone");
        everyone.block_local_addresses = true;
        everyone.limit_payloads = true;
        let ab = AdvancedBlocking::build(&[kids, everyone], Arc::default());
        let filters = ab.response_filters(ip("192.168.50.7"), "example.com", None);
        assert_eq!(filters.payloads, Some("kids"));
        // Only the first covering group decides: "everyone" is not consulted.
        assert_eq!(filters.local_addresses, None);
        // An allowed name stops later groups too.
        assert_eq!(
            ab.response_filters(ip("192.168.50.7"), "x.plex.direct", None),
            ResponseFilters::default()
        );
        assert_eq!(
            ab.response_filters(ip("10.0.0.1"), "x.plex.direct", None)
                .local_addresses,
            Some("everyone")
        );
    }

    /// A device in its own group above its LAN's group follows its own group
    /// only: the LAN group's blocks do not reach it.
    #[test]
    fn a_device_above_its_lan_group_is_not_blocked_by_the_lan_group() {
        let mut device = group("renee");
        device.clients = vec!["192.168.20.190/32".to_string()];
        device.block = vec!["social.example".to_string()];
        let mut lan = group("lan");
        lan.clients = vec!["192.168.20.0/24".to_string()];
        lan.block = vec!["ads.example".to_string()];
        let ab = AdvancedBlocking::build(&[device, lan], Arc::default());

        let renee = ip("192.168.20.190");
        assert!(ab.evaluate(renee, "ads.example", None).is_none());
        assert_eq!(
            ab.evaluate(renee, "social.example", None)
                .and_then(|d| d.group),
            Some("renee".to_string())
        );
        // Explain shows only the deciding group.
        let checks = ab.explain(renee, "ads.example", None);
        assert!(checks
            .iter()
            .all(|c| c.group.as_deref() == Some("renee") && c.result != "block"));

        // Everyone else on the LAN still gets the LAN group's blocks.
        let other = ip("192.168.20.10");
        assert_eq!(
            ab.evaluate(other, "ads.example", None)
                .and_then(|d| d.group),
            Some("lan".to_string())
        );
        assert!(ab.evaluate(other, "social.example", None).is_none());
    }

    #[test]
    fn blocks_listed_domain() {
        let mut g = group("ads");
        g.block = vec!["*.doubleclick.net".to_string(), "tracker.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "a.doubleclick.net", None)
                .map(|d| d.action),
            Some(Action::Block)
        );
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "tracker.test", None)
                .map(|d| d.action),
            Some(Action::Block)
        );
        assert!(ab.evaluate(ip("1.2.3.4"), "example.org", None).is_none());
    }

    #[test]
    fn allow_overrides_block() {
        let mut g = group("ads");
        g.block = vec!["*.doubleclick.net".to_string()];
        g.allow = vec!["safe.doubleclick.net".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        assert!(ab
            .evaluate(ip("1.2.3.4"), "safe.doubleclick.net", None)
            .is_none());
        assert!(ab
            .evaluate(ip("1.2.3.4"), "x.doubleclick.net", None)
            .is_some());
    }

    #[test]
    fn regex_block_and_allow() {
        let mut g = group("re");
        g.block_regex = vec![r"^ad[0-9]+\.".to_string()];
        g.allow_regex = vec![r"^ad1\.good\.".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        assert!(ab
            .evaluate(ip("1.2.3.4"), "ad7.tracker.test", None)
            .is_some());
        assert!(ab.evaluate(ip("1.2.3.4"), "ad1.good.test", None).is_none());
        assert!(ab.evaluate(ip("1.2.3.4"), "cdn.test", None).is_none());
    }

    #[test]
    fn group_scoped_to_client_network() {
        let mut g = group("kids");
        g.clients = vec!["192.168.1.0/24".to_string()];
        g.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        // In-network client is blocked...
        assert!(ab
            .evaluate(ip("192.168.1.50"), "games.test", None)
            .is_some());
        // ...an outside client is not.
        assert!(ab.evaluate(ip("10.0.0.1"), "games.test", None).is_none());
    }

    #[tokio::test]
    async fn account_entries_scope_the_group_to_those_accounts() {
        use crate::identity::{scope, Identity};
        let mut g = group("kids");
        g.clients = vec!["Account: Kid Tablet".to_string()];
        g.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        let as_account = |name: &str| Identity::Account(Arc::from(name));
        // The account matches wherever it connects from (case-insensitive).
        let hit = scope(as_account("kid tablet"), async {
            ab.evaluate(ip("203.0.113.7"), "games.test", Some("dot"))
        })
        .await;
        assert!(hit.is_some());
        // Another account, an unknown ID and no account are not matched: an
        // account-only group is not an "every client" group.
        for identity in [
            as_account("Laptop"),
            Identity::Unknown(Arc::from("kid tablet")),
            Identity::Anonymous,
        ] {
            let miss = scope(identity, async {
                ab.evaluate(ip("203.0.113.7"), "games.test", Some("dot"))
            })
            .await;
            assert!(miss.is_none());
        }
        // Non-ASCII names match ignoring case too.
        let mut g = group("unicode");
        g.clients = vec!["account:ÄRGER".to_string()];
        g.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        let hit = scope(as_account("ärger"), async {
            ab.evaluate(ip("203.0.113.7"), "games.test", None)
        })
        .await;
        assert!(hit.is_some());
        assert_eq!(account_entry(" ACCOUNT:Kid "), Some("Kid"));
        assert_eq!(account_entry("account:"), None);
        assert_eq!(account_entry("192.168.1.0/24"), None);
    }

    /// `DoT` in a group's client list matches external DoT users only;
    /// plain-DNS and other-listener clients are untouched, and a group
    /// already network-scoped only also matches on the listed listener.
    #[test]
    fn dot_listener_keyword_scopes_the_group_to_encrypted_clients() {
        let mut g = group("public");
        g.clients = vec!["DOT".to_string()];
        g.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        // On the DoT listener: blocked regardless of the (public) address.
        assert!(ab
            .evaluate(ip("203.0.113.7"), "games.test", Some("dot"))
            .is_some());
        // Plain DNS fires never, even from the same address.
        assert!(ab.evaluate(ip("203.0.113.7"), "games.test", None).is_none());
        // Unlisted listeners are not matched either.
        assert!(ab
            .evaluate(ip("203.0.113.7"), "games.test", Some("doh"))
            .is_none());

        // Keyword is case-insensitive, and can be mixed with networks:
        // either match makes the group apply.
        let mut both = group("mixed");
        both.clients = vec!["doq".to_string(), "192.168.1.0/24".to_string()];
        both.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[both], Arc::default());
        assert!(ab
            .evaluate(ip("198.51.100.9"), "games.test", Some("doq"))
            .is_some());
        assert!(ab
            .evaluate(ip("192.168.1.50"), "games.test", None)
            .is_some());
        assert!(ab
            .evaluate(ip("198.51.100.9"), "games.test", None)
            .is_none());
    }

    #[test]
    fn response_type_maps_to_action() {
        let mut g = group("redir");
        g.block = vec!["blocked.test".to_string()];
        g.response = BlockResponse::Redirect(ip("0.0.0.0"));
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        assert_eq!(
            ab.evaluate(ip("1.2.3.4"), "blocked.test", None)
                .map(|d| d.action),
            Some(Action::Redirect(ip("0.0.0.0")))
        );
    }

    #[test]
    fn disabled_group_is_skipped() {
        let mut g = group("off");
        g.enabled = false;
        g.block = vec!["blocked.test".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        assert!(ab.is_empty());
        assert!(ab.evaluate(ip("1.2.3.4"), "blocked.test", None).is_none());
    }

    #[test]
    fn invalid_regex_is_skipped_not_fatal() {
        let mut g = group("re");
        g.block_regex = vec!["(unclosed".to_string(), r"^bad\.".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        // The valid pattern still blocks; the invalid one is dropped.
        assert!(ab.evaluate(ip("1.2.3.4"), "bad.test", None).is_some());
    }

    #[test]
    fn group_blocks_with_its_selected_lists_only() {
        let lists = Arc::new(GroupBlocklists::default());
        let mut lan = group("lan");
        lan.clients = vec!["10.0.0.0/8".to_string()];
        lan.allow = vec!["ok.ads.test".to_string()];
        lan.blocklists = vec!["Big".to_string()];
        let ab = AdvancedBlocking::build(&[lan], lists.clone());
        // Not fetched yet: nothing to block with.
        assert!(ab.evaluate(ip("10.1.1.1"), "x.ads.test", None).is_none());

        let mut published = std::collections::HashMap::new();
        published.insert(
            "big".to_string(),
            Arc::new(Blocklist::from_lines(["ads.test", "*.ads.test"])),
        );
        lists.set(published);
        // The refreshed list applies without rebuilding the groups.
        let d = ab
            .evaluate(ip("10.1.1.1"), "x.ads.test", None)
            .expect("blocked");
        assert_eq!(d.group.as_deref(), Some("lan"));
        assert!(d.reason.contains("blocklist 'Big'"), "{}", d.reason);
        // The group's allow list overrides its blocklists.
        assert!(ab.evaluate(ip("10.1.1.1"), "ok.ads.test", None).is_none());
        // Clients outside the group are untouched.
        assert!(ab.evaluate(ip("192.168.1.1"), "x.ads.test", None).is_none());
    }

    /// A group whose client entries are all unusable (a network name that
    /// is no longer configured) covers no one: it used to compile to an
    /// empty client list and so cover every client.
    #[test]
    fn a_group_with_only_unusable_clients_covers_no_one() {
        let mut stale = group("stale");
        stale.clients = vec!["Removed Network".to_string()];
        stale.block = vec!["games.test".to_string()];
        stale.safe_search = true;
        let mut everyone = group("everyone");
        everyone.allow = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[stale.clone()], Arc::default());
        assert!(ab.evaluate(ip("10.0.0.1"), "games.test", None).is_none());
        assert_eq!(ab.safe_search(ip("10.0.0.1"), None), (false, false, None));
        // The next group decides instead.
        let ab = AdvancedBlocking::build(&[stale, everyone], Arc::default());
        assert_eq!(ab.safe_search(ip("10.0.0.1"), None).2, Some("everyone"));
        // An empty (or blank) list still means every client.
        let mut all = group("all");
        all.clients = vec!["  ".to_string()];
        all.block = vec!["games.test".to_string()];
        let ab = AdvancedBlocking::build(&[all], Arc::default());
        assert!(ab.evaluate(ip("10.0.0.1"), "games.test", None).is_some());
    }

    /// Patterns match ignoring case, as query names arrive lowercased.
    #[test]
    fn regex_patterns_ignore_case() {
        let mut g = group("g");
        g.block_regex = vec![r"^Ads\d+\.".to_string()];
        let ab = AdvancedBlocking::build(&[g], Arc::default());
        let d = ab.evaluate(ip("10.0.0.1"), "ads12.example.com", None);
        assert_eq!(d.and_then(|d| d.matched), Some(r"/^Ads\d+\./".to_string()));
    }

    /// Patterns that compile alone but not together keep the ones that
    /// fit, instead of the whole set silently becoming empty.
    #[test]
    fn oversized_regex_sets_keep_what_fits() {
        // Each pattern is large on its own (Unicode classes, repeated).
        let big = |i: usize| format!(r"^p{i}\w{{40}}\w{{40}}\w{{40}}$");
        let mut count = 1;
        while regex_set((0..count).map(big)).is_ok() {
            count *= 2;
            assert!(count < 4096, "the size limit was never reached");
        }
        let patterns: Vec<String> = (0..count).map(big).collect();
        assert!(patterns.iter().all(|p| validate_regex(p).is_ok()));
        assert!(validate_regexes(&patterns)
            .unwrap_err()
            .contains("too large"));
        let set = compile_regex(&patterns, "g");
        assert!(!set.is_empty() && set.len() < patterns.len());
        assert!(set.is_match(&format!("p0{}", "a".repeat(120))));
    }

    #[test]
    fn response_filters_come_from_the_deciding_group_only() {
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        kids.limit_payloads = true;
        kids.allow = vec!["ok.test".to_string()];
        let mut everyone = group("everyone");
        everyone.block_local_addresses = true;
        everyone.limit_payloads = true;
        let ab = AdvancedBlocking::build(&[kids, everyone], Arc::default());
        assert_eq!(
            ab.response_filters(ip("192.168.50.7"), "x.test", None),
            ResponseFilters {
                payloads: Some("kids"),
                ..ResponseFilters::default()
            }
        );
        // Allowed by the deciding group: no filter applies.
        assert_eq!(
            ab.response_filters(ip("192.168.50.7"), "ok.test", None),
            ResponseFilters::default()
        );
        assert_eq!(
            ab.response_filters(ip("10.0.0.1"), "x.test", None),
            ResponseFilters {
                local_addresses: Some("everyone"),
                payloads: Some("everyone"),
                ..ResponseFilters::default()
            }
        );
    }
}
