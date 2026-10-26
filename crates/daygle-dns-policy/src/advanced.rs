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
use regex::RegexSet;
use tracing::warn;

use daygle_dns_core::blocking::{BlockResponse, BlockingGroup};
use daygle_dns_core::config::normalize_domains;
use daygle_dns_core::schedule::{self, CompiledWindow, WeekTime};

use crate::{Action, Blocklist, Decision, GroupBlocklists};

/// Client-list keywords that match by listener instead of by address.
/// Case-insensitive; a group's client list may mix them with networks
/// (e.g. `DOT` alongside `192.168.1.0/24`). This is how a group targets
/// public/remote encrypted-DNS users, whose addresses cannot be expressed
/// as networks ("everything except my private ranges" is not a CIDR set).
pub const LISTENER_KEYWORDS: [&str; 3] = ["dot", "doh", "doq"];

/// Whether `entry` names an encrypted listener in a client list.
pub fn is_listener_keyword(entry: &str) -> bool {
    LISTENER_KEYWORDS.contains(&entry.trim().to_ascii_lowercase().as_str())
}

/// A single blocking group compiled for evaluation.
struct CompiledGroup {
    name: String,
    /// Client networks this group applies to; empty combined with
    /// [`Self::listeners`] being empty means every client.
    clients: Vec<IpNet>,
    /// Encrypted listeners (lowercased `dot`/`doh`/`doq`) this group applies
    /// to, from the special client-list entries; empty means no listener
    /// matches.
    listeners: Vec<&'static str>,
    allow: Blocklist,
    block: Blocklist,
    allow_regex: RegexSet,
    block_regex: RegexSet,
    /// The group-scoped sources this group blocks with: (lower-cased lookup
    /// key, name as written).
    blocklists: Vec<(String, String)>,
    /// Response returned when this group blocks a query.
    action: Action,
    /// Whether the AI scanner may auto-block this group's clients.
    ai_blocking: bool,
    /// Whether this group's clients get forced Safe Search.
    safe_search: bool,
    /// Whether this group's clients get YouTube Restricted Mode.
    youtube_restricted: bool,
    /// When the group applies; empty means always.
    schedule: Vec<CompiledWindow>,
    /// Blocked services: (display name, their domains and subdomains).
    services: Vec<(&'static str, Blocklist)>,
}

impl CompiledGroup {
    /// Whether a query from `client` on encrypted listener `listener`
    /// (`Some("dot"/"doh"/"doq") when the query arrived over one of them,
    /// `None` for plain DNS) matches the group: it does when the group has
    /// no client customers at all (every client), when a listed network
    /// contains the address, or when the query arrived over a listed
    /// listener.
    fn matches_client(&self, client: IpAddr, listener: Option<&str>) -> bool {
        if self.clients.is_empty() && self.listeners.is_empty() {
            return true;
        }
        self.clients.iter().any(|net| net.contains(&client))
            || matches!(listener, Some(l) if self.listeners.contains(&l))
    }

    /// Whether the group covers this query now: the client matches and the
    /// group's schedule (if any) is active. `now` is read once per query,
    /// and only when a group has a schedule.
    fn applies(&self, client: IpAddr, listener: Option<&str>, now: &mut Clock) -> bool {
        self.matches_client(client, listener)
            && (self.schedule.is_empty() || schedule::active(&self.schedule, now.get()))
    }

    fn allows(&self, qname: &str) -> bool {
        self.allow.contains(qname) || self.allow_regex.is_match(qname)
    }

    fn blocks(&self, qname: &str) -> bool {
        self.block.contains(qname) || self.block_regex.is_match(qname)
    }
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
            let (networks, listener_entries): (Vec<String>, Vec<String>) = g
                .clients
                .iter()
                .cloned()
                .partition(|c| !is_listener_keyword(c));
            let listeners = networkless_listeners(&listener_entries, &g.name);
            let clients = parse_networks(&networks, &g.name);
            compiled.push(CompiledGroup {
                listeners,
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
                ai_blocking: g.ai_blocking,
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

    /// Whether the AI scanner may auto-block a query from `client` on
    /// `listener`: the first enabled group the client belongs to decides,
    /// and clients in no group are covered. Returns the deciding group's
    /// name with the answer (`None` when no group matched).
    pub fn ai_blocking(&self, client: IpAddr, listener: Option<&str>) -> (bool, Option<&str>) {
        self.first_group(client, listener)
            .map_or((true, None), |g| (g.ai_blocking, Some(g.name.as_str())))
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

    /// Evaluate `qname` (already normalized: lowercase, no trailing dot) for
    /// `client`. Returns `Some(Decision)` when a group blocks the query, or
    /// `None` when it is explicitly allowed or matched by no group.
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
            // Whitelist wins: an allowed name is never blocked, and no later
            // group gets to block it either.
            if group.allows(qname) {
                return None;
            }
            let service = group
                .services
                .iter()
                .find(|(_, domains)| domains.contains(qname))
                .map(|(name, _)| *name);
            let reason = if group.blocks(qname) {
                Some(format!("'{qname}' blocked by group '{}'", group.name))
            } else if let Some(service) = service {
                Some(format!(
                    "'{qname}' blocked as part of {service} by group '{}'",
                    group.name
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
                        format!(
                            "'{qname}' blocked by blocklist '{name}' in group '{}'",
                            group.name
                        )
                    })
            };
            if let Some(reason) = reason {
                return Some(
                    Decision::new(reason, group.action.clone()).with_group(group.name.clone()),
                );
            }
        }
        None
    }
}

/// Lowercase listener entries, dropping anything unexpected (already
/// filtered at build time, so this never logs in practice).
fn networkless_listeners(entries: &[String], group: &str) -> Vec<&'static str> {
    entries
        .iter()
        .filter_map(|e| {
            let lowered = e.trim().to_ascii_lowercase();
            let found = LISTENER_KEYWORDS
                .into_iter()
                .find(|k| lowered.eq_ignore_ascii_case(k));
            if found.is_none() {
                warn!(group, entry = %e, "skipping unknown listener name");
            }
            found
        })
        .collect()
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

/// Compile a list of regex patterns into a [`RegexSet`], dropping (with a
/// warning) any that do not compile.
fn compile_regex(patterns: &[String], group: &str) -> RegexSet {
    let valid: Vec<&String> = patterns
        .iter()
        .filter(|p| match regex::Regex::new(p) {
            Ok(_) => true,
            Err(e) => {
                warn!(group, pattern = %p, error = %e, "skipping invalid block/allow regex");
                false
            }
        })
        .collect();
    RegexSet::new(valid).unwrap_or_else(|_| RegexSet::empty())
}

/// Validate a single regex pattern, returning the compile error as a string.
/// Used by the API to reject a bad pattern up front instead of silently
/// dropping it at build time.
pub fn validate_regex(pattern: &str) -> std::result::Result<(), String> {
    regex::Regex::new(pattern)
        .map(|_| ())
        .map_err(|e| e.to_string())
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
            ai_blocking: true,
            safe_search: false,
            youtube_restricted: false,
            schedule: vec![],
            blocked_services: vec![],
            position: 0,
            last_modified_at: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The first enabled group a client belongs to decides whether the AI
    /// may block its queries; listener groups match by listener, and
    /// clients in no group stay covered.
    #[test]
    fn first_matching_group_decides_ai_blocking() {
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        let mut public = group("public dot");
        public.clients = vec!["DoT".to_string()];
        public.ai_blocking = false;
        let mut everyone = group("everyone");
        everyone.ai_blocking = false;
        let ab = AdvancedBlocking::build(&[kids, public], Arc::default());
        assert_eq!(
            ab.ai_blocking(ip("192.168.50.7"), None),
            (true, Some("kids"))
        );
        assert_eq!(
            ab.ai_blocking(ip("203.0.113.9"), Some("dot")),
            (false, Some("public dot"))
        );
        assert_eq!(ab.ai_blocking(ip("203.0.113.9"), None), (true, None));

        // A catch-all group with AI off, last: only the groups before it
        // keep AI blocking.
        let mut kids = group("kids");
        kids.clients = vec!["192.168.50.0/24".to_string()];
        let ab = AdvancedBlocking::build(&[kids, everyone], Arc::default());
        assert!(ab.ai_blocking(ip("192.168.50.7"), None).0);
        assert_eq!(
            ab.ai_blocking(ip("10.0.0.2"), None),
            (false, Some("everyone"))
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
        kids.ai_blocking = false;
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
            assert!(!ab.ai_blocking(ip("1.2.3.4"), None).0);
            assert!(ab.scheduled_off(ip("1.2.3.4"), None).is_empty());
        }
        // Monday noon and Thursday 06:00: outside.
        for ab in [at(0, 12 * 60), at(3, 6 * 60)] {
            assert!(ab.evaluate(ip("1.2.3.4"), "games.test", None).is_none());
            assert_eq!(ab.safe_search(ip("1.2.3.4"), None), (false, false, None));
            assert_eq!(ab.ai_blocking(ip("1.2.3.4"), None), (true, None));
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
}
