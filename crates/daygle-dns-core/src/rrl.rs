//! Response rate limiting (RRL), after BIND and Knot.
//!
//! A reflection attack sends queries with a victim's address as the source,
//! so the answers (often much larger than the queries) flood the victim.
//! Such a flood asks the same question over and over, so RRL counts
//! *identical responses* to each client network: the same answer, the same
//! NXDOMAIN parent domain, or any error. Each such account earns
//! `rate` credits per second up to `rate`, and each response spends one.
//! An account in debt is limited: its response is dropped, except every
//! `slip`-th one, which is sent truncated (TC) so a real client (whose
//! address was not spoofed) retries over TCP and gets its answer.
//!
//! Debt is capped at `window` seconds of the rate, so a flood that stops
//! is forgiven after at most `window` seconds.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use parking_lot::Mutex;

use crate::config::RrlSettings;

/// Most accounts tracked at once. Past this, new accounts are not tracked
/// (fail open), so a flood of unique keys cannot exhaust memory.
const MAX_ACCOUNTS: usize = 200_000;
/// How often idle accounts are swept.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// What a response is, for counting identical responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseClass {
    /// A positive or empty (NODATA) answer: keyed by name and type.
    Answer,
    /// NXDOMAIN: keyed by the parent of the name.
    NxDomain,
    /// Any error code: one account per network.
    Error,
}

/// What to do with a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Send,
    /// Send it truncated (TC set, no records).
    Slip,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    network: IpAddr,
    class: ResponseClass,
    name: String,
}

#[derive(Debug)]
struct Account {
    balance: f64,
    last: Instant,
    /// Limited responses so far, for picking every `slip`-th.
    limited: u32,
}

#[derive(Debug)]
struct Inner {
    settings: RrlSettings,
    exempt: Vec<IpNet>,
    accounts: HashMap<Key, Account>,
    last_sweep: Instant,
}

/// The response rate limiter; cheap to consult when disabled.
#[derive(Debug)]
pub struct ResponseRateLimiter {
    enabled: AtomicBool,
    inner: Mutex<Inner>,
}

impl Default for ResponseRateLimiter {
    fn default() -> Self {
        Self::new(&RrlSettings::default(), Vec::new())
    }
}

impl ResponseRateLimiter {
    /// A limiter with `settings`; `exempt` is `settings.exempt` resolved to
    /// networks.
    pub fn new(settings: &RrlSettings, exempt: Vec<IpNet>) -> Self {
        Self {
            enabled: AtomicBool::new(settings.enabled),
            inner: Mutex::new(Inner {
                settings: settings.clone(),
                exempt,
                accounts: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Apply new settings. Accounts are kept unless the network size
    /// changed (their keys would no longer match).
    pub fn set_settings(&self, settings: &RrlSettings, exempt: Vec<IpNet>) {
        let mut inner = self.inner.lock();
        if inner.settings.ipv4_prefix != settings.ipv4_prefix
            || inner.settings.ipv6_prefix != settings.ipv6_prefix
            || !settings.enabled
        {
            inner.accounts.clear();
        }
        inner.settings = settings.clone();
        inner.exempt = exempt;
        self.enabled.store(settings.enabled, Ordering::Relaxed);
    }

    /// Whether responses are being counted at all.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Whether limited responses are only counted, not limited.
    pub fn log_only(&self) -> bool {
        self.inner.lock().settings.log_only
    }

    /// Account for one response to `client`. `name` is the query name and
    /// type for an answer (`www.example.com/A`), or the query name for
    /// NXDOMAIN (its parent is used), and is ignored for errors.
    pub fn check(&self, client: IpAddr, class: ResponseClass, name: &str) -> Verdict {
        self.check_at(client, class, name, Instant::now())
    }

    fn check_at(&self, client: IpAddr, class: ResponseClass, name: &str, now: Instant) -> Verdict {
        if !self.enabled() {
            return Verdict::Send;
        }
        let mut inner = self.inner.lock();
        let settings = &inner.settings;
        let rate = match class {
            ResponseClass::Answer => settings.responses_per_second,
            ResponseClass::NxDomain => settings.nxdomains_per_second,
            ResponseClass::Error => settings.errors_per_second,
        };
        if rate == 0 || inner.exempt.iter().any(|net| net.contains(&client)) {
            return Verdict::Send;
        }
        let rate = f64::from(rate);
        let window = f64::from(settings.window_secs);
        let slip = settings.slip;
        let key = Key {
            network: network_of(client, settings.ipv4_prefix, settings.ipv6_prefix),
            class,
            name: match class {
                ResponseClass::Answer => name.to_ascii_lowercase(),
                ResponseClass::NxDomain => parent(name).to_ascii_lowercase(),
                ResponseClass::Error => String::new(),
            },
        };

        if now.duration_since(inner.last_sweep) >= SWEEP_EVERY {
            inner.last_sweep = now;
            // An account idle for the whole window is back to full credit:
            // forgetting it changes nothing.
            let idle = Duration::from_secs(u64::from(inner.settings.window_secs) + 1);
            inner
                .accounts
                .retain(|_, a| now.duration_since(a.last) < idle);
        }
        let tracked = inner.accounts.len();
        let account = match inner.accounts.get_mut(&key) {
            Some(account) => account,
            None if tracked >= MAX_ACCOUNTS => return Verdict::Send,
            None => inner.accounts.entry(key).or_insert(Account {
                balance: rate,
                last: now,
                limited: 0,
            }),
        };
        let earned = now.duration_since(account.last).as_secs_f64() * rate;
        account.last = now;
        account.balance = (account.balance + earned).min(rate) - 1.0;
        account.balance = account.balance.max(-rate * window);
        if account.balance >= 0.0 {
            return Verdict::Send;
        }
        account.limited = account.limited.wrapping_add(1);
        if slip > 0 && account.limited % slip == 0 {
            Verdict::Slip
        } else {
            Verdict::Drop
        }
    }
}

/// The network `client` is counted in.
fn network_of(client: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match client {
        IpAddr::V4(a) => ipnet::Ipv4Net::new(a, v4.min(32))
            .map(|n| IpAddr::V4(n.network()))
            .unwrap_or(client),
        IpAddr::V6(a) => ipnet::Ipv6Net::new(a, v6.min(128))
            .map(|n| IpAddr::V6(n.network()))
            .unwrap_or(client),
    }
}

/// `name` without its first label (`a.b.example.com` -> `b.example.com`);
/// a single label stays as it is.
fn parent(name: &str) -> &str {
    let name = name.trim_end_matches('.');
    match name.split_once('.') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(rate: u32, slip: u32) -> ResponseRateLimiter {
        ResponseRateLimiter::new(
            &RrlSettings {
                enabled: true,
                responses_per_second: rate,
                nxdomains_per_second: rate,
                errors_per_second: rate,
                window_secs: 5,
                slip,
                exempt: vec![],
                ..RrlSettings::default()
            },
            vec!["10.9.0.0/16".parse().unwrap()],
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn identical_answers_are_limited_per_network() {
        let rrl = limiter(3, 0);
        let t = Instant::now();
        let check =
            |client: &str, name: &str| rrl.check_at(ip(client), ResponseClass::Answer, name, t);
        for _ in 0..3 {
            assert_eq!(check("192.0.2.1", "big.example/ANY"), Verdict::Send);
        }
        assert_eq!(check("192.0.2.1", "big.example/ANY"), Verdict::Drop);
        // Same /24: same account.
        assert_eq!(check("192.0.2.200", "big.example/ANY"), Verdict::Drop);
        // A different answer, or a different network, has its own.
        assert_eq!(check("192.0.2.1", "other.example/A"), Verdict::Send);
        assert_eq!(check("198.51.100.1", "big.example/ANY"), Verdict::Send);
        // Exempt networks are never limited.
        for _ in 0..10 {
            assert_eq!(check("10.9.1.1", "big.example/ANY"), Verdict::Send);
        }
    }

    #[test]
    fn credit_comes_back_over_time_and_debt_is_capped() {
        let rrl = limiter(2, 0);
        let t = Instant::now();
        let at = |secs: f64| {
            rrl.check_at(
                ip("192.0.2.1"),
                ResponseClass::Answer,
                "x.example/A",
                t + Duration::from_secs_f64(secs),
            )
        };
        assert_eq!(at(0.0), Verdict::Send);
        assert_eq!(at(0.0), Verdict::Send);
        assert_eq!(at(0.0), Verdict::Drop);
        // Half a second earns one response.
        assert_eq!(at(1.0), Verdict::Send);
        // A long flood runs up at most `window` seconds of debt...
        for _ in 0..1000 {
            at(1.0);
        }
        // ...so 4 s later it is still limited (10 credits owed, 8 earned)...
        assert_eq!(at(1.0 + 4.0), Verdict::Drop);
        // ...and 2 s after that the remaining debt is paid off.
        assert_eq!(at(1.0 + 6.1), Verdict::Send);
    }

    #[test]
    fn slip_sends_every_nth_limited_response_truncated() {
        let rrl = limiter(1, 2);
        let t = Instant::now();
        let check = || rrl.check_at(ip("192.0.2.1"), ResponseClass::Error, "", t);
        assert_eq!(check(), Verdict::Send);
        assert_eq!(check(), Verdict::Drop);
        assert_eq!(check(), Verdict::Slip);
        assert_eq!(check(), Verdict::Drop);
        assert_eq!(check(), Verdict::Slip);
    }

    #[test]
    fn nxdomain_floods_share_the_parent_domain() {
        let rrl = limiter(2, 0);
        let t = Instant::now();
        let check = |name: &str| rrl.check_at(ip("192.0.2.1"), ResponseClass::NxDomain, name, t);
        assert_eq!(check("a1.victim.example"), Verdict::Send);
        assert_eq!(check("b2.victim.example"), Verdict::Send);
        assert_eq!(check("c3.victim.example"), Verdict::Drop);
        assert_eq!(check("a1.other.example"), Verdict::Send);
    }

    #[test]
    fn disabled_or_unlimited_classes_always_send() {
        let rrl = ResponseRateLimiter::default();
        for _ in 0..100 {
            assert_eq!(
                rrl.check(ip("192.0.2.1"), ResponseClass::Answer, "a/A"),
                Verdict::Send
            );
        }
        let rrl = ResponseRateLimiter::new(
            &RrlSettings {
                enabled: true,
                errors_per_second: 0,
                ..RrlSettings::default()
            },
            vec![],
        );
        for _ in 0..100 {
            assert_eq!(
                rrl.check(ip("192.0.2.1"), ResponseClass::Error, ""),
                Verdict::Send
            );
        }
    }
}
