//! Who a query is from beyond its address: a DNS account.
//!
//! The encrypted listeners (DoT, DoQ, DoH) recognise an account from the
//! client ID a device puts in the host name it connects to
//! (`<client id>.<accounts.domain>`, read from the TLS SNI) or, for DoH, in
//! the URL path (`/dns-query/<client id>`). They answer each query inside
//! [`scope`], so everything that evaluates the query - the dispatcher,
//! filtering groups, the AI plugin, the query log - reads the account with
//! [`current`] without it being passed through every call.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::{ArcSwap, ArcSwapOption};

/// What a query's connection said about its account.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Identity {
    /// No client ID: plain DNS, recognition off, or a device that uses the
    /// bare server name.
    #[default]
    Anonymous,
    /// A known, enabled account (its name).
    Account(Arc<str>),
    /// A client ID that names no enabled account.
    Unknown(Arc<str>),
}

impl Identity {
    /// The account's name, for a recognised account.
    pub fn account(&self) -> Option<&str> {
        match self {
            Identity::Account(name) => Some(name),
            _ => None,
        }
    }
}

tokio::task_local! {
    static IDENTITY: Identity;
}

/// Run `f` (answering one query) as `identity`.
pub async fn scope<F: Future>(identity: Identity, f: F) -> F::Output {
    IDENTITY.scope(identity, f).await
}

/// The identity of the query being answered ([`Identity::Anonymous`]
/// outside [`scope`]).
pub fn current() -> Identity {
    IDENTITY
        .try_with(Identity::clone)
        .unwrap_or(Identity::Anonymous)
}

/// The recognised account of the query being answered, if any.
pub fn current_account() -> Option<Arc<str>> {
    IDENTITY
        .try_with(|identity| match identity {
            Identity::Account(name) => Some(name.clone()),
            _ => None,
        })
        .ok()
        .flatten()
}

/// The account domain and whether an account is required.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Settings {
    /// Lowercase, no trailing dot; empty when recognition is off.
    domain: String,
    require: bool,
}

/// [`Settings`] derived from one configuration, kept until the live
/// configuration is replaced. The `Weak` is only compared by address: it
/// keeps that allocation from being reused (so a new configuration can
/// never be mistaken for the cached one) without keeping it alive.
struct CachedSettings {
    config: Weak<daygle_dns_core::config::DaygleConfig>,
    settings: Settings,
}

/// The enabled accounts, replaced as a whole whenever one changes.
#[derive(Default)]
struct Accounts {
    /// Client ID -> name.
    by_client_id: HashMap<String, Arc<str>>,
    /// Name -> the minute it was last noted as seen. Atomics, so noting a
    /// sighting on the query path takes no lock.
    seen: HashMap<Arc<str>, AtomicI64>,
}

/// The accounts the listeners recognise, by client ID. The account list is
/// replaced whenever an account changes; the settings are read from the live
/// configuration when there is one (so a console save or config reload
/// applies at once), else from [`Self::set_settings`].
///
/// Every encrypted query consults it, so the query path neither allocates
/// for the settings (they are derived once per configuration) nor locks.
#[derive(Default)]
pub struct AccountDirectory {
    config: Option<Arc<ArcSwap<daygle_dns_core::config::DaygleConfig>>>,
    settings: ArcSwap<Settings>,
    cached: ArcSwapOption<CachedSettings>,
    accounts: ArcSwap<Accounts>,
}

impl AccountDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// A directory whose settings are the live configuration's `[accounts]`.
    pub fn with_config(config: Arc<ArcSwap<daygle_dns_core::config::DaygleConfig>>) -> Self {
        Self {
            config: Some(config),
            ..Self::default()
        }
    }

    /// Run `f` with the settings in force.
    fn with_settings<R>(&self, f: impl FnOnce(&Settings) -> R) -> R {
        let Some(config) = &self.config else {
            return f(&self.settings.load());
        };
        let current = config.load();
        if let Some(cached) = &*self.cached.load() {
            if std::ptr::eq(cached.config.as_ptr(), Arc::as_ptr(&current)) {
                return f(&cached.settings);
            }
        }
        // The configuration changed (or this is the first query): derive
        // the settings once for it.
        let fresh = CachedSettings {
            config: Arc::downgrade(&current),
            settings: Settings {
                domain: current.accounts.normalized_domain(),
                require: current.accounts.require,
            },
        };
        let result = f(&fresh.settings);
        self.cached.store(Some(Arc::new(fresh)));
        result
    }

    /// Use these settings (`domain` empty turns recognition off) when there
    /// is no live configuration.
    pub fn set_settings(&self, domain: &str, require: bool) {
        self.settings.store(Arc::new(Settings {
            domain: domain.trim().trim_end_matches('.').to_ascii_lowercase(),
            require,
        }));
    }

    /// Recognise these accounts: `(client id, name, enabled)`.
    pub fn set_accounts<'a>(&self, accounts: impl IntoIterator<Item = (&'a str, &'a str, bool)>) {
        let mut next = Accounts::default();
        for (id, name, enabled) in accounts {
            if !enabled {
                continue;
            }
            let name: Arc<str> = Arc::from(name);
            next.seen.insert(name.clone(), AtomicI64::new(i64::MIN));
            next.by_client_id.insert(id.to_ascii_lowercase(), name);
        }
        self.accounts.store(Arc::new(next));
    }

    /// Whether account recognition is on.
    pub fn enabled(&self) -> bool {
        self.with_settings(|s| !s.domain.is_empty())
    }

    /// Whether encrypted queries must name a known account.
    pub fn required(&self) -> bool {
        self.with_settings(|s| s.require && !s.domain.is_empty())
    }

    /// Who a connection is: from the client ID in the DoH path when there
    /// is one, else from the TLS server name (`<client id>.<domain>`).
    pub fn identify(&self, server_name: Option<&str>, path_id: Option<&str>) -> Identity {
        let client_id = self.with_settings(|settings| {
            if settings.domain.is_empty() {
                return None;
            }
            let id = match path_id {
                Some(id) => id.trim(),
                None => client_id_in(server_name?, &settings.domain)?,
            };
            (!id.is_empty()).then(|| id.to_ascii_lowercase())
        });
        let Some(client_id) = client_id else {
            return Identity::Anonymous;
        };
        match self.accounts.load().by_client_id.get(&client_id) {
            Some(name) => Identity::Account(name.clone()),
            None => Identity::Unknown(Arc::from(client_id)),
        }
    }

    /// Whether `account` is seen for the first time this minute `minute`
    /// (so its "last seen" time is worth writing). Exactly one caller wins
    /// each minute, however many queries race for it.
    pub fn first_sighting(&self, account: &Arc<str>, minute: i64) -> bool {
        self.accounts
            .load()
            .seen
            .get(account)
            .is_some_and(|last| last.fetch_max(minute, Ordering::Relaxed) < minute)
    }
}

/// The client ID in `server_name` (`<client id>.<domain>`, any case, an
/// optional trailing dot), as given; `None` for the bare domain or another
/// name. `domain` is already lowercase. Compared in place rather than by
/// lowercasing the whole name: this runs for every encrypted query.
fn client_id_in<'a>(server_name: &'a str, domain: &str) -> Option<&'a str> {
    let name = server_name.trim().trim_end_matches('.');
    let split = name.len().checked_sub(domain.len())?;
    let (prefix, suffix) = (name.get(..split)?, name.get(split..)?);
    if !suffix.eq_ignore_ascii_case(domain) {
        return None;
    }
    prefix.strip_suffix('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> AccountDirectory {
        let d = AccountDirectory::new();
        d.set_settings("DNS.Example.com.", false);
        d.set_accounts([("laptop1", "Laptop", true), ("old", "Old", false)]);
        d
    }

    #[test]
    fn client_ids_are_read_from_the_server_name_or_the_path() {
        let d = directory();
        let account = |name: &str| Identity::Account(Arc::from(name));
        assert_eq!(
            d.identify(Some("laptop1.dns.example.com"), None),
            account("Laptop")
        );
        assert_eq!(
            d.identify(Some("LAPTOP1.DNS.EXAMPLE.COM."), None),
            account("Laptop")
        );
        // The path wins over the server name (DoH).
        assert_eq!(
            d.identify(Some("dns.example.com"), Some("Laptop1")),
            account("Laptop")
        );
        // A disabled or unknown ID is told apart from no ID at all.
        assert_eq!(
            d.identify(Some("old.dns.example.com"), None),
            Identity::Unknown(Arc::from("old"))
        );
        assert_eq!(
            d.identify(Some("dns.example.com"), None),
            Identity::Anonymous
        );
        assert_eq!(
            d.identify(Some("xdns.example.com"), None),
            Identity::Anonymous
        );
        assert_eq!(d.identify(Some("other.org"), None), Identity::Anonymous);
        assert_eq!(d.identify(None, None), Identity::Anonymous);
    }

    #[test]
    fn recognition_is_off_without_a_domain() {
        let d = directory();
        d.set_settings("", true);
        assert!(!d.enabled());
        assert!(
            !d.required(),
            "require without a domain cannot lock everyone out"
        );
        assert_eq!(
            d.identify(Some("laptop1.dns.example.com"), None),
            Identity::Anonymous
        );
    }

    #[test]
    fn settings_follow_the_live_configuration() {
        let config = Arc::new(ArcSwap::from_pointee(
            daygle_dns_core::config::DaygleConfig::default(),
        ));
        let d = AccountDirectory::with_config(config.clone());
        d.set_accounts([("laptop1", "Laptop", true)]);
        assert!(!d.enabled());
        let mut next = daygle_dns_core::config::DaygleConfig::default();
        next.accounts.domain = "DNS.example.com".into();
        next.accounts.require = true;
        config.store(Arc::new(next));
        assert!(d.required());
        assert_eq!(
            d.identify(Some("laptop1.dns.example.com"), None),
            Identity::Account(Arc::from("Laptop"))
        );
    }

    #[test]
    fn last_seen_is_noted_once_a_minute() {
        let d = directory();
        let laptop: Arc<str> = Arc::from("Laptop");
        assert!(d.first_sighting(&laptop, 100));
        assert!(!d.first_sighting(&laptop, 100));
        assert!(d.first_sighting(&laptop, 101));
        // An account no longer in the list (renamed or deleted since the
        // query started) is not noted.
        assert!(!d.first_sighting(&Arc::from("Gone"), 102));
        // Replacing the list starts the count again.
        d.set_accounts([("laptop1", "Laptop", true)]);
        assert!(d.first_sighting(&laptop, 101));
    }

    #[test]
    fn client_ids_need_a_label_before_the_domain() {
        let d = directory();
        for name in [
            "",
            ".",
            "dns.example.com",
            ".dns.example.com",
            "example.com",
            "é",
        ] {
            assert!(
                matches!(
                    d.identify(Some(name), None),
                    Identity::Anonymous | Identity::Unknown(_)
                ),
                "{name:?}"
            );
        }
        assert_eq!(
            d.identify(Some(".dns.example.com"), None),
            Identity::Anonymous
        );
        // Non-ASCII before the domain cannot split a character.
        assert_eq!(
            d.identify(Some("é.dns.example.com"), None),
            Identity::Unknown(Arc::from("é"))
        );
        assert_eq!(
            d.identify(Some("a.b.dns.example.com"), None),
            Identity::Unknown(Arc::from("a.b"))
        );
    }

    #[test]
    fn a_new_configuration_is_picked_up_after_being_cached() {
        let config = Arc::new(ArcSwap::from_pointee(
            daygle_dns_core::config::DaygleConfig::default(),
        ));
        let d = AccountDirectory::with_config(config.clone());
        d.set_accounts([("laptop1", "Laptop", true)]);
        for domain in ["one.example", "two.example", ""] {
            let mut next = daygle_dns_core::config::DaygleConfig::default();
            next.accounts.domain = domain.into();
            config.store(Arc::new(next));
            // Twice: the first call fills the cache, the second reads it.
            for _ in 0..2 {
                let expected = if domain.is_empty() {
                    Identity::Anonymous
                } else {
                    Identity::Account(Arc::from("Laptop"))
                };
                assert_eq!(
                    d.identify(Some(&format!("laptop1.{domain}")), None),
                    expected,
                    "{domain}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_identity_is_scoped_to_the_query() {
        assert_eq!(current(), Identity::Anonymous);
        let inside = scope(Identity::Account(Arc::from("Laptop")), async {
            current_account()
        })
        .await;
        assert_eq!(inside.as_deref(), Some("Laptop"));
        assert_eq!(current_account(), None);
    }
}
