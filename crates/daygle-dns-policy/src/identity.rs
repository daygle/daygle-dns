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
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

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

/// The accounts the listeners recognise, by client ID. The account list is
/// replaced whenever an account changes; the settings are read from the live
/// configuration when there is one (so a console save or config reload
/// applies at once), else from [`Self::set_settings`].
#[derive(Default)]
pub struct AccountDirectory {
    config: Option<Arc<ArcSwap<daygle_dns_core::config::DaygleConfig>>>,
    settings: ArcSwap<Settings>,
    /// Enabled accounts: client ID -> name.
    accounts: ArcSwap<HashMap<String, Arc<str>>>,
    /// The minute each account was last noted as seen.
    seen: Mutex<HashMap<Arc<str>, i64>>,
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

    fn settings(&self) -> Arc<Settings> {
        match &self.config {
            Some(config) => {
                let accounts = &config.load().accounts;
                Arc::new(Settings {
                    domain: accounts.normalized_domain(),
                    require: accounts.require,
                })
            }
            None => self.settings.load_full(),
        }
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
        let map = accounts
            .into_iter()
            .filter(|(_, _, enabled)| *enabled)
            .map(|(id, name, _)| (id.to_ascii_lowercase(), Arc::from(name)))
            .collect();
        self.accounts.store(Arc::new(map));
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Whether account recognition is on.
    pub fn enabled(&self) -> bool {
        !self.settings().domain.is_empty()
    }

    /// Whether encrypted queries must name a known account.
    pub fn required(&self) -> bool {
        let settings = self.settings();
        settings.require && !settings.domain.is_empty()
    }

    /// Who a connection is: from the client ID in the DoH path when there
    /// is one, else from the TLS server name (`<client id>.<domain>`).
    pub fn identify(&self, server_name: Option<&str>, path_id: Option<&str>) -> Identity {
        let settings = self.settings();
        if settings.domain.is_empty() {
            return Identity::Anonymous;
        }
        let client_id = match path_id {
            Some(id) => id.trim().to_ascii_lowercase(),
            None => {
                let Some(name) = server_name else {
                    return Identity::Anonymous;
                };
                let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
                match name.strip_suffix(&settings.domain) {
                    Some(prefix) if prefix.ends_with('.') => prefix[..prefix.len() - 1].to_string(),
                    // The bare server name, or another name entirely.
                    _ => return Identity::Anonymous,
                }
            }
        };
        if client_id.is_empty() {
            return Identity::Anonymous;
        }
        match self.accounts.load().get(&client_id) {
            Some(name) => Identity::Account(name.clone()),
            None => Identity::Unknown(Arc::from(client_id)),
        }
    }

    /// Whether `account` is seen for the first time this minute `minute`
    /// (so its "last seen" time is worth writing).
    pub fn first_sighting(&self, account: &Arc<str>, minute: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match seen.get(account) {
            Some(last) if *last >= minute => false,
            _ => {
                seen.insert(account.clone(), minute);
                true
            }
        }
    }
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
