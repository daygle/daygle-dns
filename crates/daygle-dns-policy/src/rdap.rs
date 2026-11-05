//! Registration dates of domains, looked up over RDAP (RFC 9082/9083), for
//! the Newly Registered Domains category.
//!
//! The query path never waits on the network: the first time a registered
//! domain is seen, [`RegistrationDates::check`] starts a background lookup
//! and answers "unknown"; later queries get the remembered date. The RDAP
//! server of each TLD comes from IANA's bootstrap file (RFC 9224), fetched
//! once a day. TLDs without an RDAP server (some country codes) are never
//! judged.
//!
//! Each lookup tells the TLD's registry which domain was asked about (not
//! who asked), which is why the category is opt-in per filtering group.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Semaphore;
use tracing::debug;

/// IANA's RDAP bootstrap file for domain names.
pub const IANA_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

/// A domain registered less than this long ago is newly registered.
pub const NEWLY_REGISTERED: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long a known registration date is trusted before it is looked up
/// again (a domain can be dropped and registered anew).
const DATE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a failed or dateless lookup waits before it is tried again.
const RETRY: Duration = Duration::from_secs(6 * 3600);
/// How long the bootstrap file is used before it is fetched again.
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 3600);
/// Most domains remembered; past it the expired ones are dropped, and all
/// of them if none has expired.
const CAP: usize = 50_000;
/// Most RDAP lookups running at once, so a burst of new names cannot flood
/// the registries (which rate-limit) or this server.
const CONCURRENT: usize = 4;

#[derive(Debug, Clone)]
enum State {
    Pending,
    /// The registration date (when the registry gave one), valid until.
    Known(Option<DateTime<Utc>>, Instant),
}

/// TLD -> RDAP base URL, from the bootstrap file.
type Bootstrap = HashMap<String, String>;

/// Registration dates of registered domains, filled in the background.
pub struct RegistrationDates {
    client: reqwest::Client,
    bootstrap_url: String,
    bootstrap: tokio::sync::Mutex<Option<(Instant, Arc<Bootstrap>)>>,
    domains: Mutex<HashMap<String, State>>,
    permits: Semaphore,
}

impl std::fmt::Debug for RegistrationDates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationDates")
            .field("bootstrap_url", &self.bootstrap_url)
            .finish_non_exhaustive()
    }
}

impl Default for RegistrationDates {
    fn default() -> Self {
        Self::new(IANA_BOOTSTRAP)
    }
}

impl RegistrationDates {
    /// Look RDAP servers up in the bootstrap file at `bootstrap_url`.
    pub fn new(bootstrap_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("daygle-dns/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            bootstrap_url: bootstrap_url.to_string(),
            bootstrap: tokio::sync::Mutex::new(None),
            domains: Mutex::new(HashMap::new()),
            permits: Semaphore::new(CONCURRENT),
        }
    }

    /// The bootstrap file this looks RDAP servers up in.
    pub fn bootstrap_url(&self) -> &str {
        &self.bootstrap_url
    }

    /// When `domain` (a registered domain, lowercase ASCII) was registered,
    /// when known. When nothing current is known, starts a background lookup
    /// and returns `None`, so this query is answered as usual.
    pub fn check(self: &Arc<Self>, domain: &str) -> Option<DateTime<Utc>> {
        let now = Instant::now();
        {
            let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
            match domains.get(domain) {
                Some(State::Pending) => return None,
                Some(State::Known(date, until)) if *until > now => return *date,
                _ => {}
            }
            if domains.len() >= CAP {
                domains.retain(|_, s| matches!(s, State::Known(_, until) if *until > now));
                if domains.len() >= CAP {
                    domains.clear();
                }
            }
            domains.insert(domain.to_string(), State::Pending);
        }
        let this = Arc::clone(self);
        let domain = domain.to_string();
        tokio::spawn(async move {
            let date = this.look_up(&domain).await;
            let ttl = if date.is_some() { DATE_TTL } else { RETRY };
            this.domains
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(domain, State::Known(date, Instant::now() + ttl));
        });
        None
    }

    /// Whether a domain registered at `date` is newly registered now.
    pub fn is_new(date: DateTime<Utc>) -> bool {
        Utc::now()
            .signed_duration_since(date)
            .to_std()
            .map_or(true, |age| age < NEWLY_REGISTERED)
    }

    async fn look_up(&self, domain: &str) -> Option<DateTime<Utc>> {
        let _permit = self.permits.acquire().await.ok()?;
        let bootstrap = self.bootstrap().await?;
        let tld = domain.rsplit('.').next()?;
        let base = bootstrap.get(tld)?;
        let url = format!("{}/domain/{domain}", base.trim_end_matches('/'));
        let response = match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                debug!(%domain, status = %r.status(), "RDAP lookup refused");
                return None;
            }
            Err(e) => {
                debug!(%domain, error = %e, "RDAP lookup failed");
                return None;
            }
        };
        let body: serde_json::Value = response.json().await.ok()?;
        registration_date(&body)
    }

    /// The bootstrap table, fetched when missing or a day old. A failed
    /// fetch keeps the old table, if any.
    async fn bootstrap(&self) -> Option<Arc<Bootstrap>> {
        let mut cached = self.bootstrap.lock().await;
        if let Some((at, table)) = cached.as_ref() {
            if at.elapsed() < BOOTSTRAP_TTL {
                return Some(Arc::clone(table));
            }
        }
        let fetched = async {
            let body: serde_json::Value = self
                .client
                .get(&self.bootstrap_url)
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?
                .json()
                .await
                .ok()?;
            parse_bootstrap(&body)
        }
        .await;
        match fetched {
            Some(table) => {
                let table = Arc::new(table);
                *cached = Some((Instant::now(), Arc::clone(&table)));
                Some(table)
            }
            None => {
                debug!(url = %self.bootstrap_url, "cannot fetch the RDAP bootstrap file");
                cached.as_ref().map(|(_, table)| Arc::clone(table))
            }
        }
    }
}

/// The TLD -> base URL table of an RDAP bootstrap file (RFC 9224):
/// `{"services": [[["com", "net"], ["https://rdap.example/"]], ...]}`.
/// HTTPS URLs are preferred where a service lists several.
fn parse_bootstrap(body: &serde_json::Value) -> Option<Bootstrap> {
    let mut table = Bootstrap::new();
    for service in body.get("services")?.as_array()? {
        let (Some(tlds), Some(urls)) = (
            service.get(0).and_then(|v| v.as_array()),
            service.get(1).and_then(|v| v.as_array()),
        ) else {
            continue;
        };
        let urls: Vec<&str> = urls.iter().filter_map(|u| u.as_str()).collect();
        let Some(url) = urls
            .iter()
            .find(|u| u.starts_with("https://"))
            .or_else(|| urls.first())
        else {
            continue;
        };
        for tld in tlds.iter().filter_map(|t| t.as_str()) {
            table.insert(tld.to_ascii_lowercase(), url.to_string());
        }
    }
    Some(table)
}

/// The `registration` event's date of an RDAP domain object.
fn registration_date(body: &serde_json::Value) -> Option<DateTime<Utc>> {
    body.get("events")?
        .as_array()?
        .iter()
        .find(|e| e.get("eventAction").and_then(|a| a.as_str()) == Some("registration"))
        .and_then(|e| e.get("eventDate")?.as_str())
        .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
        .map(|d| d.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bootstrap_maps_tlds_to_https_servers() {
        let table = parse_bootstrap(&json!({
            "version": "1.0",
            "services": [
                [["com", "NET"], ["http://rdap.example/", "https://rdap.example/"]],
                [["org"], ["https://rdap.org.example/v1/"]],
                ["broken"]
            ]
        }))
        .unwrap();
        assert_eq!(table["com"], "https://rdap.example/");
        assert_eq!(table["net"], "https://rdap.example/");
        assert_eq!(table["org"], "https://rdap.org.example/v1/");
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn registration_dates_are_read_from_events() {
        let date = registration_date(&json!({
            "objectClassName": "domain",
            "events": [
                {"eventAction": "last changed", "eventDate": "2024-05-01T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"}
            ]
        }))
        .unwrap();
        assert_eq!(date.to_rfc3339(), "1997-09-15T04:00:00+00:00");
        assert!(!RegistrationDates::is_new(date));
        assert!(RegistrationDates::is_new(
            Utc::now() - chrono::Duration::days(3)
        ));
        assert_eq!(registration_date(&json!({"events": []})), None);
    }
}
