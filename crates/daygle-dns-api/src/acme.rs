//! Certificates from an ACME CA (Let's Encrypt by default, or a private
//! one such as step-ca), issued from the Certificates page and renewed
//! automatically.
//!
//! Control of each name is proven one of two ways:
//!
//! - **HTTP-01**: the CA fetches `http://<name>/.well-known/acme-challenge/
//!   <token>`, which the web console's HTTP listener answers. The CA always
//!   connects to port 80, so the name must reach that listener on port 80.
//! - **DNS-01**: a TXT record at `_acme-challenge.<name>` in a zone this
//!   server hosts, so the zone must be delegated to this server. The only
//!   way to get a wildcard (`*.example.com`) certificate.
//!
//! Issued certificates are stored like any other on the Certificates page,
//! so listeners using them pick up renewals in place.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use daygle_dns_authoritative::store::AcmeCertificate;
use daygle_dns_authoritative::{RecordInput, TlsCertificate};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::AppState;

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Renew this many days before a certificate expires, unless set.
const DEFAULT_RENEW_DAYS: u32 = 30;
/// How often certificates are checked for renewal.
const CHECK_EVERY: Duration = Duration::from_secs(12 * 3600);
/// How long the CA gets to validate the challenges and issue.
const ORDER_TIMEOUT: Duration = Duration::from_secs(180);

const SETTINGS_KEY: &str = "acme";

/// The ACME settings (Certificates page), stored in the database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeSettings {
    /// Contact address for the CA account (expiry warnings).
    pub email: String,
    /// The CA's directory URL; empty means Let's Encrypt.
    pub directory: String,
    /// The CA's terms of service were accepted.
    pub agree_terms: bool,
    /// PEM root certificate to trust for a private CA's directory (empty:
    /// the system's trusted roots).
    pub ca_certificate: String,
    /// Renew this many days before expiry (0: the default, 30).
    pub renew_days: u32,
}

impl AcmeSettings {
    pub fn directory_url(&self) -> &str {
        match self.directory.trim() {
            "" => LETS_ENCRYPT,
            url => url,
        }
    }

    fn renew_days(&self) -> u32 {
        if self.renew_days == 0 {
            DEFAULT_RENEW_DAYS
        } else {
            self.renew_days
        }
    }

    /// Problems that stop certificates being requested.
    pub fn check(&self) -> Result<(), String> {
        let url = self.directory_url();
        if !url.starts_with("https://") {
            return Err("the CA directory must be an https:// URL".into());
        }
        let email = self.email.trim();
        if !email.is_empty() && (!email.contains('@') || email.contains(char::is_whitespace)) {
            return Err(format!("'{email}' is not an email address"));
        }
        if !self.ca_certificate.trim().is_empty() {
            use rustls_pki_types::pem::PemObject;
            rustls_pki_types::CertificateDer::from_pem_slice(self.ca_certificate.as_bytes())
                .map_err(|e| format!("the CA certificate cannot be read: {e}"))?;
        }
        Ok(())
    }
}

/// Load the ACME settings.
pub fn settings(state: &AppState) -> AcmeSettings {
    state
        .catalog
        .store()
        .get_named_setting(SETTINGS_KEY)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// The renewal window (days before expiry) currently in force: the stored
/// ACME settings' `renew_days`, or the default when nothing is stored. The
/// encrypted-DNS listeners use it to warn when a loaded certificate is
/// already inside the window (see `daygle_dns::tls_diag`).
pub fn renewal_window_days(store: &daygle_dns_authoritative::ZoneStore) -> u32 {
    let stored: AcmeSettings = store
        .get_named_setting(SETTINGS_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    stored.renew_days()
}

pub fn save_settings(state: &AppState, settings: &AcmeSettings) -> Result<(), String> {
    settings.check()?;
    state
        .catalog
        .store()
        .put_named_setting(SETTINGS_KEY, settings)
        .map_err(|e| e.to_string())
}

/// Live ACME state: HTTP-01 answers being served, and which certificates
/// are being issued right now.
#[derive(Default)]
pub struct Acme {
    http_tokens: Mutex<HashMap<String, String>>,
    in_progress: Mutex<HashSet<String>>,
}

impl Acme {
    /// The key authorization to serve for an HTTP-01 `token`.
    pub fn http_response(&self, token: &str) -> Option<String> {
        self.http_tokens.lock().get(token).cloned()
    }

    pub fn is_issuing(&self, name: &str) -> bool {
        self.in_progress.lock().contains(name)
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Check a requested name list: DNS names only, a wildcard only with DNS-01.
pub fn check_domains(domains: &[String], challenge: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for domain in domains {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        let bare = d.strip_prefix("*.").unwrap_or(&d);
        let valid = bare.contains('.')
            && bare.len() <= 253
            && bare.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        if !valid {
            return Err(format!("'{domain}' is not a domain name"));
        }
        if d.starts_with("*.") && challenge != "dns" {
            return Err(format!(
                "'{d}' is a wildcard: wildcard certificates need the DNS challenge"
            ));
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        return Err("list at least one domain name".into());
    }
    if out.len() > 100 {
        return Err("a certificate can cover at most 100 names".into());
    }
    Ok(out)
}

/// Request (or renew) the ACME certificate `name` now. Errors are also
/// recorded on the certificate, for the Certificates page.
pub async fn issue(state: &AppState, name: &str) -> Result<(), String> {
    if !state.acme.in_progress.lock().insert(name.to_string()) {
        return Err(format!("certificate '{name}' is already being requested"));
    }
    let result = issue_locked(state, name).await;
    state.acme.in_progress.lock().remove(name);
    let store = state.catalog.store();
    match &result {
        Ok(()) => {
            daygle_dns_core::alerts::resolve(&format!("acme:{name}"));
            let _ = store.set_acme_certificate_status(name, "valid", "", now());
            state.logs.info(
                "acme",
                format!("certificate '{name}' issued by the ACME CA"),
            );
        }
        Err(e) => {
            let _ = store.set_acme_certificate_status(name, "failed", e, now());
            state.logs.push(
                daygle_dns_core::LogLevel::Error,
                "acme",
                format!("certificate '{name}' could not be issued: {e}"),
            );
            daygle_dns_core::alerts::raise(
                daygle_dns_core::alerts::AlertKind::CertificateExpiry,
                format!("acme:{name}"),
                format!("Certificate '{name}' could not be issued"),
                format!("Requesting the certificate '{name}' from the ACME CA failed: {e}"),
            );
        }
    }
    result
}

async fn issue_locked(state: &AppState, name: &str) -> Result<(), String> {
    let store = state.catalog.store();
    let cert = store
        .get_acme_certificate(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("certificate '{name}' is not an ACME certificate"))?;
    let _ = store.set_acme_certificate_status(name, "pending", "", now());
    let settings = settings(state);
    if !settings.agree_terms {
        return Err("accept the CA's terms of service in the ACME settings first".into());
    }
    let account = account(state, &settings).await?;

    let identifiers: Vec<Identifier> = cert
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("the CA refused the order: {e}"))?;

    let mut challenges = Challenges::default();
    let ready = prove_control(state, &cert, &mut order, &mut challenges).await;
    let finished = match ready {
        Ok(()) => finish_order(&mut order).await,
        Err(e) => Err(e),
    };
    challenges.clean_up(state);
    let (cert_pem, key_pem) = finished?;

    crate::handlers::install_certificate(
        state,
        TlsCertificate {
            name: name.to_string(),
            server_name: cert.domains[0].clone(),
            cert_pem,
            key_pem,
            created_at: chrono::Utc::now().to_rfc3339(),
        },
    )
    .await
    .map_err(|e| e.to_string())
}

/// Challenge answers put in place for one order, removed afterwards.
#[derive(Default)]
struct Challenges {
    http_tokens: Vec<String>,
    txt_records: Vec<String>,
}

impl Challenges {
    fn clean_up(self, state: &AppState) {
        {
            let mut tokens = state.acme.http_tokens.lock();
            for token in &self.http_tokens {
                tokens.remove(token);
            }
        }
        if !self.txt_records.is_empty() {
            let store = state.catalog.store();
            for id in &self.txt_records {
                let _ = store.delete_record(id);
            }
            if let Err(e) = state.catalog.reload() {
                tracing::warn!("reload after removing ACME TXT records failed: {e}");
            }
        }
    }
}

async fn prove_control(
    state: &AppState,
    cert: &AcmeCertificate,
    order: &mut instant_acme::Order,
    challenges: &mut Challenges,
) -> Result<(), String> {
    let dns = cert.challenge == "dns";
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization =
            authorization.map_err(|e| format!("cannot read the CA's challenges: {e}"))?;
        match authorization.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => return Err(format!("the CA's authorization is {other:?}")),
        }
        let kind = if dns {
            ChallengeType::Dns01
        } else {
            ChallengeType::Http01
        };
        let mut challenge = authorization.challenge(kind).ok_or_else(|| {
            format!(
                "the CA does not offer the {} challenge",
                if dns { "DNS-01" } else { "HTTP-01" }
            )
        })?;
        let identifier = challenge.identifier().identifier.clone();
        let Identifier::Dns(domain) = identifier else {
            return Err("only DNS names are supported".into());
        };
        let key_authorization = challenge.key_authorization();
        if dns {
            let id = add_txt_record(state, &domain, &key_authorization.dns_value())?;
            challenges.txt_records.push(id);
        } else {
            state.acme.http_tokens.lock().insert(
                challenge.token.clone(),
                key_authorization.as_str().to_string(),
            );
            challenges.http_tokens.push(challenge.token.clone());
        }
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("the CA did not accept the challenge for {domain}: {e}"))?;
    }
    Ok(())
}

async fn finish_order(order: &mut instant_acme::Order) -> Result<(String, String), String> {
    let retry = RetryPolicy::default()
        .initial_delay(Duration::from_secs(1))
        .timeout(ORDER_TIMEOUT);
    let status = order
        .poll_ready(&retry)
        .await
        .map_err(|e| format!("waiting for the CA failed: {e}"))?;
    if status != OrderStatus::Ready {
        return Err(order_problem(order, status));
    }
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("the CA refused the certificate request: {e}"))?;
    let cert_pem = order
        .poll_certificate(&retry)
        .await
        .map_err(|e| format!("the CA did not issue the certificate: {e}"))?;
    Ok((cert_pem, key_pem))
}

/// Why an order did not become ready, from the CA's own report.
fn order_problem(order: &mut instant_acme::Order, status: OrderStatus) -> String {
    let state = order.state();
    match &state.error {
        Some(problem) => format!("the CA could not verify the names: {problem}"),
        None => format!(
            "the CA could not verify the names (order {status:?}); check that each name reaches this server as the chosen challenge needs"
        ),
    }
}

/// Put the DNS-01 TXT record for `domain` in the zone this server hosts
/// for it. Returns the record's id, for removal.
fn add_txt_record(state: &AppState, domain: &str, value: &str) -> Result<String, String> {
    let store = state.catalog.store();
    let name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
    let secondaries: HashSet<String> = store
        .list_secondary()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|s| s.zone_id)
        .collect();
    let zone = store
        .list_zones()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|z| !secondaries.contains(&z.id))
        .filter(|z| name == z.name || name.ends_with(&format!(".{}", z.name)))
        .max_by_key(|z| z.name.len())
        .ok_or_else(|| {
            format!(
                "no zone on this server holds {name}: the DNS challenge needs the domain's zone hosted (as a primary) here"
            )
        })?;
    let relative = name
        .strip_suffix(&format!(".{}", zone.name))
        .unwrap_or("@")
        .to_string();
    let record = store
        .upsert_record(
            &zone.id,
            &RecordInput {
                name: relative,
                rtype: "TXT".to_string(),
                content: format!("\"{value}\""),
                ttl: 60,
                priority: 0,
                disabled: false,
            },
        )
        .map_err(|e| format!("cannot add the TXT record for {domain}: {e}"))?;
    state
        .catalog
        .reload()
        .map_err(|e| format!("cannot serve the TXT record for {domain}: {e}"))?;
    Ok(record.id)
}

fn account_key(directory: &str) -> String {
    format!("acme_account:{directory}")
}

/// The CA account for the configured directory, created on first use.
async fn account(state: &AppState, settings: &AcmeSettings) -> Result<Account, String> {
    daygle_dns_dot::crypto_provider();
    let directory = settings.directory_url().to_string();
    let store = state.catalog.store();
    let builder = || -> Result<instant_acme::AccountBuilder, String> {
        if settings.ca_certificate.trim().is_empty() {
            Account::builder().map_err(|e| format!("cannot set up the ACME client: {e}"))
        } else {
            // The library reads a custom root from a file.
            let file = std::env::temp_dir().join(format!(
                "daygle-dns-acme-root-{}-{}.pem",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::write(&file, settings.ca_certificate.as_bytes())
                .map_err(|e| format!("cannot use the CA certificate: {e}"))?;
            let built = Account::builder_with_root(&file)
                .map_err(|e| format!("cannot use the CA certificate: {e}"));
            let _ = std::fs::remove_file(&file);
            built
        }
    };
    let stored: Option<AccountCredentials> = store
        .get_named_setting(&account_key(&directory))
        .map_err(|e| e.to_string())?;
    if let Some(credentials) = stored {
        return builder()?
            .from_credentials(credentials)
            .await
            .map_err(|e| format!("cannot reach the CA at {directory}: {e}"));
    }
    let email = settings.email.trim();
    let contact = format!("mailto:{email}");
    let contacts: Vec<&str> = if email.is_empty() {
        vec![]
    } else {
        vec![contact.as_str()]
    };
    let (account, credentials) = builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.clone(),
            None,
        )
        .await
        .map_err(|e| format!("cannot create an account with the CA at {directory}: {e}"))?;
    store
        .put_named_setting(&account_key(&directory), &credentials)
        .map_err(|e| e.to_string())?;
    state
        .logs
        .info("acme", format!("created an ACME account with {directory}"));
    Ok(account)
}

/// Whether `cert` should be (re)issued now: never issued, or within the
/// renewal window of its expiry.
fn due(state: &AppState, cert: &AcmeCertificate, renew_days: u32) -> bool {
    let issued = state
        .catalog
        .store()
        .get_tls_certificate(&cert.name)
        .ok()
        .flatten()
        .and_then(|c| daygle_dns_dot::describe_certificate(&c.cert_pem).ok());
    match issued {
        None => true,
        Some(info) => info.not_after - now() < i64::from(renew_days) * 86_400,
    }
}

/// Request every ACME certificate that is missing or due for renewal.
pub async fn renew_due(state: &AppState) {
    let settings = settings(state);
    if !settings.agree_terms {
        return;
    }
    let certs = match state.catalog.store().list_acme_certificates() {
        Ok(certs) => certs,
        Err(e) => {
            tracing::warn!("cannot list ACME certificates: {e}");
            return;
        }
    };
    for cert in certs {
        if due(state, &cert, settings.renew_days()) {
            let _ = issue(state, &cert.name).await;
        }
    }
}

/// How close to its expiry a certificate raises an alert.
const EXPIRY_ALERT_DAYS: i64 = 14;

/// Raise an alert for every console-managed certificate that expires within
/// [`EXPIRY_ALERT_DAYS`] (or already has).
fn alert_expiring_certificates(state: &AppState) {
    let Ok(certs) = state.catalog.store().list_tls_certificates() else {
        return;
    };
    for cert in certs {
        let Ok(info) = daygle_dns_dot::describe_certificate(&cert.cert_pem) else {
            continue;
        };
        let days = (info.not_after - now()).div_euclid(86_400);
        if days >= EXPIRY_ALERT_DAYS {
            continue;
        }
        let when = if days < 0 {
            "has expired".to_string()
        } else if days == 0 {
            "expires today".to_string()
        } else {
            format!("expires in {days} day{}", if days == 1 { "" } else { "s" })
        };
        daygle_dns_core::alerts::raise(
            daygle_dns_core::alerts::AlertKind::CertificateExpiry,
            format!("cert-expiry:{}", cert.name),
            format!("Certificate '{}' {when}", cert.name),
            format!(
                "The certificate '{}' ({}) {when}. Renew or replace it under \
                 Certificates; clients refuse an expired certificate.",
                cert.name, cert.server_name
            ),
        );
    }
}

/// Renew certificates in the background: shortly after start, then twice a
/// day.
pub async fn run_renewals(state: AppState, shutdown: CancellationToken) {
    let mut wait = Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        renew_due(&state).await;
        alert_expiring_certificates(&state);
        wait = CHECK_EVERY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_checked_and_normalized() {
        let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            check_domains(
                &list(&["DNS.Example.com.", "dns.example.com", " www.example.com "]),
                "http"
            )
            .unwrap(),
            ["dns.example.com", "www.example.com"]
        );
        assert!(check_domains(&list(&["*.example.com"]), "http")
            .unwrap_err()
            .contains("wildcard"));
        assert_eq!(
            check_domains(&list(&["*.example.com"]), "dns").unwrap(),
            ["*.example.com"]
        );
        for bad in [
            "localhost",
            "bad_name.example.com",
            "-x.example.com",
            "a..b.com",
        ] {
            assert!(check_domains(&list(&[bad]), "http").is_err(), "{bad}");
        }
        assert!(check_domains(&list(&["", " "]), "http").is_err());
    }

    #[test]
    fn settings_default_to_lets_encrypt_and_are_checked() {
        let mut s = AcmeSettings::default();
        assert_eq!(s.directory_url(), LETS_ENCRYPT);
        assert_eq!(s.renew_days(), 30);
        assert!(s.check().is_ok());
        s.directory = "http://ca.internal/directory".into();
        assert!(s.check().is_err());
        s.directory = "https://ca.internal/acme/directory".into();
        s.email = "not an email".into();
        assert!(s.check().is_err());
        s.email = "ops@example.com".into();
        s.ca_certificate = "garbage".into();
        assert!(s.check().is_err());
    }
}
