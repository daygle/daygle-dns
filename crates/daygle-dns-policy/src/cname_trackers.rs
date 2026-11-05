//! Disguised third-party trackers: CNAME cloaking, for the Disguised
//! Third-Party Trackers privacy category.
//!
//! A site points a subdomain of its own (`metrics.shop.example`) at a
//! tracking company with a CNAME (`shop.eulerian.net`), so the tracker runs
//! as "first party": it gets the site's cookies and escapes browsers'
//! third-party protections (Safari's ITP and the like). Only DNS sees the
//! CNAME, so only DNS can catch it.
//!
//! The tracking companies' CNAME targets come from AdGuard's cname-trackers
//! catalogue (`data/cname-trackers.json`, MIT licence in
//! `data/cname-trackers.LICENSE`; refresh with
//! `scripts/update-cname-trackers.sh`). Only its `tracker` and `ad` entries
//! are used: AdGuard advises against blocking its clickthrough, microsite
//! and mail-tracker entries, which serve pages and links people open.

use std::sync::OnceLock;

use serde::Deserialize;

/// AdGuard's catalogue, as published.
const CATALOGUE: &str = include_str!("../data/cname-trackers.json");

/// The catalogue entry types that are blocked.
const BLOCKED_TYPES: &[&str] = &["tracker", "ad"];

#[derive(Deserialize)]
struct Entry {
    company_name: String,
    #[serde(rename = "type")]
    kind: String,
    domains: Vec<String>,
}

/// (CNAME target domain, company), lowercase.
fn targets() -> &'static [(String, String)] {
    static TARGETS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    TARGETS.get_or_init(|| {
        let entries: Vec<Entry> = serde_json::from_str(CATALOGUE).unwrap_or_default();
        entries
            .into_iter()
            .filter(|e| BLOCKED_TYPES.contains(&e.kind.as_str()))
            .flat_map(|e| {
                let company = e.company_name;
                e.domains.into_iter().map(move |d| {
                    (
                        d.trim().trim_end_matches('.').to_ascii_lowercase(),
                        company.clone(),
                    )
                })
            })
            .filter(|(d, _)| !d.is_empty())
            .collect()
    })
}

/// The tracking company whose infrastructure `name` (lowercase, no
/// trailing dot) belongs to, if any.
pub fn tracker_company(name: &str) -> Option<&'static str> {
    targets()
        .iter()
        .find(|(domain, _)| {
            name == domain
                || name
                    .strip_suffix(domain.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
        .map(|(_, company)| company.as_str())
}

/// The first CNAME target in `targets` that cloaks a third-party tracker
/// behind `qname`, with the tracker's company: a target on a listed
/// tracker's infrastructure under a different registered domain from
/// `qname` (a tracker queried by its own name is not disguised).
pub fn disguised_tracker<'a>(
    qname: &str,
    targets: impl IntoIterator<Item = &'a str>,
) -> Option<(&'a str, &'static str)> {
    let first_party = crate::detect::registered_domain(qname)?;
    targets.into_iter().find_map(|target| {
        let company = tracker_company(target)?;
        let target_domain = crate::detect::registered_domain(target)?;
        (target_domain != first_party).then_some((target, company))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_loads_trackers_and_ads_only() {
        assert!(targets().len() > 40, "{}", targets().len());
        assert!(tracker_company("customer.eulerian.net").is_some());
        assert!(tracker_company("shop.sc.omtrdc.net").is_some());
        // Clickthroughs and mail trackers are left alone.
        assert_eq!(tracker_company("go.pardot.com"), None);
        assert_eq!(tracker_company("mailgun.org"), None);
        assert_eq!(tracker_company("example.com"), None);
        assert_eq!(tracker_company("noteulerian.net"), None);
    }

    #[test]
    fn only_third_party_targets_are_disguised() {
        let (target, company) =
            disguised_tracker("metrics.shop.example", ["shop.eulerian.net"]).unwrap();
        assert_eq!(target, "shop.eulerian.net");
        assert!(!company.is_empty());
        // The tracker's own name, and CNAMEs to unlisted names, are not.
        assert_eq!(
            disguised_tracker("x.eulerian.net", ["y.eulerian.net"]),
            None
        );
        assert_eq!(
            disguised_tracker("www.shop.example", ["shop.cdn.example"]),
            None
        );
    }
}
