//! Disguised third-party trackers: CNAME cloaking, for the Disguised
//! Third-Party Trackers privacy category.
//!
//! A site points a subdomain of its own (`metrics.shop.example`) at a
//! tracking company with a CNAME (`shop.eulerian.net`), so the tracker runs
//! as "first party": it gets the site's cookies and escapes browsers'
//! third-party protections (Safari's ITP and the like). Only DNS sees the
//! CNAME, so only DNS can catch it.
//!
//! The tracking companies' CNAME targets are the category's feed: AdGuard's
//! cname-trackers catalogue ([`crate::feeds`]).

use crate::Blocklist;

/// The first CNAME target in `targets` that cloaks a third-party tracker
/// behind `qname`: a target on `trackers` (the feed) under a different
/// registered domain from `qname` (a tracker queried by its own name is not
/// disguised).
pub fn disguised_tracker<'a>(
    qname: &str,
    targets: impl IntoIterator<Item = &'a str>,
    trackers: &Blocklist,
) -> Option<&'a str> {
    let first_party = crate::detect::registered_domain(qname)?;
    targets.into_iter().find(|target| {
        trackers.contains(target)
            && crate::detect::registered_domain(target).is_some_and(|d| d != first_party)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_third_party_targets_are_disguised() {
        let trackers = Blocklist::from_lines(["eulerian.net", "*.eulerian.net"]);
        assert_eq!(
            disguised_tracker("metrics.shop.example", ["shop.eulerian.net"], &trackers),
            Some("shop.eulerian.net")
        );
        // The tracker's own name, and CNAMEs to unlisted names, are not.
        assert_eq!(
            disguised_tracker("x.eulerian.net", ["y.eulerian.net"], &trackers),
            None
        );
        assert_eq!(
            disguised_tracker("www.shop.example", ["shop.cdn.example"], &trackers),
            None
        );
    }
}
