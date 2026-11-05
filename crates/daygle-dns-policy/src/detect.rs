//! Registered domains: the name a domain was registered as, which several
//! checks compare (a CNAME target on another registered domain is third
//! party; registration dates are looked up per registered domain).

/// Second-level labels that are part of a country's public suffix
/// (`example.co.uk`).
const SECOND_LEVEL: &[&str] = &[
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil", "ltd",
    "plc", "sch", "nom", "info", "biz", "gen", "web", "in",
];

/// The label a domain was registered as: `example` for `www.example.com`
/// and `shop.example.co.uk`. `None` for a single-label name.
pub fn registered_label(qname: &str) -> Option<&str> {
    let mut labels = qname.rsplit('.');
    let tld = labels.next()?;
    let second = labels.next()?;
    if tld.len() == 2 && SECOND_LEVEL.contains(&second) {
        if let Some(third) = labels.next() {
            return Some(third);
        }
    }
    Some(second)
}

/// The domain a name was registered as: `example.com` for
/// `www.example.com`, `example.co.uk` for `shop.example.co.uk`. `None` for
/// a single-label name.
pub fn registered_domain(qname: &str) -> Option<&str> {
    let label = registered_label(qname)?;
    // The label is a slice of `qname`: the domain starts where it does.
    let start = label.as_ptr() as usize - qname.as_ptr() as usize;
    Some(&qname[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_labels_and_domains() {
        assert_eq!(registered_label("www.example.com"), Some("example"));
        assert_eq!(registered_label("shop.example.co.uk"), Some("example"));
        assert_eq!(registered_label("example.co"), Some("example"));
        assert_eq!(registered_label("localhost"), None);
        assert_eq!(
            registered_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registered_domain("www.example.com"), Some("example.com"));
    }
}
