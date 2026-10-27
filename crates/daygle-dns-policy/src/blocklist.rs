//! Domain blocklist supporting exact matches and `*.suffix` wildcards.

use std::collections::{BTreeSet, HashSet};

use daygle_dns_core::config::normalize_domains;

/// An immutable set of blocked domains.
///
/// Entries are stored without a trailing dot and lower-cased. An entry may be
/// either an exact name (`ads.example.com`) or a wildcard suffix prefixed with
/// `*.` (`*.example.com`). A wildcard matches any strict subdomain of the
/// suffix (`a.example.com`, `a.b.example.com`) but not the bare suffix itself
/// (`example.com`); block that with a separate exact entry if needed.
///
/// Entries prefixed with `@@` (`@@cdn.example.com`, `@@*.example.com`) are
/// exceptions, as in adblock-style lists: a name they match is not in the
/// list even when another entry matches it.
///
/// Membership is hashed, not ordered: `contains` runs on every query for the
/// allowlist, blocklist, remote blocklist and AAAA-bypass sets, which can
/// hold hundreds of thousands of entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Blocklist {
    exact: HashSet<String>,
    suffixes: HashSet<String>,
    except_exact: HashSet<String>,
    except_suffixes: HashSet<String>,
}

/// The prefix that marks an exception entry.
pub const EXCEPTION_PREFIX: &str = "@@";

/// Whether any parent of `domain` (`b.example.com`, `example.com`, `com` for
/// `a.b.example.com`) is in `suffixes`.
fn parent_in(suffixes: &HashSet<String>, domain: &str) -> bool {
    parent_match(suffixes, domain).is_some()
}

/// The nearest parent of `domain` in `suffixes`, if any.
fn parent_match<'a>(suffixes: &HashSet<String>, domain: &'a str) -> Option<&'a str> {
    if suffixes.is_empty() {
        return None;
    }
    let mut rest = domain;
    while let Some((_, parent)) = rest.split_once('.') {
        rest = parent;
        if suffixes.contains(rest) {
            return Some(rest);
        }
    }
    None
}

/// The entry of a source's raw entry set (as [`Blocklist::from_set`] takes
/// it) that lists `domain`: the name itself, or the nearest `*.parent`
/// wildcard. Exceptions are not considered; this says which entry a block
/// came from, after the merged list has decided it is blocked.
pub fn entry_for(entries: &BTreeSet<String>, domain: &str) -> Option<String> {
    if entries.contains(domain) {
        return Some(domain.to_string());
    }
    let mut rest = domain;
    while let Some((_, parent)) = rest.split_once('.') {
        rest = parent;
        let wildcard = format!("*.{rest}");
        if entries.contains(&wildcard) {
            return Some(wildcard);
        }
    }
    None
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a blocklist from a set of already-normalized domain patterns.
    pub fn from_set(entries: BTreeSet<String>) -> Self {
        let mut list = Blocklist::new();
        for entry in entries {
            let (exception, entry) = match entry.strip_prefix(EXCEPTION_PREFIX) {
                Some(rest) => (true, rest.to_string()),
                None => (false, entry),
            };
            let (exact, suffixes) = if exception {
                (&mut list.except_exact, &mut list.except_suffixes)
            } else {
                (&mut list.exact, &mut list.suffixes)
            };
            match entry.strip_prefix("*.") {
                Some(suffix) => suffixes.insert(suffix.to_string()),
                None => exact.insert(entry),
            };
        }
        list
    }

    /// Build a blocklist from raw (possibly mixed-case, possibly dotted) lines.
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Self {
        Self::from_set(normalize_domains(lines.into_iter().map(|l| l.to_string())))
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    /// Block entries (exceptions are not counted).
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    /// Whether `domain` (already normalized, no trailing dot) is blocked.
    pub fn contains(&self, domain: &str) -> bool {
        let listed = self.exact.contains(domain) || parent_in(&self.suffixes, domain);
        listed && !(self.except_exact.contains(domain) || parent_in(&self.except_suffixes, domain))
    }

    /// The entry that puts `domain` in the list (`ads.example.com` or
    /// `*.example.com`), when it is in it.
    pub fn matching_entry(&self, domain: &str) -> Option<String> {
        if !self.contains(domain) {
            return None;
        }
        if self.exact.contains(domain) {
            return Some(domain.to_string());
        }
        parent_match(&self.suffixes, domain).map(|parent| format!("*.{parent}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptions_override_blocks() {
        let list = Blocklist::from_set(
            [
                "example.com",
                "*.example.com",
                "@@cdn.example.com",
                "@@*.static.example.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );
        assert!(list.contains("example.com"));
        assert!(list.contains("ads.example.com"));
        assert!(!list.contains("cdn.example.com"));
        assert!(list.contains("a.cdn.example.com"));
        assert!(!list.contains("img.static.example.com"));
        assert!(list.contains("static.example.com"));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn reports_the_matching_entry() {
        let list =
            Blocklist::from_lines(["ads.example.com", "*.tracker.test", "@@ok.tracker.test"]);
        assert_eq!(
            list.matching_entry("ads.example.com").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            list.matching_entry("a.b.tracker.test").as_deref(),
            Some("*.tracker.test")
        );
        assert_eq!(list.matching_entry("ok.tracker.test"), None, "an exception");
        assert_eq!(list.matching_entry("example.com"), None);
        let entries: BTreeSet<String> = ["*.tracker.test".to_string()].into();
        assert_eq!(
            entry_for(&entries, "x.tracker.test").as_deref(),
            Some("*.tracker.test")
        );
        assert_eq!(entry_for(&entries, "tracker.test"), None);
    }

    #[test]
    fn exact_match() {
        let list = Blocklist::from_lines(["ads.example.com", "tracker.test"]);
        assert!(list.contains("ads.example.com"));
        assert!(!list.contains("example.com"));
        assert!(!list.contains("sub.ads.example.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let list = Blocklist::from_lines(["*.ads.example.com"]);
        assert!(list.contains("a.ads.example.com"));
        assert!(list.contains("b.a.ads.example.com"));
        assert!(!list.contains("ads.example.com"));
        assert!(!list.contains("example.com"));
    }

    #[test]
    fn normalizes_case_and_dots() {
        let list = Blocklist::from_lines(["Ads.Example.COM."]);
        assert!(list.contains("ads.example.com"));
    }

    #[test]
    fn empty_matches_nothing() {
        let list = Blocklist::new();
        assert!(list.is_empty());
        assert!(!list.contains("example.com"));
    }
}
