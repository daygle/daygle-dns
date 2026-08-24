//! Domain blocklist supporting exact matches and `*.suffix` wildcards.

use std::collections::BTreeSet;

use daygle_core::config::normalize_domains;

/// An immutable set of blocked domains.
///
/// Entries are stored without a trailing dot and lower-cased. An entry may be
/// either an exact name (`ads.example.com`) or a wildcard suffix prefixed with
/// `*.` (`*.example.com`). A wildcard matches any strict subdomain of the
/// suffix (`a.example.com`, `a.b.example.com`) but not the bare suffix itself
/// (`example.com`); block that with a separate exact entry if needed.
#[derive(Debug, Clone, Default)]
pub struct Blocklist {
    exact: BTreeSet<String>,
    suffixes: BTreeSet<String>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a blocklist from a set of already-normalized domain patterns.
    pub fn from_set(entries: BTreeSet<String>) -> Self {
        let mut list = Blocklist::new();
        for entry in entries {
            if let Some(suffix) = entry.strip_prefix("*.") {
                list.suffixes.insert(suffix.to_string());
            } else {
                list.exact.insert(entry);
            }
        }
        list
    }

    /// Build a blocklist from raw (possibly mixed-case, possibly dotted) lines.
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Self {
        Self::from_set(normalize_domains(
            lines.into_iter().map(|l| l.to_string()),
        ))
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    /// The full set of entries, `*.` wildcards included, as a `BTreeSet`.
    pub fn domains(&self) -> std::collections::BTreeSet<String> {
        let mut all = self.exact.clone();
        all.extend(self.suffixes.iter().map(|s| format!("*.{s}")));
        all
    }

    /// Whether `domain` (already normalized, no trailing dot) is blocked.
    pub fn contains(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }
        // Walk the domain's parents: for `a.b.example.com` test
        // `b.example.com`, `example.com`, `com`.
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            rest = parent;
            if self.suffixes.contains(rest) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
