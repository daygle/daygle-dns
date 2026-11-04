//! Built-in heuristic backend: keyword tables over the domain string itself.
//!
//! This is the zero-model fallback so the scanner is always functional with
//! no model file configured - deliberately wide-net and *low-confidence*:
//! heuristic verdicts carry confidences in the 0.3-0.6 band so that even in
//! `enforce` mode they can never cross the 0.99 auto-block threshold on
//! their own. They exist to (a) bootstrap verdict data, (b) make the
//! console's AI page useful before a real model is trained, and (c) queue
//! suspicious candidates for the (planned) expensive verifier stage.
//!
//! In `train` mode nothing is ever blocked regardless of backend, so these
//! heuristics are purely informational there.

use crate::backend::{ClassificationInput, DomainClassifier, Severity, Verdict};

struct Rule {
    /// Matched against label-boundary expansions of every label (so `bet` as
    /// a whole label matches `bet-slip.example`, never `rocket.example`).
    tokens: &'static [&'static str],
    category: &'static str,
    rule_confidence: f32,
    severity: Severity,
}

const RULES: &[Rule] = &[
    Rule {
        tokens: &["porn", "xxx", "adult", "nsfw", "sex"],
        category: "adult",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &[
            "casino",
            "gambling",
            "poker",
            "bingo",
            "bookmaker",
            "lottery",
            "bet",
        ],
        category: "gambling",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &["malware", "virus", "ransomware", "keylogger", "trojan"],
        category: "malware",
        rule_confidence: 0.35,
        severity: Severity::Threat,
    },
    Rule {
        tokens: &[
            "phishing",
            "phish",
            "credential",
            "loginpage",
            "securelogin",
        ],
        category: "phishing",
        rule_confidence: 0.3,
        severity: Severity::Threat,
    },
    Rule {
        tokens: &["torrent", "warez", "crack", "cheat"],
        category: "piracy",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    // Fake offers and social engineering: a label, not a blocking decision -
    // the threat channel turns only `auto_block_categories` labels into
    // Threats entries.
    Rule {
        tokens: &["scam", "giveaway", "doubler", "airdrop", "refundclaim"],
        category: "scam",
        rule_confidence: 0.35,
        severity: Severity::Threat,
    },
    Rule {
        tokens: &["dating", "singles", "matchmaker", "hookup"],
        category: "dating",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &[
            "ads",
            "adserver",
            "adservice",
            "adnetwork",
            "adnxs",
            "doubleclick",
            "googlesyndication",
            "taboola",
            "outbrain",
        ],
        category: "ads",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &["crypto", "bitcoin", "ethereum", "blockchain", "defi", "nft"],
        category: "crypto",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &["jobs", "careers", "recruit", "hiring"],
        category: "jobs",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &["realestate", "realtor", "property", "zillow", "rightmove"],
        category: "real-estate",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
    Rule {
        tokens: &["autotrader", "dealership", "motors", "carparts"],
        category: "auto",
        rule_confidence: 0.3,
        severity: Severity::Info,
    },
];

/// Label-boundary token match: `bet` matches label `bet` or `bet-slip` but
/// never `rocket`. Boundaries are label edges or any non-alphanumeric byte
/// (the split already cut dots/hyphens, so within a label this catches
/// underscore/edge cases only).
fn label_has_token(labels: &[&str], token: &str) -> bool {
    let needle = token.as_bytes();
    labels.iter().any(|label| {
        for start in 0..label.len() {
            let end = start + needle.len();
            if end > label.len() {
                break;
            }
            let bytes = label.as_bytes();
            if &bytes[start..end] == needle
                && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
                && (end == bytes.len() || !bytes[end].is_ascii_alphanumeric())
            {
                return true;
            }
        }
        false
    })
}

/// The zero-model fallback backend. Always returns verdicts in the deliberate
/// low-confidence band; see the module docs.
pub struct HeuristicBackend;

impl DomainClassifier for HeuristicBackend {
    fn name(&self) -> &str {
        "heuristic"
    }

    fn categories(&self) -> Vec<String> {
        let unique: std::collections::BTreeSet<&str> = RULES.iter().map(|r| r.category).collect();
        unique.into_iter().map(str::to_string).collect()
    }

    fn classify(&self, input: &ClassificationInput) -> Option<Verdict> {
        // Lowercase once (page title/text are not normalized like the query
        // name is), then split on dots, hyphens, slashes and spaces: every
        // `-token-` run is therefore already a label of its own.
        let hay = if input.title.is_empty() && input.text.is_empty() {
            input.domain.to_ascii_lowercase()
        } else {
            format!("{} {} {}", input.domain, input.title, input.text).to_ascii_lowercase()
        };
        let labels: Vec<&str> = hay
            .split(['.', '-', '/', ' '])
            .filter(|s| !s.is_empty())
            .collect();
        for rule in RULES {
            for token in rule.tokens {
                if label_has_token(&labels, token) {
                    return Some(Verdict {
                        category: rule.category.to_string(),
                        confidence: rule.rule_confidence,
                        severity: rule.severity,
                        evidence: format!("keyword '{token}'"),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> HeuristicBackend {
        HeuristicBackend
    }

    #[test]
    fn detects_keyword_labels() {
        let v = backend()
            .classify(&ClassificationInput::domain_only("bet-slip.example.com"))
            .expect("gambling verdict");
        assert_eq!(v.category, "gambling");
        assert!(v.confidence < 0.6, "heuristics stay in the low band");

        let v = backend()
            .classify(&ClassificationInput::domain_only("evil-virus-site.net"))
            .expect("malware verdict");
        assert_eq!(v.category, "malware");
        assert_eq!(v.severity, Severity::Threat);
    }

    #[test]
    fn matching_ignores_case() {
        let v = backend()
            .classify(&ClassificationInput::domain_only("Online-CASINO.example"))
            .expect("gambling verdict");
        assert_eq!(v.category, "gambling");
    }

    #[test]
    fn categories_are_sorted_and_unique() {
        let categories = backend().categories();
        let mut expected = categories.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(categories, expected);
        assert!(categories.contains(&"malware".to_string()));
    }

    #[test]
    fn does_not_match_substrings() {
        // 'rocket.example.com' contains 'bet' as a substring but never as a
        // label-boundary token - no verdict.
        assert!(backend()
            .classify(&ClassificationInput::domain_only("rocket.example.com"))
            .is_none());
    }
}
