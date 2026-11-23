//! Domain age: when a flagged domain was registered, as evidence about the
//! threat verdict.
//!
//! Phishing and scam sites are overwhelmingly freshly registered: they are
//! put up, used for days and dropped. A site registered years ago that the
//! name-only model flags is far more often a false positive. The registry
//! knows which it is; the domain's spelling does not.
//!
//! After each scan, the threat verdicts that do not yet carry an age note are
//! looked up over RDAP (the registries' own records, through
//! [`daygle_dns_policy::rdap`]; at most [`LOOKUPS_PER_SCAN`] per scan) and
//! adjusted:
//!
//! | Registered                 | Model confidence | Effect                                   |
//! |----------------------------|------------------|------------------------------------------|
//! | within [`NEW_DAYS`] days   | at least 90%     | raised to blocking confidence (99%)      |
//! | within [`NEW_DAYS`] days   | below 90%        | +10%, never above 95%                    |
//! | over [`OLD_DAYS`] days ago | any              | -5%, unless a threat feed confirmed it   |
//! | in between, or unknown     | any              | noted only                               |
//!
//! Only domains the threat channel already flagged are looked up, and each
//! lookup tells the TLD's registry which domain was asked about (not who
//! asked). `ai.domain_age` turns the stage off.

use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::Result;
use daygle_dns_policy::rdap::RegistrationDates;

use crate::evidence::LISTED_CONFIDENCE;
use crate::store::AiStore;

/// Registered this recently: new.
pub const NEW_DAYS: i64 = 14;
/// Registered this long ago: old.
pub const OLD_DAYS: i64 = 2 * 365;
/// Threat verdicts looked up per scan, at most.
pub const LOOKUPS_PER_SCAN: u32 = 16;
/// A new domain flagged at least this confidently is raised to blocking.
const STRONG: f32 = 0.9;
const NEW_RAISE: f32 = 0.1;
const NEW_CAP: f32 = 0.95;
const OLD_LOWER: f32 = 0.05;
/// What the stage writes into a verdict's evidence; a verdict carrying it
/// has been looked up.
pub const AGE_NOTE: &str = ", registered ";

/// The registration-date lookups the AI makes.
pub struct DomainAge {
    store: Arc<AiStore>,
    dates: ArcSwap<RegistrationDates>,
}

impl DomainAge {
    pub fn new(store: Arc<AiStore>, bootstrap_url: &str) -> Arc<Self> {
        Arc::new(Self {
            store,
            dates: ArcSwap::from_pointee(RegistrationDates::new(bootstrap_url)),
        })
    }

    /// Use another RDAP bootstrap file (`policy.rdap_bootstrap`).
    pub fn set_bootstrap(&self, url: &str) {
        if self.dates.load().bootstrap_url() != url {
            self.dates.store(Arc::new(RegistrationDates::new(url)));
        }
    }

    /// Look up and apply the age of new threat verdicts. Returns how many
    /// verdicts changed confidence. Runs on the scan's blocking thread and
    /// needs a Tokio runtime to wait on; without one (direct test calls) it
    /// does nothing.
    pub fn stage(&self, cfg: &AiSettings, now: i64) -> Result<usize> {
        if !cfg.domain_age {
            return Ok(0);
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Ok(0);
        };
        let candidates = self.store.age_candidates(LOOKUPS_PER_SCAN)?;
        if candidates.is_empty() {
            return Ok(0);
        }
        let dates = Arc::new(self.dates.load_full());
        let looked_up: Vec<(String, f32, String, Option<i64>)> = runtime.block_on(async move {
            let mut set = tokio::task::JoinSet::new();
            for (domain, confidence, evidence) in candidates {
                let dates = Arc::clone(&dates);
                set.spawn(async move {
                    let registered = match psl::domain_str(&domain) {
                        Some(registered) => dates
                            .registration_date(registered)
                            .await
                            .map(|date| date.timestamp()),
                        None => None,
                    };
                    (domain, confidence, evidence, registered)
                });
            }
            let mut out = Vec::new();
            while let Some(done) = set.join_next().await {
                if let Ok(row) = done {
                    out.push(row);
                }
            }
            out
        });
        let mut changed = 0usize;
        for (domain, confidence, evidence, registered) in looked_up {
            let Some(registered) = registered else {
                // No date yet (no RDAP server, busy, slow): left for a later
                // scan, which looks again once the lookup is remembered.
                continue;
            };
            let (new_confidence, note) = adjust(confidence, &evidence, registered, now);
            if self.store.apply_age(&domain, new_confidence, &note)?
                && (new_confidence - confidence).abs() > f32::EPSILON
            {
                changed += 1;
            }
        }
        Ok(changed)
    }
}

/// The confidence a threat verdict gets from its domain's registration
/// time, and the note recorded with it (see the module table).
pub fn adjust(confidence: f32, evidence: &str, registered: i64, now: i64) -> (f32, String) {
    let days = ((now - registered) / 86_400).max(0);
    let when = if days >= 365 {
        let years = days / 365;
        format!("{years} year{} ago", if years == 1 { "" } else { "s" })
    } else {
        format!("{days} day{} ago", if days == 1 { "" } else { "s" })
    };
    if days <= NEW_DAYS {
        let raised = if confidence >= STRONG {
            confidence.max(LISTED_CONFIDENCE)
        } else {
            confidence.max((confidence + NEW_RAISE).min(NEW_CAP))
        };
        return (raised, format!("{AGE_NOTE}{when} (newly registered)"));
    }
    if days >= OLD_DAYS && !evidence.contains(", listed by ") {
        return (
            (confidence - OLD_LOWER).max(0.0),
            format!("{AGE_NOTE}{when} (long-standing)"),
        );
    }
    (confidence, format!("{AGE_NOTE}{when}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn new_domains_are_raised_old_ones_lowered() {
        let now = 1_000 * DAY;
        let (c, note) = adjust(0.92, "model", now - 3 * DAY, now);
        assert_eq!(c, LISTED_CONFIDENCE, "new and strongly flagged: blocks");
        assert!(note.contains("3 days ago (newly registered)"), "{note}");
        let (c, _) = adjust(0.6, "model", now - DAY, now);
        assert!((c - 0.7).abs() < 1e-6);
        let (c, _) = adjust(0.89, "model", now, now);
        assert_eq!(c, NEW_CAP, "a weak detection never reaches blocking on age");
        let (c, note) = adjust(0.995, "model", now - 5 * 365 * DAY, now);
        assert!((c - 0.945).abs() < 1e-6);
        assert!(note.contains("5 years ago (long-standing)"), "{note}");
        let (c, _) = adjust(
            0.995,
            "model, listed by Phishing Army as phishing",
            now - 5 * 365 * DAY,
            now,
        );
        assert_eq!(c, 0.995, "a feed-confirmed threat is not lowered");
        let (c, note) = adjust(0.8, "model", now - 100 * DAY, now);
        assert_eq!(c, 0.8);
        assert_eq!(note, ", registered 100 days ago");
    }
}
