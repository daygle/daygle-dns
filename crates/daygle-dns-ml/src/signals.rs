//! Every evidence input, scored on its own.
//!
//! The threat channel reaches a verdict by stacking evidence - the model's
//! score, a threat-feed listing, popularity, how long this network has used
//! the name, its registration date and the shape of the name - into one
//! confidence. That sum is what the block threshold sees, so an operator
//! could not tell which input moved a verdict across it.
//!
//! These signals keep the inputs apart: each one is read from the stored
//! verdict and the same sources the channel used, scored on its own, and
//! reported beside the verdict. They change nothing yet - the block decision
//! is still made from the confidence alone (see [`crate::scanner`]) - so they
//! can be judged in the console before any of them is allowed to weigh in.

use serde::{Deserialize, Serialize};

use crate::age;
use crate::evidence::{LISTED_NOTE, UNFLAGGED_NOTE};
use crate::intel::IntelIndex;
use crate::store::AiStore;

/// Which way a signal points.
pub const THREAT: &str = "threat";
pub const BENIGN: &str = "benign";
/// Looked at, nothing either way.
pub const NEUTRAL: &str = "neutral";
/// Nothing to look at: the source is off, empty, or the row predates it.
pub const UNKNOWN: &str = "unknown";

/// Stable signal ids, in the order [`for_verdict`] reports them.
pub const MODEL: &str = "model";
pub const FEED: &str = "feed";
pub const POPULAR: &str = "popular";
pub const ESTABLISHED: &str = "established";
pub const AGE: &str = "age";
pub const NAME: &str = "name";

/// One evidence input, scored on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// One of [`MODEL`], [`FEED`], ... .
    pub signal: String,
    /// Which way it points: `threat`, `benign`, `neutral` or `unknown`.
    pub direction: String,
    /// The input's own threat-side score, when it has one: the model's
    /// threat score, or the confidence a feed listing carries.
    pub value: Option<f32>,
    /// What it saw, in the operator's words.
    pub detail: String,
}

impl Signal {
    fn new(signal: &str, direction: &str, value: Option<f32>, detail: String) -> Self {
        Self {
            signal: signal.to_string(),
            direction: direction.to_string(),
            value,
            detail,
        }
    }

    pub fn is_threat(&self) -> bool {
        self.direction == THREAT
    }
}

/// The sources the signals read, and nothing else: the stored verdict is the
/// rest.
pub struct Context<'a> {
    pub store: &'a AiStore,
    pub intel: &'a IntelIndex,
}

/// Score the evidence behind one threat verdict. `threat_score` is the
/// model's own score for the name (0 = the row predates scores), and
/// `evidence` is the note the channel stored.
pub fn for_verdict(ctx: &Context, domain: &str, threat_score: f32, evidence: &str) -> Vec<Signal> {
    vec![
        model(threat_score),
        feed(ctx.intel, domain),
        popular(ctx.intel, domain),
        established(ctx.store, domain),
        age(evidence),
        name(evidence),
    ]
}

fn model(threat_score: f32) -> Signal {
    if threat_score > 0.0 {
        Signal::new(
            MODEL,
            THREAT,
            Some(threat_score),
            format!("the model scored it {threat_score:.4}"),
        )
    } else {
        Signal::new(
            MODEL,
            UNKNOWN,
            None,
            "not scored by the model (a verdict from before scores, or a feed listing alone)"
                .to_string(),
        )
    }
}

fn feed(intel: &IntelIndex, domain: &str) -> Signal {
    if intel.is_empty() {
        return Signal::new(
            FEED,
            UNKNOWN,
            None,
            "no threat feeds are loaded".to_string(),
        );
    }
    if let Some(found) = intel.attribution(domain) {
        let how = match found.listed {
            crate::intel::Listed::Exact => "lists this name".to_string(),
            crate::intel::Listed::Wildcard => {
                format!("lists {}", found.listed_name)
            }
        };
        return Signal::new(
            FEED,
            THREAT,
            Some(crate::evidence::LISTED_CONFIDENCE),
            format!(
                "{} {how} as {}",
                found.feed.source, found.feed.label
            ),
        );
    }
    // A parent listed exactly is not evidence about this name: only a
    // wildcard entry covers the names under it.
    if let Some(parent) = intel.exact_parent(domain) {
        return Signal::new(
            FEED,
            NEUTRAL,
            None,
            format!(
                "{} lists {} exactly, which does not cover this name",
                parent.feed.source, parent.listed_name
            ),
        );
    }
    Signal::new(
        FEED,
        NEUTRAL,
        None,
        "not listed by any threat feed".to_string(),
    )
}

fn popular(intel: &IntelIndex, domain: &str) -> Signal {
    if !intel.has_popular() {
        return Signal::new(
            POPULAR,
            UNKNOWN,
            None,
            "no popular-site list is loaded".to_string(),
        );
    }
    if intel.is_popular(domain) {
        Signal::new(
            POPULAR,
            BENIGN,
            None,
            format!("its registered domain is on {}", crate::intel::POPULAR.source),
        )
    } else {
        Signal::new(
            POPULAR,
            NEUTRAL,
            None,
            "not a popular site".to_string(),
        )
    }
}

fn established(store: &AiStore, domain: &str) -> Signal {
    let Ok(seen) = store.sighting(domain) else {
        return Signal::new(
            ESTABLISHED,
            UNKNOWN,
            None,
            "no usage history could be read".to_string(),
        );
    };
    match seen {
        Some(seen) if seen.established() => Signal::new(
            ESTABLISHED,
            BENIGN,
            None,
            format!(
                "used on {} days by {}+ clients",
                seen.days, seen.clients
            ),
        ),
        Some(seen) => Signal::new(
            ESTABLISHED,
            NEUTRAL,
            None,
            format!("used on {} days by {} client(s)", seen.days, seen.clients),
        ),
        None => Signal::new(
            ESTABLISHED,
            UNKNOWN,
            None,
            "never seen on this network".to_string(),
        ),
    }
}

/// What the registration-date stage noted, when it ran: the note is the only
/// place the age is kept (see [`crate::age`]).
fn age(evidence: &str) -> Signal {
    let Some(note) = age_note(evidence) else {
        return Signal::new(
            AGE,
            UNKNOWN,
            None,
            "not looked up (domain age is off, or no registration date was found)".to_string(),
        );
    };
    if note.contains("newly registered") {
        Signal::new(AGE, THREAT, None, format!("registered {note}"))
    } else if note.contains("long-standing") {
        Signal::new(AGE, BENIGN, None, format!("registered {note}"))
    } else {
        Signal::new(AGE, NEUTRAL, None, format!("registered {note}"))
    }
}

fn age_note(evidence: &str) -> Option<&str> {
    let rest = evidence.split_once(age::AGE_NOTE)?.1;
    let end = rest.find(')').map_or(rest.len(), |at| at + 1);
    Some(rest[..end].trim())
}

/// The name's shape: only the generated-looking note is recorded, so its
/// absence is not a clean bill of health.
fn name(evidence: &str) -> Signal {
    if evidence.contains("machine-generated-looking name") {
        Signal::new(
            NAME,
            THREAT,
            None,
            "machine-generated-looking name, first seen today".to_string(),
        )
    } else if evidence.contains(UNFLAGGED_NOTE) {
        Signal::new(
            NAME,
            BENIGN,
            None,
            "the model saw no threat in the name".to_string(),
        )
    } else {
        Signal::new(NAME, NEUTRAL, None, "no shape note".to_string())
    }
}

/// The feed note a verdict carries, for the console's explanation: which feed
/// listed it, and how.
pub fn listed_note(evidence: &str) -> Option<&str> {
    Some(evidence.split_once(LISTED_NOTE)?.1.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::IntelIndex;
    use crate::store::AiStore;

    fn store() -> (tempfile::TempDir, AiStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = AiStore::open(&dir.path().join("ai.db")).expect("AI store");
        (dir, store)
    }

    fn index(entries: [(&str, bool); 2]) -> IntelIndex {
        IntelIndex::from_entries(entries.into_iter().map(|(domain, wildcard)| {
            (
                domain.to_string(),
                wildcard,
                "phishing_army".to_string(),
            )
        }))
    }

    #[test]
    fn a_wildcard_parent_is_a_hit_and_a_plain_parent_is_not() {
        let (_dir, store) = store();
        let intel = index([("bad.example", true), ("plain.example", false)]);
        let ctx = Context {
            store: &store,
            intel: &intel,
        };
        let wildcard = for_verdict(&ctx, "pay.bad.example", 0.0, "no threat in the name");
        let feed = wildcard.iter().find(|s| s.signal == FEED).expect("feed");
        assert_eq!(feed.direction, THREAT);
        assert_eq!(feed.value, Some(crate::evidence::LISTED_CONFIDENCE));
        assert!(feed.detail.contains("lists bad.example as phishing"), "{}", feed.detail);

        let plain = for_verdict(&ctx, "child.plain.example", 0.0, "no threat in the name");
        let feed = plain.iter().find(|s| s.signal == FEED).expect("feed");
        assert_eq!(feed.direction, NEUTRAL, "{}", feed.detail);
        assert!(feed.detail.contains("does not cover this name"), "{}", feed.detail);
    }

    #[test]
    fn every_input_is_its_own_row_and_none_of_them_decides() {
        let (_dir, store) = store();
        let intel = index([("bad.example", false), ("other.example", false)]);
        let ctx = Context {
            store: &store,
            intel: &intel,
        };
        let signals = for_verdict(
            &ctx,
            "bad.example",
            0.62,
            "model, malware at 0.62, registered 3 days ago (newly registered)",
        );
        let ids: Vec<&str> = signals.iter().map(|s| s.signal.as_str()).collect();
        assert_eq!(ids, vec![MODEL, FEED, POPULAR, ESTABLISHED, AGE, NAME]);
        let model = &signals[0];
        assert_eq!((model.direction.as_str(), model.value), (THREAT, Some(0.62)));
        assert_eq!(signals[2].direction, UNKNOWN, "no popular list loaded");
        assert_eq!(signals[3].direction, UNKNOWN, "never seen on the network");
        assert_eq!(signals[4].direction, THREAT);
        assert!(signals[4].detail.contains("3 days ago (newly registered)"));

        let empty = for_verdict(
            &Context {
                store: &store,
                intel: &IntelIndex::default(),
            },
            "bad.example",
            0.0,
            "no threat in the name",
        );
        assert_eq!(empty[0].direction, UNKNOWN);
        assert_eq!(empty[1].direction, UNKNOWN);
        assert!(!empty.iter().any(Signal::is_threat), "{empty:?}");
    }
}
