//! Structured signal observations: every input the threat channel uses,
//! recorded as one row with its source, direction, value, scope and time.
//!
//! The older [`crate::signals`] view reports six inputs for the console and
//! changes nothing. This module is the machine-readable form of the same
//! idea, widened to the whole assessment: the primary model, the MiniLM
//! verifier, the threat feeds, popularity, this network's usage history, the
//! registration date, the name's shape, the page reading and the language
//! model. Each observation says *what* was seen, *where* (the exact hostname
//! or the registrable domain it applies to), *when*, and *which evidence
//! family* it belongs to, so correlated inputs - the primary model and the
//! verifier reading the same name - can be recognised as one piece of
//! evidence rather than two.
//!
//! Observations are recorded beside the verdict, not summed here: fusion is
//! [`crate::fusion`], calibration is [`crate::calibration`], and operator
//! overrides and the existing hard vetoes (allowlist, "not a threat",
//! popular/established disputes, feed corroboration) stay outside both.

use serde::{Deserialize, Serialize};

use crate::age;
use crate::evidence::{LISTED_CONFIDENCE, LISTED_NOTE, UNFLAGGED_NOTE};
use crate::intel::{IntelIndex, Listed};
use crate::store::AiStore;

/// Where one observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    /// The primary fastText/heuristic classifier, reading the name.
    Model,
    /// The MiniLM/ONNX verifier, reading the same name.
    Verifier,
    /// A maintained public threat feed.
    Feed,
    /// The popular-sites list (Tranco).
    Popularity,
    /// This network's own query history for the name.
    NetworkHistory,
    /// The registration date, from RDAP.
    DomainAge,
    /// The shape of the name (machine-generated, free host, public suffix).
    Hostname,
    /// The page the domain serves, as read by the page stage.
    Page,
    /// The local language model, reading a kept page.
    Llm,
}

impl SignalSource {
    /// The stable id used in JSON and in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Verifier => "verifier",
            Self::Feed => "feed",
            Self::Popularity => "popularity",
            Self::NetworkHistory => "network_history",
            Self::DomainAge => "domain_age",
            Self::Hostname => "hostname",
            Self::Page => "page",
            Self::Llm => "llm",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "model" => Self::Model,
            "verifier" => Self::Verifier,
            "feed" => Self::Feed,
            "popularity" => Self::Popularity,
            "network_history" => Self::NetworkHistory,
            "domain_age" => Self::DomainAge,
            "hostname" => Self::Hostname,
            "page" => Self::Page,
            "llm" => Self::Llm,
            _ => return None,
        })
    }

    /// Which correlated evidence bucket this source belongs to. The primary
    /// model and the verifier read the same name, so they are one family:
    /// fusion must not count a corroborating verifier as a second, independent
    /// finding. Everything else is independent evidence, and the operator's
    /// overrides are not observations at all.
    pub fn family(self) -> EvidenceFamily {
        match self {
            Self::Model | Self::Verifier => EvidenceFamily::NameModel,
            _ => EvidenceFamily::Independent,
        }
    }

    pub const ALL: [SignalSource; 9] = [
        Self::Model,
        Self::Verifier,
        Self::Feed,
        Self::Popularity,
        Self::NetworkHistory,
        Self::DomainAge,
        Self::Hostname,
        Self::Page,
        Self::Llm,
    ];
}

/// The correlation group an observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFamily {
    /// The name-only model and its verifier: one reading of the name.
    NameModel,
    /// Evidence from outside the name: feeds, usage, age, page, ...
    Independent,
}

/// Which way an observation points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Threat,
    Benign,
    /// Looked at, nothing either way.
    Neutral,
    /// Nothing to look at (source off, empty, or not recorded).
    Unknown,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Threat => "threat",
            Self::Benign => "benign",
            Self::Neutral => "neutral",
            Self::Unknown => "unknown",
        }
    }

    /// `+1` for a threat-side observation, `-1` for a benign-side one, `0`
    /// otherwise. Fusion multiplies this by the source's weight.
    pub fn sign(self) -> f32 {
        match self {
            Self::Threat => 1.0,
            Self::Benign => -1.0,
            Self::Neutral | Self::Unknown => 0.0,
        }
    }

    pub fn from_signal(direction: &str) -> Self {
        match direction {
            "threat" => Self::Threat,
            "benign" => Self::Benign,
            "neutral" => Self::Neutral,
            _ => Self::Unknown,
        }
    }
}

/// What an observation is about: the exact hostname, or the registrable
/// domain above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Hostname,
    RegisteredDomain,
}

/// The scope an observation applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationScope {
    pub value: String,
    pub kind: Scope,
}

impl ObservationScope {
    fn host(domain: &str) -> Self {
        Self {
            value: domain.trim().trim_end_matches('.').to_ascii_lowercase(),
            kind: Scope::Hostname,
        }
    }

    fn registered(domain: &str) -> Self {
        Self {
            value: registrable(domain),
            kind: Scope::RegisteredDomain,
        }
    }
}

/// One evidence input, as observed at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalObservation {
    pub source: SignalSource,
    pub direction: Direction,
    /// The observation's own threat-side score where it has one: the model's
    /// score, the verifier's corroboration, the feed's listing confidence,
    /// the page's threat reading, or an age/name delta expressed as the
    /// confidence it justifies.
    pub value: Option<f32>,
    /// What was seen, in the operator's words.
    pub explanation: String,
    /// Unix epoch seconds.
    pub observed_at: i64,
    pub scope: ObservationScope,
    /// The correlation group, recorded so a later reader never has to know
    /// which sources are correlated.
    pub family: EvidenceFamily,
}

impl SignalObservation {
    pub fn new(
        source: SignalSource,
        direction: Direction,
        value: Option<f32>,
        explanation: impl Into<String>,
        observed_at: i64,
        scope: ObservationScope,
    ) -> Self {
        Self {
            source,
            direction,
            value,
            explanation: explanation.into(),
            observed_at,
            scope,
            family: source.family(),
        }
    }

    pub fn is_threat(&self) -> bool {
        self.direction == Direction::Threat
    }

    pub fn is_benign(&self) -> bool {
        self.direction == Direction::Benign
    }
}

/// The registrable domain a hostname sits under, by the Public Suffix List.
/// A bare public suffix or an unparseable name is returned unchanged.
pub fn registrable(domain: &str) -> String {
    let name = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&name).unwrap_or(&name).to_string()
}

/// A page reading, as the page stage stored it.
#[derive(Debug, Clone)]
pub struct PageNote {
    pub category: String,
    pub confidence: f32,
    pub cues: Vec<String>,
    pub read_at: i64,
    /// What the page rule did with the reading: the confidence before and
    /// after, and which rule ran.
    pub adjusted: Option<(f32, f32)>,
}

/// What the caller already knows about one verdict. The rest is read from the
/// store and the feed index.
pub struct AssessmentInput<'a> {
    pub domain: &'a str,
    /// The model's own threat score (0 when unknown).
    pub threat_score: f32,
    /// The channel's confidence before calibration.
    pub confidence: f32,
    /// `threat`, `info`, or `disputed`.
    pub severity: &'a str,
    /// The note the threat channel stored.
    pub evidence: &'a str,
    pub page: Option<PageNote>,
    /// When the observation is taken.
    pub now: i64,
}

/// The sources observations read from.
pub struct Context<'a> {
    pub store: &'a AiStore,
    pub intel: &'a IntelIndex,
}

/// Every observation behind one threat verdict, in a stable order. Sources
/// with nothing to say are reported as [`Direction::Unknown`] rather than
/// omitted, so "not looked at" and "looked at, nothing found" stay apart.
pub fn observe(ctx: &Context, input: &AssessmentInput) -> Vec<SignalObservation> {
    let now = input.now;
    vec![
        model(input, now),
        verifier(input, now),
        feed(ctx.intel, input.domain, now),
        popularity(ctx.intel, input.domain, now),
        network_history(ctx.store, input.domain, now),
        domain_age(input, now),
        hostname(input, now),
        page(input, now),
        llm(input, now),
    ]
}

fn model(input: &AssessmentInput, now: i64) -> SignalObservation {
    if input.threat_score > 0.0 {
        SignalObservation::new(
            SignalSource::Model,
            Direction::Threat,
            Some(input.threat_score),
            format!("the model scored the name {:.4}", input.threat_score),
            now,
            ObservationScope::host(input.domain),
        )
    } else {
        SignalObservation::new(
            SignalSource::Model,
            Direction::Unknown,
            None,
            "not scored by the model (a verdict from before scores, or a feed listing alone)",
            now,
            ObservationScope::host(input.domain),
        )
    }
}

/// The verifier's output, read from the severity and the evidence note the
/// verify stage writes. It reads the same name as the primary model, so it is
/// in the same family and its value is a corroboration, never a second
/// independent threat.
fn verifier(input: &AssessmentInput, now: i64) -> SignalObservation {
    let evidence = input.evidence;
    let disputed = input.severity == "disputed";
    if disputed {
        // A parent dispute is a different mechanism (registered-domain
        // reading) and is reported with the network-history/popularity
        // signals; only the verifier's own dispute is a verifier row.
        let by_verifier = evidence.contains("verifier")
            || evidence.contains("embedding")
            || evidence.contains("cosine");
        if by_verifier {
            return SignalObservation::new(
                SignalSource::Verifier,
                Direction::Benign,
                Some(0.0),
                "the MiniLM verifier disagreed with the model's reading",
                now,
                ObservationScope::host(input.domain),
            );
        }
        return SignalObservation::new(
            SignalSource::Verifier,
            Direction::Unknown,
            None,
            "not consulted (the dispute came from the registered-domain reading)",
            now,
            ObservationScope::host(input.domain),
        );
    }
    if evidence.contains("verifier corroborated") || evidence.contains("verifier agreed") {
        return SignalObservation::new(
            SignalSource::Verifier,
            Direction::Threat,
            Some(input.confidence),
            "the MiniLM verifier corroborated the model's reading",
            now,
            ObservationScope::host(input.domain),
        );
    }
    SignalObservation::new(
        SignalSource::Verifier,
        Direction::Unknown,
        None,
        "not consulted (no verifier configured, or the reading tied out)",
        now,
        ObservationScope::host(input.domain),
    )
}

fn feed(intel: &IntelIndex, domain: &str, now: i64) -> SignalObservation {
    if intel.is_empty() {
        return SignalObservation::new(
            SignalSource::Feed,
            Direction::Unknown,
            None,
            "no threat feeds are loaded",
            now,
            ObservationScope::registered(domain),
        );
    }
    if let Some(found) = intel.attribution(domain) {
        let how = match found.listed {
            Listed::Exact => format!("lists {}", found.listed_name),
            Listed::Wildcard => format!("lists {} as a wildcard", found.listed_name),
        };
        return SignalObservation::new(
            SignalSource::Feed,
            Direction::Threat,
            Some(LISTED_CONFIDENCE),
            format!("{} {how} as {}", found.feed.source, found.feed.label),
            now,
            ObservationScope::registered(domain),
        );
    }
    if let Some(parent) = intel.exact_parent(domain) {
        return SignalObservation::new(
            SignalSource::Feed,
            Direction::Neutral,
            None,
            format!(
                "{} lists {} exactly, which does not cover this name",
                parent.feed.source, parent.listed_name
            ),
            now,
            ObservationScope::registered(domain),
        );
    }
    SignalObservation::new(
        SignalSource::Feed,
        Direction::Neutral,
        None,
        "not listed by any threat feed",
        now,
        ObservationScope::registered(domain),
    )
}

fn popularity(intel: &IntelIndex, domain: &str, now: i64) -> SignalObservation {
    if !intel.has_popular() {
        return SignalObservation::new(
            SignalSource::Popularity,
            Direction::Unknown,
            None,
            "no popular-site list is loaded",
            now,
            ObservationScope::registered(domain),
        );
    }
    if intel.is_popular(domain) {
        SignalObservation::new(
            SignalSource::Popularity,
            Direction::Benign,
            None,
            format!(
                "its registered domain is on {}",
                crate::intel::POPULAR.source
            ),
            now,
            ObservationScope::registered(domain),
        )
    } else {
        SignalObservation::new(
            SignalSource::Popularity,
            Direction::Neutral,
            None,
            "not a popular site",
            now,
            ObservationScope::registered(domain),
        )
    }
}

fn network_history(store: &AiStore, domain: &str, now: i64) -> SignalObservation {
    let Ok(seen) = store.sighting(domain) else {
        return SignalObservation::new(
            SignalSource::NetworkHistory,
            Direction::Unknown,
            None,
            "no usage history could be read",
            now,
            ObservationScope::host(domain),
        );
    };
    match seen {
        Some(seen) if seen.established() => SignalObservation::new(
            SignalSource::NetworkHistory,
            Direction::Benign,
            None,
            format!(
                "established on this network: used on {} days by {}+ clients",
                seen.days, seen.clients
            ),
            now,
            ObservationScope::host(domain),
        ),
        Some(seen) => SignalObservation::new(
            SignalSource::NetworkHistory,
            Direction::Neutral,
            None,
            format!(
                "used on {} day(s) by {} client(s), not yet established",
                seen.days, seen.clients
            ),
            now,
            ObservationScope::host(domain),
        ),
        None => SignalObservation::new(
            SignalSource::NetworkHistory,
            Direction::Unknown,
            None,
            "never seen on this network",
            now,
            ObservationScope::host(domain),
        ),
    }
}

/// What the registration-date stage noted: the note is the only place the age
/// is kept (see [`crate::age`]).
fn domain_age(input: &AssessmentInput, now: i64) -> SignalObservation {
    let Some(note) = age_note(input.evidence) else {
        return SignalObservation::new(
            SignalSource::DomainAge,
            Direction::Unknown,
            None,
            "not looked up (domain age is off, or no registration date was found)",
            now,
            ObservationScope::registered(input.domain),
        );
    };
    if note.contains("newly registered") {
        SignalObservation::new(
            SignalSource::DomainAge,
            Direction::Threat,
            Some(input.confidence),
            format!("registered {note}"),
            now,
            ObservationScope::registered(input.domain),
        )
    } else if note.contains("long-standing") {
        SignalObservation::new(
            SignalSource::DomainAge,
            Direction::Benign,
            None,
            format!("registered {note}"),
            now,
            ObservationScope::registered(input.domain),
        )
    } else {
        SignalObservation::new(
            SignalSource::DomainAge,
            Direction::Neutral,
            None,
            format!("registered {note}"),
            now,
            ObservationScope::registered(input.domain),
        )
    }
}

/// The name's shape. Only a machine-generated note is recorded in the
/// evidence; the absence of one is not a clean bill of health, so an
/// unflagged name is reported as neutral (the model's own reading is the
/// separate `model` row).
fn hostname(input: &AssessmentInput, now: i64) -> SignalObservation {
    if input.evidence.contains("machine-generated-looking name") {
        SignalObservation::new(
            SignalSource::Hostname,
            Direction::Threat,
            None,
            "the registered label reads as machine-generated",
            now,
            ObservationScope::registered(input.domain),
        )
    } else if input.evidence.contains(UNFLAGGED_NOTE) {
        SignalObservation::new(
            SignalSource::Hostname,
            Direction::Neutral,
            None,
            "the model saw no threat in the name",
            now,
            ObservationScope::host(input.domain),
        )
    } else {
        SignalObservation::new(
            SignalSource::Hostname,
            Direction::Neutral,
            None,
            "no shape note",
            now,
            ObservationScope::host(input.domain),
        )
    }
}

fn page(input: &AssessmentInput, now: i64) -> SignalObservation {
    let Some(page) = input.page.as_ref() else {
        return SignalObservation::new(
            SignalSource::Page,
            Direction::Unknown,
            None,
            "no page has been read for this verdict",
            now,
            ObservationScope::host(input.domain),
        );
    };
    let ordinary = !is_threat_label(&page.category);
    let cues = if page.cues.is_empty() {
        String::new()
    } else {
        format!(" (cues: {})", page.cues.join(", "))
    };
    let observed_at = if page.read_at > 0 { page.read_at } else { now };
    let effect = match page.adjusted {
        Some((before, after)) if after > before => {
            format!("; the page rule raised the confidence from {before:.2} to {after:.2}")
        }
        Some((before, after)) if after < before => {
            format!("; the page rule lowered the confidence from {before:.2} to {after:.2}")
        }
        _ => String::new(),
    };
    SignalObservation::new(
        SignalSource::Page,
        if ordinary {
            Direction::Benign
        } else {
            Direction::Threat
        },
        Some(if ordinary {
            1.0 - page.confidence
        } else {
            page.confidence
        }),
        format!(
            "the page reads as '{}' at {:.0}%{cues}{effect}",
            page.category,
            page.confidence * 100.0
        ),
        observed_at,
        ObservationScope::host(input.domain),
    )
}

fn is_threat_label(category: &str) -> bool {
    daygle_dns_core::config::THREAT_FAMILIES
        .iter()
        .any(|family| family.eq_ignore_ascii_case(category))
}

/// The language model's effect, read from the note the LLM stage appends.
fn llm(input: &AssessmentInput, now: i64) -> SignalObservation {
    if input.evidence.contains("language model") || input.evidence.contains("llm") {
        SignalObservation::new(
            SignalSource::Llm,
            Direction::Threat,
            Some(input.confidence),
            "the language model read the page as a threat and raised the verdict",
            now,
            ObservationScope::host(input.domain),
        )
    } else {
        SignalObservation::new(
            SignalSource::Llm,
            Direction::Unknown,
            None,
            "not consulted (the language model is off, or has not read this page)",
            now,
            ObservationScope::host(input.domain),
        )
    }
}

fn age_note(evidence: &str) -> Option<&str> {
    let rest = evidence.split_once(age::AGE_NOTE)?.1;
    let end = rest.find(')').map_or(rest.len(), |at| at + 1);
    Some(rest[..end].trim())
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

    fn input<'a>(domain: &'a str, evidence: &'a str) -> AssessmentInput<'a> {
        AssessmentInput {
            domain,
            threat_score: 0.62,
            confidence: 0.62,
            severity: "threat",
            evidence,
            page: None,
            now: 1_700_000_000,
        }
    }

    #[test]
    fn all_nine_inputs_are_reported_in_a_stable_order() {
        let (_dir, store) = store();
        let intel = IntelIndex::default();
        let rows = observe(
            &Context {
                store: &store,
                intel: &intel,
            },
            &input("bad.example", "model, malware at 0.62"),
        );
        let sources: Vec<&str> = rows.iter().map(|r| r.source.as_str()).collect();
        assert_eq!(
            sources,
            vec![
                "model",
                "verifier",
                "feed",
                "popularity",
                "network_history",
                "domain_age",
                "hostname",
                "page",
                "llm"
            ]
        );
        assert_eq!(rows[0].direction, Direction::Threat);
        assert_eq!(rows[0].value, Some(0.62));
        // Nothing else was available: unknown, never a silent "neutral".
        assert_eq!(rows[1].direction, Direction::Unknown);
        assert_eq!(rows[2].direction, Direction::Unknown);
        assert_eq!(rows[4].direction, Direction::Unknown);
        // Every row carries its scope and family.
        for row in &rows {
            assert!(!row.scope.value.is_empty());
            assert_eq!(row.family, row.source.family());
            assert_eq!(row.observed_at, 1_700_000_000);
        }
    }

    #[test]
    fn model_and_verifier_share_one_evidence_family() {
        assert_eq!(SignalSource::Model.family(), EvidenceFamily::NameModel);
        assert_eq!(SignalSource::Verifier.family(), EvidenceFamily::NameModel);
        assert_eq!(SignalSource::Feed.family(), EvidenceFamily::Independent);
        assert_eq!(
            SignalSource::NetworkHistory.family(),
            EvidenceFamily::Independent
        );
    }

    #[test]
    fn a_registered_domain_scope_matches_the_public_suffix_list() {
        assert_eq!(
            registrable("secure.employmenthero.com"),
            "employmenthero.com"
        );
        assert_eq!(
            registrable("paypal-login.github.io"),
            "paypal-login.github.io"
        );
        assert_eq!(registrable("example.com"), "example.com");
        let (_dir, store) = store();
        let rows = observe(
            &Context {
                store: &store,
                intel: &IntelIndex::default(),
            },
            &input("secure.employmenthero.com", "model"),
        );
        let feed = rows
            .iter()
            .find(|r| r.source == SignalSource::Feed)
            .unwrap();
        assert_eq!(feed.scope.kind, Scope::RegisteredDomain);
        assert_eq!(feed.scope.value, "employmenthero.com");
        let model = rows
            .iter()
            .find(|r| r.source == SignalSource::Model)
            .unwrap();
        assert_eq!(model.scope.kind, Scope::Hostname);
    }

    #[test]
    fn a_page_reading_is_a_first_class_observation() {
        let (_dir, store) = store();
        let mut page_input = input("shop.example", "model");
        page_input.page = Some(PageNote {
            category: "shopping".to_string(),
            confidence: 0.8,
            cues: vec!["cart".to_string()],
            read_at: 1_699_999_000,
            adjusted: Some((0.7, 0.6)),
        });
        let rows = observe(
            &Context {
                store: &store,
                intel: &IntelIndex::default(),
            },
            &page_input,
        );
        let page = rows
            .iter()
            .find(|r| r.source == SignalSource::Page)
            .unwrap();
        assert_eq!(page.direction, Direction::Benign);
        assert!(page.explanation.contains("shopping"));
        assert!(page.explanation.contains("lowered"));
    }

    #[test]
    fn a_feed_listing_carries_its_confidence_and_feed_name() {
        let (_dir, store) = store();
        let intel = IntelIndex::from_entries([(
            "bad.example".to_string(),
            false,
            "phishing_army".to_string(),
        )]);
        let rows = observe(
            &Context {
                store: &store,
                intel: &intel,
            },
            &input("bad.example", "model"),
        );
        let feed = rows
            .iter()
            .find(|r| r.source == SignalSource::Feed)
            .unwrap();
        assert_eq!(feed.direction, Direction::Threat);
        assert_eq!(feed.value, Some(LISTED_CONFIDENCE));
        assert!(
            feed.explanation.contains("lists bad.example")
                && feed.explanation.contains("as phishing"),
            "{}",
            feed.explanation
        );
    }
}
