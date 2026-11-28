//! The scanner's own model maintenance: retraining the classifier from what
//! the scanner has already learned.
//!
//! A fastText model is immutable once trained - there is no online update - so
//! "maintained by the AI" means periodic retraining from the data the scanner
//! itself produces:
//!
//! * the operator's category corrections, which are authoritative;
//! * confident, unexpired verdicts, which keep the model current with what the
//!   network actually resolves.
//!
//! Corrections that say "do not block this" are normally left out: a
//! single-label classifier cannot express a negative inside another label.
//! With `ai.learn_negatives` on, `not_threat` corrections join the set as a
//! [`BENIGN_LABEL`] class instead, so the model can stop repeating the
//! mistake the operator corrected. The threat channel never reports
//! `benign` as a threat ([`crate::channel::ChannelBackend`]), and the class is
//! capped so it cannot come to dominate the corpus. `allow` corrections stay
//! out: allowing a domain says "let it through", not "it is harmless".
//!
//! A retrain starts from the shipped starter corpus, so labels this network
//! has not produced recently are not forgotten, and layers the network's own
//! material on top. A candidate is judged before it can replace anything:
//! about one correction in five (chosen by a hash of the domain, so the same
//! ones stay held back from run to run) is kept out of training, the
//! candidate must not score worse on those held-out labels than the model in
//! use, and it must still be able to emit every threat label the model in use
//! can. Once accepted - by a scheduled run or by hand - it is loaded into the
//! running channels at once; no restart.
//!
//! The model is written beside `ai.db` as `learned.bin` and preferred over
//! `ai.model_path` from then on, unless a channel names its own model or the
//! configured model file is newer. Deleting the file reverts.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};

pub use crate::maintain::{candidate_path, trial_path, trial_secs, Retrainer, Trial, TrialEntry};
use crate::scanner::looks_like_domain;
use crate::store::AiStore;

/// A retrain needs this many examples, across at least [`MIN_LABELS`] labels,
/// before it may replace a model.
pub const MIN_EXAMPLES: usize = 200;
/// One label alone cannot train a classifier.
pub const MIN_LABELS: usize = 2;
/// One label contributes at most this many examples, so a lopsided corpus
/// cannot drown the others.
const MAX_PER_LABEL: usize = 2_000;
/// The label operator "not a threat" corrections train, when
/// `ai.learn_negatives` is on.
pub const BENIGN_LABEL: &str = "benign";
/// Negative examples are capped separately and lower: a class of corrections
/// that only says "not this" must not outweigh the labels it qualifies.
const MAX_NEGATIVE_EXAMPLES: usize = 500;
/// Verdicts read per retrain, strongest first.
const MAX_VERDICTS: u32 = 20_000;
/// A candidate must reproduce at least this share of whatever it is judged on.
pub(crate) const MIN_ACCURACY: f32 = 0.5;
/// A candidate may trail the model in use by this much on held-out labels
/// before it is rejected: small differences are noise, a real regression is
/// not.
pub(crate) const VALIDATION_SLACK: f32 = 0.02;
/// About one correction in this many is held back for validation, once there
/// are enough.
const HOLDOUT_EVERY: usize = 5;
/// The labelled corpus the shipped starter model was trained from. Every
/// retrain includes it, so a label this network has not produced lately is
/// kept rather than silently dropped from the model.
const STARTER_CORPUS: &str = include_str!("../../../models/starter-training.txt");
/// The corpus's file name in the models directory, where a models bundle
/// installs the copy that matches its starter model.
pub const STARTER_CORPUS_FILE: &str = "starter-training.txt";
pub const BUILTIN_BINARY_MODEL: &str = "builtin-binary";
pub(crate) const BINARY_STARTER_FILE: &str = "binary-starter-v1.bin";

pub(crate) fn binary_training_record(learned: &Path) -> Option<serde_json::Value> {
    let raw = std::fs::read(stats_path(learned)).ok()?;
    serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()?
        .get("binary_training")
        .cloned()
}

pub(crate) fn binary_starter_pairs() -> Vec<(String, String)> {
    let mut domains = std::collections::BTreeMap::new();
    for (label, domain) in starter_pairs() {
        let threat = matches!(label.as_str(), "malware" | "phishing" | "scam");
        domains
            .entry(domain)
            .and_modify(|value| *value |= threat)
            .or_insert(threat);
    }
    domains
        .into_iter()
        .map(|(domain, threat)| binary_pair(domain, threat))
        .collect()
}

pub(crate) fn binary_pair(domain: String, threat: bool) -> (String, String) {
    (
        if threat {
            crate::backend::BINARY_THREAT_LABEL
        } else {
            BENIGN_LABEL
        }
        .to_string(),
        domain,
    )
}

fn binary_evaluation(domain: &str) -> bool {
    use sha2::{Digest, Sha256};
    let root = crate::assessment::registrable(domain);
    Sha256::digest(root.as_bytes())[0] < 128
}

/// One stable partition per registrable domain. Only external evidence and
/// explicit adjudications may supply outcomes. Model, verifier and automatic
/// page predictions never enter this dataset.
pub(crate) fn binary_outcomes(
    store: &AiStore,
    settings: &AiSettings,
    intel: &crate::intel::IntelIndex,
    evaluate: bool,
    before: i64,
) -> Result<Vec<(String, bool, crate::threshold::LabelSource)>> {
    use crate::threshold::LabelSource;
    let starter_roots: HashSet<_> = binary_starter_pairs()
        .iter()
        .map(|(_, domain)| crate::assessment::registrable(domain))
        .collect();
    let mut outcomes = std::collections::BTreeMap::new();
    for domain in intel.popular_sample() {
        if intel.label_for(&domain).is_none() {
            outcomes.insert(domain, (false, LabelSource::Popular));
        }
    }
    let (training, probe) = intel.sample(|_| true);
    for (_, domain) in training.into_iter().chain(probe) {
        outcomes.insert(domain, (true, LabelSource::FeedListing));
    }
    if !evaluate && settings.fetch_pages && settings.monitor_page_discovery {
        let exemptions = store.allow_overrides()?;
        let mut page_roots = HashSet::new();
        for (domain, category) in store.directly_corroborated_discoveries(before)? {
            if page_roots.len() >= 256 {
                break;
            }
            if !binary_evaluation(&domain)
                && !intel.is_popular(&domain)
                && !outcomes.contains_key(&domain)
                && !crate::scanner::exempt(&domain, &exemptions)
                && settings.label_role(category.as_deref().unwrap_or("phishing"))
                    != daygle_dns_core::config::LabelRole::Suppressed
                && !store
                    .sighting(&domain)?
                    .is_some_and(|sighting| sighting.established())
                && page_roots.insert(crate::assessment::registrable(&domain))
            {
                outcomes.insert(domain, (true, LabelSource::DirectPage));
            }
        }
    }
    for domain in store.reviewed_page_discovery_labels(before)?.into_keys() {
        outcomes.insert(domain, (true, LabelSource::OperatorCorrection));
    }
    for row in store.corrections_between(0, before)?.into_iter().rev() {
        let domain = row.domain.trim().trim_matches('.').to_ascii_lowercase();
        match row.action.as_str() {
            "not_threat" => {
                if settings.learn_negatives {
                    outcomes.insert(domain, (false, LabelSource::OperatorCorrection));
                } else {
                    outcomes.remove(&domain);
                }
            }
            "category"
                if row.category == crate::backend::BINARY_THREAT_LABEL
                    || is_threat_label(settings, &row.category) =>
            {
                outcomes.insert(domain, (true, LabelSource::OperatorCorrection));
            }
            _ => {}
        }
    }
    let mut evaluation_roots = HashSet::new();
    Ok(outcomes
        .into_iter()
        .filter(|(domain, _)| {
            let root = crate::assessment::registrable(domain);
            looks_like_domain(domain)
                && binary_evaluation(domain) == evaluate
                && !starter_roots.contains(&root)
                && (!evaluate || evaluation_roots.insert(root))
        })
        .map(|(domain, (outcome, source))| (domain, outcome, source))
        .collect())
}

pub(crate) fn prepare_binary_starter(path: &Path) -> Result<()> {
    if is_binary_model(path) {
        return Ok(());
    }
    let (validation, training): (Vec<_>, Vec<_>) = binary_starter_pairs()
        .into_iter()
        .partition(|(_, domain)| crate::threshold::held_out(domain));
    let dir = tempfile::tempdir()?;
    let staged = dir.path().join("model.bin");
    train(&training, &staged)?;
    let predicted = predict_all(&staged, &validation)?;
    for label in [crate::backend::BINARY_THREAT_LABEL, BENIGN_LABEL] {
        if !validation
            .iter()
            .zip(&predicted)
            .any(|((expected, _), actual)| expected == label && actual == label)
        {
            return Err(DaygleError::Config(
                "the built-in binary starter did not detect both classes on held-out names"
                    .to_string(),
            ));
        }
    }
    crate::candidate::write_artifact(path, &std::fs::read(staged)?)
}
/// A held-out threat family may take at most this share of the threat
/// verdicts out of training, so one sprawling word family cannot starve the
/// threat labels of examples.
const MAX_HELD_SHARE: usize = 4;

/// What one collection pass produced.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TrainingStats {
    pub examples: usize,
    pub labels: usize,
    /// Examples that came from an operator relabel.
    pub corrections: usize,
    /// Examples that came from the scanner's own confident verdicts.
    pub verdicts: usize,
    /// `not_threat` corrections trained as [`BENIGN_LABEL`] (0 unless
    /// `ai.learn_negatives` is on).
    pub negatives: usize,
    /// Examples from the shipped starter corpus that keep known labels alive.
    pub starter: usize,
    /// Verdicts of the scanner's own left out because nothing independent
    /// (the reference model, the page, a threat feed) agreed with them.
    pub unconfirmed: usize,
    /// Names from the maintained threat feeds that trained a threat label.
    pub intel: usize,
}

impl TrainingStats {
    /// Examples this install contributed: what decides whether a retrain is
    /// worth running at all.
    pub fn local(&self) -> usize {
        self.corrections + self.verdicts + self.negatives
    }
}

/// The training set plus the labels held back to judge the result.
pub struct Dataset {
    pub pairs: Vec<(String, String)>,
    pub validation: Vec<(String, String)>,
    /// Threat verdicts held back from training when negatives are on. The
    /// gate refuses a candidate that reads any of them as `benign`: a
    /// negative class must not buy its accuracy with detections.
    pub threat_validation: Vec<(String, String)>,
    /// Threat-feed names held back from training: every candidate must still
    /// detect at least as many of them as the model in use does.
    pub intel_validation: Vec<(String, String)>,
    pub stats: TrainingStats,
}

/// The model the scanner maintains for itself: beside the verdict store, so it
/// travels with the data rather than with the install.
pub fn learned_model_path(database: &Path) -> PathBuf {
    database.with_file_name("learned.bin")
}

/// Where the outcome of the last successful retrain is recorded.
pub fn stats_path(learned: &Path) -> PathBuf {
    learned.with_extension("json")
}

/// The model a retrain replaced. Kept so one bad-but-accepted model can be
/// rolled back without losing the previous one.
pub fn previous_model_path(learned: &Path) -> PathBuf {
    learned.with_extension("prev.bin")
}

pub(crate) fn previous_stats_path(learned: &Path) -> PathBuf {
    learned.with_extension("prev.json")
}

/// The training set and its held-out slice: corrections first, then confident
/// verdicts, then the starter corpus. One domain contributes one label: the
/// newest correction wins, then the strongest verdict, then the corpus.
pub fn collect_dataset(store: &AiStore, settings: &AiSettings) -> Result<Dataset> {
    collect_dataset_with(store, settings, &Sources::default())
}

/// Whether `label` counts as a threat: ticked under Labels Treated as
/// Threats, and never `benign`.
pub fn is_threat_label(settings: &AiSettings, label: &str) -> bool {
    label != BENIGN_LABEL && settings.is_auto_block_category(label)
}

/// The fixed reference a live retrain checks the scanner's own verdicts
/// against. It must never be the model being retrained: a reference that
/// drifts with the model cannot stop the model's mistakes from feeding on
/// themselves.
#[derive(Clone, Copy)]
pub enum Anchor<'a> {
    /// The configured (shipped) model.
    Model(&'a fasttext::FastText),
    /// The built-in keyword rules: the reference when no model file is
    /// configured. They cover fewer labels than a model, so less of the
    /// scanner's own output trains - deliberately: a learned model that went
    /// live on such an install used to train on its own verdicts unchecked.
    Rules,
}

impl Anchor<'_> {
    /// The label this reference gives `domain`, if any.
    pub fn label(&self, domain: &str) -> Option<String> {
        match self {
            Anchor::Model(model) => top_label(model, domain),
            Anchor::Rules => {
                use crate::backend::{ClassificationInput, DomainClassifier};
                crate::heuristic::HeuristicBackend
                    .classify(&ClassificationInput::domain_only(domain))
                    .map(|v| v.category)
            }
        }
    }
}

/// What a retrain draws on beyond the store itself.
#[derive(Default)]
pub struct Sources<'a> {
    /// The labels of the model in use: starter examples outside them are left
    /// out, so a custom model's label space is not widened by the starter's.
    pub known: Option<&'a HashSet<String>>,
    /// The starter corpus text; `None` uses the copy built into the binary.
    pub starter: Option<&'a str>,
    /// The fixed reference (the configured, shipped model, or the built-in
    /// keyword rules when no model file is configured). When set, a verdict
    /// of the scanner's own only trains if this reference or an independent
    /// source agrees with it, so the scanner cannot teach itself its own
    /// mistakes. `None` trains every confident verdict: for offline tools and
    /// tests only - a live retrain always passes one.
    pub anchor: Option<Anchor<'a>>,
    /// Independent confirmations of a label, by domain: what the page said,
    /// or the label the verifier model corroborated.
    pub confirmations: Option<&'a std::collections::HashMap<String, String>>,
    /// The maintained threat feeds: a confirmation for the scanner's own
    /// threat verdicts, a held-out probe for the gate and training material
    /// for the threat labels.
    pub intel: Option<&'a crate::intel::IntelIndex>,
}

/// [`collect_dataset`] with the extra [`Sources`] a live retrain uses.
pub fn collect_dataset_with(
    store: &AiStore,
    settings: &AiSettings,
    sources: &Sources<'_>,
) -> Result<Dataset> {
    let known = sources.known;
    // Two labels agree when they are the same, or both are threats: a
    // phishing verdict confirmed as scam is still a confirmed threat.
    let agrees = |left: &str, right: &str| {
        left == right || (is_threat_label(settings, left) && is_threat_label(settings, right))
    };
    let now = chrono::Utc::now().timestamp();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut validation: Vec<(String, String)> = Vec::new();
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut corrected: HashSet<String> = HashSet::new();
    // Domains that already carry a label: one domain, one label, so a
    // single-label model is never trained on a contradiction.
    let mut labelled: HashSet<String> = HashSet::new();
    let mut stats = TrainingStats::default();

    // Operator labels, oldest-filed last: deterministic enough, and the
    // holdout is what makes the gate meaningful.
    let mut corrections: Vec<(String, String)> = Vec::new();
    for correction in store.corrections()? {
        let label = correction.category.trim().to_ascii_lowercase();
        let domain = correction
            .domain
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if !looks_like_domain(&domain) {
            continue;
        }
        // Newest first: a later correction for the same domain supersedes
        // an older one (a relabel after a "not a threat", or the reverse).
        let superseded = corrected.contains(&domain);
        match correction.action.as_str() {
            "category" if !label.is_empty() => {
                corrected.insert(domain.clone());
                if !superseded {
                    corrections.push((label, domain));
                }
            }
            // The operator denied the machine label, so it must not train the
            // model either - whether or not the negation itself is learned.
            // (`confident_verdicts` already leaves overridden domains out;
            // keeping the set here means that holds even if that changes.)
            // When negatives are on, the denial is a label of its own and the
            // pair trains `benign`.
            "not_threat" => {
                corrected.insert(domain.clone());
                if settings.learn_negatives && !superseded {
                    corrections.push((BENIGN_LABEL.to_string(), domain));
                }
            }
            _ => {}
        }
    }
    // Held out by a hash of the domain, not by position: a new correction
    // must not reshuffle the held-out set, or the model in use - trained on
    // most of the new set last time - would be judged on its own training data.
    let hold_out = corrections.len() >= HOLDOUT_EVERY;
    let mut negatives = 0usize;
    for (label, domain) in corrections {
        labelled.insert(domain.clone());
        if hold_out && hash_selected(&domain) {
            validation.push((label, domain));
            continue;
        }
        if label == BENIGN_LABEL && negatives >= MAX_NEGATIVE_EXAMPLES {
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            if label == BENIGN_LABEL {
                negatives += 1;
            } else {
                stats.corrections += 1;
            }
        }
    }
    stats.negatives = negatives;

    // Threat-feed names: a stable one in five is held out to judge the
    // result, the rest train. A name the operator corrected is theirs to
    // decide, whatever a feed says.
    let (intel_training, intel_validation) = match sources.intel {
        Some(index) => {
            let (training, probe) =
                index.sample(|label| crate::intel::wanted_label(settings, known, label));
            let keep = |pairs: Vec<(String, String)>| -> Vec<(String, String)> {
                pairs
                    .into_iter()
                    .filter(|(_, domain)| !corrected.contains(domain))
                    .collect()
            };
            (keep(training), keep(probe))
        }
        None => (Vec::new(), Vec::new()),
    };
    let intel_held: HashSet<&str> = intel_validation.iter().map(|(_, d)| d.as_str()).collect();

    let mut threat_validation: Vec<(String, String)> = Vec::new();
    let mut deferred_threats: Vec<(String, String)> = Vec::new();
    for (channel, label, domain) in store.confident_verdicts(
        settings.category_confidence_floor,
        settings.block_threshold,
        now,
        MAX_VERDICTS,
    )? {
        let label = label.trim().to_ascii_lowercase();
        let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
        // A corrected domain never contributes its machine label, whether the
        // correction is training data or held-out validation.
        if label.is_empty()
            || corrected.contains(&domain)
            || intel_held.contains(domain.as_str())
            || !looks_like_domain(&domain)
        {
            continue;
        }
        // Anchored self-training: the scanner's own label trains only when
        // something independent of it agrees - the fixed reference model or
        // what the page itself says. A label nothing else backs stays out,
        // so a systematic mistake cannot feed on itself.
        if let Some(anchor) = sources.anchor {
            let anchored = anchor.label(&domain);
            let paged = sources.confirmations.and_then(|pages| pages.get(&domain));
            let listed = sources.intel.and_then(|index| index.label_for(&domain));
            let confirmed = anchored.as_deref().is_some_and(|a| agrees(a, &label))
                || paged.is_some_and(|p| agrees(p, &label))
                || listed.is_some_and(|l| agrees(l, &label));
            if !confirmed {
                stats.unconfirmed += 1;
                continue;
            }
        }
        // Strongest verdict first: a domain with verdicts on both channels
        // trains the stronger label only.
        if !labelled.insert(domain.clone()) {
            continue;
        }
        // With a benign class in the training set, whole word families stay
        // out of training so the gate can ask whether the class has started
        // swallowing threats instead of only how accurate it is. Deciding
        // after the loop keeps the sample independent of confidence order and
        // lets a small install still have one.
        if settings.learn_negatives && channel == "threat" {
            deferred_threats.push((label, domain));
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            stats.verdicts += 1;
        }
    }

    if settings.learn_negatives && !deferred_threats.is_empty() {
        // Hold out whole word families, not single verdicts. Components are
        // grouped by shared tokens, so a held-out family has no word in
        // common with anything left in training.
        let domains: Vec<String> = deferred_threats
            .iter()
            .map(|(_, domain)| domain.clone())
            .collect();
        let components = token_components(&domains);
        let disjoint = components.len() > 1;
        let selected = selected_components(&components);
        let mut component_of = vec![String::new(); domains.len()];
        for (key, members) in &components {
            for index in members {
                component_of[*index] = key.clone();
            }
        }
        let mut held = vec![false; deferred_threats.len()];
        for (index, (_, domain)) in deferred_threats.iter().enumerate() {
            held[index] = if disjoint {
                selected.contains(&component_of[index])
            } else {
                // One word component: no disjoint split exists, so hold back
                // names and let the novel variant and the current-model
                // comparison carry the check.
                hash_selected(domain)
            };
        }
        if !held.iter().any(|held| *held) {
            held[0] = true;
        }
        let mut held_pairs = Vec::new();
        for ((label, domain), is_held) in deferred_threats.into_iter().zip(held) {
            if is_held {
                held_pairs.push((label, domain));
            } else if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
                stats.verdicts += 1;
            }
        }
        threat_validation = spread_by_family(held_pairs, MAX_PROBE);
    }

    // Threat-feed names next: after everything local, so a domain this
    // network labelled keeps that label, and before the starter corpus, so
    // current threat names outweigh the shipped examples.
    for (label, domain) in intel_training {
        if labelled.contains(&domain) {
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            labelled.insert(domain);
            stats.intel += 1;
        }
    }

    // The starter corpus last: it fills in labels the network has not
    // produced, never outweighs or contradicts local material, and never
    // re-teaches a label for a domain the operator corrected.
    let starter = match sources.starter {
        Some(text) => starter_pairs_from(text),
        None => starter_pairs(),
    };
    for (label, domain) in starter {
        if known.is_some_and(|known| !known.contains(&label)) {
            continue;
        }
        if label == BENIGN_LABEL
            || labelled.contains(&domain)
            || corrected.contains(&domain)
            || intel_held.contains(domain.as_str())
        {
            continue;
        }
        if push(&mut pairs, &mut labels, &mut seen, &label, &domain) {
            labelled.insert(domain);
            stats.starter += 1;
        }
    }

    stats.examples = pairs.len();
    stats.labels = labels.len();
    Ok(Dataset {
        pairs,
        validation,
        threat_validation,
        intel_validation,
        stats,
    })
}

/// The whole set, held-out labels included: what the tests and callers that
/// only want "everything known" should read.
pub fn collect(
    store: &AiStore,
    settings: &AiSettings,
) -> Result<(Vec<(String, String)>, TrainingStats)> {
    let mut dataset = collect_dataset(store, settings)?;
    let mut pairs = std::mem::take(&mut dataset.pairs);
    pairs.extend(dataset.validation.iter().cloned());
    pairs.extend(dataset.threat_validation.iter().cloned());
    pairs.extend(dataset.intel_validation.iter().cloned());
    Ok((pairs, dataset.stats))
}

/// `(label, domain)` pairs from the shipped starter corpus.
pub fn starter_pairs() -> Vec<(String, String)> {
    starter_pairs_from(STARTER_CORPUS)
}

/// The starter corpus beside the configured model, when a models bundle
/// shipped one: it then matches the model it came with. `None` falls back to
/// the copy built into the binary.
pub fn bundled_starter_corpus(model_path: &str) -> Option<String> {
    let model = Path::new(model_path.trim());
    // Nothing configured: there is no models directory to look beside, so the
    // copy built into the binary applies.
    if model.as_os_str().is_empty() {
        return None;
    }
    let dir = model.parent()?;
    let text = std::fs::read_to_string(dir.join(STARTER_CORPUS_FILE)).ok()?;
    (!starter_pairs_from(&text).is_empty()).then_some(text)
}

/// `(label, domain)` pairs from corpus text in fastText supervised format.
pub fn starter_pairs_from(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("__label__")?;
            let (label, domain) = rest.split_once(char::is_whitespace)?;
            let label = label.trim().to_ascii_lowercase();
            let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
            (!label.is_empty() && looks_like_domain(&domain)).then_some((label, domain))
        })
        .collect()
}

/// The top label `model` gives `domain`, without the `__label__` prefix.
pub(crate) fn top_label(model: &fasttext::FastText, domain: &str) -> Option<String> {
    model
        .predict(domain, 1, 0.0)
        .first()
        .map(|p| p.label.trim_start_matches("__label__").to_ascii_lowercase())
}

/// The labels a fastText model at `model` can emit, or `None` when the file
/// is not a loadable fastText model (no model, the heuristic backend).
pub fn model_labels(model: &Path) -> Option<HashSet<String>> {
    if !model.is_file() {
        return None;
    }
    let loaded = fasttext::FastText::load_model(model).ok()?;
    Some(
        loaded
            .get_labels()
            .0
            .iter()
            .filter_map(|label| label.strip_prefix("__label__"))
            .map(str::to_ascii_lowercase)
            .filter(|label| !label.is_empty())
            .collect(),
    )
}

pub(crate) fn is_binary_model(model: &Path) -> bool {
    model_labels(model).is_some_and(|labels| {
        labels.len() == 2
            && labels.contains(BENIGN_LABEL)
            && labels.contains(crate::backend::BINARY_THREAT_LABEL)
    })
}

/// Refuse a candidate that cannot emit a threat label the model in use can:
/// a detector that has forgotten `malware` will never report it again, and
/// no held-out score notices a label that never comes up.
pub(crate) fn refuse_forgotten_threats(
    settings: &AiSettings,
    current: Option<&HashSet<String>>,
    candidate: &HashSet<String>,
) -> Result<()> {
    let Some(current) = current else {
        return Ok(());
    };
    let mut missing: Vec<&str> = current
        .iter()
        .filter(|label| is_threat_label(settings, label) && !candidate.contains(*label))
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    Err(DaygleError::Config(format!(
        "the retrained model can no longer report the threat label(s) {}, so the current model was kept",
        missing.join(", ")
    )))
}

fn push(
    pairs: &mut Vec<(String, String)>,
    labels: &mut BTreeMap<String, usize>,
    seen: &mut HashSet<(String, String)>,
    label: &str,
    domain: &str,
) -> bool {
    if label == crate::backend::BINARY_THREAT_LABEL
        || labels.get(label).copied().unwrap_or(0) >= MAX_PER_LABEL
    {
        return false;
    }
    if !seen.insert((label.to_string(), domain.to_string())) {
        return false;
    }
    *labels.entry(label.to_string()).or_insert(0) += 1;
    pairs.push((label.to_string(), domain.to_string()));
    true
}

/// Train a supervised classifier into `out`. Settings match the shipped
/// starter model (small, CPU-only, character n-grams) so a retrained file is a
/// drop-in replacement.
pub fn train(pairs: &[(String, String)], out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let corpus = out.with_extension("fasttext");
    let mut expanded = String::new();
    for (label, domain) in pairs {
        for variant in variants(domain) {
            // fastText's supervised format: the prefix is what makes the first
            // token a label rather than a feature.
            expanded.push_str("__label__");
            expanded.push_str(label);
            expanded.push(' ');
            expanded.push_str(&variant);
            expanded.push('\n');
        }
    }
    std::fs::write(&corpus, expanded)?;

    let mut args = fasttext::args::Args {
        input: corpus.clone(),
        output: out.with_extension("model"),
        ..Default::default()
    };
    args.apply_supervised_defaults();
    args.dim = 24;
    args.lr = 0.3;
    args.epoch = 40;
    args.word_ngrams = 1;
    args.minn = 3;
    args.maxn = 5;
    args.bucket = 50_000;
    args.thread = 2;
    args.seed = 42;
    args.verbose = 0;

    let trained = fasttext::FastText::train(args)
        .map_err(|e| DaygleError::Config(format!("model training failed: {e:?}")))
        .and_then(|model| {
            model
                .save_model(out)
                .map_err(|e| DaygleError::Config(format!("model save failed: {e:?}")))
        });
    let _ = std::fs::remove_file(&corpus);
    trained?;
    // The file is renamed into place next; make sure its bytes reach the
    // disk first, so a power cut cannot leave a truncated model behind.
    // Windows requires write access on the handle used to flush the file.
    std::fs::File::options().write(true).open(out)?.sync_all()?;
    Ok(())
}

/// The top-1 label `model` gives each domain, in order.
pub(crate) fn predict_all(model: &Path, pairs: &[(String, String)]) -> Result<Vec<String>> {
    let trained = fasttext::FastText::load_model(model)
        .map_err(|e| DaygleError::Config(format!("model reload failed: {e:?}")))?;
    Ok(pairs
        .iter()
        .map(|(_, domain)| {
            trained
                .predict(domain, 1, 0.0)
                .first()
                .map(|p| p.label.trim_start_matches("__label__").to_ascii_lowercase())
                .unwrap_or_default()
        })
        .collect())
}

/// How much of `pairs` a model at `model` gets right (top-1).
pub fn probe_accuracy(model: &Path, pairs: &[(String, String)]) -> Result<f32> {
    if pairs.is_empty() {
        return Ok(0.0);
    }
    let predicted = predict_all(model, pairs)?;
    let right = predicted
        .iter()
        .zip(pairs)
        .filter(|(got, (label, _))| *got == label)
        .count();
    Ok(right as f32 / pairs.len() as f32)
}

/// The label that names a registered domain: the Public Suffix List decides
/// where the suffix ends, so `shop.example.co.uk` is the `example` family and
/// not the `co` one. Unknown suffixes (including the reserved `.example`
/// used in tests) fall back to the label before the last one.
fn registrable_label(domain: &str) -> &str {
    let name = domain.trim().trim_matches('.');
    if let Some(registrable) = psl::domain_str(name) {
        return registrable
            .split_once('.')
            .map(|(label, _)| label)
            .unwrap_or(registrable);
    }
    let labels: Vec<&str> = name.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        labels.first().copied().unwrap_or("")
    }
}

/// The alphabetic words of a domain's registrable label.
fn family_words(domain: &str) -> Vec<String> {
    let mut words: Vec<String> = registrable_label(domain)
        .split(['-', '_'])
        .map(str::to_ascii_lowercase)
        .filter(|word| word.chars().any(|c| c.is_ascii_alphabetic()))
        .filter(|word| word != "www")
        .collect();
    words.sort();
    words.dedup();
    words
}

/// The word set of a domain's registrable label, used as a readable family
/// name. Whole families are grouped by shared tokens below, so this is a
/// label for reporting and sampling, not the selection key itself.
pub fn family_key(domain: &str) -> String {
    family_words(domain).join("-")
}

/// Deterministic one-in-five sample of keys. Hashing a component, not a
/// single name, is what keeps a whole word family out of training.
pub fn hash_selected(text: &str) -> bool {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.is_multiple_of(HOLDOUT_EVERY as u64)
}

/// Group domains whose word sets share a token, transitively. Holding out a
/// component therefore leaves no training name sharing a word with it.
fn token_components(domains: &[String]) -> Vec<(String, Vec<usize>)> {
    fn find(parent: &mut [usize], index: usize) -> usize {
        let mut root = index;
        while parent[root] != root {
            root = parent[root];
        }
        let mut current = index;
        while parent[current] != root {
            let next = parent[current];
            parent[current] = root;
            current = next;
        }
        root
    }

    let mut parent: Vec<usize> = (0..domains.len()).collect();
    let mut owner: BTreeMap<String, usize> = BTreeMap::new();
    for (index, domain) in domains.iter().enumerate() {
        for token in family_words(domain) {
            match owner.get(&token).copied() {
                Some(previous) => {
                    let left = find(&mut parent, index);
                    let right = find(&mut parent, previous);
                    if left != right {
                        parent[left] = right;
                    }
                }
                None => {
                    owner.insert(token, index);
                }
            }
        }
    }

    let mut tokens: BTreeMap<usize, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, domain) in domains.iter().enumerate() {
        let root = find(&mut parent, index);
        tokens.entry(root).or_default().extend(family_words(domain));
        members.entry(root).or_default().push(index);
    }
    let mut components: Vec<(String, Vec<usize>)> = members
        .into_iter()
        .map(|(root, members)| {
            let words: Vec<String> = tokens
                .remove(&root)
                .unwrap_or_default()
                .into_iter()
                .collect();
            (words.join("|"), members)
        })
        .collect();
    components.sort_by(|left, right| left.0.cmp(&right.0));
    components
}

/// Pick whole components; force one when the hash lands nowhere, and keep at
/// least one for training. A corpus with a single component has no disjoint
/// split, so the caller falls back to individual names. Real names chain
/// through common words ("login", "secure", "app") into one sprawling
/// component, so no component larger than a quarter of the names is held
/// out, and the held-out total stops at that share too: the threat labels
/// always keep most of their examples.
fn selected_components(components: &[(String, Vec<usize>)]) -> std::collections::BTreeSet<String> {
    let total: usize = components.iter().map(|(_, members)| members.len()).sum();
    let budget = (total / MAX_HELD_SHARE).max(1);
    let fits = |members: &Vec<usize>| members.len() <= budget;
    let mut selected = std::collections::BTreeSet::new();
    let mut held = 0usize;
    for (key, members) in components {
        if hash_selected(key) && fits(members) && held + members.len() <= budget {
            held += members.len();
            selected.insert(key.clone());
        }
    }
    if selected.is_empty() && components.len() > 1 {
        if let Some((first, _)) = components.iter().find(|(_, members)| fits(members)) {
            selected.insert(first.clone());
        }
    }
    if components.len() > 1 && selected.len() == components.len() {
        if let Some(last) = selected.iter().next_back().cloned() {
            selected.remove(&last);
        }
    }
    selected
}

/// At most `limit` names, taking one from each family in turn, so a large
/// family cannot crowd the others out of a probe.
fn spread_by_family(pairs: Vec<(String, String)>, limit: usize) -> Vec<(String, String)> {
    let mut groups: BTreeMap<String, std::collections::VecDeque<(String, String)>> =
        BTreeMap::new();
    for pair in pairs {
        groups
            .entry(family_key(&pair.1))
            .or_default()
            .push_back(pair);
    }
    let mut out = Vec::new();
    while out.len() < limit {
        let mut moved = false;
        for group in groups.values_mut() {
            if let Some(pair) = group.pop_front() {
                out.push(pair);
                moved = true;
                if out.len() >= limit {
                    break;
                }
            }
        }
        if !moved {
            break;
        }
    }
    out
}

/// A held-out family's registrable label with its words reordered, so the
/// probe scores a name whose word order the store never recorded. The suffix
/// and any subdomain are preserved.
pub fn held_out_variant(domain: &str) -> String {
    let name = domain.trim().trim_matches('.');
    let label = registrable_label(name);
    if label.is_empty() {
        return name.to_string();
    }
    let mut words: Vec<&str> = label
        .split(['-', '_'])
        .filter(|word| !word.is_empty())
        .filter(|word| word.chars().any(|c| c.is_ascii_alphabetic()))
        .collect();
    if words.len() > 1 {
        words.reverse();
    }
    words.push("probe");
    let replacement = words.join("-");
    match name.rfind(label) {
        Some(at) if name.is_char_boundary(at + label.len()) => {
            format!("{}{replacement}{}", &name[..at], &name[at + label.len()..])
        }
        _ => replacement,
    }
}

/// Most held-out threat names one model probe scores. Bounded so the update
/// health check stays fast on a large store.
pub const MAX_PROBE: usize = 200;

/// What probing a model against the store's held-out threats found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatProbe {
    pub checked: usize,
    pub benign: usize,
    pub downgraded: usize,
    pub skipped: usize,
    /// The exact names scored, in order. An update saves these so the model
    /// after a restart is judged on the same names as the model before it.
    pub sample: Vec<(String, String)>,
}

impl ThreatProbe {
    /// Held-out threats the model no longer reads as threats.
    pub fn lost(&self) -> usize {
        self.benign + self.downgraded
    }
}

/// Score `model` against names built from held-out threat families. Used
/// before and after a release model bundle: a bundle that loses held-out
/// threats is a regression, whatever its checksums say.
pub fn probe_threat_model(
    store: &AiStore,
    settings: &AiSettings,
    model: &Path,
) -> Result<ThreatProbe> {
    if !model.is_file() {
        return Err(DaygleError::Config(format!(
            "model file not found: {}",
            model.display()
        )));
    }
    let now = chrono::Utc::now().timestamp();
    let mut all: Vec<(String, String)> = Vec::new();
    for (channel, label, domain) in store.confident_verdicts(
        settings.category_confidence_floor,
        settings.block_threshold,
        now,
        MAX_VERDICTS,
    )? {
        if channel != "threat" {
            continue;
        }
        let label = label.trim().to_ascii_lowercase();
        let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
        if label.is_empty() || !looks_like_domain(&domain) {
            continue;
        }
        all.push((label, domain));
    }
    // The same spread sample the retrain gate uses: whole token components,
    // each scored on a word order that never appeared in the store. A store
    // too small to hit the sample still gets scored rather than skipped.
    let domains: Vec<String> = all.iter().map(|(_, domain)| domain.clone()).collect();
    let components = token_components(&domains);
    let disjoint = components.len() > 1;
    let selected = selected_components(&components);
    let mut component_of = vec![String::new(); domains.len()];
    for (key, members) in &components {
        for index in members {
            component_of[*index] = key.clone();
        }
    }
    let mut held: Vec<(String, String)> = Vec::new();
    for (index, (label, domain)) in all.iter().enumerate() {
        let chosen = if disjoint {
            selected.contains(&component_of[index])
        } else {
            hash_selected(domain)
        };
        if chosen {
            held.push((label.clone(), domain.clone()));
        }
    }
    if held.is_empty() {
        held = all.iter().take(MAX_PROBE).cloned().collect();
    }
    let sample: Vec<(String, String)> = spread_by_family(held, MAX_PROBE)
        .into_iter()
        .map(|(label, domain)| (label, held_out_variant(&domain)))
        .collect();
    probe_threat_names(settings, model, &sample)
}

/// Score exactly the supplied `(label, name)` pairs. The update apply step
/// calls this with the baseline probe's names after the restart, so both
/// models are compared on one pinned sample even if the store changed.
pub fn probe_threat_names(
    settings: &AiSettings,
    model: &Path,
    sample: &[(String, String)],
) -> Result<ThreatProbe> {
    if !model.is_file() {
        return Err(DaygleError::Config(format!(
            "model file not found: {}",
            model.display()
        )));
    }
    let predicted = predict_all(model, sample)?;
    let is_threat = |label: &str| is_threat_label(settings, label);
    let (mut checked, mut benign, mut downgraded, mut skipped) = (0, 0, 0, 0);
    for ((label, _), got) in sample.iter().zip(&predicted) {
        if !is_threat(label) {
            skipped += 1;
            continue;
        }
        checked += 1;
        if got == BENIGN_LABEL {
            benign += 1;
        } else if !is_threat(got) {
            downgraded += 1;
        }
    }
    Ok(ThreatProbe {
        checked,
        benign,
        downgraded,
        skipped,
        sample: sample.to_vec(),
    })
}

/// Reject a candidate that stops reading more held-out threats as threats
/// than the model in use does - as `benign`, or as any label that would not
/// block. Either way it is a detection the scanner would stop making.
pub(crate) fn refuse_lost_threats(
    checked: usize,
    benign: usize,
    downgraded: usize,
    baseline_lost: usize,
) -> Result<()> {
    let lost = benign + downgraded;
    if lost <= baseline_lost {
        return Ok(());
    }
    let detail = match (benign, downgraded) {
        (0, downgraded) => format!("{downgraded} as a label that would not block"),
        (benign, 0) => format!("{benign} as benign"),
        (benign, downgraded) => {
            format!("{benign} as benign and {downgraded} as a label that would not block")
        }
    };
    Err(DaygleError::Config(format!(
        "the retrained model read {lost} of {checked} held-out threat names {detail} against {baseline_lost} for the model in use, so the current model was kept; turn ai.learn_negatives off to retrain without the benign class"
    )))
}

/// Tokenization variants of one domain, matching how the scanner hands names
/// to the classifier. Duplicated from `train-starter-model` on purpose: the
/// offline tool also verifies against a curated probe list, which a runtime
/// retrain has no business carrying.
fn variants(domain: &str) -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let plain = domain.to_string();
    if !domain.starts_with("www.") {
        out.insert(format!("www.{plain}"));
    }
    out.insert(plain.clone());
    out.insert(plain.replace('.', "-"));
    out.insert(domain.split(['.', '-']).collect::<Vec<_>>().join(" "));
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_counts_both_ways_a_threat_stops_being_one() {
        assert!(refuse_lost_threats(30, 0, 0, 0).is_ok());
        assert!(
            refuse_lost_threats(30, 2, 0, 2).is_ok(),
            "the model in use loses the same names"
        );

        let benign = refuse_lost_threats(30, 2, 0, 0).unwrap_err().to_string();
        assert!(
            benign.contains("2 of 30 held-out threat names 2 as benign"),
            "{benign}"
        );

        let downgraded = refuse_lost_threats(30, 0, 3, 1).unwrap_err().to_string();
        assert!(
            downgraded.contains("3 of 30 held-out threat names 3 as a label that would not block"),
            "{downgraded}"
        );

        let both = refuse_lost_threats(30, 1, 2, 0).unwrap_err().to_string();
        assert!(
            both.contains(
                "3 of 30 held-out threat names 1 as benign and 2 as a label that would not block"
            ),
            "{both}"
        );
    }

    #[test]
    fn the_holdout_sample_is_by_family_and_novel() {
        assert_eq!(
            family_key("secure-login-3.example"),
            family_key("login-secure-9.example")
        );
        assert_eq!(family_key("secure-login-3.example"), "login-secure");
        assert_ne!(family_key("secure-login-3.example"), "secure");
        assert_eq!(
            held_out_variant("secure-login-3.example"),
            "login-secure-probe.example"
        );
        assert_eq!(held_out_variant("sneaky-1.example"), "sneaky-probe.example");
        assert_eq!(
            hash_selected(&family_key("secure-login-3.example")),
            hash_selected(&family_key("login-secure-9.example")),
            "a family is held out or trained as a whole"
        );
        let selected = (0..1000)
            .filter(|i| hash_selected(&family_key(&format!("host-{i:x}a.example"))))
            .count();
        assert!(
            (120..280).contains(&selected),
            "a fifth of families, evenly: {selected}"
        );
    }

    #[test]
    fn registrable_labels_follow_the_public_suffix_list() {
        assert_eq!(family_key("shop.example.co.uk"), "example");
        assert_eq!(family_key("www.secure-login.com"), "login-secure");
        assert_eq!(
            held_out_variant("www.secure-login.com"),
            "www.login-secure-probe.com"
        );
    }

    #[test]
    fn a_shared_word_makes_one_held_out_component() {
        let domains: Vec<String> = [
            "secure-login-1.example",
            "login-secure-2.example",
            "wallet-guide-1.example",
        ]
        .iter()
        .map(|domain| domain.to_string())
        .collect();
        let components = token_components(&domains);
        assert_eq!(components.len(), 2, "{components:?}");
        assert_eq!(components[0].0, "guide|wallet");
        assert_eq!(components[0].1, vec![2]);
        assert_eq!(components[1].0, "login|secure");
        assert_eq!(components[1].1, vec![0, 1]);
        assert!(
            selected_components(&components).len() == 1,
            "one of two components is held out"
        );
    }

    #[test]
    fn a_candidate_that_forgets_a_threat_label_is_refused() {
        let settings = AiSettings {
            auto_block_categories: vec!["malware".to_string(), "phishing".to_string()],
            ..AiSettings::default()
        };
        let set = |labels: &[&str]| -> HashSet<String> {
            labels.iter().map(|label| label.to_string()).collect()
        };
        let current = set(&["malware", "phishing", "news"]);
        assert!(
            refuse_forgotten_threats(&settings, Some(&current), &set(&["malware", "phishing"]))
                .is_ok(),
            "an ordinary label may come and go"
        );
        let refused =
            refuse_forgotten_threats(&settings, Some(&current), &set(&["phishing", "news"]))
                .unwrap_err()
                .to_string();
        assert!(refused.contains("malware"), "{refused}");
        assert!(
            refuse_forgotten_threats(&settings, None, &set(&[])).is_ok(),
            "no model in use (heuristic): nothing to forget"
        );
    }

    #[test]
    fn the_starter_corpus_covers_the_threat_labels() {
        let labels: HashSet<String> = starter_pairs()
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        for label in ["malware", "phishing", "scam"] {
            assert!(labels.contains(label), "{label} missing from {labels:?}");
        }
    }

    #[test]
    fn one_sprawling_family_is_never_held_out_whole() {
        // Forty names chained into one component by a shared word, plus a
        // handful of small families: the big one must stay in training.
        let mut domains: Vec<String> = (0..40).map(|i| format!("login-word{i}.example")).collect();
        for word in ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"] {
            domains.push(format!("{word}-site.example"));
        }
        let components = token_components(&domains);
        let selected = selected_components(&components);
        let held: usize = components
            .iter()
            .filter(|(key, _)| selected.contains(key))
            .map(|(_, members)| members.len())
            .sum();
        assert!(held > 0, "something is held out");
        assert!(
            held <= domains.len() / MAX_HELD_SHARE,
            "at most a quarter of the names: {held} of {}",
            domains.len()
        );
    }
}
