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
use std::sync::Arc;

use arc_swap::ArcSwap;
use daygle_dns_core::config::AiSettings;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::{LogLevel, LogStore};

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
const MIN_ACCURACY: f32 = 0.5;
/// A candidate may trail the model in use by this much on held-out labels
/// before it is rejected: small differences are noise, a real regression is
/// not.
const VALIDATION_SLACK: f32 = 0.02;
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
    /// (the reference model, the page) agreed with them.
    pub unconfirmed: usize,
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

fn previous_stats_path(learned: &Path) -> PathBuf {
    learned.with_extension("prev.json")
}

/// The training set and its held-out slice: corrections first, then confident
/// verdicts, then the starter corpus. One domain contributes one label: the
/// newest correction wins, then the strongest verdict, then the corpus.
pub fn collect_dataset(store: &AiStore, settings: &AiSettings) -> Result<Dataset> {
    collect_dataset_with(store, settings, &Sources::default())
}

/// What a retrain draws on beyond the store itself.
#[derive(Default)]
pub struct Sources<'a> {
    /// The labels of the model in use: starter examples outside them are left
    /// out, so a custom model's label space is not widened by the starter's.
    pub known: Option<&'a HashSet<String>>,
    /// The starter corpus text; `None` uses the copy built into the binary.
    pub starter: Option<&'a str>,
    /// The fixed reference model (the configured, shipped one). When set, a
    /// verdict of the scanner's own only trains if this model or the page
    /// behind the domain agrees with it, so the scanner cannot teach itself
    /// its own mistakes.
    pub anchor: Option<&'a fasttext::FastText>,
    /// Independent page readings, by domain.
    pub page_labels: Option<&'a std::collections::HashMap<String, String>>,
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
        left == right
            || (settings.is_auto_block_category(left) && settings.is_auto_block_category(right))
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
        if label.is_empty() || corrected.contains(&domain) || !looks_like_domain(&domain) {
            continue;
        }
        // Anchored self-training: the scanner's own label trains only when
        // something independent of it agrees - the fixed reference model or
        // what the page itself says. A label nothing else backs stays out,
        // so a systematic mistake cannot feed on itself.
        if let Some(anchor) = sources.anchor {
            let anchored = top_label(anchor, &domain);
            let paged = sources.page_labels.and_then(|pages| pages.get(&domain));
            let confirmed = anchored.as_deref().is_some_and(|a| agrees(a, &label))
                || paged.is_some_and(|p| agrees(p, &label));
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
        if label == BENIGN_LABEL || labelled.contains(&domain) || corrected.contains(&domain) {
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
    let dir = model.parent()?;
    if model.as_os_str().is_empty() {
        return None;
    }
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
fn top_label(model: &fasttext::FastText, domain: &str) -> Option<String> {
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

/// Refuse a candidate that cannot emit a threat label the model in use can:
/// a detector that has forgotten `malware` will never report it again, and
/// no held-out score notices a label that never comes up.
fn refuse_forgotten_threats(
    settings: &AiSettings,
    current: Option<&HashSet<String>>,
    candidate: &HashSet<String>,
) -> Result<()> {
    let Some(current) = current else {
        return Ok(());
    };
    let mut missing: Vec<&str> = current
        .iter()
        .filter(|label| settings.is_auto_block_category(label) && !candidate.contains(*label))
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
    if labels.get(label).copied().unwrap_or(0) >= MAX_PER_LABEL {
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
    std::fs::File::open(out).and_then(|file| file.sync_all())?;
    Ok(())
}

/// The top-1 label `model` gives each domain, in order.
fn predict_all(model: &Path, pairs: &[(String, String)]) -> Result<Vec<String>> {
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
fn hash_selected(text: &str) -> bool {
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
    let is_threat =
        |label: &str| settings.dedicated_threat_model() || settings.is_auto_block_category(label);
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
fn refuse_lost_threats(
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

/// Loads an accepted model file into the running channels. Set by the engine,
/// so every way a model is accepted - a scheduled retrain, a manual one or a
/// rollback - goes live the same way.
pub type Installer = Box<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Retrains the classifier from the store, judged against the model in use so
/// a bad run can never replace a working one.
pub struct Retrainer {
    store: Arc<AiStore>,
    settings: Arc<ArcSwap<AiSettings>>,
    logs: Arc<LogStore>,
    learned: PathBuf,
    /// The model file the running scanner loaded: the baseline the candidate
    /// has to match on held-out labels.
    current_model: Arc<ArcSwap<String>>,
    last_attempt: std::sync::Mutex<Option<i64>>,
    /// One retrain or rollback at a time: they share the temp file and
    /// rotate the same model files.
    running: std::sync::Mutex<()>,
    installer: std::sync::OnceLock<Installer>,
}

impl Retrainer {
    pub fn new(
        store: Arc<AiStore>,
        settings: Arc<ArcSwap<AiSettings>>,
        logs: Arc<LogStore>,
        learned: PathBuf,
        current_model: Arc<ArcSwap<String>>,
    ) -> Self {
        Self {
            store,
            settings,
            logs,
            learned,
            current_model,
            last_attempt: std::sync::Mutex::new(None),
            running: std::sync::Mutex::new(()),
            installer: std::sync::OnceLock::new(),
        }
    }

    /// Hand the retrainer the step that loads an accepted model into the
    /// running channels. Without one (tests of the files alone) an accepted
    /// model is only written to disk.
    pub fn set_installer(&self, installer: Installer) {
        let _ = self.installer.set(installer);
    }

    /// The model file this retrainer maintains.
    pub fn learned_model(&self) -> &Path {
        &self.learned
    }

    fn install(&self) -> Result<()> {
        match self.installer.get() {
            Some(install) => install(&self.learned),
            None => Ok(()),
        }
    }

    /// Retrain now. A rejected or failed run leaves the model in use
    /// untouched; an accepted one is in use when this returns.
    pub fn retrain(&self) -> Result<TrainingStats> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let settings = self.settings.load_full();
        let current_path = self.current_model.load_full().to_string();
        let current_model = (!current_path.trim().is_empty()).then(|| PathBuf::from(&current_path));
        let current_labels = current_model.as_deref().and_then(model_labels);
        // The configured (shipped) model is the fixed reference the scanner's
        // own verdicts are checked against, and the corpus beside it - when a
        // models bundle shipped one - is the starter set that matches it.
        let anchor = self.anchor_model(&settings);
        let corpus = bundled_starter_corpus(&settings.model_path);
        let page_labels = self.store.current_page_labels().unwrap_or_default();
        let Dataset {
            pairs,
            validation,
            threat_validation,
            stats,
        } = collect_dataset_with(
            &self.store,
            &settings,
            &Sources {
                known: current_labels.as_ref(),
                starter: corpus.as_deref(),
                anchor: anchor.as_ref(),
                page_labels: Some(&page_labels),
            },
        )?;
        // The starter corpus is always there, so what decides whether a
        // retrain is worth running is what this network contributed.
        if stats.local() < MIN_EXAMPLES || stats.labels < MIN_LABELS {
            return Err(DaygleError::Config(format!(
                "not enough training data yet: {} examples across {} labels (a retrain needs {} and {})",
                stats.local(),
                stats.labels,
                MIN_EXAMPLES,
                MIN_LABELS
            )));
        }

        let temp = self.learned.with_extension("tmp");
        let outcome = self.judge(
            &settings,
            &temp,
            &pairs,
            &validation,
            &threat_validation,
            current_model.as_deref(),
            current_labels.as_ref(),
        );
        let (train_accuracy, validation_accuracy) = match outcome {
            Ok(scores) => scores,
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        };

        // Rotate first, so a rollback always has somewhere to go. A failure
        // here restores the previous model rather than leaving none.
        let previous = previous_model_path(&self.learned);
        let had_learned = self.learned.is_file();
        if had_learned {
            if let Err(e) = std::fs::rename(&self.learned, &previous) {
                let _ = std::fs::remove_file(&temp);
                return Err(DaygleError::Io(e));
            }
            swap_stats(&self.learned, StatsMove::CurrentToPrevious);
        }
        if let Err(e) = std::fs::rename(&temp, &self.learned) {
            // Put the old model back: a retrain must never leave the scanner
            // without the model it had.
            self.restore_after_failed_rotation(had_learned);
            return Err(DaygleError::Io(e));
        }
        if let Err(e) = self.install() {
            let _ = std::fs::remove_file(&self.learned);
            self.restore_after_failed_rotation(had_learned);
            return Err(DaygleError::Config(format!(
                "the retrained model could not be loaded, so the current model was kept: {e}"
            )));
        }

        // The new model is on trial: when the window ends it is compared on
        // live traffic with the model it replaced, and rolled back if worse.
        let baseline = if had_learned {
            previous_model_path(&self.learned)
                .to_string_lossy()
                .into_owned()
        } else {
            current_path.clone()
        };
        let now = chrono::Utc::now().timestamp();
        self.write_trial(&Trial {
            started_at: Some(now),
            ends_at: Some(now + trial_secs(&settings)),
            baseline: Some(baseline),
            ..Trial::default()
        });

        let record = serde_json::json!({
            "trained_at": chrono::Utc::now().to_rfc3339(),
            "examples": stats.examples,
            "labels": stats.labels,
            "corrections": stats.corrections,
            "verdicts": stats.verdicts,
            "negatives": stats.negatives,
            "starter": stats.starter,
            "unconfirmed": stats.unconfirmed,
            "train_accuracy": (train_accuracy * 100.0).round() / 100.0,
            "validation_examples": validation.len(),
            "validation_accuracy": validation_accuracy
                .map(|a| (a * 100.0).round() / 100.0),
            "threat_validation_examples": threat_validation.len(),
        });
        match serde_json::to_vec_pretty(&record) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(stats_path(&self.learned), bytes) {
                    self.logs.push(
                        LogLevel::Warn,
                        "ai",
                        format!("could not record the retrain result: {e}"),
                    );
                }
            }
            Err(e) => self.logs.push(
                LogLevel::Warn,
                "ai",
                format!("could not encode the retrain result: {e}"),
            ),
        }
        let judged = match validation_accuracy {
            Some(accuracy) => format!(
                ", and kept {:.0}% on {} held-out corrections",
                accuracy * 100.0,
                validation.len()
            ),
            None => String::new(),
        };
        self.logs.push(
            LogLevel::Info,
            "ai",
            format!(
                "AI retrained its classifier from {} examples across {} labels ({} from your corrections, {} from the starter corpus, {} unconfirmed verdicts left out{judged}); it is in use now, on trial for {}h",
                stats.examples, stats.labels, stats.corrections, stats.starter, stats.unconfirmed,
                trial_secs(&settings) / 3600
            ),
        );
        Ok(stats)
    }

    /// Put the model files back the way they were before a rotation.
    fn restore_after_failed_rotation(&self, had_learned: bool) {
        let previous = previous_model_path(&self.learned);
        if had_learned && previous.is_file() {
            let _ = std::fs::rename(&previous, &self.learned);
            swap_stats(&self.learned, StatsMove::PreviousToCurrent);
        }
    }

    /// Train a candidate into `temp` and run every gate on it. Returns the
    /// training accuracy and, when corrections were held back, the held-out
    /// accuracy.
    #[allow(clippy::too_many_arguments)]
    fn judge(
        &self,
        settings: &AiSettings,
        temp: &Path,
        pairs: &[(String, String)],
        validation: &[(String, String)],
        threat_validation: &[(String, String)],
        current_model: Option<&Path>,
        current_labels: Option<&HashSet<String>>,
    ) -> Result<(f32, Option<f32>)> {
        train(pairs, temp)?;
        let train_accuracy = probe_accuracy(temp, pairs)?;

        // A candidate that forgot a threat label can never report it again.
        let candidate_labels = model_labels(temp).unwrap_or_default();
        refuse_forgotten_threats(settings, current_labels, &candidate_labels)?;

        // The gate: judge the candidate on labels it never saw, against the
        // model that is actually classifying right now.
        let mut validation_accuracy = None;
        if validation.is_empty() {
            if train_accuracy < MIN_ACCURACY {
                return Err(DaygleError::Config(format!(
                    "the retrained model reproduced only {:.0}% of its own training data, so the current model was kept",
                    train_accuracy * 100.0
                )));
            }
        } else {
            let candidate = probe_accuracy(temp, validation)?;
            let baseline = current_model.and_then(|model| probe_accuracy(model, validation).ok());
            if candidate < MIN_ACCURACY {
                return Err(DaygleError::Config(format!(
                    "the retrained model scored {:.0}% on {} held-out corrections, so the current model was kept",
                    candidate * 100.0,
                    validation.len()
                )));
            }
            if let Some(baseline) = baseline {
                if candidate + VALIDATION_SLACK < baseline {
                    return Err(DaygleError::Config(format!(
                        "the retrained model scored {:.0}% on {} held-out corrections against {:.0}% for the model in use, so the current model was kept",
                        candidate * 100.0,
                        validation.len(),
                        baseline * 100.0
                    )));
                }
            }
            validation_accuracy = Some(candidate);
        }

        // The negative class gets its own gate: however well the candidate
        // scores overall, it may not stop reading a held-out threat as a
        // threat. `benign` is one way; any non-blocking label is another.
        if !threat_validation.is_empty() {
            let probe: Vec<(String, String)> = threat_validation
                .iter()
                .map(|(label, domain)| (label.clone(), held_out_variant(domain)))
                .collect();
            let predicted = predict_all(temp, &probe)?;
            let is_threat_label = |label: &str| {
                settings.dedicated_threat_model() || settings.is_auto_block_category(label)
            };
            let (mut benign, mut downgraded, mut checked) = (0usize, 0usize, 0usize);
            for ((label, _), got) in probe.iter().zip(&predicted) {
                // A verdict whose own label no longer blocks was not a threat
                // to preserve; only the labels the channel would block count.
                if !is_threat_label(label) {
                    continue;
                }
                checked += 1;
                if got == BENIGN_LABEL {
                    benign += 1;
                } else if !is_threat_label(got) {
                    downgraded += 1;
                }
            }
            // The current model is judged on the same novel names, so a
            // candidate is refused only for losing detections it would have
            // kept, not for a family it was never given.
            let baseline_lost = match current_model.map(|model| predict_all(model, &probe)) {
                Some(Ok(baseline)) => baseline
                    .iter()
                    .zip(&probe)
                    .filter(|(got, (label, _))| {
                        is_threat_label(label) && (*got == BENIGN_LABEL || !is_threat_label(got))
                    })
                    .count(),
                _ => 0,
            };
            refuse_lost_threats(checked, benign, downgraded, baseline_lost)?;
        }
        Ok((train_accuracy, validation_accuracy))
    }

    /// Whether a previous model is kept and can be restored.
    pub fn has_previous(&self) -> bool {
        previous_model_path(&self.learned).is_file()
    }

    /// Swap the previous model back in for the current one and load it.
    /// Both files are kept, so this is itself reversible.
    pub fn rollback(&self) -> Result<()> {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let previous = previous_model_path(&self.learned);
        if !previous.is_file() {
            return Err(DaygleError::Config(
                "there is no previous model to restore".to_string(),
            ));
        }
        self.swap_with_previous()?;
        if let Err(e) = self.install() {
            // Leave the files as they were: the model in use stays in use.
            if let Err(undo) = self.swap_with_previous() {
                self.logs.push(
                    LogLevel::Warn,
                    "ai",
                    format!("could not undo a failed model restore: {undo}"),
                );
            }
            return Err(DaygleError::Config(format!(
                "the previous model could not be loaded, so the current model was kept: {e}"
            )));
        }
        // The operator decided; any trial in progress is over.
        self.write_trial(&Trial {
            last_outcome: Some("ended by a manual restore".to_string()),
            ..Trial::default()
        });
        self.logs
            .push(LogLevel::Info, "ai", "restored the previous classifier");
        Ok(())
    }

    /// Exchange `learned.bin` and `learned.prev.bin`, and their records.
    fn swap_with_previous(&self) -> Result<()> {
        let previous = previous_model_path(&self.learned);
        let staged = self.learned.with_extension("rolled-back.bin");
        std::fs::rename(&self.learned, &staged)?;
        if let Err(e) = std::fs::rename(&previous, &self.learned) {
            let _ = std::fs::rename(&staged, &self.learned);
            return Err(DaygleError::Io(e));
        }
        if let Err(e) = std::fs::rename(&staged, &previous) {
            // The restored model is in place; the replaced one is still on
            // disk under its staging name, so say where.
            self.logs.push(
                LogLevel::Warn,
                "ai",
                format!("the replaced model was left at {}: {e}", staged.display()),
            );
        }
        swap_stats(&self.learned, StatsMove::Exchange);
        Ok(())
    }

    /// Retrain when automatic maintenance is on, the interval has passed and
    /// there is enough material. `None` means "not due". Failures are logged
    /// and returned; they never disturb the scan loop.
    pub fn maybe_retrain(&self) -> Option<Result<TrainingStats>> {
        let settings = self.settings.load_full();
        if !settings.enabled {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        // A model on trial is judged when its window ends, and no scheduled
        // retrain replaces it before then. A rejected one pauses retraining.
        let trial = self.trial();
        if let (Some(started), Some(ends)) = (trial.started_at, trial.ends_at) {
            if now < ends {
                return None;
            }
            if settings.auto_rollback {
                self.conclude_trial(
                    &settings,
                    started,
                    ends,
                    trial.baseline.as_deref().unwrap_or(""),
                );
            } else {
                self.write_trial(&Trial {
                    last_outcome: Some("kept: automatic rollback is off".to_string()),
                    ..Trial::default()
                });
            }
            return None;
        }
        if trial.retry_after.is_some_and(|after| now < after) {
            return None;
        }
        if !settings.auto_retrain {
            return None;
        }
        let interval = settings.retrain_interval_secs.max(3_600) as i64;
        {
            let mut last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
            // The first attempt after a start waits for the last recorded
            // retrain's interval, so restarts do not each cost a retrain.
            if last.is_none() {
                *last = self.last_trained_at();
            }
            if let Some(at) = *last {
                if now - at < interval {
                    return None;
                }
            }
            *last = Some(now);
        }
        let outcome = self.retrain();
        if let Err(e) = &outcome {
            // Info, not Warn: "not enough data yet" is the normal state for a
            // young install, not a fault.
            self.logs
                .push(LogLevel::Info, "ai", format!("AI retrain skipped: {e}"));
        }
        Some(outcome)
    }

    /// The configured model as the fixed reference for anchored training:
    /// only a loadable fastText file that is not the learned model itself.
    fn anchor_model(&self, settings: &AiSettings) -> Option<fasttext::FastText> {
        let path = Path::new(settings.model_path.trim());
        if path.as_os_str().is_empty() || !path.is_file() || path == self.learned {
            return None;
        }
        fasttext::FastText::load_model(path).ok()
    }

    /// The trial state beside the model, or none.
    pub fn trial(&self) -> Trial {
        std::fs::read(trial_path(&self.learned))
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
            .map(|value| Trial::from_json(&value))
            .unwrap_or_default()
    }

    fn write_trial(&self, trial: &Trial) {
        let path = trial_path(&self.learned);
        let written = serde_json::to_vec_pretty(&trial.to_json())
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&path, bytes));
        if let Err(e) = written {
            self.logs.push(
                LogLevel::Warn,
                "ai",
                format!("could not record the model trial: {e}"),
            );
        }
    }

    /// Judge the model on trial and keep it or roll it back.
    fn conclude_trial(&self, settings: &AiSettings, started: i64, ends: i64, baseline: &str) {
        let _running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = judge_trial(
            &self.store,
            settings,
            &self.learned,
            baseline,
            started,
            ends,
        );
        let now = chrono::Utc::now().timestamp();
        match outcome {
            TrialOutcome::Keep(why) => {
                self.logs.push(
                    LogLevel::Info,
                    "ai",
                    format!("AI kept its retrained classifier after its trial: {why}"),
                );
                self.write_trial(&Trial {
                    last_outcome: Some(format!("kept: {why}")),
                    ..Trial::default()
                });
            }
            TrialOutcome::Reject(why) => {
                let restored = self.revert_to(baseline);
                let pause = settings.retrain_interval_secs.max(3_600) as i64 * 2;
                let what = match &restored {
                    Ok(()) => "the model it replaced is back in use".to_string(),
                    Err(e) => format!("the model it replaced could not be restored ({e})"),
                };
                self.logs.push(
                    LogLevel::Warn,
                    "ai",
                    format!(
                        "AI rolled back its retrained classifier after its trial: {why}; {what}. Retraining pauses for {}h.",
                        pause / 3600
                    ),
                );
                self.write_trial(&Trial {
                    retry_after: Some(now + pause),
                    last_outcome: Some(format!("rolled back: {why}")),
                    ..Trial::default()
                });
            }
        }
    }

    /// Put `baseline` back in front of the scanner: the previous learned
    /// model by swapping it back, or the configured model by setting the
    /// rejected one aside.
    fn revert_to(&self, baseline: &str) -> Result<()> {
        let previous = previous_model_path(&self.learned);
        if Path::new(baseline) == previous && previous.is_file() {
            self.swap_with_previous()?;
            return self.install();
        }
        let rejected = self.learned.with_extension("rejected.bin");
        std::fs::rename(&self.learned, &rejected)?;
        let _ = std::fs::rename(
            stats_path(&self.learned),
            self.learned.with_extension("rejected.json"),
        );
        if let Some(install) = self.installer.get() {
            if let Err(e) = install(Path::new(baseline)) {
                let _ = std::fs::rename(&rejected, &self.learned);
                return Err(e);
            }
        }
        Ok(())
    }

    /// When the model in place was trained, from its record.
    fn last_trained_at(&self) -> Option<i64> {
        let raw = std::fs::read(stats_path(&self.learned)).ok()?;
        let record: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let at = record.get("trained_at")?.as_str()?;
        chrono::DateTime::parse_from_rfc3339(at)
            .ok()
            .map(|t| t.timestamp())
    }
}

/// Where the trial of the model in place is recorded.
pub fn trial_path(learned: &Path) -> PathBuf {
    learned.with_extension("trial.json")
}

/// How long a newly accepted model is on trial before it is judged on live
/// traffic: half the retrain interval, between one hour and a day.
pub fn trial_secs(settings: &AiSettings) -> i64 {
    (settings.retrain_interval_secs / 2).clamp(3_600, 86_400) as i64
}

/// A model's trial: in progress (`started_at`/`ends_at`), or concluded, with
/// a pause on retraining after a rollback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trial {
    pub started_at: Option<i64>,
    pub ends_at: Option<i64>,
    /// The model the one on trial replaced, to return to.
    pub baseline: Option<String>,
    /// No scheduled retrain before this.
    pub retry_after: Option<i64>,
    pub last_outcome: Option<String>,
}

impl Trial {
    fn from_json(value: &serde_json::Value) -> Self {
        Self {
            started_at: value.get("started_at").and_then(|v| v.as_i64()),
            ends_at: value.get("ends_at").and_then(|v| v.as_i64()),
            baseline: value
                .get("baseline")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            retry_after: value.get("retry_after").and_then(|v| v.as_i64()),
            last_outcome: value
                .get("last_outcome")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }

    /// The record as JSON, also what the status API reports.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "started_at": self.started_at,
            "ends_at": self.ends_at,
            "baseline": self.baseline,
            "retry_after": self.retry_after,
            "last_outcome": self.last_outcome,
        })
    }
}

enum TrialOutcome {
    Keep(String),
    Reject(String),
}

/// Fewest threat labels the model replaced must find on the trial's traffic
/// before a drop in detections counts as evidence.
const TRIAL_MIN_THREATS: usize = 10;
/// Fewest corrections in the trial window before their rate counts.
const TRIAL_MIN_CORRECTIONS: usize = 3;
/// Most recent domains a trial compares the two models on.
const TRIAL_DOMAINS: u32 = 5_000;

/// Compare the model on trial with the one it replaced, on what the network
/// did during the trial. Three independent signals, any one of which rejects:
///
/// * held-out threat families: the trial model must not lose more of them;
/// * live traffic: it must not find fewer than half the threats the old
///   model finds on the same domains, nor more than twice as many (a flood
///   of new detections is as suspect as a drought);
/// * the operator: it must not need correcting more than twice as often as
///   the old model did over an equally long window before the trial.
fn judge_trial(
    store: &AiStore,
    settings: &AiSettings,
    learned: &Path,
    baseline: &str,
    started: i64,
    ends: i64,
) -> TrialOutcome {
    let mut notes: Vec<String> = Vec::new();
    let baseline_path = Path::new(baseline.trim());
    let comparable = !baseline.trim().is_empty() && baseline_path.is_file() && learned.is_file();

    if comparable {
        if let Ok(trial_probe) = probe_threat_model(store, settings, learned) {
            if let Ok(base_probe) = probe_threat_names(settings, baseline_path, &trial_probe.sample)
            {
                if trial_probe.lost() > base_probe.lost() {
                    return TrialOutcome::Reject(format!(
                        "it lost {} of {} held-out threat names against {} for the model it replaced",
                        trial_probe.lost(),
                        trial_probe.checked,
                        base_probe.lost()
                    ));
                }
                notes.push(format!(
                    "{} of {} held-out threats lost (was {})",
                    trial_probe.lost(),
                    trial_probe.checked,
                    base_probe.lost()
                ));
            }
        }

        // With a dedicated threat model the learned one only categorizes,
        // so its threat rate says nothing about detection.
        if !settings.dedicated_threat_model() {
            let domains = store
                .domains_classified_between(started, ends, TRIAL_DOMAINS)
                .unwrap_or_default();
            if !domains.is_empty() {
                let pairs: Vec<(String, String)> = domains
                    .into_iter()
                    .map(|domain| (String::new(), domain))
                    .collect();
                let threats = |model: &Path| {
                    predict_all(model, &pairs).map(|labels| {
                        labels
                            .iter()
                            .filter(|label| {
                                *label != BENIGN_LABEL && settings.is_auto_block_category(label)
                            })
                            .count()
                    })
                };
                if let (Ok(trial), Ok(base)) = (threats(learned), threats(baseline_path)) {
                    if base >= TRIAL_MIN_THREATS && trial * 2 < base {
                        return TrialOutcome::Reject(format!(
                            "it found {trial} threats on {} live domains where the model it replaced finds {base}",
                            pairs.len()
                        ));
                    }
                    if trial > base * 2 + TRIAL_MIN_THREATS {
                        return TrialOutcome::Reject(format!(
                            "it flagged {trial} threats on {} live domains where the model it replaced flags {base}",
                            pairs.len()
                        ));
                    }
                    notes.push(format!(
                        "{trial} threats on {} live domains (was {base})",
                        pairs.len()
                    ));
                }
            }
        }
    }

    let window = (ends - started).max(1);
    let during = store
        .corrections_of_verdicts_between(started, ends)
        .unwrap_or(0);
    let before = store
        .corrections_of_verdicts_between(started - window, started)
        .unwrap_or(0);
    if during >= TRIAL_MIN_CORRECTIONS && during > before * 2 + 1 {
        return TrialOutcome::Reject(format!(
            "you corrected {during} of its verdicts during the trial against {before} in the same time before it"
        ));
    }
    notes.push(format!("{during} corrections (was {before})"));
    TrialOutcome::Keep(notes.join("; "))
}

#[derive(Clone, Copy)]
enum StatsMove {
    CurrentToPrevious,
    PreviousToCurrent,
    Exchange,
}

/// Keep each model's record with the model: moved with it on a rotation,
/// exchanged on a rollback, and dropped rather than left describing the
/// wrong file when one side has none.
fn swap_stats(learned: &Path, how: StatsMove) {
    let current = stats_path(learned);
    let previous = previous_stats_path(learned);
    match how {
        StatsMove::CurrentToPrevious => {
            let _ = std::fs::remove_file(&previous);
            let _ = std::fs::rename(&current, &previous);
        }
        StatsMove::PreviousToCurrent => {
            let _ = std::fs::remove_file(&current);
            let _ = std::fs::rename(&previous, &current);
        }
        StatsMove::Exchange => {
            let staged = learned.with_extension("rolled-back.json");
            let _ = std::fs::remove_file(&staged);
            let had_current = std::fs::rename(&current, &staged).is_ok();
            let _ = std::fs::rename(&previous, &current);
            if had_current {
                let _ = std::fs::rename(&staged, &previous);
            }
        }
    }
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
