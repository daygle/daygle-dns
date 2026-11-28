//! Train a name classifier from independently labelled binary outcomes.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::path::Path;

use daygle_dns_ml::assessment::registrable;
use daygle_dns_ml::backend::{ClassificationInput, DomainClassifier, BINARY_THREAT_LABEL};
use daygle_dns_ml::fasttext_backend::FastTextBackend;
use daygle_dns_ml::learn::{train, BENIGN_LABEL};
use daygle_dns_ml::threshold::{self, Group, LabelSource, Sample};

type ToolResult<T> = Result<T, Box<dyn Error>>;

fn read_labels(path: &Path) -> ToolResult<BTreeMap<String, bool>> {
    let mut labels = BTreeMap::new();
    for (index, line) in std::fs::read_to_string(path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (threat, domain) = match (fields.next(), fields.next(), fields.next()) {
            (Some("threat"), Some(domain), None) => (true, domain),
            (Some("benign"), Some(domain), None) => (false, domain),
            _ => {
                return Err(format!(
                    "{}:{}: expected 'threat DOMAIN' or 'benign DOMAIN'",
                    path.display(),
                    index + 1
                )
                .into())
            }
        };
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !daygle_dns_ml::scanner::looks_like_domain(&domain) {
            return Err(format!("{}:{}: invalid domain", path.display(), index + 1).into());
        }
        if labels
            .insert(domain, threat)
            .is_some_and(|old| old != threat)
        {
            return Err(format!(
                "{}:{}: conflicting outcomes for the same domain",
                path.display(),
                index + 1
            )
            .into());
        }
    }
    Ok(labels)
}

fn run(training: &Path, evaluation: &Path, output: &Path, fpr: f32) -> ToolResult<()> {
    if !(0.0..=0.5).contains(&fpr) {
        return Err("false-positive target must be between 0 and 0.5".into());
    }
    let training = read_labels(training)?;
    let evaluation = read_labels(evaluation)?;
    for outcome in [false, true] {
        if training.values().filter(|value| **value == outcome).count() < 20 {
            return Err("training needs at least 20 labelled domains of each outcome".into());
        }
    }
    let training_families: HashSet<_> = training.keys().map(|domain| registrable(domain)).collect();
    if evaluation
        .keys()
        .any(|domain| training_families.contains(&registrable(domain)))
    {
        return Err("training and evaluation must use different registrable domains".into());
    }

    let pairs: Vec<_> = training
        .into_iter()
        .map(|(domain, threat)| {
            let label = if threat {
                BINARY_THREAT_LABEL
            } else {
                BENIGN_LABEL
            };
            (label.to_string(), domain)
        })
        .collect();
    let temporary = tempfile::tempdir()?;
    let staged = temporary.path().join("binary.bin");
    train(&pairs, &staged)?;
    let backend = FastTextBackend::load(&staged)?;
    let samples: Vec<_> = evaluation
        .into_iter()
        .map(|(domain, threat)| {
            let score = backend
                .classify(&ClassificationInput::domain_only(domain.clone()))
                .filter(|verdict| verdict.category == BINARY_THREAT_LABEL)
                .map_or(0.0, |verdict| verdict.confidence);
            Sample {
                registrable: registrable(&domain),
                domain,
                score,
                group: Group::Correction,
                label: LabelSource::OperatorCorrection,
                threat: Some(threat),
                scored_at: 0,
                policy_blocked: None,
            }
        })
        .collect();
    let report = threshold::run(&samples, fpr, 0.99);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed || report.tuning.caught == 0 || report.holdout.caught == 0 {
        return Err("evaluation did not meet the target with detections in both splits".into());
    }
    daygle_dns_ml::candidate::write_artifact(output, &std::fs::read(&staged)?)?;
    Ok(())
}

fn main() -> ToolResult<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [training, evaluation, output, fpr] = args.as_slice() else {
        return Err(
            "usage: train-binary-name-model TRAINING.txt EVALUATION.txt OUTPUT.bin FPR_TARGET"
                .into(),
        );
    };
    let fpr = fpr.to_str().ok_or("FPR_TARGET must be numeric")?.parse()?;
    run(
        Path::new(training),
        Path::new(evaluation),
        Path::new(output),
        fpr,
    )
}
