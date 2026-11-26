# AI scoring and enforcement: audit and staged changes

This is the working record of the "autonomous AI threat engine" development
phase. It documents the scoring pipeline as it was, what was verified, what
each stage adds, the database migration it needs, its API and UI, the tests
that cover the existing safety rails, and what remains unmeasured. The
operator-facing behaviour stays described in [AI.md](AI.md); the endpoints are
in [API.md](API.md#ai-scanner).

The changes were made in the order below, as separate modules, each with its
own tests. Nothing in the default configuration changes what blocks: fusion is
recorded (`monitor`), no calibration map is active, graduated authority is
off, and `ai.mode` still defaults to `train`.

## Stage 1 - Audit of the scoring and enforcement pipeline

### The pipeline

```
query log ──► scanner harvest ──► threat channel (fastText / heuristic)
                                        │
                                        ├─ name-model parent dispute (disputed)
                                        ├─ MiniLM verifier (corroborate / dispute)
                                        ├─ network evidence (feed, popularity,
                                        │   established, generated name)
                                        └─ confidence written to ai_verdicts
                                                 │
                      domain-age stage (+/-) ────┤
                      page rule (+/cap) ─────────┤
                      language model (+) ────────┘
                                                 │
                        gate: confidence >= ai.block_threshold
                              and fresh, undisputed, not overridden,
                              labelled a threat
                                                 │
                              block snapshot ──► AiBlockPlugin (DNS)
```

| Stage | Code |
|---|---|
| Verdict production | `scanner.rs::run_cycle` → `ChannelBackend` (`channel.rs`), `EvidenceBackend` (`evidence.rs`), `VerifyingBackend` (`verify.rs`) |
| Post-verdict evidence | `age.rs::DomainAge::stage`, page rule (`page.rs`, scanner `page_stage`), `llm.rs` via scanner `llm_stage` |
| Storage | `store.rs::save_verdicts`, `ai_verdicts(domain, channel)` |
| Gate | `store.rs::fresh_blocked`, called by `scanner.rs::blocks_with` |
| Snapshot rails | `scanner.rs::refresh_snapshot` (mode, exemptions, label list, 500-per-refresh cap) |
| Threshold trial | `threshold.rs::collect` → `run`; `store/threshold.rs::gate_scores` |
| Operator surfaces | `crates/daygle-dns-api/src/handlers.rs` (`/api/ai/*`), `web/src/views/Ai*.svelte` |

### Verified before changing anything

1. `threshold::collect()` used `store.gate_scores(limit)`.
2. `gate_scores()` read `ai_verdicts.confidence` for
   `channel = 'threat' AND status = 'classified' AND confidence > 0`.
3. `fresh_blocked()` compared the same `confidence` column against the
   `ai.block_threshold` argument passed by `scanner::blocks_with`
   (`cfg.block_threshold`).

All three used one column and one comparison, so the trial fitted the score
enforcement compared. There was **no** trial/gate mismatch on main, and no
change was made to fix one.

Stage 3 keeps that property while making the calibrated score the one score:
`gate_scores()` now delegates to `gate_samples()`, which reads
`CASE WHEN calibration_version <> '' THEN calibrated_score ELSE confidence END`
- exactly the expression `fresh_blocked()` compares. With no calibration map
active, `calibration_version` is empty and both read `confidence`, unchanged;
the version, not the score's value, distinguishes "no map" from a map that
legitimately calibrates a name to zero. The invariant is pinned by
`store::threshold::tests::the_trial_reads_the_confidence_the_gate_compares` and
`a_calibrated_zero_is_not_a_missing_calibration`.

### Scoring methods that could confuse (found in the audit)

| Item | Status |
|---|---|
| `signals.rs::for_verdict` | Six reporting-only signals for the console. Kept for `/api/ai/explain`'s `signals` field; superseded by `assessment::observe`. It reads the same sources but is *not* the assessment. |
| `store::gate_scores` | Now a projection of `gate_samples` (same score, no timestamp). Kept so there is still one named entry point for "the score the gate compares". |
| `VerdictRow::threat_score` | The model's own score, which the console calls "threat score". It is deliberately **not** the gate score; it remains informational and is one observation (`model`) now. |
| `page_fetch_candidates` / `llm_candidates` thresholds | Compare raw `confidence`, not the calibrated score. Intentional: these stages run before/independently of calibration and adjust the confidence, which is then reassessed. |
| `store::export_threats` | Used `confidence` for its threshold and ordering while the gate used the same column; after stage 3 it reads the gate score so the exported list is the enforcement list. |
| `threshold::model_version` | A display/record identity (`path@stamp:bytes`). It is not an artifact; stage 4 stops relying on it for restores. |
| `threshold::Sample::group` vs `label` | `group` is the old four-population view (used by the trial's FPR/recall). `label` (stage 3) records provenance. They are reported side by side, not merged. |

## Stage 2 - Structured signal observations

**Purpose.** Every input becomes one persisted, typed observation instead of a
sentence in `evidence`.

**Files and functions**

- `assessment.rs` (new): `SignalSource` (model, verifier, feed, popularity,
  network_history, domain_age, hostname, page, llm), `Direction`,
  `EvidenceFamily`, `Scope`, `SignalObservation`, `observe()`.
- `store/assessment.rs`: `ai_signal_observations` table, `save_observations`,
  `observations`, orphan cleanup in `delete_orphaned_page_history`.
- `scanner.rs::assess_row` (called from `assess_verdicts`, `reassess_domain`),
  `scanner.rs::set_intel`.
- `AiEngine::signal_report`, `SignalReport`.

Each observation carries `source`, `direction`, `value` (where it has one),
`explanation`, `observed_at`, `scope` (hostname or registrable domain) and
`family` (correlation group). Nine sources, always all nine rows: `unknown`
means "not looked at", `neutral` means "looked at, nothing either way".

**Migration:** `ai_signal_observations(domain, channel, observed_at,
observations)`; no change to existing rows. Observations are replaced when a
verdict is re-classified and deleted when its verdict is dropped.

**API/UI:** `GET /api/ai/signals?domain=`; `/api/ai/explain` now also returns
`signal_observations`, `fusion` and `calibrated_score` beside the legacy
`signals`. The console's Signals column is unchanged (it still reads the
legacy view).

**Tests:** `assessment::tests::*` (nine rows, scopes, families, page and feed
observations), `store::assessment::tests::observations_are_replaced_with_the_verdict_they_describe`,
and the HTTP test `signals_report_every_structured_observation_behind_a_verdict`.

**Limitation:** the legacy six-signal view still exists and is computed
separately, so it can describe an input slightly differently from the
observation. Consolidating it (mapping `Signal` from `SignalObservation`) is a
follow-up, not done here to avoid changing the console's existing text.

## Stage 3 - Calibration and validation reporting

**Purpose.** The score the gate compares is mapped to a calibrated score by a
versioned map, and the map has to prove itself on held-out data.

**Files and functions**

- `calibration.rs` (new): `CalibrationMap` (identity or isotonic
  piecewise-linear, content-hash `version`), `fit` (PAV isotonic),
  `evaluate` (`Metrics`: Brier, ECE, ten-bin reliability table), `accept`.
- `store/threshold.rs`: `gate_samples`, `gate_scores`,
  `the_trial_reads_the_confidence_the_gate_compares`.
- `store.rs`: `fresh_blocked` and `export_threats` read the gate score;
  `ai_verdicts.calibrated_score`, `calibration_version`, `fusion_score`.
- `threshold.rs`: `LabelSource`, `ProvenanceRow`, `TemporalReport`,
  registrable-domain hold-out, `provenance_report`, `temporal_report`.
- `scanner.rs::assess_row`: applies the active map to the assessment score and
  stores the result; page/LLM changes trigger `reassess_domain`.
- `AiEngine::fit_calibration`, `apply_calibration`, `disable_calibration`,
  `calibration_status`.

**Rules.** A map is fitted on the tuning split and evaluated on the held-out
split (one registrable domain in five). A candidate is recorded only if it is
accepted; it is activated only by an explicit apply, which re-runs the
acceptance gate against the map in force and refuses a candidate whose Brier
or ECE is worse (`BRIER_TOLERANCE = 0.002`, `ECE_TOLERANCE = 0.01`, at least 20
held-out names). Nothing describes the raw confidence as a probability: the
status endpoint says so, and `/api/ai/calibration` reports `active: null`
until a map is promoted.

The threshold trial is unchanged in what it chooses and reports: it still
fits the gate score on the tuning half, keeps its four group rows and its
FPR/recall on both halves. It now also reports `provenance` (operator
corrections = strong, feed listings = moderate, established/popular = weak,
unseen = none) and `temporal` (candidate measured on verdicts before and after
the 70th-percentile classification time).

**Migration:** three columns on `ai_verdicts` and `ai_calibrations` (map,
metrics, active flag, created_at). Existing verdicts read 0/empty and use the
confidence.

**API/UI:** `GET /api/ai/calibration`, `POST /api/ai/calibration/fit`,
`POST /api/ai/calibration/apply`, `POST /api/ai/calibration/disable`;
`/api/ai/status` reports `fusion`, `calibration_version`, `calibrated`; the AI
status page shows Fusion, Calibration and Authority rows.

**Tests:** `calibration::tests::*` (monotone fit, over-confidence learned,
Brier/ECE/reliability, worse candidate rejected, thin hold-out rejected),
`threshold::tests::*` (provenance, temporal split, related hostnames on one
side), `threshold_trials_are_recorded_and_never_apply_themselves` (existing
HTTP trial behaviour), and `calibration_is_identity_until_a_map_is_fitted_and_promoted`.

**Validation results:** unit fixtures only. A map fitted on a synthetic
over-confident corpus lowers held-out Brier below the identity map's and is
monotone across the whole grid; a worse candidate is refused with both
numbers. **No production held-out data was available**, so no Brier/ECE on
real traffic is claimed.

**Limitations:** isotonic regression with few positives gives coarse steps;
the acceptance gate compares two point estimates without confidence
intervals; ECE depends on ten fixed bins; and a verdict whose confidence is
raised by the page/LLM stage is reassessed, but any other direct confidence
write outside those paths would leave the stored calibrated score stale.
A map is refused at apply time when the live model is not the model it was
fitted for. Fitting while a map is already active reads that map's output
rather than the pre-calibration assessment score, so a second generation of
maps is measured in the wrong score space; that is an open review item, not
yet fixed.

## Stage 4 - Atomic candidate version

**Purpose.** A candidate is the whole scoring system, promoted and restored as
one version, including the model artifact bytes.

**Files and functions**

- `candidate.rs` (new): `CandidateSpec`, `version_of` (SHA-256 over model
  hash + threshold + calibration version + weights + scoring config),
  `build`, `restore_artifact` (hash-verified, atomic rename).
- `store/assessment.rs`: `ai_candidates`, `ai_model_artifacts` (BLOB),
  `save_candidate`, `promote_candidate`, `rollback_active_candidate`
  (single transaction each), `store_model_artifact`, `model_artifact`.
- `lib.rs`: `install_model` handle (the same closure retrains use),
  `snapshot_candidate`, `promote_candidate`, `rollback_candidate`,
  `candidates_status`, `candidate_json`.

**Promotion** restores and loads the artifact, marks the candidate active with
the previous one recorded (`superseded_id`), publishes its calibration
(identity when it has none) and signal weights, then the API publishes its
threshold through the existing config path. If loading fails the candidate
state is rolled back. **Rollback** restores the previous version's bytes,
threshold, calibration and weights together.

**Migration:** `ai_candidates`, `ai_model_artifacts`.

**API/UI:** `GET /api/ai/candidates`, `POST /api/ai/candidates/snapshot`,
`POST /api/ai/candidates/promote`, `POST /api/ai/candidates/rollback`.

**Tests:** `candidate::tests::*` (version covers threshold/model/calibration,
actual bytes restored, builtin has no artifact, missing artifact refused),
`store::assessment::tests::a_candidate_promotion_supersedes_the_previous_one`,
`a_rollback_restores_the_previous_candidate_and_its_artifact`,
`a_candidate_carries_its_calibration_map_through_promotion_and_rollback`, and
`a_candidate_is_snapshotted_promoted_and_restored_as_one_version` over HTTP.

**Limitations:** the config threshold is published after the engine promotion,
with compensating rollback on failure, not in one distributed transaction
(single process, so the window is small but real). Model artifacts are kept
forever; there is no pruning yet.

## Stage 5 - Signal fusion

**Purpose.** Page, verifier and network evidence become first-class inputs to
a score that is reported for every verdict, without double-counting the model
and its verifier.

**Files and functions:** `fusion.rs` (new): `SignalWeights`, `Contribution`,
`HardMechanism`, `Fusion`, `fuse`, `effective_score`, `disputed`;
`lib.rs::signal_report`; scanner `assess_row` (computes and stores
`fusion_score` when `ai.fusion != "off"`); `AiEngine::authority_status`'s
neighbouring config `ai.fusion` (`off` / `monitor` / `decide`).

**Rules.** The model sets the base. The verifier is in the same evidence
family: it adjusts the base by at most half its small weight and is never a
second base. Independent evidence is summed and then clamped to
`independent_scale` of the model weight, so nine inputs cannot outvote the
model. Feed corroboration and popular/established disputes are *hard
mechanisms*, returned separately and applied outside the sum - the same
mechanisms the existing pipeline already has. Operator overrides never enter.

**Migration:** `ai_verdicts.fusion_score`.

**Tests:** `fusion::tests::*` (model sets the level, verifier not double
counted, group cap, feed corroboration floor, disputes preserved, unknowns
move nothing, weights bounded), `assessment::tests::*` (all nine inputs
present).

**Validation:** unit-level only. The fused score is `monitor` by default and
does not affect enforcement; turning on `decide` is an explicit operator
choice, and there is no held-out comparison yet of fused versus unfused
blocking performance. That comparison is what stage 6's measurements and the
existing threshold trial are for.

## Stage 6 - Graduated source-specific authority

**Purpose.** Autonomy (whether the AI investigates) and authority (whether a
finding may block) are separate, and authority is per evidence source and can
be taken away automatically.

**Files and functions:** `authority.rs` (new): `Source` (feed/model),
`AuthorityDecision`, `stage_for`, `evaluate`, `decision_for`;
`daygle-dns-core::config::{AuthorityStage, AuthoritySettings}`;
`store::BlockSource`, `BlockCandidate`, `authority_measurements`;
`store/assessment.rs::set_authority_stage`, `record_authority_outcome`,
`authority`; `scanner::blocks_with` filters by stage and
`effective_new_block_limit` uses the configured cap as a tightening of the
built-in 500; `AiEngine::authority_status`.

**Defaults.** `ai.authority.enabled = false`: no filtering at all, and the
global `ai.mode` behaves exactly as before. When enabled: feed-confirmed
findings default to `enforce`, model-only findings to `propose`, operator
labels to `enforce`. A source with at least `demote_min_samples` measured
findings and a false-positive share above `demote_fp_rate` (default 5%) is
demoted to `monitor`. `propose` findings are emitted as verdicts (the Threats
tab lists them) but never reach the block snapshot. If the measurement query
fails, every source is held to monitor (fail closed).

**Migration:** `ai_authority`; `BlockSource` derived from the stored evidence
(`", listed by "` marks a feed-corroborated verdict), so no verdict rows
change.

**API/UI:** `GET /api/ai/authority`; `/api/ai/status` reports the configured
stages; the AI status page shows whether authority is on and the stages.

**Tests:** `authority::tests::*` (off changes nothing, demotion at measured
FP rate, clean source keeps its stage),
`store::assessment::tests::authority_records_each_source_and_a_demotion`, and
`graduated_authority_holds_model_findings_until_they_are_trusted` (monitor
holds, enforce admits, operator override still wins).

**Limitations:** there is no separate proposals queue UI; `propose` means
"listed as a verdict, not blocking". Demotion uses the operator's corrections
as its false-positive signal, so an install nobody corrects cannot demote a
source - it also cannot promote one. Feed listings are attributed from the
verdict's evidence note rather than a stored foreign key.

## Safety protections: effect of these changes

| Protection | Effect |
|---|---|
| Operator allowlist / not-a-threat | Unchanged: checked before plugins and filtered in `fresh_blocked`; fusion never sees them. |
| Operator category corrections | Unchanged; never filtered or demoted by authority. |
| Subdomain / registered-domain disputes | Unchanged (`channel.rs`, `evidence.rs`); the verifier observation reports them, fusion preserves them as hard mechanisms. |
| Popular and established protections | Unchanged; reported as `HardMechanism::PopularDispute` / `EstablishedDispute` and still set `disputed` upstream. |
| Threat verdict expiry | Unchanged; calibrated score travels with the verdict row. Observation rows are removed with their verdict. |
| Train mode / client-group enforcement | Unchanged; authority filtering happens inside `blocks_with`, before the snapshot, which is still empty in train mode. |
| Maximum new blocks per refresh | Still 500 by default; a configured authority limit is clamped *below* it, never above. |
| Model trial and rollback | Unchanged (`maintain.rs`); candidate promotion is a separate operator action. |

## Validation summary

- `cargo test -p daygle-dns-ml --no-default-features --lib`: 142 passed.
- `cargo test -p daygle-dns-ml --no-default-features --test integration`:
  82 passed (store upgrades, expiry, disputes, retrain gate, shadow trial,
  authority, plus all pre-existing tests).
- `cargo test -p daygle-dns-api ai_tests::`: 22 of 23 passed, including the
  new signals, calibration and candidate HTTP tests; the one failure is the
  pre-existing Windows training-path failure noted below. The full API suite
  is 94 of 95 for the same reason.
- `cargo check --workspace --all-targets`: passes.

On Windows, `ai_tests::retrain_and_rollback_succeed_over_http` fails inside
`learn::train` with `PermissionDenied` before any of this work runs. It fails
the same way at the base commit (`bf82cf5`) in a clean worktree, so it is a
pre-existing Windows limitation of the fastText training path, not a
regression; the Linux CI target is unaffected. The `nix` unused-dependency
warning is likewise platform-only.

Not measured: Brier/ECE on real traffic, fused-versus-unfused precision,
authority demotion on production corrections, and a visual check of the new
status rows (the bundle was rebuilt, but the console was not opened).
