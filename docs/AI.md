# AI scanner

`daygle-dns-ml` is a small, CPU-only classifier that runs in the background
over domains seen in the query log. It never runs on the DNS hot path. A
fastText starter model ships in [`models/`](../models/README.md), so it works
out of the box. For how it is built internally, see
[ARCHITECTURE.md](ARCHITECTURE.md#ai-scanner-daygle-dns-ml).

## Modes and defaults

The scanner is off in the built-in defaults (`ai.enabled = false`), but the
installer turns it on in **train mode**: verdicts are recorded and nothing
is blocked. Set `ai.mode = "enforce"` in the config or the console once you
are happy with the verdict log. Set `DAYGLE_DNS_AI=0` when installing to
leave the scanner off.

- The operator allowlist always wins.
- Expired verdicts go back into the scan queue.
- Verdicts are available from the REST API under `/api/ai/*` (see
  [API.md](API.md#ai-scanner)).

## Two channels

The scanner does two separate jobs. Each has its own model, confidence floor
and verdict TTL.

- **Categorization** labels sites (news, shopping, adult, ...). It never
  blocks. The **AI → Classifications** tab lists these, and you can relabel
  any of them. Blocking an ordinary category (gambling, ads, ...) is a
  setting on a filtering group, not a scanner decision.
- **Threat detection** is the only channel that can auto-block, and only
  fresh, high-confidence verdicts. The **AI → Threats** tab lists what it
  blocks.
  - With the shared model, it reports only the labels in
    `ai.auto_block_categories` (`malware`, `phishing`, `scam` by default).
  - With a dedicated `ai.threat_model_path`, every label that model produces
    is a threat and blocks above `ai.block_threshold`, so
    `ai.auto_block_categories` applies only to the shared classifier.

The threat list exports as a plain domain list or CSV, for use as a
blocklist elsewhere. A domain can be marked *not a threat*: its detection
stops blocking but is kept for review. *Not a threat* applies to that exact
name; an **allow** on a parent (for example `doubleverify.com`) also stops
every name under it from blocking, so use it when one vendor shows up under
many subdomains. Either kind of override, on the name or on any parent, keeps
the name out of retraining. Every operator correction can be downloaded as
training data.

## Models

| Setting | What it does |
|---|---|
| `ai.model_path` | The shared model (a supervised fastText `.bin`). Empty uses the zero-model heuristic backend. |
| `ai.category_model_path` | A model for the categorization channel only. |
| `ai.threat_model_path` | A model for the threat channel only (see above). |
| `[updates] auto_refresh_models` | Keep the release model bundle, including the starter corpus, up to date. |

A release model bundle is tested on a pinned sample of held-out threat names
before it is installed, and again after the restart. If it misses more of
them than the files it replaces, those files are restored and the update
fails, reporting both counts.

## Retraining

With `ai.auto_retrain` on, the scanner periodically rebuilds its model from:

- your corrections,
- its own confident verdicts, but only those the shipped reference model,
  the verifier or the page agrees with, so a mistake cannot reinforce
  itself, and
- the shipped starter corpus, so labels this network has not seen lately
  are not forgotten.

A candidate model is refused when it:

- scores worse on held-out corrections than the model in use,
- can no longer report a threat label the model in use can report, or
- misses more held-out threats than the model in use, even when its overall
  score is fine. Whole word families (grouped by shared words) are held back
  for this check, and each is probed under a word order the store never
  recorded, so a candidate that only misses new names is still caught.

With `ai.trial_new_models`, a scheduled retrain's candidate first runs in the
shadow of the live model. It is promoted, without a restart, only if it did
at least as well on held-out threats, on live traffic, on your corrections
during the trial and on independently confirmed labels. A rejected candidate
never answered a query; the rejection pauses retraining and raises an alert.

A dedicated threat model is maintained the same way. The verifier's
reference is refreshed from your corrections, never from its own verdicts.
The model that was replaced is kept, so one rollback is always available.

### Corrections as negatives (`ai.learn_negatives`)

A domain marked *not a threat* never trains under the label it was denied.
With `ai.learn_negatives` (off by default) those corrections also train as a
`benign` label, so a correction can change the next model. The threat channel
never reports `benign` as a threat, but a negative class can over-generalise,
which is why it is opt-in.

`cargo run -p daygle-dns-ml --example negatives_eval` measures the effect.
On a synthetic corpus where the negatives are domains the model had flagged,
half the held-out threats read as benign; where they are harmless sites, 2 of
30 do. The same command runs the retrain gate on a model trained the way the
retrainer trains one, prints whether it would refuse it, and fails if a
candidate that swallows threats is accepted. In the current run it refuses
both candidates (12 of 12 and 8 of 8 held-out names lost), including the
scenario where 15 of 30 unseen threats are swallowed.

## Page fetching (`ai.fetch_pages`)

Off by default. When on, the server fetches the home page of each new threat
candidate, reads its title and text with a small cue classifier, and stores
the result with the verdict. `ai.page_rule` decides what that reading may do:

| `ai.page_rule` | Effect |
|---|---|
| `evidence` (default) | Recorded only. |
| `corroborate` | A page that agrees can raise the confidence. |
| `decide` | Also caps the confidence when the page reads as an ordinary category and has no threat cue at all. |

The page is written by the site being judged, so a site that shows a fetcher
harmless text can game `decide`. That is why it is opt-in.

The page stage gets at most 90 seconds per scan cycle. Private, loopback and
link-local addresses are refused, and redirects are checked the same way.
