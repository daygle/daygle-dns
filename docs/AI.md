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
- its own confident verdicts, but only those a fixed reference or an
  independent source agrees with, so a mistake cannot reinforce itself. The
  fixed reference is the configured model, or the built-in keyword rules
  when no model file is configured (never the model being retrained); the
  independent sources are the verifier, the page and the threat feeds,
- current threat-feed names (see below), and
- the shipped starter corpus, so labels this network has not seen lately
  are not forgotten.

A candidate model is refused when it:

- scores worse on held-out corrections than the model in use,
- can no longer report a threat label the model in use can report,
- misses more held-out threats than the model in use, even when its overall
  score is fine. Whole word families (grouped by shared words) are held back
  for this check, and each is probed under a word order the store never
  recorded, so a candidate that only misses new names is still caught,
- detects fewer held-out threat-feed names than the model in use (2% slack), or
- flags more of the network's established domains as threats (2% slack).

With `ai.trial_new_models`, a scheduled retrain's candidate first runs in the
shadow of the live model. It is promoted, without a restart, only if it did
at least as well on held-out threats, on live traffic, on your corrections
during the trial, on independently confirmed labels (threat feeds included),
on held-out threat-feed names and on the established domains looked up during
the trial. The automatic signals mean a trial on an install nobody corrects
still has evidence to judge; before them, a quiet trial promoted its
candidate for lack of evidence. A rejected candidate never answered a query;
the rejection pauses retraining and raises an alert.

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

## Outside evidence

The classifiers only see a domain's spelling. Two things the server knows
that the spelling does not show give the AI a second opinion that works
without the ONNX verifier, and beside it.

### Threat feeds (`ai.threat_feeds`)

On by default. The server downloads maintained public lists every 12 hours,
through `policy.feed_mirror` when one is set, and keeps the last good copy in
`ai.db`:

| Feed | Label |
|---|---|
| URLhaus (abuse.ch), via malware-filter | `malware` |
| Phishing Army | `phishing` |
| HaGeZi Fake | `scam` |

The downloads name domains and reveal nothing about this network's traffic.
A stable one in five names is held out of training to test every candidate
model and trial. The rest train the threat labels, up to 1,000 per label per
retrain. A feed listing also confirms a threat verdict for training. Only the
labels the model treats as threats are used: `ai.auto_block_categories` for
the shared model, or every label of a dedicated threat model. Your
corrections win over a feed.

### Established domains

Each scan records the days a domain was looked up on and the clients that
looked it up. Clients are stored as short hashes, at most 16 per domain, and
a history unused for 90 days is forgotten. A domain at least 3 clients have
looked up on at least 14 days is *established*.

### Checking threat verdicts (`ai.network_evidence`)

On by default. Every threat verdict is checked against that evidence:

| Evidence | Effect |
|---|---|
| A feed lists it under a threat label | Corroborated at 99% (blocks in enforce mode at the default threshold), even over a verifier dispute |
| Established on this network | Disputed: kept and shown, never auto-blocks |
| A machine-generated name first seen today | Noted, +5%, never above 95% |

Your exemptions and corrections still win over all of it.

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

Disputed threat candidates are read too, after the undisputed ones. Their
pages are the ordinary examples the page-text model learns from.

### Page-text model

The text of each page read (the title and the first 4,000 characters) is kept
in `ai.db`, at most 5,000 pages. When automatic retraining is on, a fastText
model is trained on that text at most once per retrain interval. Only pages
with a known label are used:

- *threat*: a threat feed lists the domain;
- *ordinary*: you marked the domain *not a threat*, or it is established.

Training needs at least 20 pages of each kind. The new model is used only if
it gets at least 70% of held-out pages right, does no worse than the phrase
list and does no worse than the model in use. It can add a threat reading or
raise one. It never makes a page read as ordinary and never hides a threat
phrase, because a learned "looks harmless" would be the easiest thing for a
site to game.

The page stage gets at most 90 seconds per scan cycle. Private, loopback and
link-local addresses are refused, and redirects are checked the same way.
