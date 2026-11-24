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
- Expired verdicts go back into the scan queue. Threats are re-checked
  after 14 days and classifications after 90 days
  (`ai.threat_ttl_secs`, `ai.category_ttl_secs`), and expired verdicts are
  looked for every hour (`ai.expire_check_secs`). An expired threat stops
  blocking until it is checked again, so that check stays frequent; it costs
  one indexed query.
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
  Your own label wins on both tabs: relabelling a domain with a ticked
  threat label makes it a threat (it blocks in enforce mode whatever the AI
  scored, and never expires), and relabelling it with any other category
  stops the AI's detection from blocking it. Exemptions still win, and
  unticking the label stops your threat labels too. Removing your label
  lets the AI decide again.
  It reports only the labels in `ai.auto_block_categories` (`malware`,
  `phishing`, `scam` by default).

The model reads only the domain name. When it flags a subdomain, the
scanner also scores the registered domain above it (by the Public Suffix
List). If that reads as an ordinary site, the threat came only from the added
labels (`secure.`, `login.`, `verify.` and the like), so the verdict is
recorded as *disputed*: listed for review, never blocked and never used for
retraining. For example, `secure.employmenthero.com` is disputed because
`employmenthero.com` reads as `business`. Phishing names whose registered
domain is itself suspicious (`login.secure-paypal-verify.info`) still block,
and so do user sites on free hosts listed as public suffixes
(`*.github.io`, `*.web.app`). Phishing on a hacked subdomain of an ordinary
site is out of reach for a name-only model; use a threat feed for that.

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
From the third rejection in a row, the pause doubles each time, up to a week,
and the alert says so.

A model that goes live on its own (a trial promotion, or a scheduled retrain
with trials off) is then watched for 3 days. It is rolled back to the model
before it, with an alert, when:

- it blocks more than twice the share of scanned domains the live model
  blocked in the week before, and at least 10 domains more (judged once
  both sides have scanned 200 domains), or
- you mark 3 of its new detections *not a threat*.

Retrain Now and Restore Previous Model are your own choices and are not
watched. A threat feed or the popular-sites list that has failed to update
for 2 days raises an alert too.

The verifier's reference is refreshed from your corrections, never from its own verdicts.
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
retrain. A feed listing also confirms a threat verdict for training, except
one the feed alone made (the AI saw no threat in the name): it blocks, but
its ordinary-looking name never trains the model as a threat. Only the
labels ticked in `ai.auto_block_categories` are used. Your
corrections win over a feed.

### Popular sites

`ai.threat_feeds` also downloads Tranco's ranking of the most popular sites
(top 100,000), every 12 hours. A name-only threat detection on a popular
registered domain is disputed and never blocks. The match is on the
registered domain only: `pages.dev` is popular, but `evil.pages.dev` is a
registered domain of its own under the Public Suffix List and is not. A
threat feed listing still wins. Popular sites are also part of the ordinary
probe every candidate model is tested on, so a new install has one from its
first download.

### Domain age (`ai.domain_age`)

On by default. After each scan, up to 16 new threat verdicts have their
registered domain's creation date looked up over RDAP (through
`policy.rdap_bootstrap`):

| Registered | Effect |
|---|---|
| In the last 14 days, flagged at 90% or more | Raised to 99% (blocks at the default threshold) |
| In the last 14 days, flagged below 90% | +10%, never above 95% |
| Over 2 years ago | -5%, unless a threat feed confirmed it |
| In between | Noted only |

Each lookup tells the TLD's registry which domain was asked about, never who
asked.

### Established domains

Each scan records the days a domain was looked up on and the clients that
looked it up. Clients are stored as short hashes, at most 16 per domain, and
a history unused for 90 days is forgotten. A domain at least 3 clients have
looked up on at least 14 days is *established*.

### Checking threat verdicts (`ai.network_evidence`)

On by default. Every threat verdict is checked against that evidence:

| Evidence | Effect |
|---|---|
| A feed lists it under a threat label | Corroborated at 99% (blocks in enforce mode at the default threshold), even over a verifier dispute, and even when the AI saw no threat in the name at all |
| Established on this network | Disputed: kept and shown, never auto-blocks |
| A machine-generated name first seen today | Noted, +5%, never above 95% |

Your exemptions and corrections still win over all of it.

The evidence is applied again when it changes, not only when a verdict is
made: a threat-feed or popular-sites download re-checks every verdict whose
listing changed, and the hourly expiry check re-checks the threats on domains
that have since become established. A different model going live (a
promotion, a rollback, or new model files after a restart) brings forward the
re-check of every verdict on a domain still in use, spread over 3 days, so the
better model corrects old verdicts without waiting out their lifetime.

## Page fetching (`ai.fetch_pages`)

On by default. The server fetches the home page of each new threat
candidate, reads its title and text with a small cue classifier, and stores
the result with the verdict. `ai.page_rule` decides what that reading may do:

| `ai.page_rule` | Effect |
|---|---|
| `evidence` | Recorded only. |
| `corroborate` (default) | A page that agrees can raise the confidence. It never lowers it, so a site cannot talk its way out of a block. |
| `decide` | Also caps the confidence when the page reads as an ordinary category and has no threat cue at all. |

The page is written by the site being judged, so a site that shows a fetcher
harmless text can game `decide`. That is why it is opt-in.

Disputed threat candidates are read too, after the undisputed ones. Their
pages are the ordinary examples the page-text model learns from.

Fetching contacts the site from this server, so the site sees the server's
address. Turn `ai.fetch_pages` off if that is not acceptable.

### Categories from pages

In the same time budget, the server also reads the page of each domain the
categorizer is unsure of (below 50% confidence, or no category at all), most
looked-up first. If the page's text clearly names an ordinary category
(job listings, recipes, homes for sale and the like) more surely than the
name did, the domain takes that category. These labels are marked as the
page's, are never trained on (a site writes its own page, and the shared
model must not learn from it), and never make or clear a threat. Your own
label always wins.

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

## Language model (`ai.llm_enabled`)

Off by default. An optional local language model, served by
[Ollama](https://ollama.com), reads the pages the page stage already kept,
for the verdicts the AI is least sure of. It never contacts a site itself.

| Verdict | What the language model may do |
|---|---|
| A threat below the block threshold, not on a threat feed | Raise it: to 99% (blocks) when the verdict is at least 50% and the model reads the page as a threat at 85% or more; otherwise by 10%, never above 95%. Never lower it. With `ai.page_rule = "evidence"` it is only recorded. |
| A category below 50% | Replace it with the category the model names, when the model is surer than the name was and the label is an ordinary category the categorizer knows. |

The page is written by the site being judged, and a language model can be
talked into things by what it reads. So the model is told the page is
untrusted, its answer is constrained to a JSON schema with the label list as
an enum, it can only strengthen a threat, and its labels (`backend = llm`)
are never used for retraining. Your own labels and exemptions win.

Each answer takes seconds on a CPU, so at most `ai.llm_candidates_per_scan`
(6) pages are read per scan cycle, threats first, within 3 minutes and
`ai.llm_timeout_secs` (120) per answer. An unreachable server is skipped
until the next cycle.

The Test button on the Language Model tab gets at least 300 seconds and at
most 600, whatever `ai.llm_timeout_secs` says: a test is usually the model's
first answer, which also loads it into memory, and a shorter limit would
report that first load as a failure. The tab says which limit it uses.

| Setting | Default |
|---|---|
| `ai.llm_enabled` | `false` |
| `ai.llm_url` | `http://127.0.0.1:11434` |
| `ai.llm_model` | `qwen2.5:1.5b` |
| `ai.llm_candidates_per_scan` | `6` (1-32) |
| `ai.llm_timeout_secs` | `120` (5-600) |

### Installing and managing Ollama

- **From the console**: AI > Language Model > Install Ollama. It goes
  through the same root update service as a server update, runs Ollama's
  official installer, keeps the server on `127.0.0.1` (its API has no
  login) at low CPU and disk priority, and downloads the default model. It
  needs about 3.5 GB of memory in total. The same page updates Ollama
  (models are kept) and removes it.
- **From the installer**: `DAYGLE_DNS_OLLAMA=1` installs or updates it,
  `DAYGLE_DNS_OLLAMA_MODEL` picks the model, `DAYGLE_DNS_OLLAMA=0` removes it.
- **Bring your own**: point `ai.llm_url` at an Ollama running elsewhere, for
  example a more powerful machine on your network. Manage that server where
  it runs; the console still lists, downloads, updates and deletes its
  models.

Models are downloaded, updated (pulling the same name again fetches only
what changed) and deleted on the same page, with a progress bar. Smaller
models answer faster: `qwen2.5:0.5b` (about 0.4 GB) on slow or older CPUs,
`qwen2.5:1.5b` (about 1 GB) as the default, `qwen2.5:3b` or `llama3.2:3b`
(about 2 GB) where the CPU is fast enough. Ollama runs on CPUs without AVX2,
more slowly. Test on that page shows how long one answer takes.

The first answer after Ollama starts (or after the model has been idle for
10 minutes) also loads the model into memory, which can take minutes on a
CPU. Test allows 5 minutes for it; scans use the answer time limit. If Test
reports no answer in time, run it again once the model is loaded, raise the
limit, or pick a smaller model. If it reports the server dropped the
request, check `journalctl -u ollama` (often too little memory). The
console installs Ollama as the first process the kernel ends when memory
runs out, so a model that does not fit never takes the DNS server down;
re-run Update on the Language Model tab to apply that to an existing
install.
