# Daygle DNS architecture

Daygle DNS is a Cargo workspace of ten crates. One binary (`daygle-dns`) composes
them into a single process that serves plaintext DNS, DNS over TLS,
DNS over HTTPS, DNS over QUIC, and an HTTP API/GUI.

## Crate responsibilities

```
                        ┌───────────────────────────────┐
                        │        daygle-dns (bin)       │
                        │   DnsDispatcher + listeners   │
                        └───┬─────────┬─────────┬───────┘
                            │         │         │
           ┌────────────────┘         │         └────────────────┐
           ▼                          ▼                          ▼
┌──────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────┐
│ daygle-dns-policy    │ │ daygle-dns-authoritative │ │ daygle-dns-recursive │
│ ACLs, blocklists,    │ │ SQLite store, catalog,   │ │ recursor, forwarders,│
│ filtering groups     │ │ DNSSEC, transfers, RPZ   │ │ caching, DNSSEC      │
└──────────────────────┘ └──────────────────────────┘ └──────────────────────┘

Also composed by the binary:
  daygle-dns-api   REST API (axum) and console     daygle-dns-gui  console assets
  daygle-dns-dot   TLS for DoT/DoH/DoQ (rustls)    daygle-dns-ml   AI scanner
  daygle-dns-dhcp  DHCPv4/DHCPv6 (Linux)           daygle-dns-core config, errors,
                                                                  metrics, logs
```

- **`daygle-dns-core`** is dependency-free of the DNS stack: the TOML configuration
  model, the shared `DaygleError`, atomic `Metrics`, and a bounded `LogStore`.
- **`daygle-dns-policy`** evaluates a query in order: ACLs → allowlist →
  blocklists (static and remote sources) → ordered per-client rules → AAAA
  filter → plugins. It also holds the filtering groups (`advanced.rs`),
  which the dispatcher applies after it. A `PolicyPlugin` is a boxed async
  callback; the first plugin returning `Some(Decision)` wins.
- **`daygle-dns-authoritative`** persists zones/records/DNSSEC keys in SQLite and
  rebuilds an in-memory Hickory `Catalog` (`InMemoryZoneHandler` per zone). The
  hot query path never touches SQLite. It also owns the split-horizon index
  (`SplitHorizonIndex`): stored client networks + domain entries are
  pre-resolved into a per-query lookup structure that maps `(client IP,
  qname, query type)` to the synthetic records to serve.
- **`daygle-dns-recursive`** resolves names in one of two modes: recursive
  (from the root servers, through Hickory's recursor, patched in
  [`vendor/`](../vendor/README.md)) or forwarding (a Hickory `Resolver` over
  the configured upstreams). It configures cache size, per-server timeouts,
  attempts, and DNSSEC validation. Negative
  caching is Hickory's built-in behavior, bounded by `negative_cache_ttl`.
  With `aggressive_nsec` on (and validation), validated NSEC records are
  also kept in a bounded proof cache (`aggressive.rs`): a name a cached NSEC
  proves absent is answered NXDOMAIN, and an existing name without the
  asked type NODATA, synthesized locally with the SOA and the NSEC proofs
  (RFC 8198). Only `Proof::Secure` records are used, each proof expires
  with the earliest of the negative TTL, its own TTL and its signature's
  expiration, and NSEC3 zones are left to normal resolution.
  Conditional forwarding zones and stub zones each get their own resolver;
  routing happens at lookup time (see step 3 of the query flow).
- **`daygle-dns-dot`** produces rustls TLS configurations for the encrypted
  DNS protocols - the `dot` ALPN for DoT (RFC 7858, plus `xot` for zone
  transfers), `h2` for DoH (RFC 8484)
  and a TLS 1.3 + `doq`-ALPN setup for DoQ (RFC 9250) - and generates
  self-signed certificates when configured.
- **`daygle-dns-api`** serves the REST API and the embedded GUI, including
  console login (PBKDF2 password verification + session tokens kept in
  memory and, hashed, in the database; `admin`/`viewer` roles enforced in
  the auth middleware) and the dashboard
  statistics endpoint backed by `daygle-dns-core`'s bounded `QueryStats`.
- **`daygle-dns-gui`** embeds the compiled Svelte bundle via `rust-embed`.
- **`daygle-dns-ml`** is the AI scanner: a background classifier over the
  domains seen in the query log (see "AI scanner" below).
- **`daygle-dns-dhcp`** is the DHCPv4/DHCPv6 server (Linux only), which
  registers its leases by name in a hosted zone.
- **`daygle-dns`** (binary) binds the UDP/TCP (and DoH over HTTP/3)
  listeners onto one Hickory `Server` driven by `DnsDispatcher`, and serves
  DoT, DoH and DoQ
  with its own listeners (`dot.rs`, `doh.rs`, `doq.rs`) that feed the same
  dispatcher: DoT answers the queries of one connection concurrently and out
  of order (RFC 7766), pads answers to padded queries (RFC 8467) and caps
  connections per client; DoH caps connections the same way and bounds the
  concurrent streams of each. When `[dnstap]` is on, the dispatcher wraps
  the transport's response handler (`dnstap.rs`) so every query and the
  exact response bytes it produced are streamed as dnstap events over
  Frame Streams to a collector, through a bounded queue that drops rather
  than ever slowing a query.

## Query flow

`DnsDispatcher` implements Hickory's `RequestHandler` and is used by every
listener. A query passes these stages in order (`dispatcher.rs`, `dispatch`);
the first that answers ends it.

0. **Admission.**
   - **Per-client rate limit**: a fixed-window budget per source IP.
     Requests over it get SERVFAIL and increment the `rate_limited` metric.
     Loopback is exempt when `rate_limit.exempt_loopback` is set (the
     default). Limits live in a shared
     [`RateLimiter`](../crates/daygle-dns-core/src/rate_limit.rs) that reload
     swaps in place, so changing them never drops in-flight windows.
   - **Listener ACL**: a client outside `dot`/`doh`/`doq.allowed_networks`
     gets REFUSED on that listener.
   - **DNS accounts**: with `accounts.require`, an encrypted query must name
     a known, enabled account.
   - **DNS cookies** (RFC 7873): a client whose server cookie checks out gets
     a larger per-client allowance. **RRL** counts every UDP response from
     here on.
   - **Opcode**: RFC 2136 UPDATEs (step 5) and RFC 1996 NOTIFYs (see
     Concurrency model) branch off here, so they never reach the policy
     stages.
   - **Per-domain rate limit** (SERVFAIL, like the per-client one), then
     **DDR** (RFC 9462): `_dns.resolver.arpa` is answered locally with SVCB
     records for the encrypted listeners.
1. **Filtering.**
   - **Policy engine** (`daygle-dns-policy`): allowlist, blocklists and
     remote blocklist sources, then plugins (the AI scanner's among them).
     `Block` → NXDOMAIN (or the block page's address, when the block page is
     on), `Refused` → REFUSED, `Redirect(ip)` → a synthesized A/AAAA answer,
     `NoData` → an empty answer (the AAAA filter).
   - **Filtering groups** (`advanced.rs`): per-client-group allow/block
     rules, blocked services and categories, and the security and privacy
     protections.
   - **Response policy zones**: client-IP and QNAME triggers, in zone order.
     An allowlisted name is exempt.
   - **Safe Search** and YouTube Restricted Mode: a search engine's name is
     answered with a CNAME to its "safe" address.
2. **Local answers.**
   - **Split horizon**: for A/AAAA/MX/TXT/CNAME/SRV (and ANY), the first
     entry whose domain matches and whose networks contain the client
     answers with records of the queried type. A CNAME answers every type
     (RFC 1034 §3.6.2), and an entry with nothing for the queried type falls
     through, so a TXT-only entry never swallows A queries. It runs before
     the authoritative zones, so internal clients see internal answers even
     for hosted zones.
   - **Zone transfers** (AXFR/IXFR, `handle_transfer`) - see below.
   - **Dispatcher-made answers** from indexes the catalog rebuilds with the
     zones: ALIAS records (A/AAAA from the target), weighted A/AAAA RRsets
     (one record picked in proportion to the weights, after failover;
     unsigned zones only) and AUTOPTR records (a PTR made from the address
     when the name has none).
   - **Authoritative zones**: if the name falls inside a hosted zone
     (`Catalog::find`), the Hickory catalog answers. Signed zones carry
     DNSSEC signatures and NSEC/NSEC3 proofs. Zone aliases are served as
     zones of their own, built from the aliased zone's records with the
     owner names moved into the alias.
   - **RFC 6303 empty zones**: a name in one of `authoritative.empty_zones`
     (by default the reverse zones for private, loopback, ULA, link-local
     and documentation address space) that no hosted zone covers is answered
     authoritatively without recursing: the apex serves its SOA and NS,
     other names get NXDOMAIN with the SOA (RFC 2308). Reverse lookups for
     never-routable addresses therefore never leak to public upstreams.
3. **Recursive.** Clients the recursion gate refuses get REFUSED. Otherwise
   `RecursiveResolver` picks a route: the most specific conditional or stub
   zone (longest label-aligned suffix) first, then the client's resolution
   policy, then the default mode (recursive or forwarding). With a local root
   zone (RFC 8806), a forwarded name under a TLD the root does not have is
   answered NXDOMAIN without a lookup. The answer keeps the upstream's RCODE
   and gets the AD bit when DNSSEC validation succeeded; negative answers
   (NXDOMAIN/NODATA) are returned as-is instead of SERVFAIL. Before it goes
   out, the answer is checked by the response filters (DNS rebinding,
   blocked CNAME targets, oversized payloads), and DNS64 (RFC 6147) may
   synthesize AAAA records.

**Zone transfers.** Transfers are gated by `authoritative.axfr_enabled` and
the `axfr_networks` client allow-list (and TSIG, where a key is bound to the
zone). AXFR is answered with the full zone (`SOA, records..., SOA` per
RFC 5936). IXFR is answered incrementally: every write that bumps a zone's
serial also records the records it added and removed in that zone's change
journal (`zone_changes`, the newest `authoritative.ixfr_journal_depth`
changes, 64 by default), and a client whose serial the journal still reaches
gets RFC 1995 difference sequences - `SOA(current)`, then `SOA(old) deletions
SOA(new) additions` per step, then the current SOA again. A client already
at the current serial gets the lone SOA. When the journal cannot reach the
client's serial, or the answer would carry more than
`authoritative.ixfr_max_records` changed records (10 000 by default), the
full zone is sent instead (always valid per RFC 1995 §4-5). Zones served
verbatim from a transfer (signed zones and secondaries) keep no journal and
answer in full. The zone only goes out over a connection: a UDP source
address is not proven, so AXFR over UDP is refused and IXFR over UDP gets the
current SOA alone, which sends the client to TCP.

Transfers also run over TLS (XoT, RFC 9103): the DoT listener advertises both
the `dot` and `xot` ALPN protocols and serves transfers on either, behind the
same ACL and TSIG gates. A secondary names a TLS master as
`tls://IP[:port][#name]` (port 853) and verifies the master's certificate
against `name` (or the address when no name is given), using the public
roots plus the PEM trust anchors in `authoritative.xot_ca_certs` (for a
private CA; applied without a restart).

**Dynamic updates.** RFC 2136 `UPDATE` messages are handled by
`daygle-dns-authoritative`'s update handler (`handle_update`), not the
catalog. It validates the zone section, checks prerequisites (NXDOMAIN /
NXRRSet / YXDomain / YXRRSet), builds an atomic add/delete plan, writes it
through to SQLite (bumping the SOA serial unless the update rewrites the
SOA), and reloads the catalog so the change is served immediately. Gated by
`authoritative.allow_dynamic_updates` and the `update_networks` client
allow-list; secondary zones are always refused. A successful update sends
NOTIFY to the configured secondaries like any other zone change.

## Concurrency model

- The Hickory `Catalog` is shared through `arc_swap::ArcSwap`, so the
  dispatcher clones an owned `Arc<Catalog>` per query rather than holding a
  non-`Send` lock guard across `.await`.
- Zone mutations go through the REST API (updates SQLite, then calls
  `AuthorityCatalog::reload()`) or through RFC 2136 dynamic updates, which
  apply their changes in a single SQLite transaction via
  `ZoneStore::apply_dynamic_updates` and then reload the catalog the same
  way - either path atomically swaps in a fresh catalog. Split-horizon
  changes (networks/entries, via the REST API) rebuild the split-horizon
  index on the same `reload()`, so DNS and API views stay in sync.
- Secondary zones are driven by `daygle-dns-authoritative`'s `SecondaryRefresher`,
  which compares each zone's SOA serial against its master on a refresh
  interval and pulls when the master is newer (or the local zone has never
  been transferred). An IXFR that comes back as difference sequences is
  applied to the copy served now - deletions matched by name, type, content
  and TTL, then additions - and the result goes through the same
  `ZoneStore::replace_records` path as a full transfer; a master that answers
  with the whole zone (or a serial the journal no longer covers) takes that
  same path directly. The catalog is reloaded so updates are served
  immediately. Secondary zones are served read-only: the
  Hickory catalog marks them `ZoneType::Secondary`.
- NOTIFY (RFC 1996) closes the loop in both directions. Outbound: the
  `NotifySender` sends a NOTIFY (OpCode 4, QTYPE SOA, UDP) to each configured
  `notify_targets` whenever a primary zone is served with a new serial (the
  catalog reports these on every reload, whatever made the change).
  Inbound: the dispatcher intercepts OpCode::Notify on the regular DNS
  listeners (no extra socket) and `NotifyInbound` answers NOTIFYs for
  configured secondary zones with the current SOA, then triggers an
  immediate serial check + IXFR/AXFR pull through the `SecondaryRefresher`.
  NOTIFYs are only accepted from one of the zone's configured masters and
  are treated as hints only - serials are still compared before any
  transfer, so replayed or spoofed NOTIFYs are harmless.
- `Metrics` uses lock-free atomics; `LogStore` is a mutex-guarded ring buffer.

## Live configuration reload

`daygle-dns` watches its TOML config file (mtime polling) and applies changes
without a restart. The policy engine, the recursive resolver and the effective
config are each published through `arc_swap::ArcSwap` containers shared by the
dispatcher and the REST API, so every query observes one consistent snapshot.
When the `server`/`dot`/`doh`/`doq` sections change, a listener supervisor gracefully
stops the current sockets and rebinds new ones, self-healing back to the last
good configuration if a bind fails. Reload can also be triggered on demand via
`POST /api/config` or `BoundServer::reload()`.

The DoH listener (`doh.rs`, built on `h2` directly) serves both RFC 8484
methods at the configured `endpoint` (default `/dns-query`): POST requests
carrying an `application/dns-message` body, and GET requests carrying the
message as a base64url `dns` parameter. DoH over HTTP/3 is served by the
Hickory `Server` alongside the UDP and TCP listeners.

### Remote blocklist sources

`daygle-dns-policy`'s `BlocklistSourceManager` fetches each configured
`[[policy.blocklist_sources]]` URL over HTTP(S) (reqwest/rustls, 64 MiB body
cap, redirects, a 30 s idle-read timeout within 5 minutes overall), up to
four at a time, and parses the body in its declared format (`domains`,
`wildcard`, `hosts`, `adblock`, or `rpz`), keeping only entries that are
host names. A background task in `daygle-dns` wakes when the next source is
due - each on its own `refresh_secs`, never more often than every 5
minutes - and swaps the merged remote blocklist into the shared
`PolicyEngine` via `set_source_lists`. The static blocklist from
config/files is never discarded, and a failed fetch leaves the previous
domains in place and is retried after 5 minutes rather than a whole
interval later. While no source changed, the same merged list is reused.
`POST /api/policy/blocklist/sources` forces an immediate refresh; `GET` the
same path for per-source status.

## DNSSEC

- **Validation** (recursive path) is enabled with `recursive.dnssec_validate`;
  Hickory validates the chain and sets the AD bit; bogus chains fail the query
  with SERVFAIL and extended error 6 naming the record. The validator only
  marks a positive answer that fails; the resolver refuses it
  (`recursive.dnssec_reject_bogus`; off by default, which serves it
  unvalidated). A bogus mark on a name under a zone the validator proves
  unsigned is taken off first: servers holding both a zone and a zone
  delegated from it answer the validator's DS question from the wrong side.
- **Signing** (authoritative path) is per-zone: `POST /api/zones/:id/sign`
  generates a key with `authoritative.dnssec_algorithm` (ECDSA P-256 by
  default; ECDSA P-384 or Ed25519 also work), stores it as PKCS#8 in SQLite,
  and signs the zone on the next catalog reload, with NSEC non-existence
  proofs or, when asked, NSEC3 (RFC 9276 parameters: no extra iterations, no
  salt). Signatures are
  valid for `dnssec_sig_validity_days` (default 14) from their inception,
  which is backdated one hour to absorb validator clock skew. A signed zone
  is served with its stored serial, and transferred (AXFR/IXFR) exactly as
  served: RRSIGs, NSEC/NSEC3 and DNSKEYs included. Secondaries keep a
  transfer as received and serve it unaltered, so a signed master stays
  signed on every secondary.
- **Maintenance** (`daygle-dns-authoritative`'s `DnssecMaintenance`, spawned when
  `dnssec_enabled`) keeps signed zones valid forever. Every
  `dnssec_maintenance_secs` it checks two things: when signatures are older
  than half their validity window it bumps every signed zone's serial and
  reloads the catalog, which re-signs every zone with fresh inceptions (so
  signatures always have at least half their validity left, on secondaries
  too); and it advances the automatic key rollover state
  machine (see below). Key state changes are stored in SQLite (`dnssec_keys`:
  `active`/`retired`, with creation timestamps) so rollover survives restarts.
- **Automatic key rollover**: when the active key reaches
  `dnssec_rollover_days` (default 90), a new key is generated and both keys
  sign every RRset (double-signing) with both DNSKEYs published. Once the new
  key has been out for `dnssec_rollover_overlap_days` (default 30) the old
  key is retired: it stops signing but its DNSKEY stays published for a
  further `dnssec_rollover_retire_days` (default 14) from its retirement so validators holding cached
  RRSIGs can still build a chain (RFC 6781 pre-publish rollover), then the
  key is deleted and its DNSKEY disappears. A rollover never removes the
  only active key, does not stack a third key while one is in flight, and skips secondary
  zones. CDS/CDNSKEY (RFC 8078) is published at the signed zone's apex for
  every active key, so a parent that supports the automated DS exchange can
  fetch it. Automatic rollover still cannot update the parent's DS record by
  itself: submit the new DS to the registrar (or make sure the parent reads
  CDS/CDNSKEY) during the overlap window. Daygle DNS keeps the old key
  published long enough for that exchange.

## AI scanner (`daygle-dns-ml`)

A CPU-only background classifier over domains observed in the query log.
Off by default (`[ai] enabled = true` turns it on; the installer does so in
train mode); the DNS hot path never runs a model. For the operator's view,
see [AI.md](AI.md).

- **Two channels.** The subsystem does two different jobs, and they are
  separate passes rather than one label that has to serve both:
  `Channel::Content` categorizes (`news`, `shopping`, ...) and stores a
  label only, and `Channel::Threat` reports detected threats and is the
  only channel that can block on its own. It reports only threat labels
  (`AiSettings::threat_labels`: the built-in families minus
  `ai.auto_block_removals`, plus `ai.auto_block_categories`). Both run
  `ai.model_path`, except that `ai.model_path = "builtin-binary"` puts the
  binary name model on the threat channel and leaves the content channel on
  the built-in categorizer; each has its own confidence floor
  (`ai.category_confidence_floor` / `ai.confidence_floor`) and its own
  verdict TTL (`ai.category_ttl_secs` / `ai.threat_ttl_secs`).
  `channel::ChannelBackend` is what scopes a classifier to one job; a
  single model can still drive both channels.
- **Backends.** A [`DomainClassifier`] trait abstracts the model: the
  built-in `HeuristicBackend` (zero-model keyword tables, deliberately
  low-confidence so it can never auto-block on its own) and the
  `FastTextBackend` (supervised fastText `.bin` models trained out of
  process - labels like `__label__malware`). Backends compose: the optional
  MiniLM/ONNX verifier (`verifier-onnx` feature, wrapping the threat
  channel with `verify.rs` and the ONNX runtime in `verifier_onnx.rs`)
  re-checks threat verdicts against an embedding-distance reference set
  (cosine threshold `ai.verifier_threshold`, default 0.35): corroboration
  raises confidence, a disagreement downgrades the verdict to severity
  `disputed` (kept in the console, never auto-blocked), and a tie-out below
  threshold leaves the base verdict `unverified`. The categorizer is never
  verified: it decides nothing.
- **Scanner.** Every `scan_interval_secs`, a worker harvests new domains
  via `ZoneStore::distinct_recent_query_names`, normalizes them, classifies
  each one **once per channel**, and writes verdicts into a **separate**
  SQLite database (`ai.db` beside the zone database by default). A row is
  one channel's verdict for one domain (PRIMARY KEY `(domain, channel)`):
  category, severity, confidence, backend, evidence, observation counter
  and an expiry from that channel's TTL. Expired verdicts re-enter
  `pending` and are re-classified; categories never carry over, so a site
  that changed gets re-judged. Off the DNS path entirely: the classifier
  only runs on the scan cycle. A database from before the split is
  upgraded in place: the old verdict lands in the channel its severity
  implies (so nothing stops blocking) and the other channel is queued.
- **Enforcement (threats).** The `AiBlockPlugin` (a `PolicyPlugin`
  registered last in the engine) consults a pre-built, atomically-swapped
  block snapshot (`ArcSwap<HashMap<domain, block>>`). In `train` mode the
  snapshot stays empty and nothing blocks; in `enforce` mode it contains
  fresh *threat-channel* verdicts (disputed ones excluded) whose confidence
  meets `block_threshold`, is not vetoed by an operator override (`allow`
  exempts it, `not_threat` records a correction that suppresses it while
  keeping the verdict), and whose category is a threat label.
  Content-channel rows never reach this snapshot, whatever they are called.
  Whether the snapshot applies is decided per client: the global `ai.mode`,
  unless the first enabled filtering group covering the client sets
  `ai_mode` (`enforce` or `train`), so one group can auto-block while the
  rest record, or the reverse. The plugin suffix-matches at label
  boundaries (a verdict on `bad.example.com` also blocks
  `www.bad.example.com`) and returns NXDOMAIN via `Action::Block`, tagged
  with group `ai`.
- **Category blocking (operator policy).** The same plugin also consults a
  second, independently-published snapshot mapping each domain to its
  current *content* category. A client group's `blocked_categories` list
  (console: Clients → Filtering Groups) names the categories that group
  blocks, so the same label can block for a kids' network and be ignored
  everywhere else. This is an operator rule over a label, not a verdict the
  AI acted on: it applies in **both** train and enforce mode, and `ai.mode`
  only governs auto-blocking of detected threats. Clients in no group block
  no categories; the first enabled group that covers a client decides, the
  same rule `ai_mode` uses. Snapshot build applies operator relabels
  and drops domains an `allow` override exempts.
- **Relabelling.** `POST /api/ai/override` with `action: "category"` stores
  an operator label in `ai_category_overrides`; it is shown instead of the
  model's label and is what category blocking matches, while the scanner
  keeps classifying (and re-checking) the domain. `clear_category` drops it.
- **Operator precedence.** The engine evaluates the user allowlist and
  operator blocklists *before* plugins, and `ai_overrides` rows (the
  `allow` action of `POST /api/ai/override`) are filtered out at snapshot
  build time - so operator decisions and explicit trust always supersede AI
  verdicts.

- **Assessment, fusion, calibration and candidates.** Every threat verdict's
  inputs are recorded as structured observations (`assessment.rs`:
  source, direction, value, explanation, timestamp, hostname or registrable
  domain, evidence family). `fusion.rs` combines them without double-counting
  the primary model and the MiniLM verifier: the model sets the base, the
  verifier adjusts it inside the same family, independent evidence is bounded
  as a group, and feed corroboration and popular/established disputes remain
  hard mechanisms outside the sum. `calibration.rs` maps the assessment score
  to a calibrated one with a versioned isotonic map fitted on a tuning split
  and judged on a registrable-domain hold-out by Brier score, ECE and a
  reliability table; a worse candidate is refused. `candidate.rs` plus the
  `ai_candidates`/`ai_model_artifacts` tables keep the whole scoring system -
  model bytes, threshold, calibration, signal weights, scoring config and
  validation report - as one version that promotes and rolls back atomically.
  `authority.rs` applies a per-source stage (`monitor`, `propose`, `enforce`)
  to what may reach the block snapshot, demoting a source automatically when
  its measured false-positive share passes `ai.authority.demote_fp_rate`. All
  of it is off or in monitor mode by default;
  [AI.md](AI.md#signals-calibration-and-versioned-scoring) describes what each
  stage is worth and where it stops.
- **Outside evidence.** A name-only classifier gets a second opinion from
  what the server already knows. `intel.rs` downloads the threat feeds and
  Tranco's popular-sites ranking into `ai.db`; `age.rs` looks up a flagged
  domain's registration date over RDAP; and `evidence.rs` checks each verdict
  against a feed listing, this network's usage history and popularity. A feed
  listing corroborates a verdict even over a verifier dispute, a popular or
  established domain disputes it, and a freshly registered one is noted.
- **Page reading.** `page.rs` fetches a threat candidate's home page and
  classifies its text with cue phrases (`page_model.rs` also learns a
  fastText model from labelled pages kept in `ai.db`). `ai.page_rule` decides
  whether a reading is recorded, can raise the verdict, or can also cap it.
  With `ai.monitor_page_discovery` the scan also investigates unfamiliar names
  and uncertain results; `ai.enforce_page_discovery` lets a high-confidence
  finding block its exact host only. `llm.rs` can read the stored pages
  through a local Ollama model, and can only strengthen a threat or name an
  unsure category.
- **Binary name model.** `ai.model_path = "builtin-binary"` makes `learn.rs`
  train and maintain a hostname-only `binary-threat`/`benign` model beside
  `ai.db`, scored independently of the enabled threat families and gated by
  the same threshold, authority, exemptions and per-refresh cap.

## Console, roles and dashboard

- **Login.** Console accounts live in the database (seeded once from
  `[[api.users]]`) and are verified with PBKDF2-HMAC-SHA256
  (`daygle-dns-core/src/auth.rs`); generate hashes with
  `daygle-dns hash-password`. Successful logins mint a 256-bit random session
  token with a TTL (`api.session_ttl_secs`), kept in memory and saved to the
  database as its SHA-256 (so sessions survive a restart); the token is the
  API bearer credential. Failed logins are logged; a dummy-hash verification
  keeps the response time constant so usernames cannot be enumerated.
- **Roles.** Sessions carry the account's role. `viewer` sessions may read
  everything but any mutating method is rejected with `403` by the auth
  middleware before a handler runs; so are the `GET`s that make the server
  fetch a URL or probe the host (`is_privileged_read`). `admin` sessions (and
  the legacy static `api_token`) have full access.
- **Password hashing.** PBKDF2 runs on the blocking thread pool behind a
  small semaphore, so a login flood queues there instead of stalling the
  async workers that also serve DNS.
- **Secret redaction.** `GET /api/config` (and the config echoed by
  `PUT /api/config`) masks `api.api_token` and every password hash as
  `[redacted]`, so secrets never round-trip to a browser.
- **Settings forms.** `PUT /api/config` applies a validated partial update
  (recursive, DoT/DoH/DoQ, policy, authoritative, AI, the console-edited
  parts of `server` and `api`, and the rest; the listen addresses, the
  plain-DNS port and transports, and the API listener and token stay in the
  config file),
  persists it to the **SQLite database** as the runtime overlay (the config
  file is only the bootstrap seed), and triggers a listener rebuild through
  `request_dns_rebuild` when listeners were touched - the same mechanism
  live reload uses.
- **Dashboard statistics.** `QueryStats` (`daygle-dns-core/src/stats.rs`)
  records every served query into a 24-hour ring of one-minute buckets plus
  bounded top-N tables (clients, domains, blocked domains; pruned to 2 000
  keys at 5 000). `GET /api/stats?window=...` renders the time-series and top
  tables; the dispatcher tags each query with its outcome (authoritative,
  recursive, split-horizon, blocked, rate-limited, error) as it is answered.
  Stats are in-memory only and reset on restart.

## Extensibility points

- Add policy behavior by implementing `daygle_dns_policy::PolicyPlugin` and
  registering it in the engine.
- Add record types by extending `daygle_dns_authoritative::model::KNOWN_RECORD_TYPES` (parsing is
  delegated to Hickory's `RData::try_from_str`).
- Swap SQLite for PostgreSQL by implementing the `ZoneStore`-equivalent
  interface against a Postgres connection; the catalog builder only depends on
  `Zone`/`Record`/signing-key rows.
