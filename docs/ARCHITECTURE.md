# Daygle DNS architecture

Daygle DNS is a Cargo workspace of eight crates. One binary (`daygle-dns`) composes
them into a single process that serves plaintext DNS, DNS over TLS,
DNS over HTTPS, DNS over QUIC, and an HTTP API/GUI.

## Crate responsibilities

```
                          ┌──────────────────────────────┐
                          │           daygle-dns (bin)       │
                          │  DnsDispatcher + listeners   │
                          └──────┬──────┬──────┬─────────┘
                                 │      │      │
              ┌──────────────────┘      │      └──────────────────┐
              ▼                         ▼                         ▼
   ┌───────────────────┐    ┌────────────────────┐    ┌──────────────────┐
   │ daygle-dns-policy     │    │ daygle-dns-authoritative│    │ daygle-dns-recursive │
   │ ACLs, blocklists, │    │ SQLite store,       │    │ hickory-resolver │
   │ per-client rules  │    │ zone catalog,       │    │ caching, DNSSEC  │
   └─────────┬─────────┘    │ DNSSEC signing      │    └────────┬─────────┘
             │              └─────────┬───────────┘             │
             ▼                        ▼                         ▼
        daygle-dns-core             daygle-dns-dot (rustls DoT)     hickory-proto
   (config/error/metrics/logs)  daygle-dns-api (axum)          hickory-server
                                 daygle-dns-gui (assets)
```

- **`daygle-dns-core`** is dependency-free of the DNS stack: the TOML configuration
  model, the shared `DaygleError`, atomic `Metrics`, and a bounded `LogStore`.
- **`daygle-dns-policy`** evaluates a query in order: ACLs → blocklists →
  ordered per-client rules → user plugins. A `PolicyPlugin` is a boxed async
  callback; the first plugin returning `Some(Decision)` wins.
- **`daygle-dns-authoritative`** persists zones/records/DNSSEC keys in SQLite and
  rebuilds an in-memory Hickory `Catalog` (`InMemoryZoneHandler` per zone). The
  hot query path never touches SQLite. It also owns the split-horizon index
  (`SplitHorizonIndex`): stored client networks + domain entries are
  pre-resolved into a per-query lookup structure that maps `(client IP,
  qname, query type)` to the synthetic records to serve.
- **`daygle-dns-recursive`** wraps `hickory_resolver::TokioResolver`, configuring
  cache size, per-server timeouts, attempts, and DNSSEC validation. Negative
  caching is Hickory's built-in behavior, bounded by `negative_cache_ttl`.
  Conditional forwarding zones each get their own resolver built from the
  zone's dedicated upstreams; routing happens at lookup time by longest
  label-aligned suffix match.
- **`daygle-dns-dot`** produces rustls TLS configurations for the encrypted
  DNS protocols - the `dot` ALPN for DoT (RFC 7858), `h2` for DoH (RFC 8484)
  and a TLS 1.3 + `doq`-ALPN setup for DoQ (RFC 9250) - and generates
  self-signed certificates when configured.
- **`daygle-dns-api`** serves the REST API and the embedded GUI, including
  console login (PBKDF2 password verification + in-memory session tokens,
  `admin`/`viewer` roles enforced in the auth middleware) and the dashboard
  statistics endpoint backed by `daygle-dns-core`'s bounded `QueryStats`.
- **`daygle-dns-gui`** embeds the compiled Svelte bundle via `rust-embed`.
- **`daygle-dns`** (binary) binds the UDP/TCP/DoH listeners onto one
  Hickory `Server` driven by `DnsDispatcher`, and serves DoT and DoQ with its
  own listeners (`dot.rs`, `doq.rs`) that feed the same dispatcher: DoT
  answers the queries of one connection concurrently and out of order
  (RFC 7766), pads answers to padded queries (RFC 8467) and caps connections
  per client.

## Query flow

`DnsDispatcher` implements Hickory's `RequestHandler` and is used by every
listener:

0. **Rate limiting.** Before anything else, the request counts against two
   fixed-window budgets: one per client (source IP) and one per query name.
   Requests over either limit get SERVFAIL and increment the `rate_limited`
   metric. The client check also covers RFC 2136 UPDATEs and zone transfers,
   which never reach `request_info`. Loopback is exempt when
   `rate_limit.exempt_loopback` is set (the default). Limits live in a shared
   [`RateLimiter`](crates/daygle-dns-core/src/rate_limit.rs) that reload swaps in
   place, so tightening/relaxing them never drops in-flight windows.
1. **Policy.** The query name/type and the client IP are passed to the policy
   engine. `Block` → NXDOMAIN, `Refused` → REFUSED, `Redirect(ip)` → a
   synthesized A/AAAA answer.
1. **Split horizon.** For A/AAAA/MX/TXT/CNAME/SRV (and ANY) queries, the
   client IP is looked up in the split-horizon index. The first entry whose
   domain matches and whose networks contain the client wins; a matching
   entry synthesizes records of the queried type (TTL from the entry) instead
   of the normal ones. A CNAME   answers every query type (RFC 1034 §3.6.2),
   and an entry with nothing for the queried type falls through - so an
   internal `10.x` view can sit behind a public fallback, and a TXT-only
   entry never swallows A queries.
2. **Authoritative.** If the query name falls inside a hosted zone
   (`Catalog::find`), the Hickory catalog answers. Signed zones carry DNSSEC
   signatures and NSEC proofs. A few answers are made by the dispatcher
   first, from indexes the catalog rebuilds with the zones: ALIAS records
   (A/AAAA from the target), weighted A/AAAA RRsets (one record picked in
   proportion to the weights, after failover; unsigned zones only) and
   AUTOPTR records (a PTR made from the address when the name has none).
   Zone aliases are served as zones of their own, built from the aliased
   zone's records with the owner names moved into the alias.
3. **RFC 6303 empty zones.** When the query name falls in one of
   `authoritative.empty_zones` (by default the RFC 6303 reverse zones for
   private, loopback, ULA, link-local and documentation address space) and
   no hosted zone covers it, the dispatcher answers authoritatively
   without recursing: the apex serves its SOA and NS, interior names get
   NXDOMAIN carrying the empty zone's SOA (RFC 2308), and every answer
   carries the AA bit. This keeps reverse lookups for never-routable
   address space from leaking to public upstreams.
4. **Zone transfers.** AXFR/IXFR queries are intercepted before the normal
   lookup path (`DnsDispatcher::handle_transfer`). Transfers are gated by
   `authoritative.axfr_enabled` and the `axfr_networks` client allow-list, and
   answered with the full zone record set (`SOA, records..., SOA` per RFC 5936;
   IXFR always gets a full transfer, which RFC 1995 permits).
5. **Recursive.** Otherwise the query goes to `daygle-dns-recursive`; the
   `RecursiveResolver` routes by name - the most specific configured
   conditional zone (longest label-aligned suffix) is resolved by its own
   dedicated resolver/upstreams, everything else by the default ones. The
   resulting `Lookup` is converted into a `MessageResponse` with the
   upstream's RCODE and the AD bit when DNSSEC validation succeeded.
   Negative answers (NXDOMAIN/NODATA) carry their response code through the
   error type so they are returned as-is instead of SERVFAIL.
5. **Dynamic updates.** RFC 2136 `UPDATE` messages are handled by
   `daygle-dns-authoritative`'s update handler (`handle_update`), not the
   catalog. It validates the zone section, checks prerequisites (NXDOMAIN /
   NXRRSet / YXDomain / YXRRSet), builds an atomic add/delete plan, writes it
   through to SQLite (bumping the SOA serial unless the update rewrites the
   SOA), and reloads the catalog so the change is served immediately. Gated
   by `authoritative.allow_dynamic_updates` and the `update_networks` client
   allow-list; secondary zones are always refused. When outbound NOTIFY is
   configured, a successful update also sends an RFC 1996 NOTIFY to every
   configured target so secondaries pull immediately.

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
  interval and runs a full AXFR/IXFR pull when the master is newer (or the
  local zone has never been transferred). Transferred records replace the
  stored set via `ZoneStore::replace_records`, and the catalog is reloaded so
  updates are served immediately. Secondary zones are served read-only: the
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
When the `server`/`dot`/`doh` sections change, a listener supervisor gracefully
stops the current sockets and rebinds new ones, self-healing back to the last
good configuration if a bind fails. Reload can also be triggered on demand via
`POST /api/config` or `BoundServer::reload()`.

The DoH listener (hickory's h2 server) serves POST requests carrying
`application/dns-message` bodies at the configured `endpoint` (default
`/dns-query`); GET requests are not implemented by Hickory 0.26, so clients
must use POST.

### Remote blocklist sources

`daygle-dns-policy`'s `BlocklistSourceManager` fetches each configured
`[[policy.blocklist_sources]]` URL over HTTP(S) (reqwest/rustls, 64 MiB body
cap, redirects, 30 s timeout) and parses the body in its declared format
(`domains`, `hosts`, `adblock`, or `rpz`). A background task in `daygle-dns` polls on the
smallest configured refresh interval and, when a source is due, swaps the
merged remote blocklist into the shared `PolicyEngine` via
`set_remote_blocklist` - the static blocklist from config/files is never
discarded, and a failed/empty fetch leaves the previous domains in place.
`POST /api/policy/blocklist/sources` forces an immediate refresh; `GET` the
same path for per-source status.

## DNSSEC

- **Validation** (recursive path) is enabled with `recursive.dnssec_validate`;
  Hickory validates the chain and sets the AD bit; bogus chains fail the query.
- **Signing** (authoritative path) is per-zone: `POST /api/zones/:id/sign`
  generates an ECDSA P-256 key (stored as PKCS#8 in SQLite) and signs the zone
  with NSEC non-existence proofs on the next catalog reload. Signatures are
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
  only active key, does not stack a third key while one is in flight, and   skips secondary zones. CDS/CDNSKEY (RFC 8078) is published on the signed
   zone's apex for every active key, so a parent that supports the
   automated DS exchange can fetch it. Caveat: automatic rollover still
   cannot update the parent's DS record by itself - submit the new DS (or
   make sure the parent reads CDS/CDNSKEY) to the registrar during the
   overlap window; Daygle DNS keeps the old key published long enough
   for that exchange.

## AI scanner (`daygle-dns-ml`)

A CPU-only background classifier over domains observed in the query log.
Opt-in via `[ai] enabled = true`; the DNS hot path nevers runs a model.

- **Two channels.** The subsystem does two different jobs, and they are
  separate passes rather than one label that has to serve both:
  `Channel::Content` categorizes (`news`, `shopping`, ...) and stores a
  label only, and `Channel::Threat` looks only for the labels in
  `ai.auto_block_categories` and is the only channel that can block on its
  own. Each
  has its own model (`ai.category_model_path` / `ai.threat_model_path`,
  falling back to `ai.model_path`), its own confidence floor
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
  fresh *threat-channel* verdicts (disputed ones excluded) whose category is
  in `auto_block_categories` and whose confidence meets `block_threshold`.
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
  (console: Filtering → Client Groups) names the categories that group
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

## Console, roles and dashboard

- **Login.** `api.users` accounts are verified with PBKDF2-HMAC-SHA256
  (`daygle-dns-core/src/auth.rs`); generate hashes with
  `daygle-dns hash-password`. Successful logins mint a 128-bit random session
  token held in memory with a TTL (`api.session_ttl_secs`); the token is the
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
  (server/recursive/DoT/DoH/DoQ/API, policy, and authoritative groups),
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

- Add policy behavior by implementing `daygle_policy::PolicyPlugin` and
  registering it in the engine.
- Add record types by extending `model::KNOWN_RECORD_TYPES` (parsing is
  delegated to Hickory's `RData::try_from_str`).
- Swap SQLite for PostgreSQL by implementing the `ZoneStore`-equivalent
  interface against a Postgres connection; the catalog builder only depends on
  `Zone`/`Record`/signing-key rows.
