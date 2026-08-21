# Daygle DNS architecture

Daygle is a Cargo workspace of eight crates. One binary (`daygle`) composes
them into a single process that serves plaintext DNS, DNS over TLS, and an HTTP
API/GUI.

## Crate responsibilities

```
                          ┌──────────────────────────────┐
                          │           daygle (bin)       │
                          │  DnsDispatcher + listeners   │
                          └──────┬──────┬──────┬─────────┘
                                 │      │      │
              ┌──────────────────┘      │      └──────────────────┐
              ▼                         ▼                         ▼
   ┌───────────────────┐    ┌────────────────────┐    ┌──────────────────┐
   │ daygle-policy     │    │ daygle-authoritative│    │ daygle-recursive │
   │ ACLs, blocklists, │    │ SQLite store,       │    │ hickory-resolver │
   │ per-client rules  │    │ zone catalog,       │    │ caching, DNSSEC  │
   └─────────┬─────────┘    │ DNSSEC signing      │    └────────┬─────────┘
             │              └─────────┬───────────┘             │
             ▼                        ▼                         ▼
        daygle-core             daygle-dot (rustls DoT)     hickory-proto
   (config/error/metrics/logs)  daygle-api (axum)          hickory-server
                                 daygle-gui (assets)
```

- **`daygle-core`** is dependency-free of the DNS stack: the TOML configuration
  model, the shared `DaygleError`, atomic `Metrics`, and a bounded `LogStore`.
- **`daygle-policy`** evaluates a query in order: ACLs → blocklists →
  ordered per-client rules → user plugins. A `PolicyPlugin` is a boxed async
  callback; the first plugin returning `Some(Decision)` wins.
- **`daygle-authoritative`** persists zones/records/DNSSEC keys in SQLite and
  rebuilds an in-memory Hickory `Catalog` (`InMemoryZoneHandler` per zone). The
  hot query path never touches SQLite. It also owns the split-horizon index
  (`SplitHorizonIndex`): stored client networks + domain entries are
  pre-resolved into a per-query lookup structure that maps `(client IP,
  qname, query type)` to the synthetic records to serve.
- **`daygle-recursive`** wraps `hickory_resolver::TokioResolver`, configuring
  cache size, per-server timeouts, attempts, and DNSSEC validation. Negative
  caching is Hickory's built-in behavior, bounded by `negative_cache_ttl`.
  Conditional forwarding zones each get their own resolver built from the
  zone's dedicated upstreams; routing happens at lookup time by longest
  label-aligned suffix match.
- **`daygle-dot`** produces rustls `ServerConfig`s for both encrypted DNS
  protocols — the `dot` ALPN for DoT (RFC 7858) and the `h2` ALPN for DoH
  (RFC 8484) — and generates self-signed certificates when configured.
- **`daygle-api`** serves the REST API and the embedded GUI.
- **`daygle-gui`** embeds the compiled Svelte bundle via `rust-embed`.
- **`daygle`** (binary) binds UDP/TCP/DoT/DoH listeners onto one Hickory
  `Server` driven by `DnsDispatcher`.

## Query flow

`DnsDispatcher` implements Hickory's `RequestHandler` and is used by every
listener:

0. **Rate limiting.** Before anything else, the request counts against two
   fixed-window budgets: one per client (source IP) and one per query name.
   Requests over either limit get SERVFAIL and increment the `rate_limited`
   metric. The client check also covers RFC 2136 UPDATEs and zone transfers,
   which never reach `request_info`. Loopback is exempt when
   `rate_limit.exempt_loopback` is set (the default). Limits live in a shared
   [`RateLimiter`](crates/daygle-core/src/rate_limit.rs) that reload swaps in
   place, so tightening/relaxing them never drops in-flight windows.
1. **Policy.** The query name/type and the client IP are passed to the policy
   engine. `Block` → NXDOMAIN, `Refused` → REFUSED, `Redirect(ip)` → a
   synthesized A/AAAA answer.
1. **Split horizon.** For A/AAAA/MX/TXT/CNAME/SRV (and ANY) queries, the
   client IP is looked up in the split-horizon index. The first entry whose
   domain matches and whose networks contain the client wins; a matching
   entry synthesizes records of the queried type (TTL from the entry) instead
   of the normal ones. A CNAME answers every query type (RFC 1034 §3.6.2),
   and an entry with nothing for the queried type falls through — so an
   internal `10.x` view can sit behind a public fallback, and a TXT-only
   entry never swallows A queries.
2. **Authoritative.** If the query name falls inside a hosted zone
   (`Catalog::find`), the Hickory catalog answers. Signed zones carry DNSSEC
   signatures and NSEC proofs.
3. **Zone transfers.** AXFR/IXFR queries are intercepted before the normal
   lookup path (`DnsDispatcher::handle_transfer`). Transfers are gated by
   `authoritative.axfr_enabled` and the `axfr_networks` client allow-list, and
   answered with the full zone record set (`SOA, records…, SOA` per RFC 5936;
   IXFR always gets a full transfer, which RFC 1995 permits).
4. **Recursive.** Otherwise the query goes to `daygle-recursive`; the
   `RecursiveResolver` routes by name — the most specific configured
   conditional zone (longest label-aligned suffix) is resolved by its own
   dedicated resolver/upstreams, everything else by the default ones. The
   resulting `Lookup` is converted into a `MessageResponse` with the
   upstream's RCODE and the AD bit when DNSSEC validation succeeded.
   Negative answers (NXDOMAIN/NODATA) carry their response code through the
   error type so they are returned as-is instead of SERVFAIL.
5. **Dynamic updates.** RFC 2136 `UPDATE` messages are handled by
   `daygle-authoritative`'s update handler (`handle_update`), not the
   catalog. It validates the zone section, checks prerequisites (NXDOMAIN /
   NXRRSet / YXDomain / YXRRSet), builds an atomic add/delete plan, writes it
   through to SQLite (bumping the SOA serial unless the update rewrites the
   SOA), and reloads the catalog so the change is served immediately. Gated
   by `authoritative.allow_dynamic_updates` and the `update_networks` client
   allow-list; secondary zones are always refused.

## Concurrency model

- The Hickory `Catalog` is shared through `arc_swap::ArcSwap`, so the
  dispatcher clones an owned `Arc<Catalog>` per query rather than holding a
  non-`Send` lock guard across `.await`.
- Zone mutations go through the REST API (updates SQLite, then calls
  `AuthorityCatalog::reload()`) or through RFC 2136 dynamic updates, which
  apply their changes in a single SQLite transaction via
  `ZoneStore::apply_dynamic_updates` and then reload the catalog the same
  way — either path atomically swaps in a fresh catalog. Split-horizon
  changes (networks/entries, via the REST API) rebuild the split-horizon
  index on the same `reload()`, so DNS and API views stay in sync.
- Secondary zones are driven by `daygle-authoritative`'s `SecondaryRefresher`,
  which compares each zone's SOA serial against its master on a refresh
  interval and runs a full AXFR/IXFR pull when the master is newer (or the
  local zone has never been transferred). Transferred records replace the
  stored set via `ZoneStore::replace_records`, and the catalog is reloaded so
  updates are served immediately. Secondary zones are served read-only: the
  Hickory catalog marks them `ZoneType::Secondary`.
- `Metrics` uses lock-free atomics; `LogStore` is a mutex-guarded ring buffer.

## Live configuration reload

`daygle` watches its TOML config file (mtime polling) and applies changes
without a restart. The policy engine, the recursive resolver and the effective
config are each published through `arc_swap::ArcSwap` containers shared by the
dispatcher and the REST API, so every query observes one consistent snapshot.
When the `server`/`dot`/`doh` sections change, a listener supervisor gracefully
stops the current sockets and rebinds new ones, self-healing back to the last
good configuration if a bind fails. Reload can also be triggered on demand via
`POST /api/config/reload` or `BoundServer::reload()`.

The DoH listener (hickory's h2 server) serves POST requests carrying
`application/dns-message` bodies at the configured `endpoint` (default
`/dns-query`); GET requests are not implemented by Hickory 0.26, so clients
must use POST.

### Remote blocklist sources

`daygle-policy`'s `BlocklistSourceManager` fetches each configured
`[[policy.blocklist_sources]]` URL over HTTP(S) (reqwest/rustls, 32 MiB body
cap, redirects, 30 s timeout) and parses the body in its declared format
(`domains`, `hosts`, or `adblock`). A background task in `daygle` polls on the
smallest configured refresh interval and, when a source is due, swaps the
merged remote blocklist into the shared `PolicyEngine` via
`set_remote_blocklist` — the static blocklist from config/files is never
discarded, and a failed/empty fetch leaves the previous domains in place.
`POST /api/policy/blocklist/sources` forces an immediate refresh; `GET` the
same path for per-source status.

## DNSSEC

- **Validation** (recursive path) is enabled with `recursive.dnssec_validate`;
  Hickory validates the chain and sets the AD bit; bogus chains fail the query.
- **Signing** (authoritative path) is per-zone: `POST /api/zones/:id/sign`
  generates an ECDSA P-256 key (stored as PKCS#8 in SQLite) and signs the zone
  with NSEC non-existence proofs on the next catalog reload.

## Extensibility points

- Add policy behavior by implementing `daygle_policy::PolicyPlugin` and
  registering it in the engine.
- Add record types by extending `model::KNOWN_RECORD_TYPES` (parsing is
  delegated to Hickory's `RData::try_from_str`).
- Swap SQLite for PostgreSQL by implementing the `ZoneStore`-equivalent
  interface against a Postgres connection; the catalog builder only depends on
  `Zone`/`Record`/signing-key rows.
