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
  hot query path never touches SQLite.
- **`daygle-recursive`** wraps `hickory_resolver::TokioResolver`, configuring
  cache size, per-server timeouts, attempts, and DNSSEC validation. Negative
  caching is Hickory's built-in behavior, bounded by `negative_cache_ttl`.
- **`daygle-dot`** produces a rustls `ServerConfig` with the `dot` ALPN and
  generates self-signed certificates when configured.
- **`daygle-api`** serves the REST API and the embedded GUI.
- **`daygle-gui`** embeds the compiled Svelte bundle via `rust-embed`.
- **`daygle`** (binary) binds UDP/TCP/DoT listeners onto one Hickory `Server`
  driven by `DnsDispatcher`.

## Query flow

`DnsDispatcher` implements Hickory's `RequestHandler` and is used by every
listener:

1. **Policy.** The query name/type and the client IP are passed to the policy
   engine. `Block` → NXDOMAIN, `Refused` → REFUSED, `Redirect(ip)` → a
   synthesized A/AAAA answer.
2. **Authoritative.** If the query name falls inside a hosted zone
   (`Catalog::find`), the Hickory catalog answers. Signed zones carry DNSSEC
   signatures and NSEC proofs.
3. **Recursive.** Otherwise the query goes to `daygle-recursive`; the resulting
   `Lookup` is converted into a `MessageResponse` with the upstream's RCODE and
   the AD bit when DNSSEC validation succeeded.
4. RFC 2136 `UPDATE` messages are delegated directly to the catalog.

## Concurrency model

- The Hickory `Catalog` is shared through `arc_swap::ArcSwap`, so the
  dispatcher clones an owned `Arc<Catalog>` per query rather than holding a
  non-`Send` lock guard across `.await`.
- Zone mutations go through the REST API, which updates SQLite and then calls
  `AuthorityCatalog::reload()` to atomically swap in a fresh catalog.
- `Metrics` uses lock-free atomics; `LogStore` is a mutex-guarded ring buffer.

## Live configuration reload

`daygle` watches its TOML config file (mtime polling) and applies changes
without a restart. The policy engine, the recursive resolver and the effective
config are each published through `arc_swap::ArcSwap` containers shared by the
dispatcher and the REST API, so every query observes one consistent snapshot.
When the `server`/`dot` sections change, a listener supervisor gracefully
stops the current sockets and rebinds new ones, self-healing back to the last
good configuration if a bind fails. Reload can also be triggered on demand via
`POST /api/config/reload` or `BoundServer::reload()`.

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
