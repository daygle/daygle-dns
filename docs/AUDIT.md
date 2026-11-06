# Code audit — Daygle DNS

Date: 2026-11-04 · Workspace: 10 crates, ~87k lines of Rust

## Scope and method

This was a focused audit of the highest-risk paths, not an exhaustive
line-by-line review of all ~87,000 lines. Reviewed in depth:

- **API authentication/authorisation** — `daygle-dns-api/src/lib.rs`
  (session store, cookie/bearer handling, CSRF guard, role checks,
  privileged reads, CORS, security headers, forwarded-client parsing),
  `audit.rs`, login/2FA/setup/password handlers, personal API-token handlers,
  certificate listing.
- **Query path** — `daygle-dns/src/dispatcher.rs` (policy → RPZ → safe
  search → split horizon → authoritative → empty zones → recursion, ALIAS,
  weighted answers, AUTOPTR, AXFR chunking, record-use cache), `dot.rs`,
  `doh.rs`, `rrl.rs`, `cookies.rs`, `proxy_protocol.rs`, `query_db_log.rs`,
  `syslog.rs`.
- **Core services** — `rate_limit.rs`, `rrl.rs`, `stats.rs`, `block_log.rs`,
  password hashing (`auth.rs`), TSIG (`authoritative/src/tsig.rs`).
- **SQL** — every `format!`-built statement in `authoritative/src/store.rs`,
  `backup.rs`, `ml/src/store.rs`, `accounts.rs`: all interpolate only
  constants, column lists or `?N` placeholder lists; no user input reaches
  the SQL text. Audit-log and query-log limits are clamped server-side.

Verification environment: no Rust toolchain was installed, so current stable
(rustc 1.99.1) was installed; dependencies were left at the lockfile's pinned
versions.

| Check | Result |
|-------|--------|
| `cargo check --workspace --all-targets` | pass (no errors, no warnings shown) |
| `cargo test -p daygle-dns-core --lib` | pass — 108 tests |
| `cargo test -p daygle-dns --lib` | pass — 39 tests (incl. 3 new) |
| `cargo test --workspace` (integration suites) | not run — needs network/DNS fixtures and exceeds the session's command budget |
| `cargo clippy --workspace` | not run |
| `web/` (Svelte) build | not run |

**No Critical-severity issue was confirmed in the reviewed paths.** The
classes specifically looked for and not found: SQL injection, path traversal
(GUI assets come from an embedded map; backup/restore paths are server-side),
auth bypass on cookie/CSRF paths, missing ownership scoping on personal API
tokens, TLS key material leakage through the API, unbounded memory growth on
the query path (all caches are capped), and TSIG request/response MAC
chaining errors.

---

## High

### H-1 A poisoned PROXY peer table panics every subsequent DNS query

**Where** `crates/daygle-dns/src/proxy_protocol.rs` — `register_client`,
`unregister_client`, `real_client`.

**Problem** The module keeps one process-global `RwLock<HashMap<…>>` of
bridge peers and unwrapped every acquisition with
`.expect("proxy table lock poisoned")`. `real_client()` runs near the top of
`DnsDispatcher::handle_request`, i.e. once per DNS query, on every listener.
`std::sync::RwLock` poisons when a thread panics while holding the write
lock; the next `.expect` then panics too, so **one panic anywhere in a bridged
session permanently converts every later query into a panic** — each request
task dies, no answer is produced, and only a restart recovers. The same
pattern was already avoided elsewhere in the codebase (`dot.rs` uses
`unwrap_or_else(|e| e.into_inner())`), which suggests this module was simply
missed.

**Impact** Total denial of service (DNS outage) from an unrelated panic;
unrecoverable without a restart. Availability-critical because the lookup is
on the hot path even when no proxy protocol is configured.

**Fix** Recover poisoned guards instead of panicking (`read_table()` /
`write_table()` helpers). The map is a peer mapping, so an interrupted
mutation leaves it structurally usable.

**Risk/trade-off** A poisoned lock means some thread panicked mid-mutation, so
the map may be missing one entry. `real_client` then falls back to the
socket's own address — the loopback bridge address, not the original client
(this is also the pre-fix behaviour whenever no mapping exists). That fallback
is **not** fail-closed: with `rate_limit.exempt_loopback` enabled (the
default), `check_client_scaled()` exempts a loopback client
(`crates/daygle-dns-core/src/rate_limit.rs`), and ACLs evaluate the loopback
address rather than the real client, so a lost entry can weaken rate limiting
and ACL enforcement for that connection, not merely degrade attribution. It is
still preferable to a permanent whole-server outage: the window is one bridged
connection whose mapping was lost to a panic, versus every query failing until
restart.

---

## Medium

### M-1 A poisoned DoH sender mutex disables a whole HTTP/2 connection

**Where** `crates/daygle-dns/src/doh.rs` — `H2Responder::send`.

**Problem** `.lock().expect("h2 send lock poisoned")`. `H2Responder` is
`Clone` and shared per stream; once poisoned, every later response on that
connection panics instead of returning an error, so the connection wedges for
its lifetime.

**Impact** One client's connection stops being served (and its task panics)
rather than failing gracefully with a 500/`NetError`.

**Fix** `unwrap_or_else(|e| e.into_inner())`, matching `dot.rs`.

**Risk/trade-off** None material: `SendResponse` remains valid to use; the
send path already returns `NetError` on failure.

### M-2 Dashboard time series loses counts when the wall clock steps backwards

**Where** `crates/daygle-dns-core/src/stats.rs` — `QueryStats::record`.

**Problem** A new bucket is pushed whenever `last.minute != now_min`. If the
clock steps back (NTP correction, VM restore/resume, `SystemTime` not being
monotonic), the ring gets a bucket for an *earlier* minute than its
predecessor, and later a duplicate of the minute that already exists.
`series()` maps minute → point, so a duplicate minute silently replaces the
earlier bucket: counts vanish from the chart, and the ring is no longer
ordered.

**Impact** Wrong dashboard numbers after a clock correction, and up to 24 h
of history that cannot be trusted; no effect on query serving.

**Fix** Clamp `now_min` to at least the last bucket's minute, so a
step-back folds into the current bucket and the ring stays monotonic. Covered
by a new regression test.

**Risk/trade-off** Queries during the (usually tiny) step-back window are
counted in the bucket the clock jumped from rather than a new one. That is a
sub-minute misattribution versus losing whole buckets.

### M-3 API-token authentication blocks the async runtime on SQLite

> **Fixed in the 2026-11-06 follow-up audit** (see the end of this file).

**Where** `crates/daygle-dns-api/src/lib.rs` — `SessionStore::authenticate`,
called from the `require_auth` middleware for every request.

**Problem** For `dgl_…` tokens the middleware performs three blocking SQLite
operations per request (`find_api_token`, `get_console_user`,
`touch_api_token`) directly on a tokio worker, each taking the store's shared
connection mutex. Every other DB access in the codebase is pushed onto the
blocking pool (`spawn_blocking`) for exactly this reason; the API layer is the
exception, and here it also does a **write** per request.

**Impact** Under token-authenticated load (scripts, dashboards), worker
threads queue behind SQLite while other queries/requests wait — latency
spikes and reduced throughput proportional to token traffic. Not fixed here:
the correct fix (moving token resolution to `spawn_blocking` plus a short-TTL
cache for token→session and a throttled `last_used_at` write) is a structural
change to the middleware, and a partial version risks either a stale
revocation window or blocking inside a lock.

**Recommended follow-up** Cache resolved tokens for ~30 s keyed by token hash
(invalidated on revoke), and update `last_used_at` at most once per minute per
token.

### M-4 The self-updater trusts upstream over HTTPS only (no signed releases)

**Where** `crates/daygle-dns-api/src/update.rs`,
`crates/daygle-dns-api/src/update-apply.sh`.

**What is already defended** The service account stages `apply.bin` and
`apply.json`, but the privileged apply script does not trust either for
content: the manifest's `sha256` only proves the staged copy is intact.
For `kind=install`, root ignores the staged script and downloads the canonical
`install.sh` itself (or takes it from a fresh clone of the canonical
repository). For `kind=models`, root installs the bundle only if it matches the
checksum published with that release, which root fetches itself. Any other
kind is refused. So controlling the staging directory and manifest alone does
**not** give a compromised service account root code execution.

**Remaining risk** Everything root runs or installs is authenticated only by
HTTPS to GitHub. There is no detached signature over the installer or release
artifacts, and the published models checksum comes from the same origin as the
bundle. A compromised repository or release, or a CA-level MITM of
`github.com` / `raw.githubusercontent.com`, therefore turns into root code
execution on every host that applies an update. A compromised service account
can still *trigger* an update run at a time of its choosing, which matters only
in combination with one of those upstream compromises.

**Risk/trade-off / why not changed** Fixing this needs release-signing
infrastructure and key management (a maintainer key, a verification step in
`update-apply.sh`, and a documented rotation story) — out of scope for an
audit patch, and inventing a key would be worse than the current state.
Recorded here as a residual upstream-trust risk.

---

## Low

### L-1 The declared MSRV cannot build the lockfile

**Where** `Cargo.toml` — `[workspace.package] rust-version`.

**Problem** `rust-version = "1.92"` (described as pinned to `ort`'s MSRV),
but `Cargo.lock` pins `parking_lot 0.13` / `parking_lot_core 0.10` /
`lock_api 0.5`, which require rustc ≥ 1.95. With 1.92 cargo refuses to build
at all: *“rustc 1.92.0 is not supported by the following packages”*. Anyone
following the declared MSRV hits a wall before compiling a single line.

**Fix** Bump to `1.95` (verified: 1.99.1 builds the workspace cleanly).

**Risk/trade-off** Raises the documented minimum for contributors/CI. The
alternative (downgrading `parking_lot`) would touch the lockfile and the
dependency graph, which is a bigger, riskier change than correcting the claim.

### L-2 Security documentation contradicted the implementation

**Where** `crates/daygle-dns-api/src/lib.rs` (`CONTENT_SECURITY_POLICY`,
`cors_layer`), `crates/daygle-dns/src/cookies.rs` (module docs).

**Problem** Three comments described the pre-cookie design: tokens “live in
the browser's local storage”, CORS carries “credentials … as a bearer header,
not cookies”, and a verified DNS cookie means a client “is not held to the
per-client rate limit” (the code gives ten times the limit, and
`rate_limit.rs` documents that correctly). Stale security comments are how a
future change reintroduces a fixed vulnerability.

**Fix** Comments corrected to describe what the code does (`HttpOnly`
cookie, no `Access-Control-Allow-Credentials`, bounded allowance).

**Risk/trade-off** None; comment-only.

### L-3 `LoginThrottle` can exceed its own tracking cap

> **Fixed in the 2026-11-06 follow-up audit** (see the end of this file).

**Where** `crates/daygle-dns-api/src/lib.rs` — `LoginThrottle::record_failure`.

**Problem** At `MAX_TRACKED` the map is swept for *expired* entries and then
the new entry is inserted regardless, so a distributed attempt from more than
10,000 fresh addresses grows the map without bound (a few tens of bytes per
address).

**Impact** Slow, attacker-driven memory growth; mitigated by the fact that
the throttle keys on source address and the API is normally LAN-facing.

**Not fixed deliberately** The obvious fix (`return` when still at the cap
after the sweep) silently stops counting failures for new addresses, which is
a worse security property than bounded growth. A correct fix needs an LRU or
a probabilistic filter, i.e. a design decision.

### L-4 A single oversized record can exceed the AXFR message budget

**Where** `crates/daygle-dns/src/dispatcher.rs` — `transfer_chunks`.

**Problem** Records are packed into 16 KiB uncompressed groups, but a single
record larger than the budget is emitted alone; if it is also larger than what
one DNS message can carry, encoding fails and that transfer returns SERVFAIL.

**Impact** A pathological record (or a future record type with a large blob)
breaks zone transfer; unreachable with ordinary A/AAAA/TXT data.

**Not fixed** The correct behaviour (fail the transfer with a clear log line,
or refuse to store such a record at write time) is a policy choice; the
current fallback already surfaces SERVFAIL rather than corrupting data.

### L-5 PROXY v1 headers accept a family/address mismatch

**Where** `crates/daygle-dns/src/proxy_protocol.rs` — `parse_v1`.

**Problem** `PROXY TCP4 <ipv6-address> …` is accepted (the address parses, the
family token is only matched for `TCP4`/`TCP6`). `PROXY UNKNOWN` is handled;
trailing fields beyond the source port are ignored.

**Impact** Cosmetic/misconfiguration detection only — only a *trusted* proxy’s
header is read, and the address is used as-is either way.

**Not fixed** Tightening it would reject proxies that mislabel the family;
left documented by the new tests instead.

### L-6 Duplicate step numbering in the dispatcher

**Where** `crates/daygle-dns/src/dispatcher.rs` — the step comments labelled
`1c` twice (RPZ, then split horizon) before `1d`/`2a`.

**Problem** Section numbering in a 3,400-line query pipeline drifted, making
the comment map (“1c” means two different stages) misleading to anyone tracing
a query.

**Fix** Split horizon relabelled `1e`.

**Risk/trade-off** None; comment-only.

---

## Changes made

```diff
--- a/Cargo.toml
+++ b/Cargo.toml
@@
-rust-version = "1.92"  # pinned to the `ort` (ONNX Runtime) MSRV
+rust-version = "1.95"  # lowest toolchain the locked dependencies build on
```

```diff
--- a/crates/daygle-dns/src/proxy_protocol.rs
+++ b/crates/daygle-dns/src/proxy_protocol.rs
 fn table() -> &'static RwLock<HashMap<SocketAddr, SocketAddr>> { … }
+
+/// The table, ignoring lock poisoning: the map is a peer mapping, so a panic
+/// in an unrelated thread that happened to hold the lock (which poisons it)
+/// must not turn every later query into a panic. `real_client` runs on the
+/// DNS query path, so an `expect` here would take the whole server down.
+fn read_table() -> std::sync::RwLockReadGuard<'static, HashMap<SocketAddr, SocketAddr>> {
+    table().read().unwrap_or_else(|e| e.into_inner())
+}
+
+fn write_table() -> std::sync::RwLockWriteGuard<'static, HashMap<SocketAddr, SocketAddr>> {
+    table().write().unwrap_or_else(|e| e.into_inner())
+}
@@ pub fn register_client(local: SocketAddr, client: SocketAddr) {
-    table().write().expect("proxy table lock poisoned").insert(local, client);
+    write_table().insert(local, client);
@@ pub fn unregister_client(local: SocketAddr) {
-    table().write().expect("proxy table lock poisoned").remove(&local);
+    write_table().remove(&local);
@@ pub fn real_client(src: SocketAddr) -> SocketAddr {
-    let table = table().read().expect("proxy table lock poisoned");
+    let table = read_table();
```

Plus new tests in that module: a poisoned-lock regression test (poisons the
real lock, then asserts `register_client`/`real_client`/`unregister_client`
still work), chained-bridge resolution, and v1/v2 header parsing
(`parse_v1`, `parse_v2` with the command nibble as `read_header` passes it,
`PROXY UNKNOWN`, short v2 body, unknown command).

```diff
--- a/crates/daygle-dns/src/doh.rs
+++ b/crates/daygle-dns/src/doh.rs
-        let mut stream = self
-            .respond
-            .lock()
-            .expect("h2 send lock poisoned")
+        // Recover from lock poisoning: a panic while sending one response
+        // must not turn every later response on this stream into a panic.
+        let mut stream = self
+            .respond
+            .lock()
+            .unwrap_or_else(|e| e.into_inner())
             .send_response(response, false)
```

```diff
--- a/crates/daygle-dns-core/src/stats.rs
+++ b/crates/daygle-dns-core/src/stats.rs
@@ pub fn record(&self, client: IpAddr, qname: &str, outcome: Outcome) {
         let now_min = epoch_minutes();
         {
             let mut buckets = self.inner.buckets.lock();
+            // A wall clock that steps backwards (NTP correction, a suspended
+            // VM) would otherwise push a bucket for an earlier minute than
+            // the last one: the ring then holds duplicate minutes for the
+            // same minute and `series` keeps only one of them, losing the
+            // newest counts. Clamping keeps the ring monotonic and folds the
+            // step-back into the current minute.
+            let now_min = now_min.max(buckets.last().map_or(now_min, |b| b.minute));
             if !matches!(buckets.last(), Some(b) if b.minute == now_min) {
```

Plus a regression test (`a_backward_clock_step_does_not_duplicate_minutes`)
asserting a future-stamped bucket does not produce a second bucket and that
`series` stays strictly increasing.

```diff
--- a/crates/daygle-dns-api/src/lib.rs   (comments only)
--- a/crates/daygle-dns/src/cookies.rs  (comments only)
--- a/crates/daygle-dns/src/dispatcher.rs (comment: 1c → 1e)
```

## Not changed, and why

- **No dead/duplicate code removal.** Every public item touched in the
  reviewed paths is reachable from the binary or the API; no duplicate
  implementation of a reviewed function was found. Removing `#[cfg(test)]`
  helpers or the documented compatibility aliases (e.g. the
  `/api/split-horizon/networks` form kept for older consoles) would break
  callers, so nothing was deleted on speculation.
- **No performance tuning.** Nothing measured here warranted a change: the
  hot-path structures (rate-limit buckets, RRL accounts, record-use cache,
  stats top-N, block log) are all capped and swept, and the per-query work is
  O(1) map lookups. The one measurable cost found (M-3) needs a structural
  change, not a micro-optimisation.
- **No dependency or lockfile changes**, so builds stay reproducible at the
  versions the project pins.

---

## Follow-up audit — 2026-11-06

Whole-workspace pass on top of the review above. Tooling: `cargo clippy
--locked --workspace --all-targets --no-default-features -- -D warnings`
(clean; the default `verifier-onnx` feature could not be built here because
the ONNX Runtime binary download was blocked by the sandbox network), a
dependency-usage scan of every crate manifest (no unused dependencies), a
scan for public functions with no callers (none), and `npm audit` on the
console (two low-severity advisories in the build-time `deepmerge` chain of
`@sveltejs/vite-plugin-svelte`, no fix available upstream; not shipped in the
bundle).

| ID | Severity | Where | Issue | Change |
|----|----------|-------|-------|--------|
| F-1 | Medium (perf) | `daygle-dns-api/src/lib.rs` `require_auth` | Every API request ran `count_console_users` and, for `dgl_` tokens, three more SQLite calls on a tokio worker behind the store's single connection mutex (M-3). | The database work runs in `spawn_blocking`; a panicked task fails closed (users "configured", no session). Behaviour is otherwise unchanged. |
| F-2 | Low (security) | `daygle-dns-api/src/lib.rs` `LoginThrottle` | Map grew past `MAX_TRACKED` when no entry had expired (L-3). | When still full after the sweep, the entry whose window started first is evicted; new addresses keep being counted. Unit test added. |
| F-3 | Low (memory DoS) | `daygle-dns-policy/src/feeds.rs` `fetch` | Category feeds buffered the whole body before the 32 MiB check, so a mirror without (or lying about) `Content-Length` could make the server hold an unbounded download. | Reject on advertised length, then stream chunks and stop at the cap (same approach as `blocklist_source.rs`). |
| F-4 | Low (perf) | `daygle-dns-dhcp/src/v4.rs`, `v6.rs` `usable` | The address scan evaluated the reservation-list searches (string normalisation per reservation) before the cheap lease lookup, for every address of the range, under the DHCP state lock: O(range × reservations) per DISCOVER on a busy pool. | Cheap checks first; reservation searches are lazy and only run for a free, in-subnet address. Same result set. |
| F-5 | Low (bug) | `daygle-dns-dhcp/src/v6.rs` `choose` | `end - start + 1` underflowed for a range that starts after it ends (hand-edited config) and overflowed for the whole address space. | Checked arithmetic: such a range offers nothing. |
| F-6 | Low (bug) | `daygle-dns-dhcp/src/service.rs` | `port + 1` for the DHCPv4 client port overflowed at 65535 (panic in debug, port 0 in release). | `saturating_add(1)` (67 still maps to 68). |
| F-7 | Low (robustness) | `daygle-dns/src/dispatcher.rs` `empty_zone_covering` | `str` slicing at a computed offset on the query path would panic if it fell inside a multi-byte character. | Compare bytes (`[u8]::eq_ignore_ascii_case`). |
| F-8 | Low (robustness) | `daygle-dns/src/block_page.rs` `page` | A poisoned settings lock silently dropped the custom block message for the process lifetime, unlike `apply`, which recovers. | Recover the guard the same way. |
| F-9 | Low (hardening) | `install.sh` | The rustup bootstrap fetched with plain `curl -fsSL`. | `--proto '=https' --tlsv1.2`, as rustup recommends (curl path and the printed hint). |

Reviewed and deliberately left unchanged:

- The login response still returns the session token in its JSON body.
  `docs/API.md` documents it as the bearer credential for scripts, so
  removing it would break clients; the console itself never stores it.
- Duplicate crate versions (`base64`, `parking_lot`, `tower-http`, `nom`,
  `syn`, `getrandom`) all come from transitive dependencies (reqwest,
  hickory, rusqlite); unifying them needs upstream releases, not a local edit.
- `GET /api/backup` reads the finished backup into memory before sending it;
  streaming it needs the scratch file kept alive for the response's lifetime
  (and `tokio-util`'s `io` feature) — recorded as a follow-up.
- Most console handlers still call SQLite directly on async workers. F-1
  covers the one path every request takes; moving the rest is a larger,
  mechanical change best done handler by handler.
