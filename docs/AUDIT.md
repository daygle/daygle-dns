# Code audit - October 2026

Scope: the whole workspace (Rust crates, the embedded console, the installer
and the self-update scripts). The work concentrated on the attack surfaces:
unauthenticated DNS and HTTP input, authentication, the privileged update
path, and on-disk secrets. The codebase is mature and heavily hardened
already (bounded maps, PBKDF2 off the async runtime, constant-time
comparisons, symlink-safe writes, parameterized SQL throughout). The
findings below are what remained.

Each entry gives the problem, its impact, the fix, and the risks or
trade-offs. **Fixed** entries are changed in this commit. **Reported**
entries are left as they are, with the reason.

Verification:

- `cargo fmt --all -- --check` is clean.
- `cargo clippy --workspace --all-targets --no-default-features -- -D warnings`
  is clean.
- `cargo test --workspace --no-default-features` passes, with one
  pre-existing, environment-dependent exception (L7).
- New regression tests cover the ACL fix.
- The apply script was exercised in a sandbox with stubbed
  `curl`/`systemctl`.
- The console was driven in Chromium under the new CSP with no violations.
- A 40-request concurrent login burst was checked against the throttle.

The ONNX feature could not be built here because its prebuilt runtime
download is blocked by this environment's network proxy. None of the changes
touch that code.

---

## Critical

### C1. The self-update root step runs content staged by the unprivileged service account (local privilege escalation to root) - **Fixed**

*Where:* `crates/daygle-dns-api/src/update-apply.sh`

*Problem.* The service account (`daygle-dns`) writes two files:
`<data>/updates/staging/apply.bin` and `apply.json`, which holds the kind,
version and the sha256 *of that same file*. The root oneshot
(`daygle-dns-update.service`) "verified" `apply.bin` against that sha256.
It then did one of three things:

- `kind=install`: executed the file as a shell script **as root**.
- `kind=release` (the default when `kind` was missing): installed the file
  as `/usr/local/bin/daygle-dns`.
- `kind=models`: extracted an attacker-supplied tarball as root.

Both the content and its checksum come from the account the design is
meant to contain, so the checksum proved integrity, never authenticity.

*Impact.* Any code execution as the service account becomes root:

1. Write a script and its checksum.
2. Touch `updates/request`.
3. systemd runs the script as root within seconds.

Code execution as the service account could come from a memory-safety bug
in a dependency, a malicious model file, a compromised blocklist parser,
and so on. A network-facing DNS daemon is exactly what that boundary
exists to contain.

*Fix.* The root step now trusts nothing that it did not fetch itself:

- `kind=install`: root downloads `install.sh` itself, HTTPS-only (including
  redirects), from the same canonical URL that `install.sh` and `update.sh`
  use. If no downloader is available, it takes the script from a fresh
  `git clone` of the canonical repository. The staged copy is never
  executed.
- `kind=models`: before extracting anything, root fetches the
  `daygle-dns-models.tar.gz.sha256` published with release `v<version>`
  and requires the staged bundle to match it.
- Any other kind is refused, including a missing kind and the retired
  binary-swap `release` kind. `update.sh` never produces `release`, so that
  branch was dead code whose only remaining use was the escalation.

*Risks and trade-offs.*

- The root step now needs outbound HTTPS to GitHub. The installer it runs
  needed that anyway, since it clones and builds from GitHub.
- The `DAYGLE_DNS_UPDATE_REPO_*` overrides in `update.sh` no longer steer
  what root runs. The canonical repository is hard-coded, exactly as in
  `install.sh`.
- Model updates for a prerelease tag such as `v1.2.3-rc1` would fail
  closed. `/releases/latest` never returns prereleases.

---

## High

### H1. Login brute-force throttle bypass under concurrency (TOCTOU) - **Fixed**

*Where:* `crates/daygle-dns-api/src/handlers.rs` (`auth_login`)

*Problem.* The per-IP throttle was checked once, on arrival. Concurrent
attempts all passed the check before any of them had failed. They then
queued for the 4 PBKDF2 slots and were each verified.

*Impact.* One burst of N parallel requests got N password guesses instead
of 10 per 5 minutes. Measured: 40 parallel bad logins gave 40 checked
guesses before the fix.

*Fix.* The throttle is re-checked after the attempt acquires its PBKDF2
slot. The slot is held until the failure is recorded, so a burst is bounded
by the slots in flight. Measured after the fix: 13 × `401`, 27 × `429`.

*Risks.* A few more lines in the handler. `password_work` was split into
`password_permit` and `run_password_job` so login can hold the permit.
Other callers are unchanged.

### H2. Database, keys and secrets readable by every local account - **Fixed**

*Where:* `install.sh`

*Problem.* The installer created `$CONFIG_DIR` and `$DATA_DIR` with the
default mode 0755, and the service ran with the default umask 022. So the
SQLite database was 0644 in a world-traversable directory. It holds
DNSSEC and TLS private keys, TOTP secrets, password and token hashes, and
console-made backups. The config can hold the static API token and TSIG
secrets.

*Impact.* Any local user could read every private key and authentication
secret.

*Fix.* The installer now runs `chmod 0750` on both directories after
`chown`, which also protects existing installs whose files are already
0644. The unit gets `UMask=0027`.

*Risks.* Non-root, non-service accounts that read these paths directly,
for example an operator running `daygle-dns backup` without `sudo`, now
need to use `sudo`.

### H3. AXFR/IXFR and dynamic-update allow-lists rejected bare IP addresses - **Fixed**

*Where:*

- `crates/daygle-dns/src/dispatcher.rs` (`transfer_client_allowed`)
- `crates/daygle-dns-authoritative/src/update.rs` (`update_client_allowed`)

*Problem.* The config check accepts a bare address such as
`axfr_networks = ["192.0.2.10"]` through `parse_network`, and network-name
resolution passes it through unchanged. The runtime check, however, only
parsed CIDR (`IpNet`), so a bare address matched nobody.

*Impact.* This failed closed, so there was no exposure, but a documented
and validated config silently refused transfers and updates from the
configured secondary or updater.

*Fix.* Both checks now use `daygle_dns_core::config::parse_network`, the
same parser the validator and the encrypted-listener ACLs use. Regression
tests were added.

*Risks.* None. Only entries the validator already accepted now match.

---

## Medium

### M1. Unbounded DNS-path database writes from wildcard name floods - **Fixed**

*Where:* `crates/daygle-dns/src/dispatcher.rs` (record-use cache)

*Problem.* Each *unique* query name answered from a hosted zone (any name,
under a wildcard) inserted a cache entry and spawned a blocking task that
wrote "last used" to SQLite. Once the map passed 4 096 live entries it was
also rescanned in full on every query, under its lock.

*Impact.* A remote client could flood random names under a wildcard to
fill the blocking pool with SQLite writes contending for the database
mutex. That slows the API and every other database user, and grows the
map for as long as the flood lasts.

*Fix.*

- The logic is shared between the authoritative and split-horizon paths in
  `first_use_this_minute`, which removes duplicated code.
- The map is swept at most once a minute.
- The map is hard-capped at 16 384 keys. Past the cap, "last used"
  updates are skipped.

*Risks.* During such a flood, some "last used" timestamps are not updated.
They are informational only.

### M2. DoQ streams could be held open forever without sending a query - **Fixed**

*Where:* `crates/daygle-dns/src/doq.rs`

*Problem.* After `accept_bi`, the server waited indefinitely for the
2-byte length and the body. The QUIC idle timeout does not fire while the
client keeps the connection alive.

*Impact.* A few clients could exhaust the global stream budget
(`max_connections × max_concurrent_streams`) and deny DoQ to everyone.

*Fix.* Reading the request is now bounded by a 10 s timeout. On expiry the
stream is stopped.

*Risks.* A client that opens a stream and takes more than 10 s to send a
query of at most 64 KiB is cut off. This matches TCP/DoT practice.

### M3. No Content-Security-Policy on the console - **Fixed**

*Where:* `crates/daygle-dns-api/src/lib.rs` (`security_headers`)

*Problem.* Session tokens are kept in `localStorage`, and nothing limited
where the page could load or run script from.

*Impact.* Any HTML injection would escalate directly to session theft.

*Fix.* A strict CSP is added:

- `default-src 'self'`, `script-src 'self'`, `connect-src 'self'`
- `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`,
  `frame-ancestors 'none'`
- `style-src` and `img-src` stay the minimum the bundle needs: inline
  `style` attributes, and `data:` and `blob:` images.

Verified in Chromium: first-run setup, the dashboard and every main view,
with zero console errors or CSP violations.

*Risks.* Any future feature that loads third-party resources must extend
the policy.

### M4. AD bit set for clients that did not ask for DNSSEC - **Fixed**

*Where:* `crates/daygle-dns/src/dispatcher.rs` (recursive response)

*Problem.* AD was set on any validated answer. RFC 6840 §5.8 says to set
it only when the query had AD or DO set.

*Fix.* AD is now set only for such clients. The validation metric is
unchanged.

*Risks.* None for standard clients. `dig` sets AD by default.

### M5. Valid DNS cookies exempt a client from the rate limit entirely - *Reported (design)*

*Where:* `crates/daygle-dns/src/dispatcher.rs`

*Problem.* This is documented behavior: cookies prove the source address,
so the per-client limit is skipped. But the limit also protects against
abusive *non-spoofing* clients. Any client can fetch a cookie and then
query without limit.

*Recommendation.* Keep applying the limit to cookie-validated clients,
with a higher allowance such as 10×, rather than exempting them.

*Not changed because* this would change documented behavior that
operators may rely on.

### M6. Dynamic updates without an ACL or TSIG are open to everyone - *Reported (design)*

*Problem.* The defaults are safe (`allow_dynamic_updates = false`). But
enabling updates with an empty `update_networks` and no TSIG accepts
spoofable UDP updates from anyone.

*Recommendation.* Have the config check warn about, or refuse, that
combination.

---

## Low

### L1. Updater helper processes were never reaped - **Fixed**

*Where:* `crates/daygle-dns-api/src/update.rs` (`spawn`)

*Problem.* The `std::process::Child` was dropped without `wait`.

*Impact.* Every run that does not restart the server left a zombie until
the process exited. Failed runs, and runs whose apply step never picks up
the request, are examples.

*Fix.* A detached thread waits on the child.

### L2. TSIG response signing could overflow the additional-record count - **Fixed**

*Where:* `crates/daygle-dns-authoritative/src/tsig.rs`

*Problem.* `u16 + 1` panics in debug builds and wraps in release builds.
It can only be reached with 65 535 additionals, which a server-built
response never has.

*Fix.* `checked_add` now returns an error instead.

### L3. A damaged local-root cache file could force a huge allocation - **Fixed**

*Where:* `crates/daygle-dns-authoritative/src/root_zone.rs` (`decode`)

*Problem.* `Vec::with_capacity(count)` used a count read from the file.

*Fix.* The reservation is capped by what the file can actually hold. No
record is shorter than 11 octets.

### L4. PROXY-protocol TCP front registers the client mapping after connecting - *Reported*

*Where:* `crates/daygle-dns/src/proxy_protocol.rs` (`splice`)

*Problem.* `connection_admission::bridge` binds first and registers before
connecting. `splice` connects first and registers afterwards. Queries are
unaffected, because data only flows after registration. But an
accept-time lookup, such as the TLS session diagnostics, could briefly
attribute the connection to `127.0.0.1`.

*Recommendation.* Mirror the bind, register, connect order used in
`bridge`.

### L5. Credential re-confirmation is not throttled - *Reported*

*Problem.* `POST /auth/password` and the two-factor endpoints verify the
current password without the per-IP failure counter. They do need a valid
session, and the PBKDF2 semaphore bounds the rate.

*Recommendation.* Feed failures into the login throttle as well.

### L6. Blocking work on async threads in rare admin paths - *Reported*

*Problem.* `RecursiveResolver::build`, called from settings handlers,
resolves stub-zone host names with blocking `getaddrinfo`. Many handlers
also make short synchronous SQLite calls on the async runtime.

*Impact.* These are rare and admin-only, so the impact is small.

*Recommendation.* Use `spawn_blocking` for resolver rebuilds.

### L7. Test isolation: suite leaves `/etc/daygle-dns` behind when run as root - *Reported*

*Problem.* A test that uses the default DoT certificate paths creates
`/etc/daygle-dns/certs`. Once that directory exists, `config_dir_hint()`
treats the host as installed and the background release warmer starts
fetching. A later run of
`console::update_endpoints_report_state_and_gate_start` then sees
`latest_checked_secs_ago` set and fails. It passes on a clean `/etc`.

In-process tests in `update::connectivity_tests` and `manual_check_tests`
also share global statics and can race when run in parallel.

*Recommendation.*

- Point those tests at temporary certificate paths.
- Make the release-cache tests serialize on a shared lock.

### L8. Minor items noted, left as they are

- **Host-header redirect.** `redirect_to_https` builds its target from the
  client's own `Host` header. It only redirects the requester, so it is
  not exploitable without a caching proxy.
- **Last-admin guard race.** `last_admin_guard` and the user mutations are
  not one transaction. The store's `delete_console_user` re-checks under
  its own lock, so deletion is safe. Two concurrent demotions are a
  theoretical admin-only race.
- **Named-network lookups per query.** `listener_gate` resolves named
  networks per query, allocating the network list. This only applies to
  encrypted listeners with named-network ACLs. The cost was not
  measurable here.
