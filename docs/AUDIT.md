# Code audit - October 2026

Scope: the whole workspace (Rust crates, the embedded console, the installer
and the self-update scripts). The work concentrated on the attack surfaces:
unauthenticated DNS and HTTP input, authentication, the privileged update
path, and on-disk secrets. The codebase is mature and heavily hardened
already (bounded maps, PBKDF2 off the async runtime, constant-time
comparisons, symlink-safe writes, parameterized SQL throughout). The
findings below are what remained.

Each entry gives the problem, its impact, the fix, and the risks or
trade-offs. Every finding is **Fixed**, except one that turned out not to
be a defect (marked **Verified, no change**).

Verification:

- `cargo fmt --all -- --check` is clean.
- `cargo clippy --workspace --all-targets --no-default-features -- -D warnings`
  is clean.
- `cargo test --workspace --no-default-features` passes, including when
  run as root (see L7).
- New regression tests cover the ACL fix, the cookie allowance, refused
  open updates and the redirect host check.
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

### M5. Valid DNS cookies exempted a client from the rate limit entirely - **Fixed**

*Where:*

- `crates/daygle-dns-core/src/rate_limit.rs`
- `crates/daygle-dns/src/dispatcher.rs`

*Problem.* Cookies prove the source address, so the per-client limit was
skipped for a valid one. But the limit also protects against abusive
*non-spoofing* clients: any client could fetch a cookie and then query
without limit.

*Fix.* A client with a valid cookie now gets ten times the per-client
limit (`VERIFIED_CLIENT_ALLOWANCE`), not an exemption. Its window is shared
with its uncookied queries. The README, the example config and the config
docs say so, and the cookie integration test checks the allowance ends.

*Risks.* This changes documented behavior. A legitimate client sending
over ten times the configured limit with cookies is now limited. Operators
who need more can raise `client_max_queries`.

### M6. Dynamic updates without an ACL or TSIG were open to everyone - **Fixed**

*Where:* `crates/daygle-dns-authoritative/src/update.rs`

*Problem.* The defaults are safe (`allow_dynamic_updates = false`). But
enabling updates with an empty `update_networks` and no TSIG key for the
zone accepted spoofable UDP updates from anyone.

*Fix.* That combination now fails closed. With an empty `update_networks`,
only zones bound to a TSIG key in `tsig_update_zones` accept updates, and
only signed ones. The decision is per zone, because TSIG binding is per
zone. The config docs, example config, API docs and the Settings help text
are updated, and a test covers the refusal.

*Risks.* This changes behavior. A deployment that relied on open,
unauthenticated updates must now list its updaters in `update_networks`
(the built-in "This Server" network covers localhost) or bind a TSIG key.

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

### L4. PROXY-protocol TCP front registered the client mapping after connecting - **Fixed**

*Where:* `crates/daygle-dns/src/proxy_protocol.rs` (`splice`)

*Problem.* `connection_admission::bridge` binds first and registers before
connecting. `splice` connected first and registered afterwards. Queries
were unaffected, because data only flows after registration. But an
accept-time lookup, such as the TLS session diagnostics, could briefly
attribute the connection to `127.0.0.1`.

*Fix.* `splice` now binds the backend socket, registers its address, then
connects, like `bridge`.

### L5. Credential re-confirmation was not throttled - **Fixed**

*Where:* `crates/daygle-dns-api/src/handlers.rs` (`confirm_password`)

*Problem.* `POST /auth/password` and the two-factor endpoints verified
the current password without the per-IP failure counter. A stolen session
could be used to guess the account's password, bounded only by the PBKDF2
semaphore.

*Fix.* All four endpoints go through one `confirm_password`. It checks the
login throttle, re-checks it once the attempt holds its PBKDF2 slot (as
login does), and records a wrong password as a failed login for the client
address. The old one-off `verify_password` helper is gone.

*Risks.* Wrong passwords on these endpoints now count toward the same
10-per-5-minutes lockout as sign-in failures from that address.

### L6. Blocking work on async threads in admin paths - **Fixed**

*Where:*

- `crates/daygle-dns-api/src/handlers.rs` (`build_resolver`)
- `crates/daygle-dns-api/src/networks.rs`

*Problem.* `RecursiveResolver::build`, called from the settings and
network handlers, resolves stub-zone host names with blocking
`getaddrinfo` on an async worker thread.

*Fix.* Both handlers now build the resolver through one `build_resolver`
helper on the blocking pool. In `networks.rs`, `apply` and
`apply_resolved_changes` became `async`.

*Not changed:* the many short synchronous SQLite calls in handlers.
Moving them is a broad refactor for no measured benefit.

### L7. Test isolation: suite left `/etc/daygle-dns` behind when run as root - **Fixed**

*Problem.* `console::settings_update_applies_and_persists` enabled DoQ
with the default certificate paths, so the server wrote a self-signed
certificate to `/etc/daygle-dns/certs`. Once that directory exists,
`config_dir_hint()` treats the host as installed and the background
release warmer starts fetching, so a later
`console::update_endpoints_report_state_and_gate_start` saw
`latest_checked_secs_ago` set and failed. The release-cache tests in
`update.rs` also shared global statics and raced when run in parallel.

*Fix.*

- The test now sends temp-dir certificate paths with its DoQ settings, and
  the suite no longer writes to `/etc`.
- The six release-cache tests serialize on one lock, and the throttle
  replay test clears the cache it depends on.

### L8. Minor items

- **Host-header redirect - Fixed.** `redirect_to_https` built its target
  from the client's `Host` header. It now redirects only when that is a
  plain host name or IP address, so a crafted header cannot inject a path,
  user info or a port. Covered by a unit test.
- **Last-admin guard race - Verified, no change.** Re-checked: the store's
  `set_console_user_role`, `set_console_user_enabled` and
  `delete_console_user` each count enabled admins and write under the same
  connection lock, so concurrent demotions cannot remove the last admin.
  The handler's check only gives an earlier, friendlier error.
- **Named-network lookups per query - Fixed.** `listener_gate` called
  `find_network`, which copied the whole network list on every DoT, DoH
  or DoQ query that had a named-network ACL. The built-in networks are now
  built once, and the gate uses a new borrowing `named_network` lookup.

---

# Follow-up audit: DNS over TLS and the update pipeline

Scope:

- **DNS over TLS end to end:** listener, admission, TLS configuration,
  certificates and diagnostics. This includes the case of public users
  pointing Android's "Private DNS" (or any RFC 7858 stub) at the server.
- **The in-place update pipeline:**
  - the console's Update and AI pages;
  - the API handlers;
  - `update.rs`, `update.sh` (service account) and `update-apply.sh`
    (root);
  - `install.sh`.

Verification:

- fmt and clippy (`-D warnings`) are clean, and the full test suite passes.
- 7 new DoT integration tests:
  - pipelining;
  - padding;
  - the per-client cap, through a PROXY header;
  - idle close;
  - readiness warnings;
  - silent connections;
  - a client that never reads.
- The pipelining test was run against Hickory's listener too, and fails
  there.
- `update-apply.sh` was exercised in a sandbox with stubbed
  `curl`/`systemctl`/`sleep`:
  - a healthy update;
  - a failed health check with rollback;
  - an installer that fails after swapping the binary, now reporting its
    real exit code;
  - a service that is up while its console is not where the config file
    says.

## DNS over TLS

### T1. Queries on one DoT connection were answered strictly one at a time - **Fixed** (High)

*Where:* the DoT listener, which was Hickory's `register_tls_listener_with_tls_config`.

*Problem.* Hickory's TLS listener awaits each query's full handling before
it reads the next one from the connection ("we don't spawn here"). Android
Private DNS, and most DoT stubs, pipeline every query of a device over one
connection. So one slow recursive lookup, such as an unresponsive
authoritative server waiting out `client_timeout_ms`, delayed every query
behind it, cached ones included. RFC 7766 §6.2.1.1 asks for concurrent,
out-of-order processing.

*Impact.* Browsing over DoT stalled for seconds whenever one name was slow.
That is exactly what users of a public "Private DNS" resolver notice.

*Fix.* A native DoT listener (`crates/daygle-dns/src/dot.rs`), built like
the existing DoQ one:

- up to 32 queries per connection are answered concurrently and written as
  each completes, matched by message ID;
- past 32 the connection is not read (TCP back-pressure);
- a single writer per connection coalesces queued answers into shared TLS
  records;
- each write is bounded by the session timeout, and the session ends when
  the writer stops. A client that pipelines queries but never reads its
  answers can otherwise hold its connection, and its slot, forever. A test
  reproduces this: it fails with unbounded writes and passes now;
- `TCP_NODELAY` is set.

The integration test sends a slow and a fast query back to back on one
connection. With Hickory's listener the fast answer came second, after the
slow query timed out. Now it comes first, at once.

*Risks.* Hickory no longer handles DoT, and the dispatcher, ACLs, rate
limits and logs are unchanged. One connection can now cost up to 32
concurrent lookups instead of 1. Those are still bounded by the global
recursive admission limit and the per-client rate limit.

### T2. One address could take every DoT connection slot - **Fixed** (Medium)

*Problem.* Admission only bounded the total (`dot.max_connections`,
default 1024). A single public client could open 1024 connections, or
just keep 1024 handshakes pending for up to `handshake_timeout_secs` each,
and lock every other user out of a public resolver.

*Fix.* At most an eighth of `max_connections` (minimum 4) per public client.
A client is an IPv4 address or an IPv6 /64, and IPv4-mapped addresses
count as IPv4. Private and loopback addresses are exempt: a load balancer
that does not send PROXY headers shows every client from its own address,
and LAN clients are distinct anyway. Behind a trusted PROXY-protocol
balancer, the cap applies to the real client. A refusal is logged,
coalesced per client.

*Risks.* More than 128 simultaneous DoT sessions from one public address
(at the default) is now refused. A large carrier NAT pool in front of a
busy resolver could reach that; raise `max_connections` for such
deployments.

### T3. Answers were never padded (RFC 8467) - **Fixed** (Medium, privacy)

*Problem.* The size of an encrypted answer reveals which name was asked
for. Android, among others, pads its queries and expects padded answers.

*Fix.* When the query carries an EDNS Padding option, the answer is padded
to a multiple of 468 octets, as RFC 8467 §4.1 recommends. Unpadded
queries, TSIG-signed answers and answers that would exceed 64 KiB are left
alone.

### T4. Nothing warned about setups public Private DNS clients cannot use - **Fixed** (Medium)

*Problem.* Three common setups break Android Private DNS with only a
"couldn't connect" on the phone, and nothing on the server said why:

1. **Self-signed certificate.** The default `self_signed = true` produces
   one, and Android refuses it.
2. **No intermediates.** A certificate file holding only the leaf fails,
   because Android does not fetch intermediates.
3. **Recursion refused.** With `dot.allowed_networks` empty, recursion
   follows `recursion_access`, which defaults to `private_networks`. Public
   clients then get REFUSED, which fails Android's validation query.

*Fix.* `report_dot_readiness` runs at every listener start. It:

- warns about a self-signed certificate or a missing chain whenever DoT
  serves public clients (`0.0.0.0/0` or `::/0` listed, or recursion open to
  all);
- notes when clients outside `recursion_access` would be refused,
  explaining how to open DoT alone to them.

### T5. A failed listener rebind leaked running DoT/DoQ listeners - **Fixed** (Medium, reliability)

*Problem.* When a reload bound DoT, and DoQ or the DoT admission front,
and then failed on a later listener (a DoH port in use, say), those
already-started tasks kept running with their ports. The supervisor's
"restore the previous listeners" step then failed with "address in use",
leaving that protocol down.

*Fix.* On a bind failure, `bind_listeners` cancels the generation and
waits for its native listeners to close before returning the error.

### T6. Smaller DoT and TLS issues - **Fixed** (Low)

- **Admission bridge.** DoT went through a loopback bridge: an extra socket
  pair and a userspace copy per connection. DoT now admits connections
  itself and handles PROXY headers directly. DoH keeps the bridge.
- **Session resumption.** rustls keeps 256 resumable sessions by default.
  Mobile clients reconnect on every network change, so they mostly paid
  full handshakes. DoT, DoH and DoQ now keep 8 192.
- **DoQ TLS versions.** DoQ's TLS config was documented as TLS 1.3-only but
  offered 1.2 as well (QUIC negotiated 1.3 regardless). It is now really
  restricted.
- **Diagnostics.** Handshake timeouts were logged without a client address
  (Hickory's limitation). DoT now records every failure with the address,
  including a bad PROXY header and the per-client refusal. A
  connect-and-close with no TLS bytes (health checks, scans) is no longer
  logged as a failure. The diagnostics bridge's Hickory DoT patterns, and
  the "idle expiry" special case they needed, are removed as dead code.
- **Dead code.** `daygle_dns_dot::register_dot` is removed.

### T7. Certificate renewal restarts every DNS listener - *Reported*

When a certificate a listener uses is renewed (ACME, every ~60 days) or
replaced, the console requests a full listener rebuild. Every DNS
listener stops and rebinds, plain UDP/TCP included, so all DoT sessions
drop and every client reconnects.

*Recommendation.* Serve the TLS config through a swappable resolver
(`ArcSwap<ServerConfig>`, or a rustls `ResolvesServerCert`) and swap it in
place on renewal.

*Not changed:* the interruption is brief and rare, and the change touches
the reload supervisor, which this audit kept stable.

## Update pipeline

### U1. "Update to the latest release" built the tip of `main` - **Fixed** (High)

*Where:* `install.sh`

*Problem.* The installer cloned `main` but stamped the binary with the
latest release's version. An update therefore installed whatever was on
`main` (unreleased, possibly broken), labelled as the release. Afterwards
the console reported "up to date" while running different code.

*Fix.* The installer resolves the latest release first and clones that tag
(`git clone --branch <tag>`). It still stamps the version, because a tag's
manifest can lag the tag.

*Risks.* Fixes on `main` now reach hosts only when a release is tagged.
That includes the hardened `update-apply.sh` from this PR, which the
installer copies from the source it builds. **Tag a release after merging
this PR.**

### U2. A failed installer update had no rollback - **Fixed** (High)

*Problem.* The installer replaces the binary and then restarts the
service. If the new version did not come up, or the installer failed after
the swap, the broken binary stayed in place. The old binary-swap path had
a rollback, but the installer path, the only one in use, never did.

*Fix.* Before the installer runs, the root step keeps a copy of the running
binary, preferring `/proc/<pid>/exe`. If the health check fails, or the
installer fails after replacing the binary, the root step:

1. puts the copy back;
2. restarts the service;
3. checks its health again;
4. reports exactly what happened.

*Risks.* Only the binary is rolled back. A new version that already
migrated the database leaves the migration in place; Daygle's migrations
are additive.

### U3. The health check could fail healthy updates - **Fixed** (Medium)

*Problem.* The check gave the service 15 s and probed only the plain-HTTP
console address from the config file. A console moved to another port, or
to HTTPS only in Settings (those settings live in the database), always
failed it, as did a slow start. With U2's rollback, that would have
reverted a good update.

*Fix.* The window is now 90 s, and the check passes on either of:

- the console answering;
- the unit staying active under one process for 20 s (a failing start
  exits and is restarted under a new process).

### U4. GUI updates built in `/tmp` - **Fixed** (Medium)

*Problem.* The root step ran the installer with the default temp
directory. The installer's checkout and release build (gigabytes) landed
on `/tmp`, which many distributions mount as RAM-backed tmpfs. The disk
preflight checked the service's temp dir and passed at 100 MB.

*Fix.*

- The installer runs with `TMPDIR=/var/tmp` (as `update.sh` already did).
- The preflight checks `/var/tmp` and asks for 3 GB. For reference, a debug
  build of the workspace takes 3.3 GB.

### U5. Smaller pipeline issues - **Fixed** (Low)

- **Installer exit code.** It was always reported as 1. Under `set -e` the
  subshell exited before recording the real code. Now it records the
  installer's own code (verified: 3).
- **Concurrent starts.** Two concurrent update or model-update starts (a
  double click, or the Update and AI pages) could both pass the "already
  running" check and launch two helpers. Starting is now serialized.
- **Version ordering.** `version_lt` read build metadata (`1.0.3+abc`) as
  `1.0` and reported such a build as outdated. Build metadata is now
  ignored, as SemVer specifies.
- **Phase lists.** The Update and AI pages' running-phase lists missed
  `cloning`/`building`, which the server counts as running.
- **Polling.** The Update page polled forever on `401`/`403` instead of
  stopping.

### U6. Remaining limitations - *Reported*

- **Workspace in `/tmp`.** The update workspace is `/tmp/daygle-dns-update`.
  Another local account can create that directory first and so block
  updates. It cannot hijack them: the directory's owner is checked, and
  root only renames files into it.
- **`hidepid`.** On hosts mounting `/proc` with `hidepid`, the service
  cannot see the root step's process. A running update then reads as
  "stopped", and the console would allow a second start.
- **`TMPDIR` mismatch.** If the service ran with its own `TMPDIR`, it and
  the root step would disagree on the workspace path. The installed unit
  sets none.
