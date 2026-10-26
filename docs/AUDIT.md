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

# Follow-up audit: blocklists, client groups, networks and settings persistence

Scope:

- **Blocklists:** source parsing (hosts, plain domains, Adblock), the
  blocklist matcher, scheduled and manual refresh, and DoT-scoped sources.
- **Client groups:** advanced blocking, how groups are rebuilt, and the
  console's "Test blocking" tool.
- **Named networks:** create, edit and delete, and what each one rebuilds.
- **Settings:** every save on the Settings tabs, followed through
  `PUT /api/config` → live config → config file and database overlay →
  restart and config-file reload.

Verification:

- fmt and clippy (`-D warnings`) are clean, and the full test suite passes.
- New tests:
  - `every_console_setting_survives_the_database_overlay`. It changes every
    setting the console owns (recursive, DoT, DoH, DoQ, policy,
    authoritative, AI, display, web, updates, syslog, DNS64, ECS and
    networks). Then it checks that each value survives the database
    overlay's save → JSON → startup round trip. It failed before the
    fixes below.
  - `adblock_rules_follow_dns_filtering_syntax` and
    `exceptions_override_blocks`.
  - The DoT-scoped source integration test now also removes the source.
    It checks that DoT queries stop being blocked, which failed before
    fix B2.

## Blocklists

### B1. Adblock lists were read with the wrong meaning - **Fixed** (High)

*Problem.* Adblock DNS filters (AdGuard, OISD, HaGeZi "adblock" formats)
were read as plain domain lists:

- `||example.com^` blocks `example.com` and every subdomain. It was stored
  as an exact name, so `ads.example.com` passed. Most entries in these
  lists depend on the subdomain match.
- `@@||example.com^` is an exception that unblocks a name. It was turned
  into a block instead, so the names a list author had deliberately
  unblocked were blocked.
- Rules with modifiers the resolver cannot honour, such as
  `$client=`, `$dnsrewrite=` or `$badfilter`, were applied as
  unconditional blocks.

*Impact.* Adblock-format lists blocked far less than they should, and also
blocked names they were written to allow.

*Fix.*

- `||x^` now matches `x` and its subdomains, and `|x^` matches exactly.
- `@@` rules go into a separate exception set, and an exception always wins
  over a block from the same lists.
- Rules with `badfilter`, `client`, `ctag`, `denyallow`, `dnsrewrite` or
  `dnstype` are skipped. Other modifiers, such as `$important`, do not
  change a DNS answer and are ignored.
- The domain count shown for a source counts block rules only, so a
  `||x^` rule counts once.

*Risk.* Adblock sources will now block more names (the subdomains they
always meant to cover). The allowlist still takes precedence over them.

### B2. Removing a DoT-scoped source never stopped it blocking - **Fixed** (High)

*Problem.* A source scoped to DoT compiles into its own list. When the
source was removed, disabled or rescoped, the refresh published only the
everyone list, and the old DoT list stayed live until restart. "Refresh
now" did not rebuild the DoT list at all.

*Impact.* DoT clients (including public Private DNS users) went on being
blocked by a list the operator had removed.

*Fix.* Both lists are published together on every refresh, manual or
scheduled, and both are cleared when every source is disabled.

### B3. Lost updates between a refresh and a settings save - **Fixed** (Medium, race)

*Problem.* A settings save rebuilt the policy engine from the old engine's
source lists and then stored it. A blocklist refresh finishing in between
was overwritten, and the new list was lost until the next refresh (up to a
day later). The reverse order lost the settings change instead.

*Fix.* Both paths now publish through a read-copy-update
(`publish_rebuilt` / `publish_source_lists`). A rebuild always adopts
whatever source lists are live at the moment it is stored, so neither
change can erase the other.

### B4. Every policy rebuild deep-copied the remote lists - **Fixed** (Low, performance)

*Problem.* Each settings or network save cloned the full downloaded list
(hundreds of thousands of names for common lists) into the new engine.

*Fix.* The lists are shared (`Arc`) between engines. A rebuild now costs
the same whatever the list size. A refresh that produced an identical list
does not republish it.

### B5. A source's status could be recorded against the wrong URL - **Fixed** (Low)

*Problem.* Refresh status rows were matched to sources by name only. If a
source's URL or format was edited while a fetch was in flight, the old
fetch's result (domain count, last-updated time) was shown for the new URL,
and the new URL was not fetched until the next interval.

*Fix.* Status rows are matched on name, URL and format, so an edited source
is treated as new and fetched at once.

## Client groups and networks

### N1. Allowed and denied networks reverted at restart - **Fixed** (High)

*Problem.* The database overlay stored `policy.allowed_networks` and
`policy.denied_networks` on every save but never applied them back at
startup or on a config-file reload.

*Impact.* Restricting service to a set of networks from the console worked
until the next restart. The setting then silently reverted to the file's
value (usually "everyone").

*Fix.* The overlay applies both lists. The new round-trip test covers every
other console-owned setting too, and found no further gaps.

### N2. "Test blocking" did not match what the resolver does - **Fixed** (Medium)

*Problem.*

- An IPv4-mapped client address (`::ffff:192.0.2.10`) was tested as IPv6.
  The resolver unmaps it first, so a group defined by IPv4 network reported
  "not blocked" while the resolver blocked it.
- The resolver skips client-group blocking for allowlisted names. The tool
  ignored the allowlist and reported such names as blocked.

*Fix.* The tool canonicalizes the address and applies the allowlist the way
the resolver does. It reports "domain is on the allowlist" in that case.

### N3. Concurrent saves could undo each other - **Fixed** (Medium, race)

*Problem.* Settings, blocklist sources, networks and zones are saved by
reading the live config, changing it and storing it. Two saves at the same
time (two tabs, or a save during a config-file reload) could each start
from the same config, so the second silently undid the first.

*Fix.* One config-write lock is held by every handler that changes the
config and by both config-file reload paths. Reads are unaffected.

### N4. Things reported but not changed

- **Config-file `[[networks]]` edits.** A file reload rebuilds client
  groups from the file's networks. When the console has never saved a
  network, the file is the source of truth and this is correct. Once the
  console has saved networks, the database copy wins, as designed.
- **DNS64 and ECS.** Prefixes are parsed per query. The cost is a few
  string parses, too small to measure against a lookup, so this is left
  as is.

## Settings save and reload

Every Settings tab was traced from its save button to the running server.
After the fixes above, each value is:

1. validated (an invalid save is rejected with nothing changed);
2. applied to the live config, so requests see it at once;
3. written to the config file and the database overlay;
4. restored at restart and after a config-file reload.

### S1. Recursive concurrency limit needed a restart - **Fixed** (Medium)

*Problem.* "Max concurrent lookups" was saved but the admission limit was
only set at startup, so the new value had no effect until restart.

*Fix.* A save applies the new limit to the running admission control.

### S2. A cleared default primary NS came back - **Fixed** (Low)

*Problem.* Clearing "Default primary NS" saved an empty value, but the
overlay treated empty as "not set" and restored the file's value at
restart.

*Fix.* An empty value now stays empty.

### S3. DoQ idle timeout could not be set through the API - **Fixed** (Low)

*Problem.* `docs/API.md` listed `doq.idle_timeout_secs` as settable, but
the API rejected the field. The docs also listed `handshake_timeout_secs`
for DoQ, which has no such setting.

*Fix.* The API accepts `doq.idle_timeout_secs` (validated at 30 seconds or
more, and the listeners are rebuilt). The docs now say which fields apply
to which listener.

### S4. Server and API sections revert at restart - *By design*

The `server` and `api` sections (listen addresses, CORS origins) apply live
but stay owned by the config file. That way a bad console change cannot
lock the operator out across a restart. This was already documented and is
unchanged.

# Follow-up audit: authoritative zones and DNSSEC

Scope:

- **Serving:** how hosted zones are built into the serving catalog, and
  health-checked failover.
- **Zone transfers:** AXFR/IXFR served to secondaries, and the transfer
  client and refresher used by secondary zones.
- **Dynamic updates and NOTIFY:** RFC 2136 updates, and NOTIFY in both
  directions.
- **DNSSEC:** signing, NSEC/NSEC3, signature renewal, key rollover, and
  what the console shows.

Verification:

- fmt and clippy (`-D warnings`) are clean, and the full suite passes (500
  tests).
- New tests:
  - **End to end:** a signed zone too big for one DNS message, behind
    TSIG, replicated to a secondary. The secondary must serve the master's
    own signatures, byte for byte, and its NSEC denial proofs.
  - **Scripted master:** a fake master answering IXFR with a lone SOA and
    AXFR with the opening SOA in a message of its own.
  - **TSIG chaining:** multi-message signing and verification, checked
    against hickory's own verifier.
  - **Unit tests:** the served serial, inception backdating, the NOTIFY
    change feed, rollover timing, and renewal serial bumps.

## Zone transfers and secondaries

### Z1. Signed zones were transferred unsigned, with the wrong serial - **Fixed** (High)

*Problem.* AXFR/IXFR was built from the database, not from the signed
zone. A secondary of a signed Daygle zone therefore received no RRSIG,
NSEC or DNSKEY records and served the zone unsigned.

There was also a serial mismatch. Hickory bumps the SOA serial by one when
it signs, so a signed zone answered SOA queries with serial N+1 while its
transfers carried N. Two consequences:

- A secondary saw a newer serial on every check and re-transferred the zone
  every refresh interval.
- Unsigning a zone moved the served serial *backwards*, after which
  secondaries ignored changes until the serial passed the old value again.

*Impact.* Once the parent publishes a DS, a validating resolver that asks a
secondary for the zone gets unsigned answers and treats the zone as bogus.

*Fix.*

- A signed zone is built one serial below the stored value, so after
  hickory's bump it is served with exactly the serial the console shows.
- Its transfers are taken from the served, signed data: SOA, RRSIGs,
  NSEC/NSEC3 and DNSKEY records included.

### Z2. Secondaries threw away their master's signatures - **Fixed** (High)

*Problem.* The refresher dropped every DNSSEC record from a transfer and
stored the rest as text records, then served those.

*Impact.* A zone signed by any master was served unsigned by a Daygle
secondary, which made it bogus for validators. Re-parsing every record
from text also risked changing record data in ways that would break the
master's signatures.

*Fix.* Each transfer is also stored exactly as received (wire format), and
a secondary zone is served from that copy:

- signatures are attached to the record sets they cover;
- the NSEC chain, or the NSEC3 chain with its NSEC3PARAM settings, is used
  for denial proofs;
- nothing is re-signed or re-encoded from text.

The record table is still filled, for the console. A secondary zone kept
from before this change is transferred again once, at its next check.

### Z3. Renewed signatures never reached secondaries - **Fixed** (High)

*Problem.* Signature renewal re-signed zones without changing their
serial. Secondaries only transfer when the serial changes, so they kept
the old signatures until those expired (14 days by default). With Z1
fixed, this would have made every secondary copy of a signed zone go bogus.

*Fix.*

- Renewal bumps the serial of every signed primary zone, at half the
  signature validity.
- The new NOTIFY feed (Z9) tells secondaries at once.

### Z4. Zones over 64 KiB could not be transferred - **Fixed** (High)

*Problem.* A whole transfer was sent as one DNS message. A zone larger than
the 64 KiB message limit was cut off and marked truncated, and secondaries
reject that. The limit is roughly 1,500 plain records, and far fewer once
the zone is signed.

*Fix.*

- Transfers are split into messages of at most about 16 KiB (RFC 5936).
- With TSIG, every message is signed, each MAC chained from the one before
  (RFC 8945 §5.3.1). A test checks this format against hickory's own
  verifier.

### Z5. A secondary could stay empty, or be emptied - **Fixed** (High)

*Problem.*

- To fill a new or empty secondary zone, the refresher asked for an IXFR
  from its current serial. A new zone's default serial (1) often matches
  the master's, and the master then answers "no change" with a lone SOA.
  That reply was applied as the full zone: the zone was marked
  transferred, every record was deleted, and it stayed empty from then on.
- A lone *newer* SOA, which means "use AXFR" (RFC 1995), was also read as
  "no change".
- Any transfer that came back without records would have replaced the
  zone with nothing.

*Fix.*

- A zone that has never been transferred, or has no data, is fetched with
  AXFR.
- A lone newer SOA leads to an AXFR, and a lone current SOA changes
  nothing.
- A transfer that does not open and close with the SOA is rejected.

### Z6. Secondary zones ignored their TSIG key - **Fixed** (Medium)

*Problem.* `secondary_zones[].tsig_key` was documented as signing transfer
requests, but nothing used it.

*Impact.* Transfers from a master that requires TSIG were always refused.

*Fix.*

- Transfer requests are signed with the named key.
- Every reply message must verify, chained from the request. Up to 99
  unsigned messages in a row are allowed between signed ones, and the last
  message must be signed (RFC 8945).
- An unknown key name is an error.
- The SOA serial check stays unsigned. It is only a hint, and many masters
  (Daygle included) do not sign ordinary answers.

### Z7. Smaller transfer issues - **Fixed** (Low)

- **Lone opening SOA.** The transfer client stopped at a first message
  holding only the SOA, which some servers send on its own. An AXFR now
  ends only on a closing SOA.
- **Overlapping refreshes.** A refresh started by a NOTIFY could run at the
  same time as the periodic one, and the older transfer could be stored
  last. Refreshes now run one at a time.

## DNSSEC

### D1. Signature inception was "now" - **Fixed** (Medium)

*Problem.* Every reload re-signs the zone (any record edit triggers one),
stamping each RRSIG with the current second as its inception. A validator
whose clock runs even a few seconds behind sees those signatures as not
yet valid.

*Impact.* After every edit, validators with a slow clock treated the zone
as bogus until their clock caught up.

*Fix.*

- Zones are signed with a clock that reads one hour early, as BIND does.
  It is a small runtime wrapper that hickory's zone handler uses only to
  stamp inceptions.
- Expiry moves one hour earlier with it. That is immaterial against a
  14-day validity, renewed at half.

### D2. Key rollover could skip its overlap and grace periods - **Fixed** (Medium)

*Problem.* Both rollover stages were measured from the *old key's
creation*:

- The old key retired once it was older than rollover + overlap, whenever
  its successor had appeared.
- The old key was deleted once it was older than rollover + overlap +
  retire.

After an outage, or with rollover turned on for an old zone, the successor
appeared, the old key retired at the next check (an hour later, not
30 days), and it was deleted at the check after that.

*Impact.* Validators holding the old DNSKEY set had no time to learn the
new key. There was also no window to update the DS at the parent.

*Fix.*

- The old key retires when its successor has been out for the overlap
  period.
- A retired key is deleted when the grace period has passed since its
  retirement. Keys now record a `retired_at` time. Keys already retired
  when upgrading start their grace period then.

### D3. The DS record was never shown - **Fixed** (Medium)

*Problem.* After signing, the console said "Publish its DS record at the
parent zone", but neither the console nor the API showed it.

*Fix.*

- `GET /api/zones` reports `ds`: the DS records, with SHA-256 digests, for
  the active keys. During a rollover there are two.
- The Zones page has a DS button that shows them, and opens them right
  after a zone is signed.

### D4. "Sign" did nothing when signing was turned off - **Fixed** (Low)

*Problem.* With `authoritative.dnssec_enabled = false`, signing a zone
stored a key and reported success, but the zone was served unsigned.

*Impact.* The console listed the zone as signed. A DS published for it
made it bogus.

*Fix.* Signing now fails with a clear error while DNSSEC signing is off.

## Updates, NOTIFY and the catalog

### N1. Console changes did not notify secondaries - **Fixed** (Medium)

*Problem.* NOTIFY was sent only after a dynamic update. Changes made any
other way reached secondaries only at their refresh interval (an hour by
default). That covered console edits, imports, signing and renewal.

*Fix.*

- Each catalog reload reports the primary zones whose served serial
  changed, whatever changed it, and a background task notifies their
  secondaries.
- Dynamic updates use the same path, so a zone is notified once.

### N2. Concurrent dynamic updates could both pass their prerequisites - **Fixed** (Medium)

*Problem.* Each update read the zone, checked its prerequisites and then
applied its changes, with nothing stopping another update in between. Two
clients that each required a name to be absent before adding it could
both succeed. RFC 2136 §3.7 requires updates to be serialized.

*Fix.* Updates now run one at a time, from the zone read to the reload.

### N3. Concurrent reloads could publish a stale catalog - **Fixed** (Medium)

*Problem.* Many things reload the catalog: console edits, updates,
transfers, health changes and DNSSEC maintenance. A slow rebuild that read
the database first could finish last and replace a newer catalog, leaving
a change unserved until the next reload.

*Fix.* Building and publishing a catalog happen under one lock.

### N4. Smaller issues - **Fixed** (Low)

- **Backwards SOA in updates.** A dynamic update whose SOA serial was not
  newer than the zone's was applied, moving the serial back. It is now
  ignored, as RFC 2136 §3.4.2.2 requires.
- **Empty updates.** An update with nothing left to apply no longer bumps
  the serial.
- **Reload cost.** The catalog build filtered every record once per zone
  (zones × records). It now groups records in one pass.
- **Signing maintenance.** It read the list of secondary zones only at
  startup, so a zone made secondary later could still have its keys
  rolled. The list is now read on every pass.

## Reported, not changed

- **Every change re-signs every zone.** A reload rebuilds and re-signs all
  zones. That is fine for typical sizes. With many large signed zones,
  rebuilding only the changed zone would be worth doing.
- **CDS/CDNSKEY.** These are not published (RFC 7344/8078). The DS update
  at the parent during a rollover is still manual.
- **Inbound NOTIFY behind a PROXY front.** The NOTIFY master check uses
  the socket's source address, not a PROXY-restored client.
- **ALIAS to a local target.** Answering it reads the database on each
  query.

# Follow-up fix: console settings reverted to the config file at startup

Reported from the field: with Recursion Access set to "Everyone", public
clients (for example Android Private DNS over DoT) were refused recursion
after every update, while the console still showed "Everyone". Saving
"Private Networks" and then "Everyone" again worked around it.

*Problem.* At startup, `bind_with` resolved the network names in the config
*before* applying the settings saved in the console (the database
overlay). The overlay was applied afterwards to the config the console
reads, but these were built from the earlier copy, which held the config
file's values:

- the recursive resolver;
- the filtering policy engine;
- the client groups;
- the authoritative catalog's settings.

*Impact (High).* After every restart, which every update causes, each of
those ran on the file's values until the relevant setting was saved again
in the console. Affected settings include:

- recursion access, upstreams and resolution mode;
- conditional forwarders and client policies;
- the allowlist and blocklist, and the allowed and denied networks;
- the zone-transfer and dynamic-update settings.

The console showed the saved values throughout, so nothing looked wrong.

*Fix.* The overlay is applied (or seeded on first boot) as soon as the
database opens, before anything is built from the config.

*Test.* `console_settings_apply_after_a_restart` saves Recursion Access
"Everyone" and a blocklist entry, restarts on the same database and config
file, and checks that the resolver admits a public client and the entry is
blocked. It fails without the fix.

# Follow-up audit: the AI scanner

Scope:

- **Pipeline:** the background scanner, from query-log harvest through
  classification to the block snapshot.
- **Storage and enforcement:** the verdict store and the policy plugin.
- **Classifiers:** the heuristic, fastText and MiniLM/ONNX verifier
  backends.
- **Live settings:** how the console's changes reach the running engine.

Verification:

- fmt and clippy (`-D warnings`) are clean, and the full suite passes (507
  tests).
- New tests:
  - a rebuild keeps the policy plugins;
  - a disputed threat never blocks;
  - a weak verifier answer does not count;
  - an unqueried domain is dropped at expiry;
  - local and hosted names are not classified;
  - a panicking classifier worker does not shift verdicts.
- The MiniLM/ONNX feature cannot be built in this environment (its
  runtime download is blocked). The only change in code gated behind it is
  one argument passed to the verifier wrapper; CI builds it.

### AI1. Any filtering or network save switched AI blocking off - **Fixed** (High)

*Problem.* The AI auto-blocker is a policy-engine plugin, installed once at
startup. A policy rebuild kept the downloaded blocklists but dropped the
plugins. Rebuilds happen on every Filtering save, every network save and
every config reload.

*Impact.* After any of those, enforce mode silently stopped blocking until
the next restart, while the console still showed it enforcing.

*Fix.* A rebuild keeps the live engine's plugins, as it already kept its
source lists.

### AI2. The verifier could not veto a threat - **Fixed** (High)

*Problem.* When the MiniLM verifier disagreed with a threat verdict, the
verdict was relabelled from `threat` to `info`. Its category and confidence
were unchanged, and the block snapshot goes by category and confidence, so
a disputed phishing verdict at 0.99 still auto-blocked.

*Fix.*

- Such verdicts are now `disputed`, which the snapshot excludes.
- Disputed verdicts are re-checked on the threat schedule.
- The console marks them "Disputed".
- Verdicts stored by earlier versions are relabelled when the database is
  opened.

### AI3. The verifier's threshold was never applied - **Fixed** (Medium)

*Problem.* Neither `ai.verifier_threshold` nor the verifier's built-in
0.35 cosine threshold was used. The verifier answered with its nearest
category however weak the match. That noise:

- corroborated threats (raising their confidence); or
- disputed them (see AI2).

*Fix.* Verifier answers below `ai.verifier_threshold` count as no answer.
The verdict is then kept as the primary classifier made it, marked
"unverified".

### AI4. One failing classifier thread put verdicts on the wrong domains - **Fixed** (High)

*Problem.* With several workers, a worker that panicked returned no
results at all. The remaining verdicts were then paired with domains in
order, so every verdict after the gap landed on a different domain.

*Impact.* In enforce mode this could block domains whose own verdict was
harmless.

*Fix.* A failed worker yields "no verdict" for each of its domains, so the
results stay aligned. The failure is logged.

### AI5. Local and hosted names were classified, and could be blocked - **Fixed** (Medium)

*Problem.* Every query-log name was a candidate, including:

- single-label names such as `wpad` and printers;
- reverse lookups;
- `.local`, `.home.arpa` and other local-only names;
- names in zones this server hosts.

In enforce mode, a verdict on a hosted name blocked the operator's own
records, because policy runs before authoritative answers.

*Fix.* Only names with at least two labels are classified, outside the
special-use and local-only suffixes and outside hosted zones.

### AI6. Every domain ever queried was kept and re-classified forever - **Fixed** (Medium)

*Problem.* Rows were never removed. Each expired verdict went back in the
queue, even for a domain queried once months ago. The store grew without
bound and the classifier's work grew with it.

*Fix.*

- Rows now record when the domain was last seen.
- At expiry, a verdict is re-checked only if its domain has been queried
  since. Otherwise the row is dropped, and the domain starts over as new
  if it is queried again.
- Rows that existed before the upgrade get one more check.

### AI7. The harvest committed one row at a time - **Fixed** (Low, performance)

*Problem.* Each cycle recorded every queried domain with its own SELECT
and UPDATE or INSERT, each committed separately. Each cycle's verdicts
were also saved one commit per domain.

*Fix.* Both are single transactions. Measured on 20,000 names: 1.79 s
before, 75 ms after.

### AI8. Smaller issues - **Fixed** (Low)

- **Turning AI off.** The plugin stopped blocking, but the scanner kept
  harvesting and classifying until restart. It now idles while disabled.
- **Snapshot race.** A scan cycle could publish a block snapshot computed
  just before an operator override, undoing the override until the next
  cycle. Snapshot publication is now serialized.
- **Capitalised fastText labels.** A model labelled `__label__Malware`
  produced `info` verdicts, because threat labels were matched before
  lowercasing. They are now lowercased first.

## Reported, not changed

- **Subdomain coverage.** A verdict on a domain also blocks its subdomains,
  as designed. For shared-hosting parents (`*.github.io`-style names), a
  single verdict would block every tenant. A public-suffix check would
  catch this, but no suffix list ships today.
- **Startup-only changes.** Enabling AI on a server that started with it
  off, or changing the model or database path, still takes effect only
  after a restart. The console already says so.

# Follow-up audit: the AI console pages

Scope: the AI page, with its Scanner and Verdicts tabs, and the API
responses they use.

Verification:

- The pages were driven in Chromium against a running server in enforce
  mode, with real DNS traffic and a scan.
- Checked: both tabs, exempting a domain by pasting a URL, invalid input,
  and the scanner turned off at runtime.
- No console or page errors.

### G1. Controls hidden or refused depending on how roles were checked - **Fixed** (Medium)

*Problem.* The AI pages decided who is an administrator with
`role === 'admin'`, unlike the rest of the console, which treats every
non-viewer as one. Two problems followed:

- The model update controls disappeared for sessions without a stored role.
- The Scan Now, Exempt and Unexempt actions were shown to everyone and
  never checked the role at all, so a read-only account would have had
  them refused by the server.

*Fix.* Both pages follow the console's rule: viewers get a read-only page
without action buttons, and everyone else gets the full page.

### G2. A scanner turned off in Settings still looked active - **Fixed** (Medium)

*Problem.* Turning the AI off in Settings stops it at once, but the page
kept showing the mode as Enforce and the "Auto-Blocked Now" count.

*Fix.*

- A banner says the scanner is off.
- The mode reads "Off" and the counts read "Would Auto-Block".
- Scan Now is disabled.

### G3. Misleading "scanner is off" message - **Fixed** (Low)

*Problem.* When the scanner is turned on in Settings but the service has
not been restarted since, the page still said to turn it on.

*Fix.* The page now says it only needs a restart.

### G4. Exempting a domain - **Fixed** (Low)

*Problem.* A pasted URL (`https://www.example.com/page`), `*.example.com`
or `example.com:443` was rejected with "domain is required".

*Fix.*

- The form takes the domain out of what was pasted.
- Anything that is not a domain gets a clear message, and the API's own
  message for invalid domains says the same.

### G5. Verdict list - **Fixed** (Low)

- **Empty last page.** Paging past the end, which now happens as stale
  verdicts are dropped, showed "No verdicts yet". The list now moves to
  the last page instead.
- **Confidence.** "No signal" rows showed 0% confidence; they now show
  "-".
- **Seen column.** A new column shows how many scans found the domain in
  DNS traffic.
- **Re-Check column.** Its header explains what happens at expiry.
- **Disputed verdicts.** These are labelled "Disputed".

### G6. Smaller display issues - **Fixed** (Low)

- **Percentages.** They showed as "30.0%" and "99.0%" because the values
  arrive as 32-bit floats; they now read "30%" and "99%".
- **Spacing.** The Exempt tag touched the domain name.
- **Heuristic warning.** The "nothing can be auto-blocked" warning missed
  the heuristic rules running with the verifier.
- **Page text.** The header now says exempt domains are never blocked
  *by the AI*; blocklists still apply to them.
