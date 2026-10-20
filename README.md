# Daygle DNS

A modern, combined DNS server written entirely in Rust and built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns) (the actively
maintained continuation of the `trust-dns` crates - `trust-dns-proto`,
`trust-dns-server`, and `trust-dns-resolver` were rebranded to `hickory-*` and
the old names are deprecated per RUSTSEC-2025-0017).

Daygle combines, in a single process:

- **Authoritative DNS** with zone storage backed by **SQLite**, BIND zone-file
  import, and **DNSSEC zone signing** with **automatic key rollover** and
  **background RRSIG renewal**, so signed zones never go bogus after the
  signature window passes.
- **Zone transfers**: serve **AXFR/IXFR** (RFC 5936, with per-network ACLs)
  and replicate **secondary zones** from remote masters on a refresh interval.
- **NOTIFY (RFC 1996)**: primary zones send NOTIFY to configured secondaries
  when they change (e.g. after a dynamic update), and secondary zones accept
  NOTIFYs from their masters to pull immediately instead of waiting out the
  refresh interval.
- **Dynamic updates**: RFC 2136 UPDATE messages with write-through to SQLite,
  prerequisite checking, and atomic apply - records added over the wire
  persist and go live immediately (gated by `allow_dynamic_updates`).
- **TSIG authentication** (RFC 8945): protect zone transfers and dynamic
  updates with HMAC-signed requests (HMAC-SHA256, HMAC-SHA384,
  HMAC-SHA512). Per-zone key binding, signed responses, and request-MAC
  chaining.
- **Split horizon**: serve different answers for the same domain depending
  on the client's network (named client groups like `LAN`/`VPN`/`IoT` or
  literal CIDRs), managed from the GUI - internal clients see internal
  answers (A, AAAA, MX, TXT, CNAME, SRV), everyone else gets the public view.
- **Recursive resolution** (root → TLD → authoritative) with **caching**,
  **negative caching**, **retries**, **timeouts**, and **DNSSEC validation**,
- **Conditional forwarding** so specific zones resolve via dedicated
  upstreams, plus **stub zones** that send queries straight to a zone's own
  nameservers (no root→TLD walk) - both matched by longest suffix.
- **DNS over TLS (DoT)**, **DNS over HTTPS (DoH, RFC 8484)**, and
  **DNS over QUIC (DoQ, RFC 9250)** using **rustls**.
- **Cache prefetch & serve-stale**: popular names are refreshed in the
  background as their TTLs near expiry, and the last-known-good answers keep
  being served during upstream outages (bounded staleness, e.g. 1 h).
- A **dashboard with charts & top-N tables**: per-minute query time-series
  (1 h / 6 h / 24 h windows), top clients, top domains, and top blocked
  domains - all bounded in memory.
- A **searchable query log**: every served query is recorded into SQLite
  (client, name, type, transport, outcome, rcode, duration) with retention,
  and the console's **Logs → Query Log** tab filters, paginates, live-updates
  and CSV-exports the history.
- An **AI scanner** (`daygle-dns-ml`): a small CPU-only classifier
  ships with the install (a bundled fastText starter model under
  [`models/`](models/)) and runs in the background over domains observed in
  the query log, assigns categories (malware, phishing, adult, ...) with
  confidence scores and expiry dates, and can auto-block fresh
  high-confidence threat verdicts. On by default after an install in
  **train mode** (records verdicts, nothing blocks) - flip `ai.mode` to
  `enforce` in the config or GUI when you are happy with the verdict log.
  Operator allowlist always wins, and expired verdicts re-enter the scan
  queue. Point `ai.model_path` at your own supervised fastText `.bin`
  (or empty it for the zero-model heuristic backend) to replace the
  starter model. Verdicts are visible via the REST API (`/api/ai/*`).
- A **REST API** (tower/axum) for configuration, zone management, logs, and
metrics.
- An embedded **Svelte** web GUI with **username/password login and roles**
  (`admin` = full access, `viewer` = read-only), editable settings forms for
  server/recursive/DoT/DoH/DoQ/API, zones, records, split horizon, status,
  logs, and settings.
- A **plugin-style policy engine** for blocklists, ACLs, and per-client rules,
  including **remote blocklist sources** (hosts files, AdGuard lists, plain
  domain lists) fetched over HTTP(S) and refreshed on a schedule.
- **Rate limiting** per client (source IP) and per domain (query name) with
  configurable fixed windows, loopback exemption, and live reload - queries
  over the limit get SERVFAIL and are counted in the `rate_limited` metric.


## Quick start

```bash
# One-line installer (Linux/macOS; auto-installs Rust, a C compiler, and git if missing)
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh

# …or build and run directly from source
cargo run --release -p daygle-dns -- --config daygle-dns.toml.example
```

The installer also drops the bundled AI starter model into
`/etc/daygle-dns/models/` (or your `CONFIG_DIR/models`) and enables the AI
scanner in safe train mode; set `DAYGLE_DNS_AI=0` to keep the scanner off.

The installer provisions missing prerequisites itself: Rust via rustup; a C
compiler, git, and curl via your package manager (apt, dnf/yum, apk, pacman,
zypper, or Xcode Command Line Tools on macOS); DNS test tools (dig) where
available. Set `DAYGLE_DNS_NO_DEPS=1` to skip the automatic installs and get
manual instructions instead.

The installer automatically detects whether it is performing a fresh install
or upgrading an existing installation. It treats an existing configuration,
binary, or systemd unit as an upgrade, preserves the configuration and data,
and restarts an existing service (or enables it if an interrupted installation
left it stopped). Fresh installs create the default configuration and start the
service.

The web GUI is exposed on the LAN by default (the API listener is rebound to
0.0.0.0:5380) so the first-run setup page can create the admin account in the
browser; opt out with `DAYGLE_DNS_LAN_GUI=0`. For scripted installs pass
`DAYGLE_DNS_ADMIN_USER` and `DAYGLE_DNS_ADMIN_PASSWORD` to create the admin
account immediately. On upgrades the installer rebinds the API listener to
0.0.0.0:5380 when it is still on 127.0.0.1 and preserves any existing console
account (its password is never replaced).

Then open the dashboard at <http://127.0.0.1:5380>.

Test a query:

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 -p 853 example.com A +tls   # DNS over TLS
```

## Workspace layout

| Crate                   | Purpose |
|-------------------------|---------|
| `daygle-dns-core`           | Configuration model, shared error type, metrics, log store |
| `daygle-dns-policy`         | Plugin-style policy engine (blocklists, ACLs, per-client rules) |
| `daygle-dns-authoritative`  | SQLite zone storage, zone-file parser, Hickory catalog + DNSSEC signing |
| `daygle-dns-recursive`      | Recursive resolver (caching, negative caching, retries, timeouts, DNSSEC) |
| `daygle-dns-dot`            | DoT (RFC 7858) + DoH (RFC 8484) + DoQ (RFC 9250) TLS certificates |
| `daygle-dns-ml`            | AI domain scanner: verdict store, fastText/heuristic backends, AI policy plugin |
| [`models/`](models/)                       | Bundled AI starter model + training data (used out of the box) |
| `daygle-dns-api`           | REST API (axum) + embedded GUI serving |
| `daygle-dns-gui`            | Embedded web GUI assets (Svelte build output) |
| `daygle-dns`             | The server binary: UDP/TCP/DoT listeners + the combined dispatcher |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit
together and [`docs/API.md`](docs/API.md) for the REST API reference.

## Configuration

The server is configured via a TOML file (default
`/etc/daygle-dns/daygle-dns.toml`) **and** a SQLite database. The TOML file
is the bootstrap: it seeds runtime settings into the database on first boot,
then the database is authoritative for recursive settings, policy
(allowlist/blocklist), DoT/DoH/DoQ, and console accounts. Listener addresses,
`[authoritative]`, and `[api]` remain file-owned so a broken config can always
be fixed by hand.
A fully commented example lives in
[`daygle-dns.toml.example`](daygle-dns.toml.example).
The skeleton, with the live values that matter most:

```toml
# ── File-owned: bootstrap values and listeners ──────────────────────
[server]
port = 53

[api]
port = 5380
# Console login is ON by default: the first GUI visit asks you to create the
# admin account, and every API call needs a session afterwards. Set
# auth_required = false to serve the console open (development only).
# Accounts are stored in the database and managed from the console's Users
# page. Optional config seed entries (roles: admin, or read-only viewer) -
# hash first with:  daygle-dns hash-password 'your-password'
# [[api.users]]
# username = "admin"
# password_hash = "pbkdf2-sha256$210000$...$..."
# role = "admin"

[authoritative]
database = "/var/lib/daygle-dns/daygle.db"

# ── DB-seeded: these values seed the database on first boot ──────────
# After that, changes made in the GUI or via PUT /api/config are
# authoritative and survive restarts and config-file edits.
[recursive]
# "recursive" (default when no upstreams are listed) resolves from the root
# servers itself; "forwarding" sends queries to `upstreams`, or /etc/resolv.conf
# when the list is empty and use_system_config = true.
mode = "recursive"
# Only private networks may use recursion by default (not an open resolver).
recursion_access = "private_networks"
# Local root zone (RFC 8806): answer root queries from a verified local copy.
# local_root = { enabled = true }
upstreams = []
use_system_config = true
dnssec_validate = true
# prefetch_enabled = true      # refresh popular names before their TTL expires
# serve_stale_secs = 86400     # serve last-known-good answers for up to 24 h
#                              # when all upstreams are unreachable
# Conditional forwarding: resolve corp.internal via the office DNS servers.
# [[recursive.conditional_zones]]
# name = "corp.internal"
# upstreams = [ "192.0.2.10", "tls://192.0.2.10:853@ns.corp.example" ]

[dot]
enabled = false
port = 853
self_signed = true

[doh]
enabled = false
port = 443
self_signed = true
endpoint = "/dns-query"

[doq]
# DNS over QUIC (RFC 9250), default port 853/udp.
enabled = false
port = 853
self_signed = true

# ── Policy: blocklist_sources are file-owned (via file watcher), ─────
# allowlist/blocklist are DB-backed (GUI or PUT /api/config).
[policy]
# Fetch a remote blocklist (hosts file) every 12 hours.
# [[policy.blocklist_sources]]
# name = "StevenBlack hosts"
# url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
# format = "hosts"
# refresh_secs = 43200
```

Sources are also manageable from the **Filtering → Blocklists** tab of the web console:
add, edit, remove and validate (including auto-detecting the format) without
touching the config file - saved changes are stored in the SQLite database
and applied to the running server immediately (the config file is no longer
rewritten).

### TSIG authentication

Zone transfers (AXFR/IXFR) and RFC 2136 dynamic updates can be protected
with **TSIG** (RFC 8945). Define HMAC keys in the config and bind them to
specific zones:

```toml
[authoritative]
tsig_keys = [
  { name = "transfer-key", algorithm = "hmac-sha256", secret = "<base64>" },
]
tsig_transfer_zones = ["internal.example.com=transfer-key"]
```

When a TSIG key is bound to a zone, unsigned transfer/update requests are
refused and all responses are signed. TSIG also covers secondaries pulling
from masters - see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

### Live reload

With `server.reload_enabled = true` (the default), Daygle polls the config
file (every `server.reload_interval_ms`, default 2000) and applies edits
**without restarting** - the UDP/TCP listener settings update in place.
A bad config is rejected and the previous configuration stays active. You
can also trigger an immediate re-read with `POST /api/config` (see
[`docs/API.md`](docs/API.md)).

## Building the web GUI

The workspace compiles out of the box with a minimal fallback dashboard. To
build the full Svelte GUI:

```bash
cd web
npm install
npm run build     # outputs to web/dist, embedded by daygle-dns-gui
cargo build --release -p daygle-dns
```

## Testing

```bash
cargo test --workspace
```

This runs unit tests for configuration, policy, zone storage/parsing, upstream
parsing, TLS certificates, and the GUI, plus integration tests that spin up a
real server on ephemeral ports and exercise:

- authoritative answers over **UDP** and **TCP**,
- **split-horizon** synthetic answers per client network,
- **policy** blocking and **remote blocklist sources**,
- full **recursive** resolution through a local stub upstream (no internet
  required) and **conditional forwarding**,
- **zone transfers** (AXFR/IXFR) and secondary-zone replication,
- **RFC 2136 dynamic updates** and **NOTIFY** propagation,
- **query logging** into SQLite and the console's query-log filters,
- **rate limiting** per client and per domain,
- **live config reload** of policy, upstreams and listeners, both via the
  reload API and the file watcher,
- **console login, roles and settings**: login flow, read-only `viewer`
  accounts (403 on mutations), secret redaction in `GET /api/config`,
  settings updates persisted to the database (the config file seeds the
  first boot), and the dashboard stats endpoint,
- **DNS over TLS** and **DNS over HTTPS** against a self-signed certificate,
- **DNS over QUIC** (RFC 9250) against the generated self-signed certificate,
- **TSIG** covering HMAC-SHA256 request/response round-trips with
  request-MAC chaining.

## Upgrading

### Installer-based installs (systemd)

The one-line installer is **idempotent** - re-running it is the supported
upgrade path. It detects the existing installation, fetches the latest `main`,
rebuilds the release binary, replaces `/usr/local/bin/daygle-dns`, preserves
`/etc/daygle-dns/daygle-dns.toml`, and restarts (or re-enables) the service:

```bash
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
```

The installer never overwrites an existing `/etc/daygle-dns/daygle-dns.toml`,
and your zones, certificates, and SQLite database under `/var/lib/daygle-dns`
are left untouched. Before upgrading, back up the database just in case:

```bash
sudo cp /var/lib/daygle-dns/daygle.db /var/lib/daygle-dns/daygle.db.bak
```

Installations on systemd can also be upgraded **from the web console**: the
console's updater downloads and verifies a release into
`/var/lib/daygle-dns/updates`, stages the binary, then hands the privileged
swap, service restart, health-check, and rollback to a root systemd oneshot
(`daygle-dns-update.service`, provisioned by the installer). No sudo or
setuid for the service account. `GET /api/update/preflight` probes GitHub and
the staging directory beforehand.

### Source builds

If you cloned the repository, pull, rebuild, and restart:

```bash
git pull
cargo build --release -p daygle-dns
sudo systemctl restart daygle-dns   # systemd installs
# …or copy the binary over your existing one:
sudo install -m 0755 target/release/daygle-dns /usr/local/bin/daygle-dns
```

### After upgrading

- Confirm the new version with `daygle-dns --version` (or check the dashboard's
  Status page).
- New configuration options appear in
  [`daygle-dns.toml.example`](daygle-dns.toml.example); existing settings are
  validated at startup, so an invalid config aborts cleanly instead of
  silently corrupting state.
- If you changed nothing about listeners, your running config still applies -
  runtime settings live in the [database](#configuration) and are preserved
  across restarts. Only the binary itself requires the restart above.

## License

Apache-2.0.
