# Daygle DNS

A modern DNS server written in Rust on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns) (the successor to
`trust-dns`). One process combines an authoritative server, a recursive
resolver, encrypted DNS, filtering, DHCP and a web console.

## Features

**Authoritative DNS**

- Zones stored in **SQLite**, with BIND zone-file import.
- **DNSSEC signing** (NSEC or NSEC3) with automatic key rollover and
  background RRSIG renewal, so signed zones never go bogus.
- **Zone transfers**: AXFR and real IXFR (RFC 5936, RFC 1995) with
  per-network ACLs, secondary zones pulled from masters, optionally over TLS
  (XoT, RFC 9103), **NOTIFY** (RFC 1996) and **catalog zones** (RFC 9432).
- **Dynamic updates** (RFC 2136), written through to SQLite, and **TSIG**
  (RFC 8945, HMAC-SHA256/384/512) for transfers and updates.
- **Health-checked failover** (TCP, HTTP or HTTPS checks) and **weighted
  load balancing** for A/AAAA records.
- **ALIAS (ANAME)** records at a zone apex, **AUTOPTR** records that answer
  every reverse lookup in a zone, and **zone aliases** (one zone served
  under several names).
- **Split horizon**: different answers per client network.

**Resolver**

- **Recursive resolution** from the root servers, or **forwarding** to
  upstreams, with **DNSSEC validation**, aggressive NSEC caching (RFC 8198)
  and an optional local root zone (RFC 8806).
- **Conditional forwarding** and **stub zones** for chosen domains.
- **Prefetch** of popular names, **serve-stale** during upstream outages,
  and an optional cache snapshot that survives restarts.
- **DNS64** (RFC 6147) and **EDNS Client Subnet** (RFC 7871) to forwarding
  upstreams.
- A **Lookup page** that resolves any name and shows every query sent on
  the way, with timings and the reason for a failure.

**Encrypted DNS**

- **DoT**, **DoH** (RFC 8484, HTTP/2 and optionally HTTP/3) and **DoQ**
  (RFC 9250), on rustls.
- **Let's Encrypt certificates** (ACME, HTTP or DNS challenge, wildcards
  included), or a private ACME CA such as step-ca.
- **DDR** (RFC 9462), so Windows 11, Apple and Android devices discover the
  encrypted listeners by themselves.
- **DNS accounts**: each device or person gets a client ID
  (`<id>.dns.example.com` for DoT/DoQ, `/dns-query/<id>` for DoH) and is
  recognised from any network.
- Certificate and handshake diagnostics in the Server Log.

**Filtering**

- **Blocklists** fetched over HTTP(S) on a schedule (hosts files, AdGuard
  lists, domain lists, RPZ), for everyone or for chosen filtering groups.
- **Response policy zones (RPZ)** with every action and trigger type, loaded
  by zone transfer, URL or typed in the console.
- **Filtering groups** and **resolution policies** per client: extra rules,
  **blocked services** (TikTok, YouTube, Roblox and 30-odd more), blocked
  categories, and security and privacy protections (newly registered
  domains, Google Safe Browsing, DNS rebinding, native trackers, and more).
- An **AI scanner** that categorizes visited domains and can block threats.
  It ships in safe train mode; see [`docs/AI.md`](docs/AI.md).
- **Why was it blocked?**: every blocked query names what blocked it, and
  Filtering → Domain Check walks a domain through every check.
- A **block page** that explains what was blocked and why.

**Protection**

- **Rate limiting** per client and per domain, **response rate limiting**
  (RRL) with slip, and **DNS cookies** (RFC 7873, RFC 9018).
- **Extended DNS Errors** (RFC 8914) that say why an answer was blocked,
  refused or stale.
- **PROXY protocol** (v1/v2) on TCP, DoT and DoH.

**Network services**

- **DHCP** (IPv4 and IPv6, Linux only) with reservations and custom
  options; leases are registered by name in a zone you host.
- **Device names** from the console, DHCP leases or reverse DNS, shown in
  logs and reports instead of IP addresses.
- **Named networks** (`LAN`, `VPN`, `IoT`...) defined once and used by every
  setting that takes client networks.

**Console and operations**

- A **web console** (Svelte) with admin and read-only viewer roles,
  two-factor login and personal API tokens, plus a **REST API** with an
  OpenAPI description.
- A **dashboard**, a searchable **query log** in SQLite, and **reports** by
  period or device, with a daily or weekly summary by email or webhook.
- **Prometheus metrics**, **syslog** (RFC 5424), **query export** over
  HTTP(S) (NDJSON or JSON) and **dnstap**.
- An **audit log** of every change and sign-in.
- **Backup and restore** of everything as one file, from the console or the
  command line.
- **Updates from the console** on systemd installs, with automatic rollback.

## Quick start

```bash
# One-line installer (Linux/macOS; auto-installs Rust, a C compiler, and git if missing)
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh

# ...or build and run directly from source (as root: the example config
# listens on port 53 and keeps its database under /var/lib/daygle-dns)
sudo cargo run --release -p daygle-dns -- --config daygle-dns.toml.example
```

On Linux the installer sets the server up as a systemd service. Without
systemd (macOS, for example) it builds and installs the binary and prints the
command to start it. It finishes by checking that the service is running and
printing the web console address (open it to create the admin account) and
the DNS server address to give your router or devices.

What the installer does:

- **Prerequisites**: installs Rust (rustup), a C compiler, git and curl
  (apt, dnf/yum, apk, pacman, zypper, or Xcode Command Line Tools on macOS),
  and `dig` where available.
- **Fresh install or upgrade**: an existing config, binary or systemd unit
  means an upgrade. The config and data are kept and the service is
  restarted; a fresh install writes the default config and starts it.
- **Web console on the LAN**: the API listener is bound to `0.0.0.0:5380` so
  the first-run page can create the admin account. On upgrades it is rebound
  from `127.0.0.1`; existing accounts and passwords are never replaced.
- **AI scanner**: installs the bundled starter model into
  `/etc/daygle-dns/models/` and turns the scanner on in train mode (nothing
  is blocked).
- **Port 53**: turns off systemd-resolved's stub listener
  (`/etc/systemd/resolved.conf.d/daygle-dns.conf`) and points
  `/etc/resolv.conf` at `/run/systemd/resolve/resolv.conf`, so the host keeps
  resolving. Any other program on port 53 (dnsmasq, bind9, unbound) is named
  in a warning.
- **Firewall**: when ufw or firewalld is active, opens ports 53, 853 and 5380
  to private networks only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  100.64.0.0/10, 169.254.0.0/16, fc00::/7, fe80::/10). Other firewalls are
  left to you.

Environment variables that change this:

| Variable | Effect |
|---|---|
| `DAYGLE_DNS_ADMIN_USER`, `DAYGLE_DNS_ADMIN_PASSWORD` | Create the admin account now (for scripted installs). |
| `DAYGLE_DNS_LAN_GUI=0` | Keep the web console on `127.0.0.1` (this also skips creating the admin account). |
| `DAYGLE_DNS_AI=0` | Leave the AI scanner off. |
| `DAYGLE_DNS_KEEP_RESOLVED=1` | Leave systemd-resolved alone. |
| `DAYGLE_DNS_NO_DEPS=1` | Do not install prerequisites; print instructions instead. |

Test a query:

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 -p 853 example.com A +tls   # DNS over TLS, once [dot] is enabled
```

## Command line

```bash
daygle-dns --config /etc/daygle-dns/daygle-dns.toml   # run the server (this path is the default)
daygle-dns backup <file> [--query-logs]   # back up zones, keys, settings, users, certificates
daygle-dns restore <file>                 # stage a backup for the next start
daygle-dns hash-password 'password'       # hash for an [[api.users]] entry
daygle-dns reset-web-access               # put the console back on plain HTTP on api.port
daygle-dns --version
```

Restart the service after `restore` or `reset-web-access`. The backup file
holds private keys and password hashes, so keep it safe.

## Workspace layout

| Crate | Purpose |
|---|---|
| `daygle-dns` | The server binary: UDP, TCP, DoT, DoH and DoQ listeners, the query dispatcher and the web console listeners |
| `daygle-dns-core` | Configuration model, shared error type, metrics, log store |
| `daygle-dns-policy` | Policy engine (blocklists, ACLs, per-client rules) |
| `daygle-dns-authoritative` | SQLite zone storage, zone-file parser, Hickory catalog and DNSSEC signing |
| `daygle-dns-recursive` | Recursive resolver (caching, retries, timeouts, DNSSEC validation) |
| `daygle-dns-dot` | TLS certificates and configuration for DoT, DoH and DoQ |
| `daygle-dns-api` | REST API (axum) and console serving |
| `daygle-dns-gui` | Embedded web console assets (Svelte build output) |
| `daygle-dns-ml` | AI scanner: verdict store, fastText/heuristic backends, AI policy plugin |
| `daygle-dns-dhcp` | DHCPv4 and DHCPv6 server with DNS registration of leases (Linux) |

[`models/`](models/README.md) holds the bundled AI starter model and its
training data, and [`vendor/`](vendor/README.md) holds patched copies of two
Hickory crates.

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the crates fit together, query flow, concurrency, DNSSEC |
| [`docs/API.md`](docs/API.md) | REST API reference (also served as OpenAPI 3 at `GET /api/openapi.json`) |
| [`docs/AI.md`](docs/AI.md) | The AI scanner: channels, models, retraining, page fetching |
| [`docs/UPDATE_ROLLBACK.md`](docs/UPDATE_ROLLBACK.md) | Rehearsing a console update and its rollback on a test VM |
| [`daygle-dns.toml.example`](daygle-dns.toml.example) | Every configuration option, commented |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability |

## Configuration

The server is configured via a TOML file (default
`/etc/daygle-dns/daygle-dns.toml`) **and** a SQLite database. The TOML file
is the bootstrap: it seeds runtime settings into the database on first boot,
then the database is authoritative for everything the console edits -
recursive settings, policy (allowlist, blocklist, blocklist sources), the
DoT/DoH/DoQ settings, authoritative settings, AI, logging, alerts and
the rest - and for console accounts. What a bad setting could lock you out
with stays file-owned, so it can always be fixed by hand: the listen
addresses, the plain-DNS port and transports, the database path, and the API
listener and its token.
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
# password_hash = "pbkdf2-sha256$600000$...$..."
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
# handshake_timeout_secs = 20   # TLS handshake bound
# idle_timeout_secs = 120       # read-inactivity timeout of a session,
#                               # advertised to clients in EDNS keepalive
# Clients outside these networks get REFUSED on the DoT listener; clients
# inside it may recurse there even when recursion_access is private_networks.
# Empty (default) serves everyone. Addresses, CIDRs or Settings->Network names.
# allowed_networks = ["192.168.0.0/16", "LAN"]

[doh]
enabled = false
port = 443
self_signed = true
endpoint = "/dns-query"
# allowed_networks = ["192.168.0.0/16"]   # as [dot]: empty serves everyone

[doq]
# DNS over QUIC (RFC 9250), default port 853/udp.
enabled = false
port = 853
self_signed = true
# allowed_networks = ["192.168.0.0/16"]   # as [dot]: empty serves everyone

# ── Policy: seeded like the rest; the console keeps the allowlist, ─────
# blocklist and blocklist sources in the database from then on.
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

With `server.reload_enabled = true` (the default), Daygle DNS polls the config
file (every `server.reload_interval_ms`, default 2000) and applies edits
**without restarting** - listener changes rebind the affected listeners in
place. Settings the database holds (see [Configuration](#configuration)) keep
their stored values; change those in the console or with `PUT /api/config`.
A bad config is rejected and the previous configuration stays active. You
can also trigger an immediate re-read with `POST /api/config` (see
[`docs/API.md`](docs/API.md)).

## Building the web GUI

The built GUI (`web/dist`) is committed and embedded in the binary, so the
workspace compiles without Node. After changing anything under `web/src`,
rebuild it and commit the result (CI fails when `web/dist` is stale):

```bash
cd web
npm ci
npm run build     # outputs to web/dist, embedded by daygle-dns-gui
cargo build --release -p daygle-dns
```

## Testing

```bash
cargo test --workspace
```

This runs the unit tests and integration tests that start a real server on
ephemeral ports and test it over the wire: authoritative and recursive
answers (with a local stub upstream, so no internet is needed), zone
transfers, dynamic updates and NOTIFY, filtering and RPZ, rate limiting,
live reload, console login and roles, DoT, DoH and DoQ, TSIG, DDR and more
(see `crates/daygle-dns/tests/`). The ACME tests run against Pebble, Let's
Encrypt's test CA, when `PEBBLE` and `PEBBLE_DIR` are set, and are skipped
otherwise.

## Upgrading

### Installer-based installs (systemd)

The one-line installer is **idempotent** - re-running it is the supported
upgrade path. It detects the existing installation, fetches the latest release,
rebuilds the binary, replaces `/usr/local/bin/daygle-dns`, preserves
`/etc/daygle-dns/daygle-dns.toml`, and restarts (or re-enables) the service:

```bash
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh
```

The installer never replaces an existing `/etc/daygle-dns/daygle-dns.toml`. It
only edits it to rebind the API listener to `0.0.0.0` while it is still on
`127.0.0.1`, to add an `[ai]` section (train mode) when there is none, and to
add an admin account when you pass `DAYGLE_DNS_ADMIN_USER` and
`DAYGLE_DNS_ADMIN_PASSWORD`. Your zones, certificates, and SQLite database
under `/var/lib/daygle-dns` are left untouched. Before upgrading, back up the
database just in case (or use `daygle-dns backup <file>`, which also
covers settings, users and certificates):

```bash
sudo cp /var/lib/daygle-dns/daygle.db /var/lib/daygle-dns/daygle.db.bak
```

Installations on systemd can also be upgraded **from the web console**: the
console's updater downloads and verifies a release into
`/var/lib/daygle-dns/updates`, stages the binary, then hands the privileged
swap, service restart, health-check, and rollback to a root systemd oneshot
(`daygle-dns-update.service`, provisioned by the installer). No sudo or
setuid for the service account. `GET /api/update/preflight` probes GitHub and
the staging directory beforehand. See
[`docs/UPDATE_ROLLBACK.md`](docs/UPDATE_ROLLBACK.md) for a disposable-VM
runbook covering both rollback branches, with the exact phases, log lines and
post-rollback checks.

### Source builds

If you cloned the repository, pull, rebuild, install the binary over the old
one, and restart:

```bash
git pull
cargo build --release -p daygle-dns
sudo install -m 0755 target/release/daygle-dns /usr/local/bin/daygle-dns
sudo systemctl restart daygle-dns   # systemd installs
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
