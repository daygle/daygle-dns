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
  updates with HMAC-signed requests (HMAC-MD5, HMAC-SHA1, HMAC-SHA256,
  HMAC-SHA512). Per-zone key binding, signed responses, and request-MAC
  chaining.
- **Split horizon**: serve different answers for the same domain depending
  on the client's network (named client groups like `LAN`/`VPN`/`IoT` or
  literal CIDRs), managed from the GUI - internal clients see internal
  answers (A, AAAA, MX, TXT, CNAME, SRV), everyone else gets the public view.
- **Recursive resolution** (root → TLD → authoritative) with **caching**,
  **negative caching**, **retries**, **timeouts**, and **DNSSEC validation**,
  plus **conditional forwarding** so specific zones resolve via dedicated
  upstreams.
- **DNS over TLS (DoT)**, **DNS over HTTPS (DoH, RFC 8484)**, and
  **DNS over QUIC (DoQ, RFC 9250)** using **rustls**.
- **Cache prefetch & serve-stale**: popular names are refreshed in the
  background as their TTLs near expiry, and the last-known-good answers keep
  being served during upstream outages (bounded staleness, e.g. 1 h).
- A **dashboard with charts & top-N tables**: per-minute query time-series
  (1 h / 6 h / 24 h windows), top clients, top domains, and top blocked
  domains - all bounded in memory.
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

The installer provisions missing prerequisites itself: Rust via rustup; a C
compiler, git, and curl via your package manager (apt, dnf/yum, apk, pacman,
zypper, or Xcode Command Line Tools on macOS); DNS test tools (dig) where
available. Set `DAYGLE_NO_DEPS=1` to
skip the automatic installs and get manual instructions instead.

The installer automatically detects whether it is performing a fresh install
or upgrading an existing installation. It treats an existing configuration,
binary, or systemd unit as an upgrade, preserves the configuration and data,
and restarts an existing service (or enables it if an interrupted installation
left it stopped). Fresh installs create the default configuration and start the
service.

The installer also offers to expose the web GUI on your LAN when run
interactively (adds an admin login and binds the API to 0.0.0.0:5380); for
scripted installs use `DAYGLE_LAN_GUI=1` with `DAYGLE_ADMIN_USER` and
`DAYGLE_ADMIN_PASSWORD`. On upgrades, existing LAN binding and console
credentials are preserved automatically, and the existing admin password is
never replaced. Without either, fresh installs keep the GUI loopback-only for
security.

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
| `daygle-dns-api`            | REST API (axum) + embedded GUI serving |
| `daygle-dns-gui`            | Embedded web GUI assets (Svelte build output) |
| `daygle-dns`             | The server binary: UDP/TCP/DoT listeners + the combined dispatcher |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit
together and [`docs/API.md`](docs/API.md) for the REST API reference.

## Configuration

The server is configured with a single TOML file (default
`/etc/daygle-dns/daygle-dns.toml`). A fully commented example lives in
[`daygle-dns.toml.example`](daygle-dns.toml.example).

### TSIG authentication

Zone transfers (AXFR/IXFR) and RFC 2136 dynamic updates can be protected
with **TSIG** (RFC 8945). Define HMAC keys in the config and bind them to
specific zones:

```toml
[authoritative]
tsig_keys = [
  { name = "transfer-key", algorithm = "hmac-sha256", secret = "<base64>" },
]

[[authoritative.zones]]
name = "internal.example.com"
tsig_key = "transfer-key"
```

When a TSIG key is bound to a zone, unsigned transfer/update requests are
refused and all responses are signed. TSIG also covers secondaries pulling
from masters - see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

```toml
[server]
port = 53

[recursive]
upstreams = ["1.1.1.1", "tls://8.8.8.8:853@dns.google"]
dnssec_validate = true
# Keep popular answers fresh and survive upstream outages:
# prefetch_enabled = true      # refresh popular names before their TTL expires
# serve_stale_secs = 1800      # serve last-known-good answers for up to 30 min
#                              # when all upstreams are unreachable
# Conditional forwarding: resolve corp.internal via the office DNS servers.
# [[recursive.conditional_zones]]
# name = "corp.internal"
# upstreams = ["192.0.2.10"]

[authoritative]
database = "/var/lib/daygle-dns/daygle-dns.db"

[dot]
port = 853
self_signed = true

[doh]
enabled = true
port = 443
self_signed = true
endpoint = "/dns-query"

[doq]
# DNS over QUIC (RFC 9250), default port 853/udp.
enabled = true
port = 853
self_signed = true
server_name = "daygle.local"

[api]
port = 5380
# Console login with roles. Generate the hash first:
#   daygle-dns hash-password 'your-password'
# `viewer` accounts are read-only (403 on every mutation).
# [[api.users]]
# username = "admin"
# password_hash = "pbkdf2-sha256$210000$...$..."
# role = "admin"

[policy]
# Fetch a remote blocklist (hosts file) every 12 hours.
# [[policy.blocklist_sources]]
# name = "StevenBlack hosts"
# url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
# format = "hosts"
# refresh_secs = 43200
```

Sources are also manageable from the **Blocklists** page of the web console:
add, edit, remove and validate (including auto-detecting the format) without
touching the config file - saved changes are written back to
`daygle-dns.toml` and applied to the running server immediately.

### Live reload

With `server.reload_enabled = true` (the default), Daygle polls the config
file (every `server.reload_interval_ms`, default 2000) and applies edits
**without restarting** - policy rules and blocklists, recursive upstreams, and
the UDP/TCP/DoT listeners all update in place. A bad config is rejected and
the previous configuration stays active. You can also trigger an immediate
re-read with `POST /api/config/reload` (see [`docs/API.md`](docs/API.md)).

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
- **policy** blocking,
- **DNS over TLS** against a self-signed certificate,
- full **recursive** resolution through a local stub upstream (no internet
  required),
- **live config reload** of policy, upstreams and listeners, both via the
  reload API and the file watcher,
- **console login, roles and settings**: login flow, read-only `viewer`
  accounts (403 on mutations), secret redaction in `GET /api/config`,
  settings updates persisted to the config file, and the dashboard stats
  endpoint, and
- **DNS over QUIC** (RFC 9250) against the generated self-signed certificate,
- **TSIG** unit tests covering HMAC-SHA256 request/response round-trips
  with request-MAC chaining.

## Upgrading

### Installer-based installs (systemd)

The one-line installer is **idempotent** - re-running it is the supported
upgrade path. It detects the existing installation, fetches the latest `main`,
rebuilds the release binary, replaces `/usr/local/bin/daygle-dns`, preserves
`/etc/daygle-dns/daygle-dns.toml`, and restarts (or re-enables) the service:

```bash
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
```

The installer never overwrites an existing `/etc/daygle-dns/daygle-dns.toml`, and your
zones, certificates, and SQLite database under `/var/lib/daygle-dns` are left
untouched. Before upgrading, back up the database just in case:

```bash
sudo cp /var/lib/daygle-dns/daygle-dns.db /var/lib/daygle-dns/daygle-dns.db.bak
```

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
- If you changed nothing about listeners, upstreams, or policy, your running
  config still applies - no restart is needed for `daygle-dns.toml` edits thanks
  to [live reload](#live-reload). Only the binary itself requires the restart
  above.

## License

Apache-2.0.
