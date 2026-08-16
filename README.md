# Daygle DNS

A modern, combined DNS server written entirely in Rust and built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns) (the actively
maintained continuation of the `trust-dns` crates — `trust-dns-proto`,
`trust-dns-server`, and `trust-dns-resolver` were rebranded to `hickory-*` and
the old names are deprecated per RUSTSEC-2025-0017).

Daygle combines, in a single process:

- **Authoritative DNS** with zone storage backed by **SQLite**, BIND zone-file
  import, and **DNSSEC zone signing**.
- **Zone transfers**: serve **AXFR/IXFR** (RFC 5936, with per-network ACLs)
  and replicate **secondary zones** from remote masters on a refresh interval.
- **Dynamic updates**: RFC 2136 UPDATE messages with write-through to SQLite,
  prerequisite checking, and atomic apply — records added over the wire
  persist and go live immediately (gated by `allow_dynamic_updates`).
- **Recursive resolution** (root → TLD → authoritative) with **caching**,
  **negative caching**, **retries**, **timeouts**, and **DNSSEC validation**,
  plus **conditional forwarding** so specific zones resolve via dedicated
  upstreams.
- **DNS over TLS (DoT)** and **DNS over HTTPS (DoH, RFC 8484)** using
  **rustls**.
- A **plugin-style policy engine** for blocklists, ACLs, and per-client rules,
  including **remote blocklist sources** (hosts files, AdGuard lists, plain
  domain lists) fetched over HTTP(S) and refreshed on a schedule.
- **Rate limiting** per client (source IP) and per domain (query name) with
  configurable fixed windows, loopback exemption, and live reload — queries
  over the limit get SERVFAIL and are counted in the `rate_limited` metric.
- A **REST API** (tower/axum) for configuration, zone management, logs, and
  metrics.
- An embedded **Svelte** web GUI for zones, records, status, logs, and
  settings.

## Quick start

```bash
# One-line installer (Linux/macOS; requires Rust via https://rustup.rs)
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh

# …or build and run directly from source
cargo run --release -p daygle -- --config daygle.toml.example
```

Then open the dashboard at <http://127.0.0.1:5380>.

Test a query:

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 -p 853 example.com A +tls   # DNS over TLS
```

## Workspace layout

| Crate                   | Purpose |
|-------------------------|---------|
| `daygle-core`           | Configuration model, shared error type, metrics, log store |
| `daygle-policy`         | Plugin-style policy engine (blocklists, ACLs, per-client rules) |
| `daygle-authoritative`  | SQLite zone storage, zone-file parser, Hickory catalog + DNSSEC signing |
| `daygle-recursive`      | Recursive resolver (caching, negative caching, retries, timeouts, DNSSEC) |
| `daygle-dot`            | DoT (RFC 7858) + DoH (RFC 8484) via rustls + certificate management |
| `daygle-api`            | REST API (axum) + embedded GUI serving |
| `daygle-gui`            | Embedded web GUI assets (Svelte build output) |
| `daygle`                | The server binary: UDP/TCP/DoT listeners + the combined dispatcher |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit
together and [`docs/API.md`](docs/API.md) for the REST API reference.

## Configuration

The server is configured with a single TOML file (default
`/etc/daygle/daygle.toml`). A fully commented example lives in
[`daygle.toml.example`](daygle.toml.example).

```toml
[server]
port = 53

[recursive]
upstreams = ["1.1.1.1", "tls://8.8.8.8:853@dns.google"]
dnssec_validate = true
# Conditional forwarding: resolve corp.internal via the office DNS servers.
# [[recursive.conditional_zones]]
# name = "corp.internal"
# upstreams = ["192.0.2.10"]

[authoritative]
database = "/var/lib/daygle/daygle.db"

[dot]
port = 853
self_signed = true

[doh]
enabled = true
port = 443
self_signed = true
endpoint = "/dns-query"

[api]
port = 5380

[policy]
# Fetch a remote blocklist (hosts file) every 12 hours.
# [[policy.blocklist_sources]]
# name = "StevenBlack hosts"
# url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
# format = "hosts"
# refresh_secs = 43200
```

### Live reload

With `server.reload_enabled = true` (the default), Daygle polls the config
file (every `server.reload_interval_ms`, default 2000) and applies edits
**without restarting** — policy rules and blocklists, recursive upstreams, and
the UDP/TCP/DoT listeners all update in place. A bad config is rejected and
the previous configuration stays active. You can also trigger an immediate
re-read with `POST /api/config/reload` (see [`docs/API.md`](docs/API.md)).

## Building the web GUI

The workspace compiles out of the box with a minimal fallback dashboard. To
build the full Svelte GUI:

```bash
cd web
npm install
npm run build     # outputs to web/dist, embedded by daygle-gui
cargo build --release -p daygle
```

## Testing

```bash
cargo test --workspace
```

This runs unit tests for configuration, policy, zone storage/parsing, upstream
parsing, TLS certificates, and the GUI, plus integration tests that spin up a
real server on ephemeral ports and exercise:

- authoritative answers over **UDP** and **TCP**,
- **policy** blocking,
- **DNS over TLS** against a self-signed certificate,
- full **recursive** resolution through a local stub upstream (no internet
  required), and
- **live config reload** of policy, upstreams and listeners, both via the
  reload API and the file watcher.

## Upgrading

### Installer-based installs (systemd)

The one-line installer is **idempotent** — re-running it is the supported
upgrade path. It fetches the latest `main`, rebuilds the release binary,
replaces `/usr/local/bin/daygle`, and restarts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
```

The installer never overwrites an existing `/etc/daygle/daygle.toml`, and your
zones, certificates, and SQLite database under `/var/lib/daygle` are left
untouched. Before upgrading, back up the database just in case:

```bash
sudo cp /var/lib/daygle/daygle.db /var/lib/daygle/daygle.db.bak
```

### Source builds

If you cloned the repository, pull, rebuild, and restart:

```bash
git pull
cargo build --release -p daygle
sudo systemctl restart daygle   # systemd installs
# …or copy the binary over your existing one:
sudo install -m 0755 target/release/daygle /usr/local/bin/daygle
```

### After upgrading

- Confirm the new version with `daygle --version` (or check the dashboard's
  Status page).
- New configuration options appear in
  [`daygle.toml.example`](daygle.toml.example); existing settings are
  validated at startup, so an invalid config aborts cleanly instead of
  silently corrupting state.
- If you changed nothing about listeners, upstreams, or policy, your running
  config still applies — no restart is needed for `daygle.toml` edits thanks
  to [live reload](#live-reload). Only the binary itself requires the restart
  above.

## License

Apache-2.0.
