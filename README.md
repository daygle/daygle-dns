# Daygle DNS

A modern, combined DNS server written entirely in Rust and built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns) (the actively
maintained continuation of the `trust-dns` crates — `trust-dns-proto`,
`trust-dns-server`, and `trust-dns-resolver` were rebranded to `hickory-*` and
the old names are deprecated per RUSTSEC-2025-0017).

Daygle combines, in a single process:

- **Authoritative DNS** with zone storage backed by **SQLite**, BIND zone-file
  import, and **DNSSEC zone signing**.
- **Recursive resolution** (root → TLD → authoritative) with **caching**,
  **negative caching**, **retries**, **timeouts**, and **DNSSEC validation**.
- **DNS over TLS (DoT)** using **rustls**.
- A **plugin-style policy engine** for blocklists, ACLs, and per-client rules.
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
| `daygle-dot`            | DNS over TLS via rustls + certificate management |
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

[authoritative]
database = "/var/lib/daygle/daygle.db"

[dot]
port = 853
self_signed = true

[api]
port = 5380
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

## License

Apache-2.0.
