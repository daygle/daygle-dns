# Daygle DNS

A modern, combined DNS server written entirely in Rust and built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns) (the actively
maintained continuation of the `trust-dns` crates - `trust-dns-proto`,
`trust-dns-server`, and `trust-dns-resolver` were rebranded to `hickory-*` and
the old names are deprecated per RUSTSEC-2025-0017).

Daygle DNS combines, in a single process:

- **Authoritative DNS** with zone storage backed by **SQLite**, BIND zone-file
  import, and **DNSSEC zone signing** (NSEC or **NSEC3**) with **automatic key rollover** and
  **background RRSIG renewal**, so signed zones never go bogus after the
  signature window passes.
- **Health-checked failover**: A/AAAA records checked over TCP, HTTP or
  HTTPS are left out of answers while down, with backups by priority.
- **ALIAS (ANAME) records**: point a zone apex at another host name (a CDN or
  load balancer) and answer A/AAAA with that host's current addresses.
- **Weighted load balancing**: give A/AAAA records weights and each answer
  holds one address, picked in proportion to them (alongside failover).
- **Automatic PTR records**: an AUTOPTR record in a reverse zone answers every
  address without a PTR record with a name made from it
  (`ip-192-168-1-47.home.arpa`), so reverse lookups never come back empty.
- **Zone aliases**: serve a zone under other names too (`example.net` and
  `example.org` answering like `example.com`).
- **Zone transfers**: serve **AXFR/IXFR** (RFC 5936, with per-network ACLs)
  and replicate **secondary zones** from remote masters on a refresh interval.
- **Catalog zones (RFC 9432)**: publish a catalog of your zones so
  secondaries provision themselves, and follow other servers' catalogs to
  add and remove secondary zones automatically.
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
- **Named networks**: name a set of addresses once (`LAN`, `VPN`, `IoT`...)
  in Clients -> Networks and pick it wherever a setting takes client
  networks; changing it changes them all, renaming it keeps them pointing at
  it, and a network in use cannot be deleted.
- **Encrypted DNS discovery (DDR, RFC 9462)**: devices that support it
  (Windows 11, Apple, Android) learn of the DoH, DoT and DoQ listeners and
  switch to them by themselves.
- **Block page**: blocked sites can point at a page on this server that
  says what was blocked and why, instead of "site not found".
- **Reports**: queries, blocks, the busiest devices and the most asked and
  most blocked domains for any period (overall or per device) on the
  Reports page, and a daily or weekly summary by email or webhook.
- **Device names**: logs, reports and the dashboard show "Kids-iPad"
  instead of 192.168.1.47. Name devices under Clients → Devices, or let
  names come from DHCP leases and reverse DNS.
- **DHCP (IPv4 and IPv6)**: hand out addresses, gateway and DNS settings
  with reservations and custom options, and DHCPv6 addresses or DNS
  settings only (stateless); devices are registered by name (A/AAAA and
  PTR) in a zone you host. Linux only.
- **Why was it blocked?** Every blocked query in the Query Log says what
  blocked it (which blocklist, list entry, filtering group, blocked service,
  AI category or response policy zone), with a filter by it, and Filtering
  → Domain Check walks a domain through every check for a device and shows
  which one decides.
- **Blocked services**: block TikTok, YouTube, Roblox, Discord, ChatGPT and
  30-odd other apps for a filtering group with one tick each, or block a
  whole AI content category (gambling, adult, ads, ...) for that group.
- **Per-client rules** on the console's Clients page: **filtering groups**
  (extra allow/block rules, blocklists and AI auto-blocking for a set of
  clients) and **resolution policies** (forward some clients to their own
  upstreams, resolve them from the root servers, or refuse them).
- **Split horizon**: serve different answers for the same domain depending
  on the client's network (named networks like `LAN`/`VPN`/`IoT` or
  literal CIDRs), managed from the GUI - internal clients see internal
  answers (A, AAAA, MX, TXT, CNAME, SRV), everyone else gets the public view.
- **Recursive resolution** (root → TLD → authoritative) with **caching**,
  **negative caching**, **retries**, **timeouts**, and **DNSSEC validation**,
- **DNS64 (RFC 6147)** for IPv6-only networks behind NAT64: IPv4-only names
  get AAAA answers inside the gateway's prefix.
- **EDNS Client Subnet (RFC 7871)** to forwarding upstreams, so CDNs answer
  with servers near your clients.
- **PROXY protocol** (v1/v2) on TCP, DoT and DoH, so clients behind a load
  balancer keep their real address.
- **Conditional forwarding** so specific zones resolve via dedicated
  upstreams, plus **stub zones** that send queries straight to a zone's own
  nameservers (no root→TLD walk) - both matched by longest suffix.
- **DNS over TLS (DoT)**, **DNS over HTTPS (DoH, RFC 8484)** over HTTP/2
  and optionally **HTTP/3**, and **DNS over QUIC (DoQ, RFC 9250)** using
  **rustls**.
- **Encrypted-DNS diagnostics**: every DoT/DoH/DoQ listener start or reload
  reports its certificate's subject and expiry, warning when it is already
  expired or inside the ACME renewal window, and failed handshakes, dropped
  connections and rejected DoH requests (wrong endpoint path or content
  type) reach the console's Server Log and syslog as coalesced warnings
  with the client address and reason - tagged `tls`/`https`/`quic` like the
  query log, and counted per client so a loop of failures cannot flood the
  log.
- **DNS cookies** (RFC 7873, with RFC 9018 server cookies): clients that
  send a cookie get a server cookie back, and ones that prove their address
  with it get ten times the per-client rate limit, so spoofed floods cannot
  lock real clients out.
- **Extended DNS Errors** (RFC 8914): blocked, filtered, refused, stale and
  failed answers say why (`dig` shows it as `EDE: 15 (Blocked)` and so on),
  and every response to an EDNS client carries an OPT record.
- **Let's Encrypt certificates** (ACME): issued from the Certificates page
  and renewed automatically, proving control over HTTP (the web console) or
  DNS (a TXT record in a zone hosted here, so wildcards work too). A private
  ACME CA such as step-ca works as well.
- **Backup and restore** of everything the server keeps (zones, keys,
  settings, users, certificates) as one file, from the console or
  `daygle-dns backup` / `daygle-dns restore`.
- **Cache prefetch & serve-stale**: popular names are refreshed in the
  background as their TTLs near expiry, and the last-known-good answers keep
  being served during upstream outages (bounded staleness, e.g. 1 h).
  With `recursive.persist_cache` the cache is snapshotted on shutdown and
  reloaded on startup (remaining TTLs kept; expired and stale-past-window
  entries pruned), so a restart or reboot does not start with a cold cache.
- A **dashboard with charts & top-N tables**: per-minute query time-series
  (1 h / 6 h / 24 h windows), top clients, top domains, and top blocked
  domains - all bounded in memory.
- **Remote logging** to a syslog server (RFC 5424, UDP or TCP): the
  server log, and optionally a line per query.
- **Query export** over HTTP(S): every query as JSON (NDJSON or an array),
  batched to a log collector such as Vector, Fluent Bit, Logstash or Splunk
  HEC, with an optional Authorization header.
- An **audit log** of every change and sign-in, with who, how and from where.
- **Prometheus metrics** at `/api/metrics/prometheus`.
- A **searchable query log**: every served query is recorded into SQLite
  (client, name, type, transport, outcome, rcode, duration) with retention,
  and the console's **Logs → Query Log** tab filters, paginates, live-updates
  and CSV-exports the history.
- An **AI scanner** (`daygle-dns-ml`): a small CPU-only classifier
  ships with the install (a bundled fastText starter model under
  [`models/`](models/)) and runs in the background over domains observed in
  the query log. It works in two independent channels, each with its own
  model, confidence floor and verdict TTL: **categorization** labels sites
  (news, shopping, adult, ...) and never blocks, while **threat detection**
  looks only for the categories you list in `ai.auto_block_categories` and is
  the only channel that can auto-block fresh high-confidence verdicts. The
  two lists are separate on purpose: the AI → Classifications tab is the
  categorizer's growing list of visited domains (relabel any of them
  yourself), the AI → Threats tab is what the AI blocks, and blocking an
  ordinary category (gambling, ads, ...) is a per-filtering-group setting
  rather than a scanner decision. On by
  default after an install in **train mode** (records verdicts, nothing
  blocks) - flip `ai.mode` to `enforce` in the config or GUI when you are
  happy with the verdict log. Operator allowlist always wins, and expired
  verdicts re-enter the scan queue. Point `ai.model_path` at your own
  supervised fastText `.bin` (or empty it for the zero-model heuristic
  backend) to replace the starter model, and `ai.category_model_path` /
  `ai.threat_model_path` to give a channel its own model. Verdicts are
  visible via the REST API (`/api/ai/*`).
- A **REST API** (tower/axum) for configuration, zone management, logs, and
metrics.
- An embedded **Svelte** web GUI with **username/password login and roles**
  (`admin` = full access, `viewer` = read-only), optional **two-factor
  login** (authenticator app codes, recovery codes), sessions that survive
  restarts, **personal API tokens** for scripts, editable settings forms for
  server/recursive/DoT/DoH/DoQ/API, zones, records, split horizon, status,
  logs, and settings.
- A **plugin-style policy engine** for blocklists, ACLs, and per-client rules,
  including **remote blocklist sources** (hosts files, AdGuard lists, plain
  and wildcard domain lists, response policy zones) fetched over HTTP(S) and
  refreshed on a schedule. A source blocks for everyone or only for the
  filtering groups that select it.
- **Response policy zones (RPZ)**: DNS firewall feeds loaded by zone
  transfer (AXFR, with TSIG) or URL, or rules typed in the console, with
  every RPZ action (NXDOMAIN, NODATA, passthru, drop, TCP-only, local data
  and walled gardens), QNAME, client-IP, answer-IP, NSDNAME and NSIP triggers, per-zone
  policy overrides, a log-only mode and a tester.
- **Response rate limiting (RRL)**: identical UDP answers to one network
  are capped per second, with slip (truncated answers that send real
  clients to TCP), against reflection and amplification attacks.
- **Rate limiting** per client (source IP) and per domain (query name) with
  configurable fixed windows, loopback exemption, and live reload - queries
  over the limit get SERVFAIL and are counted in the `rate_limited` metric.


## Quick start

```bash
# One-line installer (Linux/macOS; auto-installs Rust, a C compiler, and git if missing)
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh

# ...or build and run directly from source
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

Port 53 must be free. On Ubuntu, Fedora and other systemd distributions,
systemd-resolved runs a stub resolver on 127.0.0.53:53 that would stop the
server starting, so the installer turns it off with
`/etc/systemd/resolved.conf.d/daygle-dns.conf` (`DNSStubListener=no`) and links
`/etc/resolv.conf` to `/run/systemd/resolve/resolv.conf`, the upstream servers
systemd-resolved already knows, so the host itself keeps resolving. Set
`DAYGLE_DNS_KEEP_RESOLVED=1` to leave systemd-resolved alone. Any other program
still on port 53 (dnsmasq, bind9, unbound) is named in a warning.

When ufw or firewalld is active, the installer opens ports 53, 853 (TCP and
UDP) and 5380 to private networks only: 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 100.64.0.0/10 (CGNAT, also used by Tailscale), 169.254.0.0/16
and the IPv6 local ranges fc00::/7 and fe80::/10. These are the same networks
Recursion Access → Private Networks Only trusts. Other firewalls are left to you.

The installer finishes by checking that the service is running and printing
the web console address (open it to create the admin account) and the DNS
server address to give your router or devices.

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

With `server.reload_enabled = true` (the default), Daygle DNS polls the config
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
- **rate limiting** per client and per domain, and **response rate
  limiting** (RRL) with slip,
- **response policy zones**: every action and trigger type, and zones
  loaded by zone transfer,
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
upgrade path. It detects the existing installation, fetches the latest release,
rebuilds the binary, replaces `/usr/local/bin/daygle-dns`, preserves
`/etc/daygle-dns/daygle-dns.toml`, and restarts (or re-enables) the service:

```bash
curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh
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
# ...or copy the binary over your existing one:
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
