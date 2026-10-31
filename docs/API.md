# Daygle DNS REST API

Base path: `/api`. The web GUI is served at `/`.

## Authentication

Console authentication is **on by default** (`api.auth_required = true`): every
API call (reads included) requires a login session. On first run - with no
accounts configured yet - the GUI shows a one-time setup that creates the
initial admin account (see `POST /api/auth/setup` below). Set
`api.auth_required = false` to serve the console fully open (development
only).

Legacy alternative: when `api.api_token` is configured (and no users exist),
every mutating request (anything other than `GET`/`OPTIONS`) must include the
header:

```
Authorization: Bearer <token>
```

Missing or invalid tokens receive `401 Unauthorized`.

### Console users and roles

When `[[api.users]]` accounts are configured, the whole API (reads included)
requires a **login session**. Log in with:

```
POST /api/auth/login
{ "username": "admin", "password": "secret" }
```

```json
{
  "token": "1f2e3d4c5b6a7988...",
  "username": "admin",
  "role": "admin",
  "expires_in_secs": 43200
}
```

Send the returned token as the `Authorization: Bearer` header on every call.
Sessions are kept in the database (only a hash of each token), so they
survive a restart until they expire (`api.session_ttl_secs`) or sign out.

**Personal API tokens.** For scripts, each account can make long-lived
tokens (`dgl_...`) from **API Tokens** below its name in the sidebar, or with
the endpoints below. A token acts as its account (or as a viewer when made
read-only, and always for a viewer account), works until it expires or is
revoked, and skips two-factor login. Only its hash is stored; the token is
shown once. A token cannot manage tokens, two-factor login or the
password: those need a login session. Disabling or deleting the account
stops its tokens.
Password hashes for the config file are generated with
`daygle-dns hash-password 'your-password'` (PBKDF2-HMAC-SHA256).

**Where accounts live.** Console accounts are stored in the SQLite database
(`authoritative.database`) and managed at runtime from the console's **Users**
page (or the `/api/users` endpoints below). `[[api.users]]` entries in the
config file act as a seed: they are imported at startup unless a user with
the same name already exists, so config-managed accounts keep working while
accounts created in the GUI survive config rewrites.

Additional endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/auth/me` | identity of the presented session or API token (`username`, `role`, `expires_at_secs`, `api_token`), the account's own date/time `preferences` and the server's `display_defaults` |
| `PUT /api/auth/preferences` | signed-in user sets their own `{time_zone, date_format, time_format, theme}`; an empty field means the server default (viewers may use it too) |
| `GET /api/auth/columns` | the signed-in user's hidden table columns: `{"columns": {"<table>": ["<column>", ...]}}` |
| `PUT /api/auth/columns` | signed-in user hides columns of one table: `{"table": "query-log", "hidden": ["took"]}` (an empty list shows them all again); names are lowercase letters, digits, `-` and `_`, at most 50 columns and 100 tables (viewers may use it too) |
| `POST /api/auth/logout` | revoke the presented token |
| `POST /api/auth/password` | signed-in user rotates their own password (current password required; other sessions revoked) |
| `GET /api/auth/tokens` | the signed-in account's API tokens (`id`, `name`, `read_only`, `created_at`, `last_used_at`, `expires_at`; UNIX seconds, 0 = never) |
| `POST /api/auth/tokens` | `{name, read_only, expires_in_days}` (0 or absent: never expires): make an API token; the response's `token` is shown only now. At most 50 per account |
| `DELETE /api/auth/tokens/{id}` | revoke one of the signed-in account's tokens |
| `GET /api/auth/two-factor` | whether the signed-in account uses two-factor login (`enabled`) and its `recovery_codes_left` |
| `POST /api/auth/two-factor/setup` | `{password}`: start setting up two-factor login; returns a new `secret` and its `otpauth://` `uri` (for a QR code). Nothing changes until `/enable` |
| `POST /api/auth/two-factor/enable` | `{code}` from the app: turn two-factor login on; returns 10 `recovery_codes`, shown only now. Other sessions are signed out |
| `POST /api/auth/two-factor/recovery-codes` | `{password}`: replace the recovery codes |
| `POST /api/auth/two-factor/disable` | `{password}`: turn two-factor login off |
| `GET /api/auth/setup` | whether the one-time first-run setup is still pending |
| `POST /api/auth/setup` | one-time creation of the first admin account (returns a session); body: `{ "username", "password" }` plus optional `name` (first/last display name), `email` |
| `GET /api/users` | list accounts (password hashes redacted) |
| `POST /api/users` | create an account (`username`, `password`, optional `role`) |
| `PATCH /api/users/{username}` | reset password / change role / enable-disable |
| `DELETE /api/users/{username}` | delete an account |
| `DELETE /api/users/{username}/two-factor` | turn off two-factor login for an account that lost its app and recovery codes (signs its sessions out) |

**Two-factor login.** An account with two-factor login on needs a code as
well as its password. `POST /api/auth/login` without one answers `401` with
`"two_factor": true`; send the same body again with `"code"`: the 6-digit
code from the authenticator app (TOTP, RFC 6238: SHA-1, 30-second steps, one
step of clock drift allowed) or one of the recovery codes (`xxxx-xxxx`, case
and dashes ignored). Each code works once. A wrong code counts as a failed
login for the throttle below, which is only reset once both steps pass. Each
account sets up its own two-factor login, viewers included; the setup,
recovery-code and disable calls ask for the password again. The users list
shows `two_factor` for each account.

The last enabled `admin` account cannot be deleted, demoted, or disabled. The initial admin account may be created with an optional display name (`name`, stored as `first_name`/`last_name`) and `email`; these follow the same profile fields as accounts created through `POST /api/users` and can be edited later.

Password, role, and enabled changes (and deletions) immediately revoke the
affected account's sessions; disabled accounts cannot log in.

Roles:

- `admin` - full access (reads *and* mutations).
- `viewer` - read-only; every mutating method (`POST`/`PUT`/`PATCH`/`DELETE`)
  is rejected with `403 Forbidden`. The two `GET`s that make the server reach
  out - `/api/policy/blocklist/sources/validate` (fetches the given URL) and
  `/api/update/preflight` (probes GitHub and the staging directory) - are
  treated like mutations: admin role (or the static `api_token`) only.

Sensitive values are never echoed back: `GET /api/config` and the
configuration returned by `PUT /api/config` report `api.api_token`, every
`api.users[].password_hash` and every `authoritative.tsig_keys[].secret` as
`"[redacted]"`. Failed login attempts are logged and do not reveal whether the
username exists. After 10 failed logins from one client address within
5 minutes, further `POST /api/auth/login` attempts from it get
`429 Too Many Requests` (with `Retry-After`) until the window lapses; a
successful login resets the count. Passwords are limited to 8-1024 characters.

`api.cors_origins` lists browser origins (e.g. `https://ops.example`, or `*`)
allowed to call the API cross-origin; it is read live, so a console edit
applies immediately. Empty (the default) means same-origin only. Every
response carries `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
and `Referrer-Policy: same-origin`.

## Endpoints

### Health

```
GET /api/health
```

```json
{
  "status": "ok",
  "version": "1.0.0",
  "console_build": "index-abc123"
}
```

Public liveness endpoint, exempt from authentication (the in-place updater
uses it to verify a restarted service is serving HTTP without carrying
credentials); it exposes no configuration or zone data. `console_build` is
the entry bundle embedded in this build's console (`null` when unparseable):
the console compares it with the bundle it is running and offers a reload
when the server was updated while a page stayed open.

### Status

```
GET /api/status
```

```json
{
  "version": "1.0.0",
  "uptime_secs": 123,
  "zones": 2,
  "records": 17,
  "recursion": true,
  "resolution_mode": "recursive",
  "recursion_access": "private_networks",
  "local_root": false,
  "dnssec": true,
  "dot_enabled": true,
  "doh_enabled": false,
  "doq_enabled": false,
  "api_enabled": true,
  "update_available": true,
  "latest_release": "1.0.2"
}
```

`update_available` (whether the running binary is older than the latest
published release) and `latest_release` are compared against GitHub; both
are `null` on hosts that cannot self-update (dev installs, non-Linux) or
while update checks are disabled under `[updates]` (the Update page's
"Update Checks"), so the dashboard hides the update banner there. The
release lookup is a pure cached read - only a background task probes
GitHub, at the configured `[updates].check_interval_secs` cadence (default
hourly, minimum 10 minutes to respect GitHub's unauthenticated rate
budget) - so status polls never wait on the network.

### Metrics

```
GET /api/metrics
```

Returns a flat snapshot of the atomic counters:

```json
{
  "total_queries": 1024,
  "authoritative": 300,
  "recursive": 700,
  "cache_hits": 0,
  "cache_misses": 700,
  "blocked": 12,
  "split_horizon": 4,
  "rate_limited": 3,
  "errors": 0,
  "rrl_dropped": 0,
  "rrl_slipped": 0,
  "rrl_would_limit": 0,
  "rpz_hits": 7,
  "dnssec_validated": 500,
  "bytes_in": 45056,
  "bytes_out": 0
}
```

```
GET /api/metrics/prometheus
```

`rrl_dropped` and `rrl_slipped` count UDP responses dropped or sent
truncated by response rate limiting, `rrl_would_limit` those it would have
limited in log-only mode, and `rpz_hits` the queries a response policy zone
acted on.

The same counters, plus the resolver's routes, outcomes, upstream
connections and lookup-time histogram, and `uptime_seconds` and `zones`
gauges, in the Prometheus text format (`text/plain; version=0.0.4`), every
name prefixed `daygle_dns_`. It needs the same authorization as the rest of
the API; give Prometheus a read-only personal API token:

```yaml
scrape_configs:
  - job_name: daygle-dns
    metrics_path: /api/metrics/prometheus
    authorization:
      credentials: dgl_...
    static_configs:
      - targets: ["dns.example.com:5380"]
```

### Dashboard statistics

```
GET /api/stats?window=1h
```

Time-series and top-N tables powering the dashboard. `window` is `1h`
(default), `6h` or `24h`:

```json
{
  "window": 60,
  "series": [
    {
      "t": 1756000000,
      "queries": 42,
      "authoritative": 10,
      "recursive": 30,
      "blocked": 2,
      "errors": 0,
      "rate_limited": 0
    }
  ],
  "top_clients":  [{ "key": "192.168.20.5", "count": 941 }],
  "top_domains":  [{ "key": "example.com", "count": 412 }],
  "top_blocked":  [{ "key": "ads.example.com", "count": 87 }]
}
```

`series` holds one point per minute (gaps zero-filled) over the requested
window; the top lists are ranked by query count. All statistics live in a
bounded in-memory ring (24 h of minute buckets, ≤ 5 000 keys per table) and
reset on restart.

### Logs

```
GET /api/logs?limit=200
```

Returns the most recent `limit` (≤ 10 000) log entries, oldest first:

```json
[
  {
    "timestamp": "2026-08-15T12:00:00Z",
    "level": "info",
    "component": "authoritative",
    "message": "zone example.com signed with DNSSEC"
  }
]
```

Encrypted-DNS entries tag `component` with the query log's protocol values
(`tls`, `https`, `quic`): certificate lifecycle reports on every listener
start or reload (subject, expiry, renewal window), a `TLS configuration
reloaded` line after a rebuild, and coalesced `session failure` warnings for
failed handshakes, dropped connections and rejected DoH requests - at most
one warning per client per protocol per minute, with the client address and
the reason. Addresses name the real client (behind a PROXY-protocol load
balancer too); a DoT session closed for read inactivity past its handshake
timeout (also the session's read timeout) is normal keep-alive expiry and is
not logged as a failure. DoT also warns at start when a listener open to
every client has a certificate public clients such as Android Private DNS
refuse (self-signed, or without its intermediates), and notes when clients
outside `recursion_access` would be refused recursion on it.

### Query logs

```
GET    /api/querylogs?client=&qname=&qtype=&protocol=&outcome=&rcode=&block_source=&from=&to=&page=1&per_page=50
GET    /api/querylogs/stats
DELETE /api/querylogs
```

Every served DNS query is recorded into the SQLite database (when
`logging.query_db_enabled`, on by default) with its client address, query
name/type, transport (`udp`, `tcp`, `tls`, `https`, `quic`), outcome
(`authoritative`, `recursive`, `split_horizon`, `blocked`, `rate_limited`,
`error`), response code and server-side handling time. The console's
**Logs → Query Log** tab searches this history.

A blocked query also keeps why it was blocked, as `block`:
`{"source", "group", "matched", "reason"}` (`null` for queries that were
not blocked, and for blocks logged before reasons were kept). `source`
says what blocked it: `blocklist` (the server's own Custom Block list),
`blocklist_source` (a feed configured under Blocklists that applies to
everyone or to the DoT listener; `matched` is its name), `group` (a filtering group's own
block entries or patterns; `matched` is the entry), `service` (a blocked
service; `matched` is its name), `group_blocklist` (a source from Blocklists
selected by a group), `ai` (`matched` is the category), `rpz` (`matched` is
the zone), `cname` (the answer led through a CNAME to a blocked name;
`matched` is that name), `denied_network`, `listener` (the client may not
use that encrypted listener), `aaaa_filter`, `client_rule` or `plugin`.
`group` names the filtering group when a group blocked it, and `reason` is
the whole explanation in words, as the Extended DNS Error carries it.
`block_source` filters on it. The CSV export has `block_source`,
`block_group`, `block_matched` and `block_reason` columns, and syslog query
lines end in `source=... group="..." matched="..." reason="..."` for blocks.

`GET` returns a page of entries (newest first) plus the total count under
the same filter. `qname` accepts `*` wildcards (`*.example.com`, `www.*`)
and substring matching otherwise; `from`/`to` are RFC 3339 timestamps
with any UTC offset (a bare `YYYY-MM-DDTHH:MM[:SS]` is taken as UTC;
anything else is `400`), both inclusive to the second;
`per_page` is capped at 500. `format=csv` streams the whole filtered set
(no pagination) as a CSV download. `DELETE` clears the log (admin only).

Retention: the oldest rows are deleted beyond `logging.query_db_max_rows`
rows (0 = no limit) and, when `logging.query_db_retention_days` is set,
once older than that many days (checked every minute); whichever limit is
reached first applies. `GET /api/querylogs/stats` returns `{"rows",
"oldest", "database_bytes"}`: the number of kept rows, the oldest one's
time (`null` when empty), and the size of the whole database file.

### Configuration

```
GET  /api/config
PUT  /api/config
POST /api/config
```

`GET` returns the effective `DaygleConfig` document (the TOML configuration,
serialized as JSON) with secrets redacted (see [Console users and roles](#console-users-and-roles)).

`GET /api/config/defaults` returns the built-in defaults in the same shape,
which is what a key left out of the config file gets. The Settings page's
**Reset to Defaults** button reads it.

`PUT /api/config` applies a **partial settings update** from the console
(the Settings page uses this). `null`/absent fields are left unchanged;
unknown fields are rejected with `400`. The merged configuration is validated
first (invalid input changes nothing), persisted to the **database** (not the
config file), applied
to the live server, and listeners are rebound when the update touched them:

```json
PUT /api/config
{
  "recursive": { "dnssec_validate": true, "serve_stale_secs": 1800 },
  "doq": { "enabled": true }
}
```

Editable groups: `server` (listen/ipv6_only/port/udp_enabled/tcp_enabled/proxy_protocol,
and the stored, console-edited `client_timeout_ms` (1000-10000, applied live),
`tcp_timeout_ms` and `dns_cookies`), `recursive`
(enabled/mode/upstreams/use_system_config/dnssec_validate/cache_size/
min_cache_ttl/max_cache_ttl/negative_cache_ttl/failure_cache_ttl/
prefetch_* (including prefetch_window_secs)/serve_stale_secs/max_concurrent_lookups/
timeout_secs (per nameserver, 1-300)/conditional_zones/recursion_access/recursion_networks/root_hints/
case_randomization/rebinding_protection/local_root/opportunistic_encryption/
outbound_ip_versions/client_policies), `dot`,
`doh`, `doq` (enabled/port/self_signed/server_name/cert_path/key_path/
certificate/max_connections [+ `dot`/`doh` handshake_timeout_secs, `doh.endpoint`,
`doq.idle_timeout_secs`/`doq.max_concurrent_streams`]
/allowed_networks; `doh.http3`, default off, also serves DoH over HTTP/3 (QUIC)
on UDP at the same addresses and port number, with the same certificate,
endpoint and allowed networks - for clients configured for HTTP/3 DoH and
those that learn of it through DDR (below); browsers are not told through
`Alt-Svc`; it cannot share a UDP port with DoQ), `api`
(gui_enabled/cors_origins), `display` (the console's date/time defaults:
`time_zone` = `system`, `UTC` or an IANA zone; `date_format` = `system`/`dmy`/
`mdy`/`ymd`/`d_mon_y`; `time_format` = `system`/`24h`/`12h`; `theme` = `system`/`light`/`dark`), `syslog`, `dns64` and `ecs` (see below), `policy`
(allowlist/blocklist/denied_networks/allowed_networks/filter_aaaa/
filter_aaaa_except/blocklist_sources, and `cname_inspection`, default on:
a recursive answer whose CNAME chain reaches a blocked name is blocked
too, unless the queried name is allowlisted; `safe_search` and
`youtube_restricted`, default off: answer Google, Bing and DuckDuckGo with
their forced Safe Search addresses, and YouTube with Restricted Mode, for
every client - see Safe Search below), and `authoritative`
(default_record_ttl/default_primary_ns/default_admin_mailbox/axfr_enabled/axfr_networks/
allow_dynamic_updates/update_networks/notify_enabled/notify_targets/
notify_listen_enabled/stub_zones/catalog_zone/catalog_consumers/empty_zones
(below), and the
DNSSEC timing dnssec_enabled/dnssec_sig_validity_days/dnssec_rollover_days/
dnssec_rollover_overlap_days/dnssec_rollover_retire_days/dnssec_maintenance_secs,
applied live: turning signing on or off or a new validity re-signs at once),
and `rate_limit` (the whole `[rate_limit]` section: enabled/client_max_queries/
client_window_secs/domain_max_queries/domain_window_secs/exempt_loopback/
client_ipv6_prefix, applied live). Runtime groups (`recursive`, `dot`, `doh`, `doq`,
`policy`, `authoritative`, `ai`, `display`, `alerts`, `rrl`, `rate_limit`, `rpz`)
are stored in the database and survive restarts and config-file edits, as
are `server.client_timeout_ms`/`tcp_timeout_ms`/`dns_cookies`; the rest of
`server.*` and `api.*` stay config-file-owned so a broken listener can always
be fixed by editing the file. Those are applied to the running server when
sent in a `PUT` but not stored, so they revert at the next restart; the
console shows them read-only.

`web` controls how the console and API themselves are served:
`http_enabled`/`http_port` (0 = `api.port`), `https_enabled`/`https_port`,
`https_certificate` (a certificate from `/api/certificates`; empty
generates and selects a self-signed `web-console` certificate) and
`redirect_http` (with both on, HTTP answers `308` to the same path over
HTTPS). It is stored in the database and applied live. New ports are bound
and the certificate loaded before the running listeners change, so a port
in use, a missing or unusable certificate, or turning both off gets `400`
and changes nothing. If the saved settings cannot start at boot, the server
logs an error and serves plain HTTP on `api.port`. `daygle-dns
reset-web-access` clears the stored settings (restart afterwards) for when
a change locks you out. Login users are managed
from the console's **Users** page (see [Console users and roles](#console-users-and-roles)).

The `authoritative` group holds zone-creation defaults, used for zones
created without their own SOA values (no explicit value and no imported
SOA):

- `authoritative.default_primary_ns` (Settings → **DNS Server Domain**) is
  the SOA primary nameserver (MNAME), also used to synthesize the zone's
  default `@` NS record. A trailing dot is added when missing. Empty (the
  default) means this server's own host name, made fully qualified with the
  `domain` (or first `search`) entry of `/etc/resolv.conf`; when that
  cannot be read either, `ns1.<zone>.`.
- `authoritative.default_admin_mailbox` (Settings → **Default
  Administrator Email**) is the SOA contact (RNAME). It takes an email
  address (`jane.doe@example.com`, stored as `jane\.doe.example.com.`) or
  the SOA form. Empty (the default) means the email of the first
  administrator account that has one (normally the account created at
  first-run setup); with none, `admin.<zone>.`.

Blank values clear a setting. The placeholder values earlier versions
shipped (`ns1.daygle.test.`, `admin.daygle.test.`) count as empty.
`admin_mailbox` on `POST /api/zones` and `PUT /api/zones/{id}/soa` also
accepts an email address.

`GET /api/zones/defaults` reports what a new zone would get:
`primary_ns` and `admin_mailbox` (with `primary_ns_source` =
`setting`/`hostname`/`none` and `admin_mailbox_source` =
`setting`/`admin_email`/`none`), `admin_email` (the mailbox as an email
address when unambiguous), and the automatic fallbacks `server_name` and
`first_admin_email` whatever is set.

`authoritative.empty_zones` sets the RFC 6303 (BCP 163) empty zones answered
directly by this server: reverse zones whose addresses never appear on the
public Internet (RFC 1918 private space, RFC 5737 documentation space, IPv6
unique-local and link-local space and friends) are answered authoritatively
from a synthesized SOA/NS-only zone instead of being recursed, so those
lookups never leak upstream and fail fast even with recursion off. The list
starts with the RFC's recommended zones; `PUT /api/config` replaces it
wholesale (an empty JSON list disables the feature). Zone names may carry a
trailing dot and are lowercased and canonicalized on save. A hosted
(primary, secondary or stub) zone that contains the queried name is served
as usual and wins over an empty zone of the same address space.

`recursive.mode` is `"recursive"` (resolve from the root servers; DNSSEC is
validated against the built-in root trust anchor and query names are
minimized) or `"forwarding"` (send queries to `recursive.upstreams`, or the
system resolver when that list is empty). When unset it is inferred:
forwarding if upstreams are configured, otherwise recursive. Saving settings
stores the effective mode explicitly. `recursive.recursion_access` decides who
may use recursion - `"private_networks"` (default: loopback, RFC 1918, CGNAT,
link-local, IPv6 ULA, and the global IPv6 networks this host has addresses
in, re-read every minute from `/proc/net/if_inet6`), `"allow"`, `"custom"` (the CIDRs or IPs in
`recursion_networks`) or `"deny"`; refused clients get `REFUSED`, while the
server's own zones are answered for everyone. In recursive mode,
`case_randomization` enables 0x20 query-case randomization and
`rebinding_protection` drops private, loopback and unspecified addresses
from public answers, including IPv4-mapped IPv6 forms such as
`::ffff:192.168.1.1`; `root_hints` overrides the built-in root server addresses.

`recursive.local_root` (`{ "enabled": true, "sources": [] }`) keeps a local
copy of the root zone (RFC 8806; the console's **Secondary ROOT Zone**). It is
transferred over AXFR from `sources` (IP, IP:port or [IPv6]:port, tried in
order; empty uses ICANN's transfer servers and the root servers that allow
transfers) and accepted only when its ZONEMD digest (RFC 8976) matches and
the ZONEMD and DNSKEY records are signed by a key matching the built-in root
trust anchor. The verified copy is cached next to the database, refreshed on
the zone's SOA refresh interval, and dropped when it cannot be refreshed
within the SOA expire time. In recursive mode the resolver's root queries are
answered from it; in forwarding mode names under top-level domains the root
zone does not have are answered `NXDOMAIN` without asking the upstreams
(conditional forwarders and stub zones still take precedence, so use one for
a private TLD).

`recursive.opportunistic_encryption` (recursive mode, off by default) turns on
RFC 9539 opportunistic encryption: nameservers are probed for DNS over TLS or
QUIC in the background and the encrypted transport is used where it works,
with plain DNS as the fallback.

`recursive.outbound_ip_versions` (`"both"` by default, `"ipv4"` or `"ipv6"`)
limits which IP versions the server uses for its own queries: root hints and
the name servers the recursor is referred to, upstreams, conditional
forwarders, forwarding client policies, stub zone name servers and local root
sources. Servers of the other version are skipped (a `https://` upstream
named by host is resolved to an address of an allowed version). A save that
leaves an upstream, conditional-forwarder or client-policy list with no
usable server is refused with `400`, as is a `root_hints` or
`local_root.sources` list with none. When `/etc/resolv.conf` has no server of
an allowed version, all of them are used and a warning is logged. Zone
transfers and NOTIFY use the addresses configured for them regardless. This
is about transport only: AAAA records are still resolved and served.

Every `listen` setting (`server`, `api`, `dot`, `doh`, `doq`) takes one
address or several separated by commas (in the config file, an array works
too): `"192.168.1.2, fd00::53"`. Each address gets its own socket on the
listener's port. `::` next to IPv4 addresses covers every IPv6 address plus
those IPv4 ones. A repeated address, or one a wildcard in the same list
already covers (`"0.0.0.0, 192.168.1.2"`), is a config error, since the
second socket could not be bound.

`logging` takes any of `query_db_enabled`, `query_db_max_rows`,
`query_db_retention_days` (the database query log; applied at once, see
Query logs above), `query_log_enabled`, `query_log_dir` (a full path) and
`query_log_retention_days` (the daily JSON-lines files; applied when the
service restarts). The log level and server log size stay file-only.

`syslog` (`{enabled, server, facility, level, queries}`, replaced whole)
sends the server log to a syslog server as RFC 5424 lines: `server` is
`host`, `host:port`, `udp://host:port` or `tcp://host:port` (UDP and port
514 by default; TCP frames are octet-counted, RFC 6587); `facility` is
`daemon` (default), `user` or `local0`-`local7`; `level` is the lowest
server-log level sent (`info`, `warn` or `error`); `queries` adds one line
per answered query (`client=... qname=... qtype=... protocol=... outcome=... rcode=...
ms=...`, message id `query`). Lines are queued and sent in the background;
if the server cannot be reached they are dropped and counted, and the count
is sent once it can be.

`log_export` (`{enabled, url, format, authorization, batch_size,
flush_secs}`, replaced whole) POSTs every answered query, as JSON, to an
HTTP(S) endpoint such as Vector, Fluent Bit, Logstash or Splunk HEC. Each
query is an object with `time` (RFC 3339, UTC), `server` (this host),
`client`, `qname`, `qtype`, `protocol`, `outcome`, `rcode` (or `null`) and
`elapsed_ms`; `format` `ndjson` (default) sends one per line
(`application/x-ndjson`), `json` sends an array (`application/json`).
`authorization`, when set, is sent as the `Authorization` header (e.g.
`Bearer abc` or `Splunk <token>`); it reads back as `[redacted]`, and
sending `[redacted]` keeps the stored one. A request goes out once
`batch_size` queries (1-10000, default 500) are queued, or `flush_secs`
(1-300, default 5) after the first. A batch the endpoint does not accept
(not 2xx) is tried twice more, 2 and 4 seconds apart, then dropped; drops
are counted and noted in the server log once the endpoint answers again.

```
GET  /api/log-export
POST /api/log-export/test
```

`GET /api/log-export` answers `{"sent", "dropped", "last_error"}`: queries
delivered and dropped since start, and why the last batch failed (`null`
once one succeeds). `POST /api/log-export/test` sends one sample query
(`qname` `test.daygle-dns.invalid`, `outcome` `test`) with the saved
settings, or with `{"log_export": {...}}` from the body (unsaved form
values), whether or not export is enabled. It answers `{"sent": true}`,
`400` for invalid settings, or `502` with why the endpoint refused it.

`dns64` (`{enabled, prefix, clients}`, replaced whole) turns on DNS64
(RFC 6147) for IPv6-only networks behind NAT64: when a recursive AAAA query
finds no IPv6 address (NODATA, or only `::ffff:` mapped addresses), the
name's A records are answered as AAAA records inside `prefix` (RFC 6052:
a /32, /40, /48, /56, /64 or /96; `64:ff9b::/96` by default), along with
any CNAMEs leading to them. The well-known prefix carries public IPv4
addresses only. `clients` limits it to those networks (empty: every
client). Clients that set both DO and CD get the real answer, as they
validate for themselves; synthesized answers never carry the AD bit.
Answers from this server's own zones are not changed.

`ecs` (`{enabled, subnet, ipv4_prefix, ipv6_prefix}`, replaced whole) sends
EDNS Client Subnet (RFC 7871) to forwarding upstreams (and when looking up
ALIAS targets), so CDNs answer with servers near the client. `subnet` (e.g.
`203.0.113.0/24`) is sent for every query; when empty, each client's own
address is sent cut to `ipv4_prefix` (24) / `ipv6_prefix` (56) bits, and
nothing is sent for private, loopback, link-local or documentation
addresses. It is never sent when walking the hierarchy from the root, so
root and TLD servers do not see it. A fixed `subnet` is the same for every
client, so its answers are cached as usual. A per-client subnet's answer is
for that network alone (RFC 7871 section 7.3): such a lookup bypasses the
shared caches and goes to the upstream every time (which caches per
network itself), and its answer is never kept for other clients. Clients
with no subnet sent (private addresses) are cached as usual.

`server.proxy_protocol` (file-only) lists the networks of trusted load
balancers that speak the PROXY protocol (HAProxy v1 or v2) on the TCP, DoT
and DoH listeners. A connection from one of them must start with a PROXY
header (5 s to send it, else it is closed); the client it names is used
everywhere a client address matters (recursion access, policies, rate
limits, transfer and update ACLs, logs). A v2 `LOCAL` header (a health
check) or `UNKNOWN` v1 header keeps the proxy's own address. Connections
from other addresses are served directly. UDP and DoQ are not affected.

`server.ipv6_only` (`false` by default; the console shows it but leaves it to the file) makes a `::` listen
address, in `[server]` or in `[api]`, `[dot]`, `[doh]` or `[doq]`, accept
IPv6 clients only; by default `::` accepts IPv4 clients too.

`recursive.client_policies` resolves some clients differently. Each policy is
`{ "name", "enabled", "clients": [CIDRs or IPs], "action", "upstreams" }` with
`action` `"forward"` (to the policy's `upstreams`, same forms as
`recursive.upstreams`), `"recursive"` (from the root servers, whatever the
default mode) or `"refuse"` (REFUSED; local zones are still answered). The
first enabled policy covering the client wins; `recursion_access` still
decides who may use recursion at all, and conditional forwarders and stub
zones still answer for their own names. Each policy keeps its own cached
answers. The list is replaced as a whole; invalid upstreams are rejected with
`400`. Each policy also carries `modified_at` (RFC 3339): the server stamps it
when a policy is created or edited and keeps it for unchanged policies, the
console shows it as *Last Modified*, and a value sent in an update is ignored.

Recursive settings and stub zones apply to live traffic immediately: the
resolver is rebuilt whenever `recursive.*` or `authoritative.stub_zones`
changes (a failed rebuild keeps the previous resolver and logs a warning).
`recursive.conditional_zones` and `authoritative.stub_zones` replace the whole
list. Zone names are lowercased with any trailing dot removed, and blank
upstream / nameserver entries are dropped. A forwarder needs at least one
upstream and an enabled stub at least one nameserver, otherwise the update is
rejected with `400`:

```json
PUT /api/config
{
  "recursive": {
    "conditional_zones": [{ "name": "corp.internal", "upstreams": ["10.0.0.53"] }]
  },
  "authoritative": {
    "stub_zones": [{ "name": "branch.example.com", "nss": ["192.0.2.53"], "refresh_secs": 3600, "enabled": true }]
  }
}
```

The console manages both from **Zones → Zones** (Add Zone → Stub Zone /
Conditional Forwarder Zone).

`POST /api/config` asks the server to re-read its configuration file and
apply policy, upstream and listener changes immediately, without waiting for
`server.reload_interval_ms`. It returns `202 Accepted` when a reload was
requested and `409 Conflict` when live reload is unavailable (no config file
was provided, or `server.reload_enabled = false`). Reload failures are
reported through [`GET /api/logs`](#logs); the server keeps its previous
configuration when a new one cannot be applied.

### Zones

```
GET    /api/zones
POST   /api/zones
DELETE /api/zones/{id}
POST   /api/zones/import
PUT    /api/zones/{id}/soa
GET    /api/zones/{id}/export
```

Create a zone:

```json
POST /api/zones
{
  "name": "example.com",
  "zone_type": "primary",
  "primary_ns": "ns1.example.com.",
  "admin_mailbox": "admin.example.com.",
  "default_admin_mailbox": null,
  "serial": 1,
  "refresh": 3600,
  "retry": 600,
  "expire": 86400,
  "minimum": 3600,
  "serial_date_scheme": false,
  "import_text": null,
  "masters": [],
  "refresh_secs": null
}
```

Only `name` is required for a primary zone. If `primary_ns` is omitted (and
`import_text` carries no SOA), it defaults to
`authoritative.default_primary_ns` - the **DNS Server Domain** setting (see
[Configuration](#configuration)) - falling back to `ns1.<zone>.` when that is
unset. `zone_type` defaults to `primary`.
Set `serial_date_scheme` to `true` to generate a `YYYYMMDDnn`-style SOA
serial. When `import_text` contains a BIND zone file, it is parsed and its
records are imported; SOA fields from the file supply defaults unless explicit
request values override them. Listing returns each zone plus `dnssec`,
`zone_type`, `masters`, and `refresh_secs` fields.

To create a secondary zone, provide at least one IPv4/IPv6 master address:

```json
POST /api/zones
{
  "name": "branch.example.com",
  "zone_type": "secondary",
  "masters": ["192.0.2.10", "192.0.2.11:5353"],
  "refresh_secs": 600
}
```

Secondary zones are stored in the database with their masters, applied to
the running refresher immediately (and again at every start), and pulled
over AXFR/IXFR from the first reachable master. Their records are read-only in
the GUI and record mutation endpoints return `409 Conflict`. Secondary zones
can also be listed in `daygle-dns.toml` under `[[authoritative.secondary_zones]]`.

Import a BIND zone file (creates the zone and replaces its records):

```json
POST /api/zones/import
{
  "name": "example.com",
  "text": "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ...\n"
}
```

Zone transfers (AXFR/IXFR, RFC 5936) are served over the plaintext TCP
listener - not over HTTP - gated by `authoritative.axfr_enabled` and the
`axfr_networks` client allow-list in `daygle-dns.toml`. Secondary zones (zones
replicated from remote masters on a refresh interval) are also configured in
`daygle-dns.toml` under `[[authoritative.secondary_zones]]`; each replicated zone
appears in `GET /api/zones` like any other zone, but is served read-only.

RFC 2136 dynamic updates are also a DNS-protocol feature (over UDP/TCP/DoT,
not HTTP): `UPDATE` messages for hosted primary zones are applied atomically
with write-through to SQLite and served immediately after a catalog reload.
They are gated by `authoritative.allow_dynamic_updates` (default off) and the
`authoritative.update_networks` client allow-list (when it is empty, only
zones bound to a TSIG key in `authoritative.tsig_update_zones` take updates,
signed ones only), and are always refused for secondary zones. Prerequisites (value-dependent / value-independent /
not-exists forms) are fully checked; failed updates return their RFC 2136
RCODE (YXDOMAIN, YXRRSet, NXDOMAIN, NXRRSet, NOTAUTH, ...).

NOTIFY (RFC 1996) is likewise a DNS-protocol feature. When
`authoritative.notify_enabled` is set, every change to a primary zone's
serial (a console edit or import, a dynamic update, a DNSSEC signature
renewal) sends a NOTIFY (OpCode 4, QTYPE SOA, UDP) to every address in
`authoritative.notify_targets`; secondaries that receive it immediately query
our SOA and pull an IXFR/AXFR when the serial advanced. When
`authoritative.notify_listen_enabled` is set, the server also accepts
NOTIFYs for its secondary zones (and followed catalog zones) on the main UDP port, replies with
the current SOA, and refreshes that zone immediately (the refresh interval
remains the fallback and serials are always compared before a transfer).

### Zone aliases

```
PUT    /api/zones/{id}/aliases   { "aliases": ["example.net", "example.org"] }
GET    /api/zone-aliases
```

A zone alias serves a zone under another name too: every query for a name
in the alias is answered from the zone's records, with the owner name
moved into the alias (`www.example.net` answers like `www.example.com`) and
record data unchanged, NXDOMAIN and NODATA included; the alias has the
zone's SOA under its own name. Changes to the zone show at once. Aliases
are served unsigned, are not transferred, and are not listed in a
published catalog zone. `PUT` replaces the zone's aliases and answers with
them (`[{name, zone_id, created_at}]`); a name that is a hosted zone,
another zone's alias, the catalog zone, or inside or above the zone itself
is refused (409 or 400), as are reverse zones. A zone cannot be created
under a name that is an alias. Deleting the zone removes its aliases.
`GET /api/zone-aliases` lists every alias.

### Catalog zones (RFC 9432)

A catalog zone is a zone listing other zones, so secondaries can follow a
whole server instead of being told about each zone. Both directions are set
under `authoritative` (in Settings, or `PUT /api/config`):

```json
{
  "authoritative": {
    "catalog_zone": "catalog.example.com",
    "catalog_consumers": [
      { "name": "catalog.example.net", "masters": ["198.51.100.10"], "refresh_secs": 3600, "enabled": true }
    ]
  }
}
```

- `catalog_zone` publishes a schema-version-2 catalog of this server's
  primary zones under that name (empty: none). Each zone gets a PTR at
  `<unique-id>.zones.<catalog>` that stays the same for the life of the zone;
  the serial moves forward whenever the list changes, and with NOTIFY on the
  `notify_targets` are told. Secondaries fetch it by AXFR, so it obeys
  `axfr_enabled`/`axfr_networks` like any zone. A hosted zone of the same
  name takes precedence (the catalog is then not published).
- `catalog_consumers` (the whole list) follows remote catalogs. Each catalog
  is checked every `refresh_secs` (at least 30) and transferred again when
  its serial changed; every member zone it lists is added as a secondary
  zone from the catalog's `masters`, and the zones it drops are removed. A
  zone this server already has is left alone. With `notify_listen_enabled`,
  a NOTIFY for the catalog from one of its masters checks it at once. A
  disabled catalog keeps its zones; removing it from the list removes them.

Zones added by a catalog show `"catalog": "<name>"` in `GET /api/zones`, and
`DELETE /api/zones/{id}` refuses them with `409` (remove them from the catalog
instead).

`PUT /api/zones/{id}/soa` edits a primary zone's SOA metadata. Every field is
optional; omitted fields keep their current value. `bump_serial` increments
the serial automatically (so secondaries pick up the change); it wins over
an explicit `serial`.

`GET /api/zones/{id}/export` returns the zone as a BIND-style zone file
(`text/plain`) - SOA plus every record, with disabled records included as
`; disabled:` comments, so an export doubles as a full-zone backup that
round-trips through `/api/zones/import`.

### Records

```
GET    /api/zones/{id}/records
PUT    /api/zones/{id}/records
PUT    /api/zones/{id}/records/{rid}/disabled
DELETE /api/zones/{id}/records/{rid}
```

Upsert a record. `name` may be relative (`www`), fully qualified
(`www.example.com.`), or `@` for the apex. `content` is the RDATA in zone-file
presentation format (an MX stores `10 mail.example.com.`, a TXT stores
`"hello"`).

```json
PUT /api/zones/{id}/records
{
  "name": "www",
  "rtype": "A",
  "content": "192.0.2.1",
  "ttl": 3600,
  "priority": 0,
  "disabled": false
}
```

Supported `rtype` values: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`,
`SRV`, `PTR`, `CAA`, `HTTPS`, `SVCB`, `DS`, `TLSA`, `SSHFP`, `NAPTR`, `ALIAS`,
`AUTOPTR`.
`content` must parse as that type's RDATA, otherwise the request fails with
400. `priority` is not served: MX and SRV take their priority from `content`.
For A and AAAA records with health checks it is the failover priority (see
below).

**Reverse (PTR) records.** `PUT /api/zones/{id}/records`,
`PUT /api/zones/{id}/records/{rid}` (replace a record in place) and
`DELETE /api/zones/{id}/records/{rid}` take two query options for A and AAAA
records:

- `update_ptr=true` keeps the record's PTR record in step, in the most
  specific hosted zone covering its address. A save adds the PTR (pointing
  at the record's full name, with its TTL); a change of address or name
  moves it; a delete removes it. Only PTR records pointing at this record's
  name are removed, and a PTR at the address for another name is left as it
  is. A disabled record gets no PTR.
- `create_reverse_zone=true` (with `update_ptr`) creates the reverse zone
  when none covers the address: its /24 (`20.168.192.in-addr.arpa` for
  192.168.20.5) or, for IPv6, its /64, with the default nameserver and
  mailbox.

With `update_ptr`, a save answers with the record plus `"reverse": {"added":
[...], "removed": [...], "zone_created": "...", "problem": "..."}` (owner
names; `zone_created` and `problem` only when they apply; `problem` says why
no PTR was added, e.g. no reverse zone or another name's PTR), and a delete
answers `200` with `{"reverse": {...}}` instead of `204`.
`PUT /api/zones/{id}/records/{rid}/disabled?update_ptr=true` removes the
record's PTR when it is disabled and adds it back when it is enabled (its
answer gains the same `reverse` field).

**Health-checked failover.** An A or AAAA record can carry a health check:

```
PUT    /api/zones/{id}/records/{rid}/health   { "kind": "https", "port": 443, "path": "/health", "host": "", "interval_secs": 30 }
DELETE /api/zones/{id}/records/{rid}/health
GET    /api/health-checks
```

`kind` is `tcp` (a connection opens), `http` or `https` (a GET answers with a
status below 400; certificates are not verified). `host` is the name sent
in the Host header and SNI (empty: the record's name); the request goes to
the record's address. `interval_secs` is 5-86400 (default 30). After 2
failed checks in a row a record is left out of answers, and it returns
after 2 passes. At a name whose A (or AAAA) records include a checked one,
only the healthy records with the lowest `priority` are served, so a higher
priority makes a record a backup; when none is healthy, all are served.
`GET /api/health-checks` lists every check with its record (`zone_id`,
`name`, `rtype`, `address`, `priority`) and `healthy`, `last_checked` (UNIX
seconds) and `last_error`. Zone transfers still carry every record.

**Weighted load balancing.** An A or AAAA record can carry a weight:

```
PUT    /api/zones/{id}/records/{rid}/weight   { "weight": 3 }
GET    /api/record-weights
```

At a name whose A (or AAAA) records include a weighted one, each answer
holds a single record, picked at random in proportion to the weights
(`3` gets three times the answers of `1`); records with weight `0` (the
default, and how a weight is removed) are not picked. Failover applies
first, so records that are down are not picked either. `weight` is
0-10000; other record types are refused with 400. A DNSSEC-signed zone
always answers with the whole RRset (its signature covers every record),
and zone transfers carry every record. `GET /api/record-weights` answers
`{record_id: weight}` for every weighted record.

**Automatic PTR records.** An `AUTOPTR` record in a reverse zone
(`in-addr.arpa` or `ip6.arpa`) makes up a PTR answer for every address
under its name that has no PTR record of its own. Its `content` is a host
name template containing `{ip}`, which becomes the address with dashes:
`ip-{ip}.home.arpa.` answers `47.1.168.192.in-addr.arpa` with
`ip-192-168-1-47.home.arpa.`, and an IPv6 address gives every group in hex
(`2001-db8-0-0-0-0-0-1`). Put it at `@` to cover the whole zone, or lower to
cover part of it (the most specific one wins); the answer's TTL is the
record's. A name may have one AUTOPTR record. Like ALIAS, AUTOPTR answers
are made when asked, so the record cannot be added to a DNSSEC-signed zone
(nor can a zone holding one be signed), and it is not sent in zone
transfers.

An `ALIAS` record (also called ANAME) lets a name - including the zone apex,
where a CNAME is not allowed - follow another host's addresses: its `content`
is the target name (e.g. `"myapp.cdn.example.net."`), and A and AAAA queries
for the name are answered with the target's current addresses, looked up
when asked (from the server's own zones, or recursively) and served under
the alias's name with the lower of the two TTLs. Other types at that name are
answered from the zone as usual. An alias cannot share its name with an A,
AAAA, CNAME or another ALIAS record, cannot point at itself, and cannot be
added to a DNSSEC-signed zone (nor can a zone holding one be signed).

`PUT /api/zones/{id}/records/{rid}` replaces an existing record in place with
the same body, keeping its id and disabled state (the collection `PUT` above
always adds a new record). It returns 404 when the record does not exist in
that zone.

`PUT /api/zones/{id}/records/{rid}/disabled` stages (or re-enables) a single
record without deleting it - a disabled record stays in the zone but stops
being served. The serial is bumped and the catalog reloaded, so the change
is live immediately.

### Networks

```
GET    /api/networks
POST   /api/networks
DELETE /api/networks/{name}
```

Named networks (Clients -> Networks in the console) give a set of addresses a name, such
as `LAN` = `192.168.20.0/24`, so settings that take client networks can name
it instead of repeating the addresses. They are part of the configuration
(`[[networks]]` in the config file, saved with the console's settings).
Names are matched without regard to case. Two built-in networks always
exist and cannot be changed: `Private` (private, shared, link-local and
loopback addresses) and `This Server` (loopback).

Every setting that takes client networks accepts these names as well as
addresses: recursion access, allow/deny lists, zone transfers, dynamic
updates, PROXY protocol, DNS64 clients, client policies and policy rules.
A name that is not a configured network is refused. A change to a network
applies to every setting that names it, at once.

`GET` lists them, each with `builtin` and `used_by` (the settings that name
it):

```json
{
  "networks": [
    { "name": "LAN", "cidrs": ["192.168.20.0/24"], "description": "Home devices",
      "builtin": false, "used_by": ["Split horizon 'nas.home.example'"] }
  ]
}
```

`POST` adds a network, or changes one when `original_name` is given; a
different `name` renames it and every reference to it:

```json
{ "original_name": "LAN", "name": "Home", "cidrs": ["192.168.20.0/24", "fd00:20::/64"], "description": "" }
```

A name must not look like an address and must not be taken (`409`); every
address must be a CIDR or a single address (`400`). `DELETE` removes a
network nothing uses; a network still in use is `409` with `used_by`.

### Split horizon

```
GET    /api/split-horizon
POST   /api/split-horizon/networks
DELETE /api/split-horizon/networks/{name}
POST   /api/split-horizon/entries
PUT    /api/split-horizon/entries/{id}
POST   /api/split-horizon/entries/{id}/move
DELETE /api/split-horizon/entries/{id}
```

Split horizon serves different answers for the same domain depending on the
client's network. An **entry** maps a domain to a list of typed records for
a set of networks: names of named networks (see Networks above) and/or
literal CIDRs or addresses; empty = every client. An entry naming a network
that does not exist is rejected with `400`.

`GET` returns everything. `ips` is kept for backward compatibility and always
holds the A/AAAA subset of `records`:

```json
{
  "networks": [
    { "id": "...", "name": "LAN", "cidrs": ["192.168.20.0/24"] }
  ],
  "entries": [
    {
      "id": "...",
      "domain": "www.example.com",
      "networks": ["LAN"],
      "ips": ["10.0.0.5"],
      "records": [
        { "rtype": "A", "content": "10.0.0.5" },
        { "rtype": "TXT", "content": "\"internal only\"" }
      ],
      "ttl": 60,
      "disabled": false,
      "position": 0,
      "last_modified_at": "2026-10-24T09:30:00+00:00",
      "last_used_at": "2026-10-24T10:02:11+00:00"
    }
  ]
}
```

`last_modified_at` is RFC 3339 and is set when an entry is created or edited;
`last_used_at` is set when the entry last served a split-horizon answer
(written at most once per entry per minute). Both are absent when unknown:
entries created before timestamps were tracked carry neither until edited,
and a never-used entry has no `last_used_at`.

`networks` in the `GET` response lists the named networks (built-in ones
included). `POST /api/split-horizon/networks` (`{"name", "cidrs"}`) and
`DELETE /api/split-horizon/networks/{name}` are the older forms of the
Networks endpoints and behave the same way. Networks that split horizon kept
on its own before networks were shared become named networks on the first
start after upgrading (one named like a built-in network gets
` (Split Horizon)` added, along with the entries that use it).

Create an entry (appended after existing entries for the same domain).
`records` entries hold the query type and its RDATA in zone-file presentation
format - supported types are `A`, `AAAA`, `MX`, `TXT`, `CNAME`, and `SRV`
(e.g. `MX` → `"10 mail.example.com."`, `TXT` → `"\"hello\""`, `CNAME` →
`"target.example.com."`, `SRV` → `"0 5 5060 sip.example.com."`). TXT values
are auto-quoted when no quotes are present:

```json
POST /api/split-horizon/entries
{
  "domain": "www.example.com",
  "networks": ["LAN", "VPN"],
  "ips": ["10.0.0.5"],
  "records": [
    { "rtype": "A", "content": "10.0.0.5" },
    { "rtype": "MX", "content": "10 mail.example.com." }
  ],
  "ttl": 60,
  "disabled": false
}
```

For compatibility, `ips` alone is also accepted and converted to A/AAAA
records; when both are present `records` wins.

`PUT /api/split-horizon/entries/{id}` updates an entry in place (keeping its
ordering position). Entries are evaluated in order; the first one whose domain
matches and whose networks contain the client wins, so a catch-all entry with
no networks acts as the public fallback behind the specific internal ones.
Matching applies to A/AAAA queries; an entry with no address of the requested
family falls through to normal resolution.

Move an entry one position up or down within its domain's ordering:

```json
POST /api/split-horizon/entries/{id}/move
{
  "direction": "up"
}
```

`direction` is `"up"` (higher precedence) or `"down"` (lower precedence).
Returns `{"moved": true}` when the entry was swapped with its neighbour,
`{"moved": false}` when it is already at the edge of its domain (a no-op),
and `404` when the entry does not exist. Entries of other domains are never
affected.

A matching entry answers queries of the same record type - a CNAME answers
every query type (RFC 1034 §3.6.2), and `ANY` queries receive all records.
When the entry has no record for the queried type the query falls through to
normal resolution, so an entry holding only a TXT never swallows A queries.

### Certificates

```
GET    /api/certificates
POST   /api/certificates
DELETE /api/certificates/{name}
```

TLS certificates stored in the database and managed from the console; the
`dot`/`doh`/`doq` listener sections select one with `certificate = "<name>"`
(overriding `cert_path`/`key_path`/`self_signed`). `GET` lists metadata only
- PEM material is never returned. Each entry has `name`, `server_name`,
`created_at` (rewritten whenever the stored material is replaced - by a
re-upload or an ACME renewal - so it doubles as "last modified"),
`in_use` (the listeners using it) and details read from the
leaf certificate: `subject`, `issuer`, `self_signed`, `names` (DNS and IP
subject alternative names) and `not_before`/`not_after` (RFC 3339); these
are `null` if the certificate cannot be read. `POST` creates a self-signed certificate
or uploads PEM material; uploading with the same `name` replaces the entry,
and listeners referencing the name are rebuilt immediately. `DELETE`
removes the certificate; one still referenced by a listener cannot be
deleted.

#### Let's Encrypt (ACME)

```
GET  /api/acme
PUT  /api/acme
POST /api/certificates/acme
POST /api/certificates/{name}/renew
GET  /.well-known/acme-challenge/{token}
```

Certificates can be issued and renewed automatically by an ACME CA: Let's
Encrypt, or a private one such as step-ca. `PUT /api/acme` sets
`{email, directory, agree_terms, ca_certificate, renew_days}`: `directory`
empty means Let's Encrypt; `ca_certificate` is a PEM root to trust for a
private CA's directory; `renew_days` (default 30) is how long before expiry
to renew. `GET /api/acme` returns the `settings`, the `directory_url` in use,
and the Let's Encrypt (`lets_encrypt`, `lets_encrypt_staging`) directories.
An account with the CA is created on first use and kept in the database.

`POST /api/certificates/acme` `{name, domains, challenge}` requests a
certificate (`agree_terms` must be set). It answers `202` and runs in the
background; the certificate list then carries an `acme` object
(`domains`, `challenge`, `status`: `pending`/`valid`/`failed`,
`last_error`, `last_attempt`), and lists the entry even before the CA has
issued it. Control of each name is proven by:

- `http` (HTTP-01): the CA fetches `/.well-known/acme-challenge/{token}` on
  port 80, which the web console's HTTP listener answers (open, outside
  `/api`, and never redirected to HTTPS). The name must reach that listener
  on port 80.
- `dns` (DNS-01): a TXT record at `_acme-challenge.<name>` is added to the
  primary zone hosted here that holds it, and removed afterwards. The zone
  must be delegated to this server. Wildcard names need `dns`.

Certificates are checked a minute after start and then twice a day, and
renewed `renew_days` before expiry; `POST /api/certificates/{name}/renew`
renews one now. A renewal is stored like an upload, so listeners using the
certificate switch to it straight away. An ACME certificate cannot be
replaced by an upload (`409`); deleting it stops its renewals.

### DNSSEC signing

```
POST /api/zones/{id}/sign
POST /api/zones/{id}/unsign
```

`sign` generates a signing key (if absent), signs the zone, and reloads the
catalog. `unsign` removes the key.

`sign` takes an optional body `{ "nsec3": true }` to prove that names and
types do not exist with NSEC3 (hashed owner names, so the zone's contents
cannot be listed by walking its NSEC chain) instead of NSEC, the default.
NSEC3 uses the RFC 9276 parameters: SHA-1, no extra iterations, no salt and
no opt-out (NSEC3PARAM is published at the apex). Calling `sign` on a signed
zone with `nsec3` switches between the two without changing keys; without a
body it keeps the zone's current choice. `GET /api/zones` reports `dnssec`
and `nsec3` for each zone, and `ds`: the DS records (SHA-256) the parent
zone must publish, one per active key (two during a key rollover).`sign` fails while `authoritative.dnssec_enabled` is off.

A signed zone also publishes RFC 8078 CDS and CDNSKEY RRsets at its apex,
one record per active key with a SHA-256 digest and the same TTL the zone
uses for its DNSSEC records: a parent that supports the automated DS
exchange (a CDS-scanning registrar or `dnssec-monitor` tooling) can fetch
them and publish the matching DS without the DS being copied by hand.
During a rollover the records of both the active and retired keys appear,
just like the DS report.

Once signed, a zone is maintained automatically: RRSIGs are renewed before
they expire (with a serial bump, so secondaries pick up the new signatures)
and keys are rolled over on schedule (double-signing during the
overlap, the old key retired and eventually removed) - see the `dnssec_*`
settings under `authoritative` in `daygle-dns.toml`. Manual `unsign` removes all
keys (including any mid-rollover ones) and stops the maintenance for that
zone.

### Cache

```
GET  /api/cache
POST /api/cache/clear
POST /api/cache/flush
```

`GET` returns the cache configuration (`capacity`, `prefetch_enabled`,
`serve_stale_secs`), the resolution `mode` and runtime counters: `hits` and
`misses` (a hit is a lookup answered without any query leaving the server,
negative answers included) and `tracked_names`.

`POST /api/cache/clear` flushes the whole resolver cache.

`POST /api/cache/flush` with `{ "name": "www.example.com", "type": "AAAA" }`
drops one name from the cache (`type` is optional; without it the common
record types are flushed). It answers `{ "name", "complete" }`: `complete` is
`false` in recursive mode when the name is resolved by the recursor, whose
cache cannot drop a single entry - the forwarding resolvers (conditional
forwarders, stub zones, forwarding client policies) and the serve-stale and
failure caches are still flushed, and the recursor's copy expires on its own
or with `/api/cache/clear`. Invalid names or types are `400`; `409` when
recursion is disabled.

### Resolver dashboard

```
GET /api/resolver
```

Counters since the server started, behind the Status page's Resolver card:

```json
{
  "enabled": true,
  "mode": "recursive",
  "dnssec_validation": true,
  "opportunistic_encryption": true,
  "local_root": { "enabled": true, "serving": true, "serial": 2026101901 },
  "client_policies": 1,
  "conditional_zones": 1,
  "stub_zones": 0,
  "queries": 18234,
  "dnssec_validated": 9876,
  "stats": {
    "routes": { "recursive": 15210, "forwarding": 0, "conditional": 412,
                "stub": 0, "client_policy": 2380, "local_root": 232 },
    "outcomes": { "noerror": 15900, "nodata": 1210, "nxdomain": 980,
                  "servfail": 96, "refused": 3, "other": 0, "failures": 45,
                  "stale_served": 12, "failures_replayed": 310 },
    "latency": { "bounds_ms": [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500],
                 "counts": [9800, 1200, 900, 1700, 1600, 1100, 700, 160, 40, 30, 4],
                 "p50_ms": 1, "p90_ms": 100, "p99_ms": 500, "mean_ms": 21.4 },
    "connections": { "udp": 5400, "tcp": 620, "tls": 1310, "quic": 85 }
  }
}
```

`routes` counts lookups by the way they were resolved (`local_root` is
NXDOMAIN answered from the local root zone without a lookup). `latency.counts`
has one entry per bound plus a final one for slower lookups; the percentiles
are bucket upper bounds. `connections` counts outbound connections to
nameservers and upstreams by transport (`tls` and `quic` come from
opportunistic encryption and from `tls://`/`quic://` upstreams).

### Local root zone

```
GET  /api/local-root
POST /api/local-root/refresh
```

`GET` reports the local root zone (see `recursive.local_root` above):

```json
{
  "enabled": true,
  "serving": true,
  "serial": 2026101901,
  "records": 22417,
  "tlds": 1443,
  "last_checked": "2026-10-20T04:10:00+00:00",
  "expires": "2026-10-27T04:10:00+00:00",
  "source": "192.0.32.132",
  "last_error": null,
  "last_error_at": null
}
```

`serving` is true while a verified, unexpired copy is in use. `source` is the
server the copy came from (`"cache"` after a restart). `POST .../refresh`
checks the sources for a newer serial now (`409` when the local root zone is
not enabled).

### Blocklist sources

```
GET  /api/policy/blocklist/sources
POST /api/policy/blocklist/sources
PUT  /api/policy/blocklist/sources
GET  /api/policy/blocklist/sources/validate?url=...&format=...
```

`GET` returns per-source status for the remote blocklist sources configured
under `[[policy.blocklist_sources]]`: name, URL, format, scope, refresh
interval, last-fetch age (`last_fetch`, seconds since the last successful
fetch) with its wall-clock time (`last_fetch_at`, RFC 3339, `null` before
the first fetch), and the number of domains each source contributed.
`total_domains` counts the sources that apply to everyone.

`POST` forces an immediate refresh of every source and applies the merged
result, returning the new total domain count.

```json
{
  "sources": [
    {
      "name": "StevenBlack hosts",
      "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
      "enabled": true,
      "format": "hosts",
      "scope": "everyone",
      "refresh_secs": 43200,
      "last_fetch": 3600,
      "last_fetch_at": "2026-10-24T09:15:00+00:00",
      "domains": 182344,
      "last_error": null
    }
  ],
  "total_domains": 182344
}
```

Returns `404` when no sources are configured.

`PUT` replaces the complete source list (body: `{"sources": [...]}` with the
same fields as the config file) - this is what the console's add / edit /
remove flow calls. An optional `"renames": {"old name": "new name"}` keeps
the filtering groups that select a renamed source pointing at it; groups drop
any source that is no longer in the list.

A source's `scope` is `everyone` (the default: it blocks for every client)
or `groups` (it blocks only for the filtering groups that list it in their
`blocklists`; see Blocking groups below). The legacy `dot` scope is still
accepted for existing configurations but is no longer offered in the console.
For listener-specific filtering, use a filtering group whose `clients` includes
`DOT`, `DOH` or `DOQ`. Each source is validated, the list is persisted to the
**SQLite database** (the config file is no longer rewritten), and the
running server swaps its sources and refetches
them in the background immediately; the change survives a restart.
Removing the last source (or disabling all of them) clears the remote
blocklist right away.

`GET /validate` probes a candidate URL **without saving it** and reports
whether its content matches the declared format, so a mislabeled source is
caught before it is added:

```json
{
  "ok": true,
  "format": "hosts",
  "domains": 182344,
  "sample": ["0.0.0.0", "ads.example.com"]
}
```

`format` accepts `domains`, `wildcard`, `hosts`, `adblock`, `rpz`, or `auto`
(empty = auto) to auto-detect the format from the content. A `wildcard`
source is a list of names that each also cover their subdomains (oisd's
`domainswild2`: `example.com` blocks `ads.example.com` too); auto-detect
picks it for a plain list of names when the URL or the list's comments say
"wild". `domains` and `wildcard` content looks the same, so either can be
chosen for such a list. An `rpz` source is a
Response Policy Zone in zone-file form (as served over HTTP by most RPZ
feeds): every QNAME trigger in it is blocked, wildcards (`*.example.com`)
included, whatever its action (NXDOMAIN, NODATA, drop, a walled-garden CNAME
or local data); `rpz-passthru.` entries are exceptions and are left out, and
IP and NSDNAME triggers are ignored (to use an RPZ feed's own actions, add it
under Response Policy Zones instead). `ok: false` with a `reason` means
the URL fetched fine but the content does not parse as (or does not match)
`format`; a `502` means the URL itself could not be fetched.

### AI scanner

```
GET  /api/ai/status
GET  /api/ai/verdicts?status=classified&category=phish&severity=threat&exemption=not_exempt&q=example&page=1&per_page=50
GET  /api/ai/threats?category=phish&severity=threat&exemption=not_exempt&q=example&page=1&per_page=50
GET  /api/ai/overrides
POST /api/ai/override          {"domain": "x.example", "action": "allow|clear|category|clear_category", "category": "gambling", "reason": "..."}
POST /api/ai/rescan
GET  /api/ai/model-status
POST /api/ai/update-models
```

Available when `[ai] enabled = true`. The scanner runs two independent
channels: `content` categorizes sites (`news`, `shopping`, ...) and stores a
label only, `threat` looks only for `ai.auto_block_categories` and is the
only channel that can block on its own. Each channel has its own model,
confidence floor and verdict TTL. Blocking a *content* category is an
operator rule on a client group (`blocked_categories`, see Advanced
blocking) - the label comes from the scanner, the decision does not.

`GET /api/ai/status` reports the mode (`train`/`enforce`), the pipelines
actually running (`backend`, plus `content_backend` and `threat_backend`
individually: `heuristic`, `fasttext` or `fasttext+minilm-onnx`; a
configured model file that is missing falls back to `heuristic`), workers,
intervals, TTLs and thresholds (`confidence_floor` is the threat channel's,
`category_confidence_floor` the categorizer's), per-status domain counts,
`blockable_counts` (domains that qualify for auto-blocking, by category:
blocked in enforce mode, what would be blocked in train mode) and the
current block-snapshot size.

A domain qualifies for auto-blocking when its *threat-channel* verdict is in
one of `ai.auto_block_categories` with a confidence at or above
`ai.block_threshold`, and neither it nor a parent domain is exempt. A
content-channel verdict never qualifies, whatever it is called. A threat
verdict the MiniLM verifier disagreed with (severity `disputed`, decided at
`ai.verifier_threshold`) never qualifies.
The built-in heuristic rules score at most 0.35, so they never auto-block on
their own. Only internet names are classified: single-label names, reverse
lookups, local-only suffixes (`.local`, `.home.arpa`, `.internal`, `.lan`,
...) and names in zones this server hosts are skipped.

`GET /api/ai/verdicts` pages through the categorizer's verdicts (`channel`
defaults to `content`; `channel=threat` shows the threat channel, which
`/api/ai/threats` presents), most recently
classified first (pending rows last), optionally filtered by `status`
(`pending`/`classified`/`skipped`), category substring `category`, severity
(`info`/`threat`/`disputed`), exemption (`exempt`/`not_exempt`), and domain
substring `q`: domain, channel,
category, severity, status, confidence, backend, evidence, observation count
(scan cycles the domain appeared in), `overridden` (the domain is exempt) and
`classified_at`/`expires_at` in RFC 3339 (at expiry the verdict is
re-checked if the domain has been queried since; otherwise it is dropped,
and the domain starts over if it is queried again). `per_page` is capped at 500.

`GET /api/ai/threats` is the same paging with the same row shape, restricted
to classified threats: verdicts with severity `threat` or `disputed`,
highest confidence first, with optional category substring `category`, severity
(`threat`/`disputed`), exemption (`exempt`/`not_exempt`) and domain substring
`q` filters. Each row
also carries `blocked`, whether the domain is in the *current* block
snapshot - actually auto-blocked in enforce mode (in train mode the snapshot
is empty, so every row is `false`). The console's AI → Threats tab renders
this list.

Model files are managed over the API too: `GET /api/ai/model-status` reports
the models directory, each installed model file (presence, size, sha256) and
the shared update state (so an in-flight update can be followed from there);
`POST /api/ai/update-models` starts a models-only update - download the
models bundle from the latest release and hand it to the privileged apply
service, which installs the files and restarts the server. A `202` only
means the update began; poll `GET /api/ai/model-status` until `done`/`error`.

`POST /api/ai/override` with `action: "allow"` exempts a domain and its
subdomains from AI blocking; `clear` removes the exemption (`404` when there
is none). `GET /api/ai/overrides` lists the exemptions, newest first.
`action: "category"` relabels the domain with `category` (one of the
labels reported in `backend_categories`; `400` otherwise, with the known
list), and `clear_category` drops the relabel (`404` when there is none).
A relabel is shown and filtered instead of the model's label, survives
re-scans, and is what category blocking matches; the row also carries
`category_overridden` so the console can mark it.
`POST /api/ai/rescan` wakes the scanner for one immediate cycle.

All of these return `404` when the AI subsystem is disabled.

### Advanced blocking




```
GET    /api/policy/blocking
POST   /api/policy/blocking
DELETE /api/policy/blocking/{id}
POST   /api/policy/blocking/{id}/move
POST   /api/policy/blocking/test
```

Blocking groups (the console's **Clients → Filtering Groups**; the
`recursive.client_policies` list is its **Clients → Resolution Policies**)
extend the policy engine with per-group client and domain criteria, including regular expressions (`allow_regex` / `block_regex`;
invalid patterns are rejected with `400` instead of being silently dropped
at engine-build time). A group's `clients` list normally holds CIDRs or
single addresses (or network names); the special case-insensitive entries
`DOT`, `DOH` and `DOQ` instead match a query by the encrypted listener it
arrived on (plain port-53 queries never match those entries), which is how
a group targets public/remote users - their addresses cannot be expressed
as networks. Any combination of networks and listener entries is allowed;
a group matches when either side matches. `blocklists` names remote
blocklist sources whose
`scope` is `groups`: their domains are blocked for the group's clients, and
the group's `allow` list still overrides them (`400` for a name that is not
a configured source).
`ai_blocking` (default `true`) lets the AI scanner auto-block the group's
clients in enforce mode. A client follows the first enabled group that
covers it, and clients in no group are covered; to use the AI for some
groups only, put a group covering every client with `ai_blocking: false`
last.
`safe_search` and `youtube_restricted` (default `false`) turn Safe Search
and YouTube Restricted Mode on for the group's clients, by the same
first-group rule; the global `policy.safe_search` and
`policy.youtube_restricted` switches apply to every client whatever the
groups say.
`blocked_services` lists services (by id, e.g. `["tiktok", "roblox"]`) the
group blocks: every domain the service uses, and its subdomains (`400` for
an unknown id; ids are stored in their canonical form). `GET
/api/policy/services` returns the catalog: `{"services": [{"id", "name",
"category", "domains"}]}`. The group's `allow` list still wins.
`blocked_categories` lists AI content categories (lowercase labels, e.g.
`["gambling", "ads"]`; the model's own labels as reported by
`GET /api/ai/status`'s `backend_categories`) whose domains the group
blocks, subdomains included. It is independent of `ai_blocking`: the AI
scanner only supplies the label, so this applies in both `train` and
`enforce` mode, while `ai_blocking` governs auto-blocking of detected
threats. The group's `allow` list and any AI exemption still win.
`schedule` limits when the group applies: a list of
`{"days": ["mon", "fri"], "start": "21:00", "end": "07:00"}` windows
(`days` from `mon`..`sun`, full names accepted, empty for every day; times
`HH:MM`, 24-hour). An `end` earlier than `start` runs past midnight into
the next day, and equal times cover the whole day. Outside every window
the group is skipped as if it did not exist (for blocking, AI blocking
and Safe Search alike). Times are read in `display.time_zone` (`system`:
the server's own zone). An empty list (the default) means always; a bad
window is `400`.
`POST /api/policy/blocking` creates a group or updates the one with the same
name; with an `id` it updates that group, so it can be renamed (`400` if
another group has the new name, `404` if the id is unknown). The
dispatcher's blocking engine is rebuilt immediately. Group objects carry
`last_modified_at` (RFC 3339): the time of the last create or edit.
Reordering with `move` does not change it, and rows written before the
field existed read `null` until their next edit.
`DELETE /api/policy/blocking/{id}` removes a group.
`POST /api/policy/blocking/{id}/move` with `{"direction": "up"}` or
`{"direction": "down"}` swaps the group with its neighbour and returns the
reordered list. Groups are evaluated in this order.
`POST /api/policy/blocking/test` accepts an optional `"listener"` of
`"doT"` / `"doH"` / `"doq"` (case-insensitive, omitted or `null` for plain
DNS) so a group's listener entries can be tested.

```
GET    /api/policy/explain?domain=&client=&qtype=A&listener=
```

`GET /api/policy/explain` says why `domain` is or is not blocked for
`client` (an address, or a device name from Clients -> Devices; `400`
otherwise), as an `A` query unless `qtype` says otherwise, over plain DNS
unless `listener` is `dot`, `doh` or `doq`. It answers:

- `verdict`: what the server does with the query now, decided as a real
  query is: `{"blocked": true, "source", "group", "matched", "reason",
  "action"}` (`source` as in the query log; `action` is `block` for
  NXDOMAIN, `refused`, `redirect`, `nodata`, or the RPZ action), or
  `{"blocked": false, "source", "reason"}` (`source` is `allowlist` when
  Custom Allow lets it through).
- `checks`: every check that is set up, in the order queries meet them, and
  what each does with the domain, without stopping at the first that
  decides: denied networks, Custom Allow, Custom Block, each subscribed
  feed in Blocklists that lists it, per-client rules, Filter AAAA, the AI scanner,
  then each filtering group covering the device (including groups outside
  their schedule, as `off`), response policy zones and Safe Search. Each is
  `{"source", "result", "detail", "matched", "group", "action"}`, with
  `result` one of `block`, `allow`, `rewrite`, `none` or `off`.
- `recent`: the latest blocks of exactly this domain in the query log (any
  device, up to 10), with their `block` reasons, which also covers checks
  made on answers (CNAME inspection, RPZ answer triggers).

It changes nothing, so read-only accounts may use it.

`POST /api/policy/blocking/test` evaluates a `{client, domain}` pair against
the live filtering groups and reports whether (and why) it is blocked, so an
operator can verify rules before relying on them. It also reports
`ai_blocking` (whether the AI may auto-block that client's queries) and
`ai_group` (the group that decided; `null` when the client is in no
group), whether `safe_search` and `youtube_restricted` apply to the client,
and `safe_search_target`: the safe address the domain is answered with
(`null` when it is not rewritten), and `scheduled_off`: the groups covering
the client that are outside their schedule right now.

#### Safe Search

With Safe Search on for a client, `google.com` and Google's country sites
(`google.de`, `google.co.uk`, `google.com.au`, with or without `www.`),
`www.bing.com` and `duckduckgo.com` are answered with a CNAME to
`forcesafesearch.google.com`, `strict.bing.com` or `safe.duckduckgo.com`
plus that name's addresses; with YouTube Restricted Mode on,
`www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`,
`youtube.googleapis.com` and `www.youtube-nocookie.com` point at
`restrict.youtube.com`. `HTTPS`/`SVCB` queries for those names are answered
empty and other types resolve as usual. It applies only to clients allowed
to use recursion, and not to names hosted in a zone here.

### Response policy zones (RPZ)

```
GET    /api/rpz
POST   /api/rpz
POST   /api/rpz/test
```

Response policy zones (the console's **Filtering → Response Policy Zones**)
are DNS firewall rules in the standard RPZ format. The list is the `rpz`
settings group, replaced as a whole and in order by `PUT /api/config` with
`{"rpz": [...]}`; each zone:

| Field | Default | Meaning |
|---|---|---|
| `name` | | The zone's name, e.g. `rpz.example.com`: what is transferred, and the suffix stripped from owner names. |
| `enabled` | `true` | |
| `source` | `local` | `local` (the rules in `rules`), `url` (a zone file fetched from `url`) or `transfer` (AXFR from `primaries`, signed with the TSIG key `tsig_key` when set). |
| `rules` | `""` | `local`: zone-file lines; a line that does not parse is a `400`. |
| `url` | `""` | `url`: an http(s) URL. |
| `primaries`, `tsig_key` | `[]`, `""` | `transfer`: the feed's servers (`IP` or `IP:port`), and a key from `authoritative.tsig_keys`. |
| `refresh_secs` | `3600` | `url`/`transfer`: how often to check for changes (60 at least). A transfer is repeated only when the SOA serial changes. |
| `policy` | `given` | `given` (each rule's own action), `disabled` (count matches, act on none), or an action for every match: `nxdomain`, `nodata`, `passthru`, `drop`, `tcp_only`, `cname` (redirect to `cname_target`). |
| `cname_target` | `""` | The walled-garden name for `policy` `cname`. |

Triggers (owner names, relative to the zone): a domain or `*.domain`
(`*.example.com` covers names under `example.com`, not the name itself);
`prefix.reversed-address.rpz-client-ip` for the client's address
(`32.7.1.168.192.rpz-client-ip` is `192.168.1.7/32`; IPv6 words are reversed
too, `zz` standing for `::`); and `prefix.reversed-address.rpz-ip` for an
address in the answer. A domain trigger also matches a name in the answer's
CNAME chain. `name.rpz-nsdname` (or `*.name.rpz-nsdname`) matches a name
server of the answer's domain by name, and `prefix.reversed-address.rpz-nsip`
by address: the name servers are those of the closest enclosing name with NS
records (below the top-level domain), looked up through the resolver (and
their addresses, for NSIP) only when some zone has such triggers. Triggers
of an unknown kind are counted as `unsupported` and skipped.

Actions: `CNAME .` is NXDOMAIN, `CNAME *.` NODATA, `CNAME rpz-passthru.`
exempts the query from the rest of RPZ (as does a CNAME to the trigger
itself), `CNAME rpz-drop.` sends no answer, and `CNAME rpz-tcp-only.`
answers UDP queries truncated so the client retries over TCP (TCP queries
go through). Any other records are local data, answered instead of the real
answer: records of the queried type, else a CNAME (followed, so a walled
garden returns its address; a target `*.garden.example.` becomes the query
name under the garden), else NODATA.

Zones are checked in order and the first that matches decides. Within a
zone, triggers are checked in the standard order (client IP, domain, answer
IP, NSDNAME, NSIP), an exact domain before a wildcard, and the longest
wildcard or address prefix wins. Answer triggers (CNAME targets, answer
addresses, name servers) are checked on recursive answers.
RPZ applies to what the blocklists and filtering groups let through, and an
allowlisted name is exempt. A zone that cannot be loaded keeps its last
loaded rules; failures raise a `blocklist_failure` (URL) or
`zone_transfer_failure` (transfer) alert.

`GET /api/rpz` returns `{"zones": [...]}`, each with `name`, `enabled`,
`source`, `policy`, `loaded`, `rules` (`qname`, `wildcard`, `client_ip`,
`response_ip`, `nsdname`, `nsip`, `unsupported` counts), `serial`, `last_loaded`, `last_checked`
(RFC 3339), `last_error` and `hits` (matches since start, those of a
`disabled` zone included). `POST /api/rpz` checks every URL and transfer
zone for changes now (`202`). `POST /api/rpz/test` with `{"client",
"domain"}` lists the zones that match, in order: `{"allowlisted", "matches":
[{"zone", "trigger", "action", "log_only"}]}`; the first match that is not
`log_only` is the one that acts.

### Encrypted DNS discovery (DDR)

The `ddr` settings group (Settings → Encrypted DNS) answers Discovery of
Designated Resolvers (RFC 9462): an `SVCB` query for `_dns.resolver.arpa`,
or for `_dns.<name>` where `<name>` is a name the encrypted listeners go by
(and not a zone hosted here), gets one SVCB record per enabled DoH, DoT and
DoQ listener the client is allowed on (its `allowed_networks`): priority 1
upwards, the target name, `alpn` (`h2`, plus `h3` with `doh.http3`; `dot`;
`doq`), `port`, `ipv4hint`/`ipv6hint` when the listener is bound to
specific addresses, and for DoH `dohpath` (`<endpoint>{?dns}`, RFC 9461).

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Off: the queries are answered empty. |
| `name` | `""` | The target name devices connect to (it must be in the certificate); empty: each listener's certificate name (`server_name`, or the stored certificate's). |

Other queries under `resolver.arpa` are never forwarded: `resolver.arpa` and
`_dns.resolver.arpa` are answered empty for other types, and other names
under it NXDOMAIN. Devices verify the designated resolver's certificate
(it must be trusted and cover the address they use for this server), so a
self-signed certificate is usually not taken up.

### Block page

The `block_page` settings group (Filtering → Response Filters, replaced as
a whole by `PUT /api/config` with `{"block_page": {...}}`) answers blocked
names with this server's address, where a small web server shows a page
saying what was blocked and why:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Requires `ipv4` or `ipv6`. |
| `ipv4`, `ipv6` | `""` | The address blocked A (AAAA) queries are answered with: this server, as clients reach it. Without `ipv6`, blocked AAAA queries are answered empty; without `ipv4`, A queries keep NXDOMAIN. |
| `listen`, `port` | `0.0.0.0`, `80` | Where the page is served (plain HTTP). The port may not be one the web console, the API or a DoH/DoT listener uses (`400`). |
| `message` | `""` | Extra text on the page (escaped; 2000 characters at most). |

It applies to blocks that would be NXDOMAIN: Blocklists, Custom Allow and
Custom Block, the AI scanner, CNAME inspection, and filtering groups whose
`response` is NXDOMAIN. `HTTPS`/`SVCB` queries for blocked names are
answered empty. The page answers every path with `403` and HTML naming the
`Host` and, when the visitor's lookup was within the last 10 minutes, the
block reason. HTTPS sites cannot show it (the browser reports a certificate
or connection error instead).

### Response rate limiting (RRL)

The `rrl` settings group (Settings → Rate Limiting, replaced as a whole by
`PUT /api/config` with `{"rrl": {...}}`) limits identical UDP responses per
client network, against reflection and amplification attacks:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `responses_per_second` | `10` | Identical answers (same name and type) per second per network. |
| `nxdomains_per_second` | `10` | NXDOMAIN answers per second per network and parent domain. |
| `errors_per_second` | `10` | Error answers (SERVFAIL, REFUSED...) per second per network. `0` in any of the three: no limit. |
| `window_secs` | `15` | How much excess (in seconds of the rate) a network's account remembers. |
| `slip` | `2` | Every `slip`-th limited response is sent truncated (TC, no records) instead of dropped, so a real client retries over TCP; `0` drops all, `1` truncates all. |
| `ipv4_prefix`, `ipv6_prefix` | `24`, `56` | The size of a client network. |
| `exempt` | loopback | Networks never limited (addresses, CIDRs or network names). |
| `log_only` | `false` | Count what would be limited (`rrl_would_limit`) without limiting. |

TCP responses, and responses to a request with a valid DNS server cookie
(whose source address is proven), are never limited.

### Alerts

```
POST   /api/alerts/test
```

The `alerts` settings group (Settings -> Alerts, replaced as a whole by
`PUT /api/config` with `{"alerts": {...}}`) sends an alert when something
needs attention:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Send alerts at all (needs a webhook or an SMTP server). |
| `webhook_url` | `""` | Each alert is `POST`ed here as JSON: `source`, `host`, `kind`, `title`, `message`, `time`, plus `text`/`content` (the summary, for Slack, Mattermost, Discord and Teams webhooks). |
| `smtp_server`, `smtp_port` | `""`, `587` | Email via this server (empty: no email). |
| `smtp_security` | `starttls` | `starttls`, `tls` (implicit TLS, usually port 465) or `none`. |
| `smtp_username`, `smtp_password` | `""` | Sign-in, when the server needs it. The password reads back as `[redacted]`; sending `[redacted]` keeps the stored one. |
| `email_from`, `email_to` | `""`, `[]` | Sender and recipients (required with an SMTP server). |
| `blocklist_failures` | `true` | A remote blocklist cannot be downloaded (`kind` `blocklist_failure`). |
| `zone_transfer_failures` | `true` | A secondary zone cannot be refreshed (`zone_transfer_failure`). |
| `certificate_expiry` | `true` | A console-managed certificate expires within 14 days, or an ACME request failed (`certificate_expiry`). |
| `dnssec` | `true` | A key rollover started (the parent DS needs the new key), or re-signing failed (`dnssec`). |
| `update_available` | `true` | A newer release is available (`update_available`), once per release. |
| `update_failure` | `true` | A scheduled stable-release update failed; includes rollback and service health-check results (`update_failure`). |
| `ai_blocks` | `false` | The AI scanner in Enforce mode started blocking new domains (`ai_blocks`). |

A failure that persists is reported again after 6 hours at the soonest (24
hours for certificates); once it clears, the next failure is reported right
away. `POST /api/alerts/test` sends a test alert (`kind` `test`) with the
saved settings, or with `{"alerts": {...}}` from the body (unsaved form
values), whether or not alerts are enabled. It answers `{"sent": true}`, `400`
for invalid settings, or `502` naming each destination that failed.

### Reports

```
GET    /api/reports?hours=24[&client=192.168.1.7][&top=20]
POST   /api/reports/send
```

`GET /api/reports` summarizes the query log (the database one; see
`logging.query_db_enabled`, also returned as `query_log_enabled`) over the
last `hours` (default 24, at most 90 days), for every client or only
`client`: `{"hours", "query_log_enabled", "report": {"since", "queries",
"blocked", "clients_seen", "clients": [{"client", "queries", "blocked",
"last_seen"}], "top_domains": [{"name", "count"}], "top_blocked":
[{"name", "count", "source", "group", "matched"}],
"timeline": [{"hour", "queries", "blocked"}], "outcomes": [{"name",
"count"}], "rcodes": [...], "block_sources": [...], "block_rules":
[{"source", "group", "matched", "count"}], "failing": [{"name", "rcode",
"count"}], "qtypes": [{"name", "count"}], "protocols": [...], "latency":
{"queries", "average_ms", "median_ms", "p95_ms", "max_ms"},
"latency_buckets": [{"name", "count"}], "slowest": [{"name", "queries",
"average_ms", "max_ms"}], "new_names_total", "new_names": [{"name",
"first_seen", "queries", "blocked"}], "zones": [{"zone", "queries",
"nxdomain"}]}}`, the lists cut to `top` entries (default 20, at most 100),
busiest first.

- `timeline`: queries and blocks per UTC hour (`hour` is its start, RFC
  3339), oldest first; hours without queries are left out.
- `outcomes`, `rcodes`: every query by outcome (`recursive`,
  `authoritative`, `split_horizon`, `blocked`, `rate_limited`, `error`) and
  by response code (`""` when none was recorded). Not cut to `top`.
- `block_sources`: blocked queries by what blocked them (the query log's
  `block.source`; `""` for blocks logged before reasons were kept). Not cut
  to `top`. `block_rules` breaks them down further by filtering group and
  matched entry, list, service, AI category or zone.
- `top_blocked`: like `top_domains`, but each name also carries the rule
  behind most of its blocked queries: `source` (the query log's
  `block.source`, `""` for blocks logged before reasons were kept),
  `group`, and `matched`
  (the entry, list, service, AI category or zone).
- `failing`: the names answered NXDOMAIN, SERVFAIL or REFUSED most often,
  not counting the server's own blocks and rate limiting.
- `qtypes`, `protocols`: every query by record type and by transport
  (`udp`, `tcp`, `tls`, `https`, `quic`, `h3`). Not cut to `top`.
- `latency`: response times of resolved (`recursive`) queries, cache hits
  included; the server's own answers are left out. `latency_buckets`
  counts them as `under_10`, `10_50`, `50_200`, `200_1000` and
  `over_1000` milliseconds, in that order. `slowest`: the names asked at
  least 3 times with the highest average, slowest first.
- `new_names_total`: how many names (for `client`, when given) were asked
  for the first time in the period, as far back as the query log is kept;
  `new_names` lists the newest of them.
- `zones`: queries answered from each hosted zone, with a zone's aliases
  counted towards it and each name going to the longest zone it is in.

The `reports` settings group (Settings → Alerts, replaced as a whole by
`PUT /api/config` with `{"reports": {...}}`) sends that summary as plain
text on a schedule, to the alert destinations (`alerts.webhook_url` and/or
email; alerts themselves need not be enabled), as an alert of `kind`
`report`:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Requires an alert destination (`400` otherwise). |
| `frequency` | `weekly` | `daily` (covers the last 24 hours) or `weekly` (the last 7 days). |
| `weekday` | `mon` | `weekly`: the day it goes out. |
| `hour` | `8` | The hour it goes out (0-23), in `display.time_zone`. |
| `top` | `10` | Entries per list (1-50). |

One report goes out per period, also across restarts. `POST
/api/reports/send` sends one now, with the saved settings or `{"reports":
{...}}` from the body: `{"sent": true}`, `400` for invalid settings, or
`502` naming what failed (including no destination).

### Devices

```
GET    /api/devices?hours=168
PUT    /api/devices/name
```

`GET /api/devices` lists the clients in the query log over the last
`hours` (default a week, at most 90 days), the addresses holding a DHCP
lease, and addresses named by hand, busiest first: `{"hours",
"query_log_enabled", "devices": [{"address", "mac", "name", "source",
"manual_name", "queries", "blocked", "last_seen"}]}`. `name` is what the
console shows (empty when there is none) and `source` where it came from:
`manual` (named by hand), `dhcp` (the lease's host name) or `reverse_dns`
(a PTR record: a hosted reverse zone, else the resolver, remembered for an
hour). `mac` comes from an IPv4 DHCP lease.

`PUT /api/devices/name` with `{"address", "mac", "name"}` names a device:
for its MAC address when `mac` is given (the name then follows the device
to a new address), else for its IP address. An empty `name` clears it.
Names are at most 63 characters (`400` otherwise, or for a bad address or
MAC); `204` on success. The scheduled report shows devices as
`name (address)`.

### DHCP

```
GET    /api/dhcp
DELETE /api/dhcp/leases/{address}
```

`GET /api/dhcp` returns `{"status": {"supported", "v4", "v6",
"server_duid"}, "interfaces": [{"name", "index", "addresses"}], "leases":
[...]}`. `v4` and `v6` say `Off`, `Listening on UDP port 67` (`547`), or
why the listener could not start; `supported` is false off Linux. Each
lease is `{"address", "scope", "client_id", "hw_address", "hostname",
"state", "expires", "dns_name", "dns_records", "updated_at"}`: `state` is
`offered`, `bound`, `released` or `declined` (the address is in use by
another device and is skipped for an hour), `expires` is UNIX seconds,
`hw_address` is the MAC address (IPv4) or the DUID (IPv6), and
`dns_records` the ids of the zone records registered for it. `DELETE`
forgets a lease and removes its records (`204`, `404` when there is none).

The `dhcp` settings group (DHCP → Settings and the scope tabs, replaced as
a whole by `PUT /api/config` with `{"dhcp": {...}}`, `400` naming the
problem):

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Run the server (UDP 67 and 547; needs root or `CAP_NET_BIND_SERVICE`). |
| `dns_zone` | `""` | Hosted zone that bound leases with a host name are registered in (A/AAAA, plus a PTR in the most specific hosted reverse zone). A name with records of its own is left alone. |
| `scopes` | `[]` | IPv4 scopes, below. |
| `scopes_v6` | `[]` | IPv6 scopes, below. |

An IPv4 scope is `{"name", "enabled", "interface", "subnet", "range_start",
"range_end", "router", "dns_servers", "domain_name", "ntp_servers",
"lease_secs", "reservations", "options"}`. It serves `interface`, or when
that is empty the interface with an address in `subnet`, and requests
from a DHCP relay whose address (`giaddr`) is in `subnet`. Empty
`dns_servers` hands out this server's address on that network.
`lease_secs` defaults to 86400. `reservations` are `{"client": MAC,
"address", "hostname", "description"}`; `options` are extra DHCP options,
`{"code": 1-254, "value"}` with the value as text or as hex starting
`0x`. Subnets may not overlap.

An IPv6 scope is `{"name", "enabled", "interface", "prefix",
"range_start", "range_end", "dns_servers", "domain_search",
"preferred_secs", "valid_secs", "reservations"}`, with reservations keyed
by DUID (hex). With no range it is stateless: it answers
Information-request with the DNS servers and search list only. Routers
keep sending the router advertisements; their managed (M) and other (O)
flags decide whether devices ask. Rapid Commit is supported; relayed
DHCPv6 and prefix delegation are not.

### Backup and restore

```
GET    /api/backup[?query_logs=true]
GET    /api/backup/restore
POST   /api/backup/restore
DELETE /api/backup/restore
```

Admin only (viewers get `403`): a backup holds private keys and password
hashes.

`GET /api/backup` downloads a backup as one SQLite file
(`daygle-dns-backup-YYYYMMDD-HHMM.db`): a consistent copy of the database
(zones, records, DNSSEC keys, settings, console users, certificates,
blocking groups, split horizon, secondary and stub zones) plus the AI
scanner's operator overrides. AI verdicts are a cache and are not included.
Query logs are left out unless `query_logs=true`.

`POST /api/backup/restore` takes a backup file as the request body (up to
1 GiB). It checks the file is an intact backup made by this or an earlier
version, then stages it to replace the database when the server next
starts; nothing changes while it runs. The response, and
`GET /api/backup/restore`, report what is staged (`null` when nothing is):

```json
{ "pending": { "created_at": 1792000000, "app_version": "1.0.0", "zones": 4,
  "records": 52, "users": 2, "certificates": 1, "query_logs": 0, "ai_overrides": 3 } }
```

A file that is not a backup gets `400`. `DELETE /api/backup/restore` drops
the staged restore (`204`, or `404` when none is staged). On the next start
the current database is renamed `<database>.before-restore-<unix time>` and
the backup takes its place; the backup's AI overrides replace those in the
AI database. The same is available from the command line:
`daygle-dns backup FILE [--query-logs]` (safe while the server runs) and
`daygle-dns restore FILE` (then restart).

### Audit log

```
GET /api/audit[?user=NAME][&q=TEXT][&before_id=ID][&limit=100]
```

Admin only. Every change made through the API (any method other than
`GET`/`HEAD`/`OPTIONS`), every backup download, and every sign-in attempt
and first-run setup is recorded once it has run, newest first:

```json
[{ "id": 42, "ts": 1792540000, "username": "glen", "via": "session",
   "client": "192.168.1.20", "action": "Changed settings",
   "method": "PUT", "path": "/api/config", "status": 200 }]
```

`via` is how the caller signed in: `session`, `api_token`, `static_token`,
`open` (authentication off), or `password` for a sign-in. `action` says
what was done in words, falling back to the method and path. Request
bodies are never stored. Requests refused before they ran (`401`/`403` from
authorization) are not recorded, apart from failed sign-ins. `q` matches the
action or path; `before_id` pages back. Entries are kept for a year, and
backups carry them.

### In-place updates

```
GET    /api/update
GET    /api/update/status
POST   /api/update/start
POST   /api/update/dismiss
GET    /api/update/preflight
```

`GET /api/update` reports host-level information relevant to upgrading. The
canonical update path is the one-line installer; on a qualifying systemd
install (`can_update: true`) the console can upgrade in place with
`POST /api/update/start` (admin only) - a `202 Accepted` only means the
update began, because the updater runs detached, hands the privileged step
to the root systemd update service, and restarts the server; poll
`GET /api/update/status` for progress and to detect the restart (the status
is read from a shared state file, so it still reports the outcome of the
run that restarted the server). `POST /api/update/dismiss` (admin only)
clears the last result. `GET /api/update/preflight` (admin only - it probes
GitHub and the staging directory) checks readiness beforehand.

## Errors

Errors use a uniform body and an appropriate status code:

```json
{ "error": "already exists: zone already exists" }
```

Status codes: `400` invalid input, `401` unauthorized, `403` forbidden
(read-only `viewer` account), `404` not found, `409` conflict, `500`
internal error.
