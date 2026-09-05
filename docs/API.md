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
  "token": "1f2e3d4c5b6a7988…",
  "username": "admin",
  "role": "admin",
  "expires_in_secs": 43200
}
```

Send the returned token as the `Authorization: Bearer` header on every call.
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
| `GET /api/auth/me` | identity of the presented session (`username`, `role`, `expires_at_secs`) |
| `POST /api/auth/logout` | revoke the presented token |
| `POST /api/auth/password` | signed-in user rotates their own password (current password required; other sessions revoked) |
| `GET /api/auth/setup` | whether the one-time first-run setup is still pending |
| `POST /api/auth/setup` | one-time creation of the first admin account (returns a session) |
| `GET /api/users` | list accounts (password hashes redacted) |
| `POST /api/users` | create an account (`username`, `password`, optional `role`) |
| `PATCH /api/users/{username}` | reset password / change role / enable-disable |
| `DELETE /api/users/{username}` | delete an account |

The last enabled `admin` account cannot be deleted, demoted, or disabled.
Password, role, and enabled changes (and deletions) immediately revoke the
affected account's sessions; disabled accounts cannot log in.

Roles:

- `admin` - full access (reads *and* mutations).
- `viewer` - read-only; every mutating method (`POST`/`PUT`/`DELETE`) is
  rejected with `403 Forbidden`.

Sensitive values are never echoed back: `GET /api/config` reports
`api.api_token` and every `api.users[].password_hash` as `"[redacted]"`.
Failed login attempts are logged and do not reveal whether the username
exists.

## Endpoints

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
  "dnssec": true,
  "dot_enabled": true,
  "api_enabled": true
}
```

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
  "dnssec_validated": 500,
  "bytes_in": 45056,
  "bytes_out": 0
}
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

### Query logs

```
GET    /api/querylogs?client=&qname=&qtype=&protocol=&outcome=&rcode=&from=&to=&page=1&per_page=50
DELETE /api/querylogs
```

Every served DNS query is recorded into the SQLite database (when
`logging.query_db_enabled`, on by default) with its client address, query
name/type, transport (`udp`, `tcp`, `tls`, `https`, `quic`), outcome
(`authoritative`, `recursive`, `split_horizon`, `blocked`, `rate_limited`,
`error`), response code and server-side handling time. The console's
**Logs → Query Logs** tab searches this history.

`GET` returns a page of entries (newest first) plus the total count under
the same filter. `qname` accepts `*` wildcards (`*.example.com`, `www.*`)
and substring matching otherwise; `from`/`to` are RFC 3339 timestamps;
`per_page` is capped at 500. `format=csv` streams the whole filtered set
(no pagination) as a CSV download. `DELETE` clears the log (admin only);
retention is bounded by `logging.query_db_max_rows` (0 = unlimited).

### Configuration

```
GET  /api/config
POST /api/config/reload
```

`GET` returns the effective `DaygleConfig` document (the TOML configuration,
serialized as JSON) with secrets redacted (see [Console users and roles](#console-users-and-roles)).

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

Editable groups: `server` (listen/port/udp_enabled/tcp_enabled), `recursive`
(enabled/upstreams/dnssec_validate/prefetch_* /serve_stale_secs), `dot`,
`doh`, `doq` (enabled/port/self_signed/server_name [+ `doh.endpoint`]), and
`api` (gui_enabled/cors_origins). Runtime groups (`recursive`, `dot`, `doh`,
`doq`, `policy`) are stored in the database and survive restarts and
config-file edits; `server.*` and `api.*` stay config-file-owned so a broken
listener can always be fixed by editing the file. Login users are managed
from the console's **Users** page (see [Console users and roles](#console-users-and-roles)).

`POST /api/config/reload` asks the server to re-read its configuration file and
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
```

Create a zone:

```json
POST /api/zones
{
  "name": "example.com",
  "zone_type": "primary",
  "primary_ns": "ns1.example.com.",
  "admin_mailbox": "admin.example.com.",
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

Only `name` is required for a primary zone. `zone_type` defaults to `primary`.
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

Secondary zones are added to `authoritative.secondary_zones`, persisted to the
configuration file, applied to the running refresher immediately, and pulled
over AXFR/IXFR from the first reachable master. Their records are read-only in
the GUI and record mutation endpoints return `409 Conflict`.

> Note: secondary-zone definitions are still config-file-owned (they describe
> infrastructure that must be available before the database is consulted),
> unlike runtime settings such as upstreams and policy lists, which live in
> the database.

Import a BIND zone file (creates the zone and replaces its records):

```json
POST /api/zones/import
{
  "name": "example.com",
  "text": "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA …\n"
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
`authoritative.update_networks` client allow-list, and are always refused for
secondary zones. Prerequisites (value-dependent / value-independent /
not-exists forms) are fully checked; failed updates return their RFC 2136
RCODE (YXDOMAIN, YXRRSet, NXDOMAIN, NXRRSet, NOTAUTH, …).

NOTIFY (RFC 1996) is likewise a DNS-protocol feature. When
`authoritative.notify_enabled` is set, a successful dynamic update sends a
NOTIFY (OpCode 4, QTYPE SOA, UDP) to every address in
`authoritative.notify_targets`; secondaries that receive it immediately query
our SOA and pull an IXFR/AXFR when the serial advanced. When
`authoritative.notify_listen_enabled` is set, the server also accepts
NOTIFYs for its configured secondary zones on the main UDP port, replies with
the current SOA, and refreshes that zone immediately (the refresh interval
remains the fallback and serials are always compared before a transfer).

### Records

```
GET    /api/zones/{id}/records
PUT    /api/zones/{id}/records
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
`SRV`, `PTR`, `CAA`.

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
client's network. A **network** is a named group of CIDRs (e.g. `LAN =
["192.168.20.0/24"]`); an **entry** maps a domain to a list of typed records
for a set of networks (network names and/or literal CIDRs; empty = every
client).

`GET` returns everything. `ips` is kept for backward compatibility and always
holds the A/AAAA subset of `records`:

```json
{
  "networks": [
    { "id": "…", "name": "LAN", "cidrs": ["192.168.20.0/24"] }
  ],
  "entries": [
    {
      "id": "…",
      "domain": "www.example.com",
      "networks": ["LAN"],
      "ips": ["10.0.0.5"],
      "records": [
        { "rtype": "A", "content": "10.0.0.5" },
        { "rtype": "TXT", "content": "\"internal only\"" }
      ],
      "ttl": 60,
      "disabled": false,
      "position": 0
    }
  ]
}
```

Create or update a network (matched by `name`; the `id` is kept stable on
update):

```json
POST /api/split-horizon/networks
{
  "name": "LAN",
  "cidrs": ["192.168.20.0/24", "10.0.0.0/8"]
}
```

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

### DNSSEC signing

```
POST /api/zones/{id}/sign
POST /api/zones/{id}/unsign
```

`sign` generates a signing key (if absent), signs the zone, and reloads the
catalog. `unsign` removes the key.

Once signed, a zone is maintained automatically: RRSIGs are renewed before
they expire and keys are rolled over on schedule (double-signing during the
overlap, the old key retired and eventually removed) - see the `dnssec_*`
settings under `authoritative` in `daygle-dns.toml`. Manual `unsign` removes all
keys (including any mid-rollover ones) and stops the maintenance for that
zone.

### Cache

```
POST /api/cache/clear
```

Flushes the recursive resolver cache.

### Blocklist sources

```
GET  /api/policy/blocklist/sources
POST /api/policy/blocklist/sources
PUT  /api/policy/blocklist/sources
GET  /api/policy/blocklist/sources/validate?url=...&format=...
```

`GET` returns per-source status for the remote blocklist sources configured
under `[[policy.blocklist_sources]]`: name, URL, format, refresh interval,
last-fetch age, and the number of domains each source contributed.

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
      "refresh_secs": 43200,
      "last_fetch": 3600,
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
remove flow calls. Each source is validated, the list is persisted to
`daygle-dns.toml`, and the running server swaps its sources and refetches
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

`format` accepts `domains`, `hosts`, `adblock`, or `auto` (empty = auto) to
auto-detect the format from the content. `ok: false` with a `reason` means
the URL fetched fine but the content does not parse as (or does not match)
`format`; a `502` means the URL itself could not be fetched.

## Errors

Errors use a uniform body and an appropriate status code:

```json
{ "error": "already exists: zone already exists" }
```

Status codes: `400` invalid input, `401` unauthorized, `403` forbidden
(read-only `viewer` account), `404` not found, `409` conflict, `500`
internal error.
