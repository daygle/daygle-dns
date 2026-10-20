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
| `GET /api/auth/me` | identity of the presented session (`username`, `role`, `expires_at_secs`), the account's own date/time `preferences` and the server's `display_defaults` |
| `PUT /api/auth/preferences` | signed-in user sets their own `{time_zone, date_format, time_format}`; an empty field means the server default (viewers may use it too) |
| `POST /api/auth/logout` | revoke the presented token |
| `POST /api/auth/password` | signed-in user rotates their own password (current password required; other sessions revoked) |
| `GET /api/auth/setup` | whether the one-time first-run setup is still pending |
| `POST /api/auth/setup` | one-time creation of the first admin account (returns a session); body: `{ "username", "password" }` plus optional `name` (first/last display name), `email` |
| `GET /api/users` | list accounts (password hashes redacted) |
| `POST /api/users` | create an account (`username`, `password`, optional `role`) |
| `PATCH /api/users/{username}` | reset password / change role / enable-disable |
| `DELETE /api/users/{username}` | delete an account |

The last enabled `admin` account cannot be deleted, demoted, or disabled. The initial admin account may be created with an optional display name (`name`, stored as `first_name`/`last_name`) and `email`; these follow the same profile fields as accounts created through `POST /api/users` and can be edited later.

Password, role, and enabled changes (and deletions) immediately revoke the
affected account's sessions; disabled accounts cannot log in.
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

Public liveness endpoint, exempt from authentication (the in-place updater
uses it to verify a restarted service is serving HTTP without carrying
credentials); it exposes no configuration or zone data.

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
**Logs → Query Log** tab searches this history.

`GET` returns a page of entries (newest first) plus the total count under
the same filter. `qname` accepts `*` wildcards (`*.example.com`, `www.*`)
and substring matching otherwise; `from`/`to` are RFC 3339 timestamps
with any UTC offset (a bare `YYYY-MM-DDTHH:MM[:SS]` is taken as UTC;
anything else is `400`), both inclusive to the second;
`per_page` is capped at 500. `format=csv` streams the whole filtered set
(no pagination) as a CSV download. `DELETE` clears the log (admin only);
retention is bounded by `logging.query_db_max_rows` (0 = unlimited).

### Configuration

```
GET  /api/config
PUT  /api/config
POST /api/config
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
(enabled/mode/upstreams/use_system_config/dnssec_validate/cache_size/
min_cache_ttl/max_cache_ttl/negative_cache_ttl/failure_cache_ttl/
prefetch_* /serve_stale_secs/
conditional_zones/recursion_access/recursion_networks/root_hints/
case_randomization/rebinding_protection/local_root/opportunistic_encryption/
client_policies), `dot`,
`doh`, `doq` (enabled/port/self_signed/server_name [+ `doh.endpoint`]), `api`
(gui_enabled/cors_origins), `display` (the console's date/time defaults:
`time_zone` = `system`, `UTC` or an IANA zone; `date_format` = `system`/`dmy`/
`mdy`/`ymd`/`d_mon_y`; `time_format` = `system`/`24h`/`12h`), and `authoritative`
(default_record_ttl/default_primary_ns/default_admin_mailbox/axfr_enabled/axfr_networks/
allow_dynamic_updates/update_networks/notify_enabled/notify_targets/
notify_listen_enabled/stub_zones). Runtime groups (`recursive`, `dot`, `doh`, `doq`,
`policy`, `authoritative`, `ai`, `display`) are stored in the database and survive restarts and
config-file edits; `server.*` and `api.*` stay config-file-owned so a broken
listener can always be fixed by editing the file. A `server` or `api` group
in a `PUT` is applied to the running server but not stored, so it reverts
at the next restart; the console shows these values read-only. Login users are managed
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

`recursive.mode` is `"recursive"` (resolve from the root servers; DNSSEC is
validated against the built-in root trust anchor and query names are
minimized) or `"forwarding"` (send queries to `recursive.upstreams`, or the
system resolver when that list is empty). When unset it is inferred:
forwarding if upstreams are configured, otherwise recursive. Saving settings
stores the effective mode explicitly. `recursive.recursion_access` decides who
may use recursion - `"private_networks"` (default: loopback, RFC 1918, CGNAT,
link-local, IPv6 ULA), `"allow"`, `"custom"` (the CIDRs or IPs in
`recursion_networks`) or `"deny"`; refused clients get `REFUSED`, while the
server's own zones are answered for everyone. In recursive mode,
`case_randomization` enables 0x20 query-case randomization and
`rebinding_protection` drops private and loopback addresses from public
answers; `root_hints` overrides the built-in root server addresses.

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

`recursive.client_policies` resolves some clients differently. Each policy is
`{ "name", "enabled", "clients": [CIDRs or IPs], "action", "upstreams" }` with
`action` `"forward"` (to the policy's `upstreams`, same forms as
`recursive.upstreams`), `"recursive"` (from the root servers, whatever the
default mode) or `"refuse"` (REFUSED; local zones are still answered). The
first enabled policy covering the client wins; `recursion_access` still
decides who may use recursion at all, and conditional forwarders and stub
zones still answer for their own names. Each policy keeps its own cached
answers. The list is replaced as a whole; invalid upstreams are rejected with
`400`.

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
`authoritative.default_primary_ns` — the **DNS Server Domain** setting (see
[Configuration](#configuration)) — falling back to `ns1.<zone>.` when that is
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
`SRV`, `PTR`, `CAA`, `HTTPS`, `SVCB`, `DS`, `TLSA`, `SSHFP`, `NAPTR`.
`content` must parse as that type's RDATA, otherwise the request fails with
400. `priority` is stored but not served: MX and SRV take their priority from
`content`.

`PUT /api/zones/{id}/records/{rid}` replaces an existing record in place with
the same body, keeping its id and disabled state (the collection `PUT` above
always adds a new record). It returns 404 when the record does not exist in
that zone.

`PUT /api/zones/{id}/records/{rid}/disabled` stages (or re-enables) a single
record without deleting it - a disabled record stays in the zone but stops
being served. The serial is bumped and the catalog reloaded, so the change
is live immediately.

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
`created_at`, `in_use` (the listeners using it) and details read from the
leaf certificate: `subject`, `issuer`, `self_signed`, `names` (DNS and IP
subject alternative names) and `not_before`/`not_after` (RFC 3339); these
are `null` if the certificate cannot be read. `POST` creates a self-signed certificate
or uploads PEM material; uploading with the same `name` replaces the entry,
and listeners referencing the name are rebuilt immediately. `DELETE`
removes the certificate; one still referenced by a listener cannot be
deleted.

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
remove flow calls. Each source is validated, the list is persisted to the
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
````format` accepts `domains`, `hosts`, `adblock`, or `auto` (empty = auto) to
auto-detect the format from the content. `ok: false` with a `reason` means
the URL fetched fine but the content does not parse as (or does not match)
`format`; a `502` means the URL itself could not be fetched.

### AI scanner

```
GET  /api/ai/status
GET  /api/ai/verdicts?status=classified&q=example&page=1&per_page=50
GET  /api/ai/overrides
POST /api/ai/override          {"domain": "x.example", "action": "allow|clear", "reason": "..."}
POST /api/ai/rescan
```

Available when `[ai] enabled = true`. `GET /api/ai/status` reports the mode
(`train`/`enforce`), the classification pipeline actually running
(`backend`: `heuristic`, `fasttext` or `fasttext+minilm-onnx`; a configured
model file that is missing falls back to `heuristic`), workers, intervals,
TTLs and thresholds, per-status verdict counts, `blockable_counts` (domains
that qualify for auto-blocking, by category: blocked in enforce mode, what
would be blocked in train mode) and the current block-snapshot size.

A domain qualifies for auto-blocking when its current verdict is in one of
`ai.auto_block_categories` (any category, not only threats) with a
confidence at or above `ai.block_threshold`, and neither it nor a parent
domain is exempt. The built-in heuristic rules score at most 0.35, so they
never auto-block on their own.

`GET /api/ai/verdicts` pages through the verdict store, most recently
classified first (pending rows last), optionally filtered by `status`
(`pending`/`classified`/`skipped`) and a domain substring `q`: domain,
category, severity, status, confidence, backend, evidence, observation count
(scan cycles the domain appeared in), `overridden` (the domain is exempt) and
`classified_at`/`expires_at` in RFC 3339 (the verdict is re-checked at
expiry). `per_page` is capped at 500.

`POST /api/ai/override` with `action: "allow"` exempts a domain and its
subdomains from AI blocking; `clear` removes the exemption (`404` when there
is none). `GET /api/ai/overrides` lists the exemptions, newest first.
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

Blocking groups extend the policy engine with per-group client and domain
criteria, including regular expressions (`allow_regex` / `block_regex`;
invalid patterns are rejected with `400` instead of being silently dropped
at engine-build time).
`POST /api/policy/blocking` creates a group or updates the one with the same
name; with an `id` it updates that group, so it can be renamed (`400` if
another group has the new name, `404` if the id is unknown). The
dispatcher's blocking engine is rebuilt immediately.
`DELETE /api/policy/blocking/{id}` removes a group.
`POST /api/policy/blocking/{id}/move` with `{"direction": "up"}` or
`{"direction": "down"}` swaps the group with its neighbour and returns the
reordered list. Groups are evaluated in this order.

`POST /api/policy/blocking/test` evaluates a `{client, domain}` pair against
the live blocking groups and reports whether (and why) it is blocked, so an
operator can verify rules before relying on them.

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
