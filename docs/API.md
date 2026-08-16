# Daygle DNS REST API

Base path: `/api`. The web GUI is served at `/`.

## Authentication

When `api.api_token` is configured, every mutating request (anything other than
`GET`/`OPTIONS`) must include the header:

```
Authorization: Bearer <token>
```

Missing or invalid tokens receive `401 Unauthorized`.

## Endpoints

### Status

```
GET /api/status
```

```json
{
  "version": "0.1.0",
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

### Configuration

```
GET  /api/config
POST /api/config/reload
```

`GET` returns the effective `DaygleConfig` document (the TOML configuration,
serialized as JSON).

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
  "primary_ns": "ns1.example.com.",
  "admin_mailbox": "admin.example.com.",
  "serial": 1,
  "refresh": 3600,
  "retry": 600,
  "expire": 86400,
  "minimum": 3600
}
```

Only `name` is required. Listing returns each zone plus a `dnssec` boolean
indicating whether a signing key is present.

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
`axfr_networks` client allow-list in `daygle.toml`. Secondary zones (zones
replicated from remote masters on a refresh interval) are also configured in
`daygle.toml` under `[[authoritative.secondary_zones]]`; each replicated zone
appears in `GET /api/zones` like any other zone, but is served read-only.

RFC 2136 dynamic updates are also a DNS-protocol feature (over UDP/TCP/DoT,
not HTTP): `UPDATE` messages for hosted primary zones are applied atomically
with write-through to SQLite and served immediately after a catalog reload.
They are gated by `authoritative.allow_dynamic_updates` (default off) and the
`authoritative.update_networks` client allow-list, and are always refused for
secondary zones. Prerequisites (value-dependent / value-independent /
not-exists forms) are fully checked; failed updates return their RFC 2136
RCODE (YXDOMAIN, YXRRSet, NXDOMAIN, NXRRSet, NOTAUTH, …).

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
DELETE /api/split-horizon/entries/{id}
```

Split horizon serves different answers for the same domain depending on the
client's network. A **network** is a named group of CIDRs (e.g. `LAN =
["192.168.20.0/24"]`); an **entry** maps a domain to a list of IPs for a set
of networks (network names and/or literal CIDRs; empty = every client).

`GET` returns everything:

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

Create an entry (appended after existing entries for the same domain):

```json
POST /api/split-horizon/entries
{
  "domain": "www.example.com",
  "networks": ["LAN", "VPN"],
  "ips": ["10.0.0.5"],
  "ttl": 60,
  "disabled": false
}
```

`PUT /api/split-horizon/entries/{id}` updates an entry in place (keeping its
ordering position). Entries are evaluated in order; the first one whose domain
matches and whose networks contain the client wins, so a catch-all entry with
no networks acts as the public fallback behind the specific internal ones.
Matching applies to A/AAAA queries; an entry with no address of the requested
family falls through to normal resolution.

### DNSSEC signing

```
POST /api/zones/{id}/sign
POST /api/zones/{id}/unsign
```

`sign` generates a signing key (if absent), signs the zone, and reloads the
catalog. `unsign` removes the key.

### Cache

```
POST /api/cache/clear
```

Flushes the recursive resolver cache.

### Blocklist sources

```
GET  /api/policy/blocklist/sources
POST /api/policy/blocklist/sources
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

## Errors

Errors use a uniform body and an appropriate status code:

```json
{ "error": "already exists: zone already exists" }
```

Status codes: `400` invalid input, `401` unauthorized, `404` not found,
`409` conflict, `500` internal error.
