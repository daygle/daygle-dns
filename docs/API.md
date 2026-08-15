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

## Errors

Errors use a uniform body and an appropriate status code:

```json
{ "error": "already exists: zone already exists" }
```

Status codes: `400` invalid input, `401` unauthorized, `404` not found,
`409` conflict, `500` internal error.
