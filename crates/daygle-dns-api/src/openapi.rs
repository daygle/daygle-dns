//! The published OpenAPI 3 description of the HTTP API, served at
//! `GET /api/openapi.json`.
//!
//! `docs/API.md` describes the same endpoints in prose. Two descriptions of
//! one contract drift, so this module is generated from a table that tests
//! hold against `router()`: one fails when the router serves a path the
//! table does not name, another when the table names a path the router does
//! not serve, and a third when the table and the router disagree about which
//! methods a path answers. Adding an endpoint therefore means a handler, a
//! route and a table line - and a route added without its table line fails
//! the build rather than silently dropping out of the schema.
//!
//! The table carries the operation inventory (path, methods, one-line
//! summary); the request and response *bodies* are described in
//! [`components`] and attached in [`documented_operation`] for the endpoints
//! an integration scripts against first - health, status, the query sinks
//! and the backup download. Everything else answers with the generic
//! `200`/`400`/`401`/`403` set and is described fully in `docs/API.md`;
//! filling one in is a single match arm here.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Map, Value};

/// One operation: the HTTP method and a one-line summary.
type Operation = (&'static str, &'static str);

/// Endpoints reachable without a session or API token (`require_auth`).
const OPEN_PATHS: &[&str] = &["/health", "/auth/login", "/auth/setup"];

/// Every path the API router serves, with its operations. Summaries come
/// from the handler names, so they read as the endpoint's action
/// ("Update settings") rather than restating the path.
const PATHS: &[(&str, &[Operation])] = &[
    ("/status", &[("get", "Status")]),
    ("/health", &[("get", "Health")]),
    ("/openapi.json", &[("get", "OpenAPI description")]),
    ("/host-stats", &[("get", "Host stats")]),
    ("/metrics", &[("get", "Metrics")]),
    ("/metrics/prometheus", &[("get", "Metrics prometheus")]),
    ("/stats", &[("get", "Stats")]),
    ("/logs", &[("get", "Logs")]),
    (
        "/querylogs",
        &[("get", "Query logs"), ("delete", "Clear query logs")],
    ),
    ("/querylogs/stats", &[("get", "Query log stats")]),
    ("/ai/status", &[("get", "Ai status")]),
    ("/ai/verdicts", &[("get", "Ai verdicts")]),
    ("/ai/threats", &[("get", "Ai threats")]),
    ("/ai/threats/export", &[("get", "Ai threats export")]),
    ("/ai/explain", &[("get", "Ai explain")]),
    ("/ai/corrections", &[("get", "Ai corrections")]),
    ("/ai/retrain", &[("post", "Ai retrain")]),
    ("/ai/override", &[("post", "Ai override")]),
    ("/ai/overrides", &[("get", "Ai overrides")]),
    ("/ai/rescan", &[("post", "Ai rescan")]),
    ("/ai/model-status", &[("get", "Ai model status")]),
    ("/ai/update-models", &[("post", "Ai update models")]),
    (
        "/config",
        &[
            ("get", "Config"),
            ("put", "Update settings"),
            ("post", "Reload config"),
        ],
    ),
    ("/config/defaults", &[("get", "Config defaults")]),
    ("/auth/login", &[("post", "Auth login")]),
    ("/auth/logout", &[("post", "Auth logout")]),
    ("/auth/me", &[("get", "Auth me")]),
    ("/auth/preferences", &[("put", "Auth set preferences")]),
    (
        "/auth/columns",
        &[("get", "Auth columns"), ("put", "Auth set columns")],
    ),
    ("/auth/password", &[("post", "Auth change password")]),
    (
        "/auth/tokens",
        &[("get", "List api tokens"), ("post", "Create api token")],
    ),
    ("/auth/tokens/{id}", &[("delete", "Delete api token")]),
    ("/auth/two-factor", &[("get", "Two factor status")]),
    ("/auth/two-factor/setup", &[("post", "Two factor setup")]),
    ("/auth/two-factor/enable", &[("post", "Two factor enable")]),
    (
        "/auth/two-factor/recovery-codes",
        &[("post", "Two factor new recovery codes")],
    ),
    (
        "/auth/two-factor/disable",
        &[("post", "Two factor disable")],
    ),
    (
        "/auth/setup",
        &[("get", "Auth setup status"), ("post", "Auth setup")],
    ),
    ("/users", &[("get", "List users"), ("post", "Create user")]),
    (
        "/users/{username}",
        &[("patch", "Update user"), ("delete", "Delete user")],
    ),
    (
        "/users/{username}/two-factor",
        &[("delete", "Reset user two factor")],
    ),
    (
        "/certificates",
        &[("get", "List certificates"), ("post", "Create certificate")],
    ),
    ("/certificates/{name}", &[("delete", "Delete certificate")]),
    (
        "/certificates/acme",
        &[("post", "Request acme certificate")],
    ),
    (
        "/certificates/{name}/renew",
        &[("post", "Renew acme certificate")],
    ),
    (
        "/acme",
        &[("get", "Get acme settings"), ("put", "Put acme settings")],
    ),
    ("/zones", &[("get", "List zones"), ("post", "Create zone")]),
    ("/zones/import", &[("post", "Import zone")]),
    ("/zones/defaults", &[("get", "Zone defaults")]),
    ("/zones/{id}", &[("delete", "Delete zone")]),
    ("/zones/{id}/enabled", &[("put", "Set zone enabled")]),
    ("/zones/{id}/soa", &[("put", "Update zone soa")]),
    (
        "/zones/{id}/records",
        &[("get", "List records"), ("put", "Upsert record")],
    ),
    (
        "/zones/{id}/records/{rid}/disabled",
        &[("put", "Set record disabled")],
    ),
    (
        "/zones/{id}/records/{rid}/health",
        &[
            ("put", "Set health check"),
            ("delete", "Delete health check"),
        ],
    ),
    ("/health-checks", &[("get", "List health checks")]),
    (
        "/zones/{id}/records/{rid}/weight",
        &[("put", "Set record weight")],
    ),
    ("/record-weights", &[("get", "List record weights")]),
    ("/zones/{id}/aliases", &[("put", "Set zone aliases")]),
    ("/zone-aliases", &[("get", "List zone aliases")]),
    ("/zones/{id}/export", &[("get", "Export zone")]),
    (
        "/zones/{id}/records/{rid}",
        &[("put", "Replace record"), ("delete", "Delete record")],
    ),
    ("/zones/{id}/sign", &[("post", "Sign zone")]),
    ("/zones/{id}/unsign", &[("post", "Unsign zone")]),
    ("/cache", &[("get", "Cache status")]),
    ("/cache/clear", &[("post", "Clear cache")]),
    ("/cache/flush", &[("post", "Flush cache name")]),
    ("/local-root", &[("get", "Local root status")]),
    ("/resolver", &[("get", "Resolver stats")]),
    ("/local-root/refresh", &[("post", "Local root refresh")]),
    (
        "/networks",
        &[("get", "List networks"), ("post", "Save network")],
    ),
    ("/networks/{name}", &[("delete", "Delete network")]),
    ("/split-horizon", &[("get", "Get split horizon")]),
    (
        "/split-horizon/networks",
        &[("post", "Upsert split horizon network")],
    ),
    (
        "/split-horizon/networks/{name}",
        &[("delete", "Delete split horizon network")],
    ),
    (
        "/split-horizon/entries",
        &[("post", "Create split horizon entry")],
    ),
    (
        "/split-horizon/entries/{id}",
        &[
            ("put", "Update split horizon entry"),
            ("delete", "Delete split horizon entry"),
        ],
    ),
    (
        "/split-horizon/entries/{id}/move",
        &[("post", "Move split horizon entry")],
    ),
    (
        "/policy/blocklist/sources",
        &[
            ("get", "Blocklist sources"),
            ("post", "Refresh blocklist sources"),
            ("put", "Replace blocklist sources"),
        ],
    ),
    (
        "/policy/blocklist/sources/validate",
        &[("get", "Validate blocklist source")],
    ),
    ("/policy/blocking/test", &[("post", "Test blocking")]),
    ("/policy/explain", &[("get", "Explain blocking")]),
    ("/alerts/test", &[("post", "Test alert")]),
    ("/log-export", &[("get", "Log export status")]),
    ("/log-export/test", &[("post", "Test log export")]),
    ("/dnstap/test", &[("post", "Test dnstap")]),
    ("/reports", &[("get", "Report")]),
    ("/reports/send", &[("post", "Send report")]),
    ("/policy/services", &[("get", "Blockable services")]),
    ("/policy/security", &[("get", "Security categories")]),
    ("/rpz", &[("get", "Rpz status"), ("post", "Rpz refresh")]),
    ("/rpz/test", &[("post", "Rpz test")]),
    (
        "/accounts",
        &[("get", "List accounts"), ("post", "Create account")],
    ),
    (
        "/accounts/{id}",
        &[("put", "Update account"), ("delete", "Delete account")],
    ),
    ("/accounts/{id}/new-id", &[("post", "New client id")]),
    ("/devices", &[("get", "List devices")]),
    ("/devices/name", &[("put", "Set device name")]),
    ("/dhcp", &[("get", "Dhcp status")]),
    ("/dhcp/leases/{address}", &[("delete", "Delete dhcp lease")]),
    (
        "/policy/blocking",
        &[
            ("get", "List blocking groups"),
            ("post", "Upsert blocking group"),
        ],
    ),
    (
        "/policy/blocking/{id}",
        &[("delete", "Delete blocking group")],
    ),
    (
        "/policy/blocking/{id}/move",
        &[("post", "Move blocking group")],
    ),
    ("/backup", &[("get", "Download backup")]),
    (
        "/backup/restore",
        &[
            ("get", "Pending restore"),
            ("post", "Stage restore"),
            ("delete", "Cancel restore"),
        ],
    ),
    ("/update", &[("get", "Update info")]),
    ("/update/status", &[("get", "Update status")]),
    ("/update/start", &[("post", "Update start")]),
    ("/update/check", &[("post", "Update check")]),
    ("/update/dismiss", &[("post", "Update dismiss")]),
    ("/update/preflight", &[("get", "Update preflight")]),
    ("/audit", &[("get", "Audit log")]),
];

/// The section of the console a path belongs to, used as its OpenAPI tag so
/// generated clients group operations the way the UI does.
fn tag_for(path: &str) -> &'static str {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    let first = first.split('{').next().unwrap_or(first);
    match first {
        "auth" | "users" => "auth",
        "zones" | "zone-aliases" | "record-weights" | "health-checks" => "zones",
        "policy" | "rpz" | "alerts" => "policy",
        "cache" | "resolver" | "local-root" => "resolver",
        "split-horizon" | "networks" => "split horizon",
        "ai" => "ai",
        "config" => "settings",
        "log-export" | "dnstap" | "querylogs" | "logs" => "logging",
        "status" | "health" | "host-stats" | "metrics" | "stats" | "openapi.json" => "diagnostics",
        "certificates" | "acme" => "certificates",
        "accounts" => "accounts",
        "devices" => "devices",
        "dhcp" => "dhcp",
        "reports" => "reports",
        "backup" | "update" | "audit" => "maintenance",
        _ => "other",
    }
}

/// The reusable schemas and the shared error responses.
fn components() -> Value {
    let error = json!({ "$ref": "#/components/schemas/Error" });
    json!({
        "schemas": schemas(),
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "An API token from `POST /api/auth/tokens`, or `api.api_token`."
            },
            "sessionCookie": {
                "type": "apiKey",
                "in": "cookie",
                "name": "session",
                "description": "The console's session cookie, set by `POST /api/auth/login`."
            }
        },
        "responses": {
            "BadRequest": {
                "description": "The request or its settings were refused; nothing changed.",
                "content": { "application/json": { "schema": error } }
            },
            "Unauthorized": {
                "description": "No valid session or API token.",
                "content": { "application/json": { "schema": error } }
            },
            "Forbidden": {
                "description": "Signed in, but the role does not allow this.",
                "content": { "application/json": { "schema": error } }
            }
        }
    })
}

/// A `$ref` to one of this document's schemas.
fn schema_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// A JSON response with a named schema.
fn json_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": { "application/json": { "schema": schema } }
    })
}

/// A response with no body of its own.
fn empty_response(description: &str) -> Value {
    json!({ "description": description })
}

/// A JSON request body. `required` is false where the body carries optional
/// settings the server falls back on.
fn request_body(schema: Value, description: &str, required: bool) -> Value {
    json!({
        "required": required,
        "description": description,
        "content": { "application/json": { "schema": schema } }
    })
}

/// Every named schema, gathered from the endpoint groups below.
fn schemas() -> Value {
    let mut schemas = Map::new();
    let groups = [
        common_schemas(),
        auth_schemas(),
        policy_schemas(),
        admin_schemas(),
        ai_schemas(),
        resolver_schemas(),
        diagnostics_schemas(),
        maintenance_schemas(),
        logging_schemas(),
        zone_schemas(),
        record_schemas(),
        settings_schemas(),
    ];
    for group in groups {
        if let Some(group) = group.as_object() {
            for (name, schema) in group {
                schemas.insert(name.clone(), schema.clone());
            }
        }
    }
    Value::Object(schemas)
}

/// The error and acknowledgement bodies every endpoint can produce.
fn common_schemas() -> Value {
    json!({
        "Error": {
            "type": "object",
            "description": "An error: the same text the console shows.",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" }
            }
        },
        "Sent": {
            "type": "object",
            "description": "A test sink accepted what was sent to it.",
            "required": ["sent"],
            "properties": {
                "sent": { "type": "boolean" }
            }
        }
    })
}

/// Liveness and the console bundle this build embeds.
fn diagnostics_schemas() -> Value {
    json!({
        "Health": {
            "type": "object",
            "description": "Liveness and the console bundle this build embeds.",
            "required": ["status", "version"],
            "properties": {
                "status": { "type": "string", "enum": ["ok"] },
                "version": { "type": "string" },
                "bundle": {
                    "type": "string",
                    "description": "Entry bundle hash, so an open console can reload after an update."
                }
            }
        },
        "Status": {
            "type": "object",
            "description": "What the dashboard shows: counts, which listeners are on, whether \
                setup is pending, and the cached release data behind the update banner.",
            "required": [
                "version", "uptime_secs", "zones", "records", "recursion",
                "resolution_mode", "recursion_access", "local_root", "dnssec",
                "dot_enabled", "doh_enabled", "doq_enabled", "users_configured",
                "setup_pending", "api_enabled", "update_available", "latest_release",
                "blocklist_sources", "remote_blocklist_domains"
            ],
            "properties": {
                "version": { "type": "string" },
                "uptime_secs": { "type": "integer" },
                "zones": { "type": "integer" },
                "records": { "type": "integer" },
                "recursion": { "type": "boolean", "description": "Whether a resolver is loaded." },
                "resolution_mode": {
                    "type": ["string", "null"],
                    "enum": ["recursive", "forwarding", null],
                    "description": "Null while recursion is turned off."
                },
                "recursion_access": {
                    "type": "string",
                    "enum": ["allow", "private_networks", "custom", "deny"],
                    "description": "Which clients may use recursion."
                },
                "local_root": {
                    "type": "boolean",
                    "description": "Whether a verified local root zone (RFC 8806) is serving."
                },
                "dnssec": { "type": "boolean", "description": "Whether DNSSEC validation is on." },
                "dot_enabled": { "type": "boolean" },
                "doh_enabled": { "type": "boolean" },
                "doq_enabled": { "type": "boolean" },
                "users_configured": { "type": "boolean" },
                "setup_pending": {
                    "type": "boolean",
                    "description": "No console account exists yet, so the one-time setup is due."
                },
                "api_enabled": { "type": "boolean" },
                "update_available": {
                    "type": ["boolean", "null"],
                    "description": "Null on hosts that cannot self-update or when checks are off."
                },
                "latest_release": {
                    "type": ["string", "null"],
                    "description": "The cached latest release, e.g. `1.0.2`."
                },
                "blocklist_sources": { "type": "integer", "description": "Configured sources." },
                "remote_blocklist_domains": {
                    "type": "integer",
                    "description": "Domains the fetched blocklists hold."
                }
            }
        }
    })
}

/// The `[dnstap]` and `[log_export]` sections and their test traffic.
fn logging_schemas() -> Value {
    json!({
        "DnstapSettings": {
            "type": "object",
            "description": "The `[dnstap]` section: every client query and its response, \
                streamed to a collector as dnstap events.",
            "properties": {
                "enabled": { "type": "boolean", "default": false },
                "server": {
                    "type": "string",
                    "description": "`tcp://host:port`, a bare `host:port`, or \
                        `unix:/path/to/socket` on Unix."
                },
                "identity": {
                    "type": "string",
                    "description": "Identity sent with every event (empty: this host's name)."
                },
                "version": {
                    "type": "string",
                    "description": "Version sent with every event (empty: this build's version)."
                }
            }
        },
        "DnstapTestInput": {
            "type": "object",
            "properties": {
                "dnstap": { "$ref": "#/components/schemas/DnstapSettings" }
            }
        },
        "LogExportSettings": {
            "type": "object",
            "description": "The `[log_export]` section: queries posted to an HTTP endpoint.",
            "properties": {
                "enabled": { "type": "boolean", "default": false },
                "url": { "type": "string", "description": "An HTTP(S) endpoint." },
                "format": {
                    "type": "string",
                    "enum": ["ndjson", "json"],
                    "default": "ndjson"
                },
                "authorization": {
                    "type": "string",
                    "description": "Sent as the Authorization header. Reads back as \
                        `[redacted]`; sending `[redacted]` keeps the stored value."
                },
                "batch_size": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 500 },
                "flush_secs": { "type": "integer", "minimum": 1, "maximum": 300, "default": 5 }
            }
        },
        "LogExportTestInput": {
            "type": "object",
            "properties": {
                "log_export": { "$ref": "#/components/schemas/LogExportSettings" }
            }
        },
        "LogExportStatus": {
            "type": "object",
            "required": ["sent", "dropped"],
            "properties": {
                "sent": { "type": "integer", "description": "Queries delivered since start." },
                "dropped": { "type": "integer", "description": "Queries dropped since start." },
                "last_error": {
                    "type": ["string", "null"],
                    "description": "Why the last batch failed; null once one succeeds."
                }
            }
        }
    })
}

/// Zones, their SOA metadata, aliases and signing.
fn zone_schemas() -> Value {
    let soa = json!({
        "primary_ns": {
            "type": "string",
            "description": "SOA primary nameserver. Omitted (or blank): kept."
        },
        "admin_mailbox": {
            "type": "string",
            "description": "Administrator mailbox, as an email address or RNAME. \
                Omitted (or blank): kept."
        },
        "serial": {
            "type": "integer",
            "format": "int32",
            "description": "Set the serial explicitly. Omitted: kept, unless `bump_serial`."
        },
        "bump_serial": {
            "type": "boolean",
            "default": false,
            "description": "Increment the serial so secondaries pick the change up. \
                Wins over `serial`."
        },
        "refresh": { "type": "integer", "format": "int32", "description": "Omitted (or 0): kept." },
        "retry": { "type": "integer", "format": "int32", "description": "Omitted (or 0): kept." },
        "expire": { "type": "integer", "format": "int32", "description": "Omitted (or 0): kept." },
        "minimum": { "type": "integer", "format": "int32", "description": "Omitted (or 0): kept." }
    });
    json!({
        "Zone": {
            "type": "object",
            "description": "A hosted zone. The apex `name` carries no trailing dot.",
            "required": [
                "id", "name", "primary_ns", "admin_mailbox", "serial", "enabled",
                "refresh", "retry", "expire", "minimum", "created_at"
            ],
            "properties": {
                "id": { "type": "string", "description": "Primary key (UUID)." },
                "name": { "type": "string", "description": "Zone apex, e.g. `example.com`." },
                "primary_ns": {
                    "type": "string",
                    "description": "SOA primary nameserver, e.g. `ns1.example.com.`."
                },
                "admin_mailbox": {
                    "type": "string",
                    "description": "SOA administrator mailbox in RNAME form, e.g. `admin.example.com.`."
                },
                "serial": { "type": "integer", "format": "int32" },
                "enabled": {
                    "type": "boolean",
                    "default": true,
                    "description": "Whether the zone is currently served."
                },
                "refresh": { "type": "integer", "format": "int32" },
                "retry": { "type": "integer", "format": "int32" },
                "expire": { "type": "integer", "format": "int32" },
                "minimum": { "type": "integer", "format": "int32" },
                "created_at": { "type": "string", "description": "RFC 3339 timestamp." },
                "last_modified_at": {
                    "type": "string",
                    "description": "RFC 3339 timestamp of the latest zone change."
                }
            }
        },
        "ZoneView": {
            "description": "A zone as `GET /api/zones` lists it: the zone plus what the \
                server knows about serving it.",
            "allOf": [
                { "$ref": "#/components/schemas/Zone" },
                {
                    "type": "object",
                    "required": ["dnssec", "nsec3", "ds", "zone_type", "masters"],
                    "properties": {
                        "dnssec": { "type": "boolean", "description": "Whether the zone is signed." },
                        "nsec3": {
                            "type": "boolean",
                            "description": "Whether a signed zone uses NSEC3 rather than NSEC."
                        },
                        "ds": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "DS records the parent must publish; one per \
                                active key, so two during a rollover."
                        },
                        "zone_type": { "type": "string", "enum": ["primary", "secondary"] },
                        "catalog": {
                            "type": ["string", "null"],
                            "description": "The consumed catalog zone that added this zone, if any."
                        },
                        "masters": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Transfer masters of a secondary zone."
                        },
                        "refresh_secs": {
                            "type": ["integer", "null"],
                            "description": "Secondary refresh interval."
                        }
                    }
                }
            ]
        },
        "CreateZoneInput": {
            "type": "object",
            "description": "The Add Zone form. SOA values that are omitted come from \
                `GET /api/zones/defaults`, then from the store's own fallbacks.",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "zone_type": {
                    "type": "string",
                    "enum": ["primary", "secondary"],
                    "default": "primary"
                },
                "primary_ns": { "type": "string" },
                "admin_mailbox": {
                    "type": "string",
                    "description": "An email address or an RNAME; stored as RNAME."
                },
                "default_admin_mailbox": {
                    "type": "string",
                    "description": "Fallback mailbox when `admin_mailbox` is absent."
                },
                "serial": { "type": "integer", "format": "int32" },
                "refresh": { "type": "integer", "format": "int32" },
                "retry": { "type": "integer", "format": "int32" },
                "expire": { "type": "integer", "format": "int32" },
                "minimum": { "type": "integer", "format": "int32" },
                "serial_date_scheme": {
                    "type": "boolean",
                    "default": false,
                    "description": "Generate an RFC 1912-style YYYYMMDDnn serial."
                },
                "import_text": {
                    "type": "string",
                    "description": "Optional BIND zone file. Its SOA, when present, supplies \
                        the fields not given here."
                },
                "masters": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Secondary zones only: at least one master address."
                },
                "refresh_secs": {
                    "type": "integer",
                    "format": "int64",
                    "description": "Secondary zones only; 3600 when omitted."
                }
            }
        },
        "ImportRequest": {
            "type": "object",
            "description": "Create a zone from a BIND zone file, SOA included.",
            "required": ["name", "text"],
            "properties": {
                "name": { "type": "string" },
                "text": { "type": "string" }
            }
        },
        "UpdateZoneSoaInput": {
            "type": "object",
            "description": "Edit a primary zone's SOA metadata. Omitted fields keep their \
                current value; a field that must be non-empty is refused when blank.",
            "additionalProperties": false,
            "properties": soa
        },
        "ZoneEnabledInput": {
            "type": "object",
            "additionalProperties": false,
            "required": ["enabled"],
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "description": "Stop or resume serving the zone, keeping its records."
                }
            }
        },
        "ZoneDefaults": {
            "type": "object",
            "description": "The SOA values a new zone would get, and where each came from, \
                so the Add Zone form can pre-fill them.",
            "required": [
                "primary_ns", "primary_ns_source", "admin_mailbox",
                "admin_mailbox_source", "admin_email", "server_name", "first_admin_email"
            ],
            "properties": {
                "primary_ns": { "type": ["string", "null"] },
                "primary_ns_source": { "type": "string", "enum": ["setting", "hostname", "none"] },
                "admin_mailbox": { "type": ["string", "null"], "description": "RNAME form." },
                "admin_mailbox_source": {
                    "type": "string",
                    "enum": ["setting", "admin_email", "none"]
                },
                "admin_email": {
                    "type": ["string", "null"],
                    "description": "The mailbox as an email address, when unambiguous."
                },
                "server_name": { "type": ["string", "null"] },
                "first_admin_email": { "type": ["string", "null"] }
            }
        },
        "ZoneAlias": {
            "type": "object",
            "description": "An extra name a zone is also served under.",
            "required": ["name", "zone_id", "created_at"],
            "properties": {
                "name": { "type": "string" },
                "zone_id": { "type": "string" },
                "created_at": { "type": "string", "description": "RFC 3339 timestamp." }
            }
        },
        "ZoneAliasesInput": {
            "type": "object",
            "description": "Replaces every alias of the zone; an empty list removes them all.",
            "additionalProperties": false,
            "required": ["aliases"],
            "properties": {
                "aliases": { "type": "array", "items": { "type": "string" } }
            }
        },
        "SignZoneBody": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "nsec3": {
                    "type": "boolean",
                    "description": "Prove non-existence with NSEC3 rather than NSEC; \
                        absent keeps the zone's current choice."
                }
            }
        }
    })
}

/// Records, their staged state, weights, health checks and PTR upkeep.
fn record_schemas() -> Value {
    json!({
        "Record": {
            "type": "object",
            "description": "A record in a zone. `content` is the full RDATA as it would \
                appear in a zone file: an MX stores `10 mail.example.com.`, a TXT stores \
                `\"hello world\"`.",
            "required": [
                "id", "zone_id", "name", "rtype", "content", "ttl", "priority", "disabled"
            ],
            "properties": {
                "id": { "type": "string" },
                "zone_id": { "type": "string" },
                "name": {
                    "type": "string",
                    "description": "Owner name, fully qualified, no trailing dot."
                },
                "rtype": {
                    "type": "string",
                    "description": "Record type: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, \
                        PTR, CAA, HTTPS, SVCB or DS."
                },
                "content": { "type": "string" },
                "ttl": { "type": "integer", "format": "int32" },
                "priority": {
                    "type": "integer",
                    "description": "MX/SRV priority (informational; the value is also \
                        embedded in `content`)."
                },
                "disabled": {
                    "type": "boolean",
                    "description": "A disabled record stays in the zone but stops being served."
                },
                "last_modified_at": { "type": "string", "description": "RFC 3339 timestamp." },
                "last_used_at": {
                    "type": ["string", "null"],
                    "description": "RFC 3339 timestamp of the latest answer using this record."
                }
            }
        },
        "RecordInput": {
            "type": "object",
            "required": ["name", "rtype", "content"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Relative (`www`) or fully qualified (`www.example.com.`)."
                },
                "rtype": { "type": "string" },
                "content": { "type": "string" },
                "ttl": { "type": "integer", "format": "int32", "default": 3600 },
                "priority": { "type": "integer", "default": 0 },
                "disabled": { "type": "boolean", "default": false }
            }
        },
        "RecordDisabledInput": {
            "type": "object",
            "required": ["disabled"],
            "properties": {
                "disabled": {
                    "type": "boolean",
                    "description": "Stage the record (true) or serve it again (false), \
                        without deleting it."
                }
            }
        },
        "RecordDisabledResponse": {
            "type": "object",
            "required": ["id", "disabled"],
            "properties": {
                "id": { "type": "string" },
                "disabled": { "type": "boolean" },
                "reverse": { "$ref": "#/components/schemas/ReverseOutcome" }
            }
        },
        "RecordWeightInput": {
            "type": "object",
            "required": ["weight"],
            "properties": {
                "weight": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10000,
                    "description": "Load-balancing weight; 0 takes the record out of \
                        load balancing."
                }
            }
        },
        "RecordWeight": {
            "type": "object",
            "required": ["record_id", "weight"],
            "properties": {
                "record_id": { "type": "string" },
                "weight": { "type": "integer" }
            }
        },
        "HealthCheckInput": {
            "type": "object",
            "required": ["kind", "port"],
            "properties": {
                "kind": { "type": "string", "enum": ["tcp", "http", "https"] },
                "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                "path": {
                    "type": "string",
                    "description": "HTTP(S) only; a leading `/` is added when missing."
                },
                "host": {
                    "type": "string",
                    "description": "Host header to send, for a virtual host."
                },
                "interval_secs": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": 86400,
                    "default": 30
                }
            }
        },
        "HealthCheck": {
            "type": "object",
            "description": "A health check on an A or AAAA record: a failing record is \
                taken out of its answer set until it passes again.",
            "required": ["record_id", "kind", "port", "path", "host", "interval_secs"],
            "properties": {
                "record_id": { "type": "string" },
                "kind": { "type": "string", "enum": ["tcp", "http", "https"] },
                "port": { "type": "integer" },
                "path": { "type": "string" },
                "host": { "type": "string" },
                "interval_secs": { "type": "integer" }
            }
        },
        "HealthStatus": {
            "description": "A health check with the record it guards and the latest probe.",
            "allOf": [
                { "$ref": "#/components/schemas/HealthCheck" },
                {
                    "type": "object",
                    "required": ["zone_id", "name", "rtype", "address", "priority", "healthy"],
                    "properties": {
                        "zone_id": { "type": "string" },
                        "name": { "type": "string" },
                        "rtype": { "type": "string" },
                        "address": { "type": "string" },
                        "priority": { "type": "integer" },
                        "healthy": { "type": "boolean" },
                        "last_checked": {
                            "type": ["integer", "null"],
                            "description": "UNIX seconds of the last probe, if any yet."
                        },
                        "last_error": {
                            "type": ["string", "null"],
                            "description": "Why the last probe failed; null when it passed."
                        }
                    }
                }
            ]
        },
        "ReverseOutcome": {
            "type": "object",
            "description": "What happened to the matching PTR record, when `update_ptr` \
                was given.",
            "required": ["added", "removed"],
            "properties": {
                "added": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "PTR owner names added."
                },
                "removed": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "PTR owner names removed."
                },
                "zone_created": {
                    "type": "string",
                    "description": "A reverse zone created for the address."
                },
                "problem": {
                    "type": "string",
                    "description": "Why the PTR could not be added, when it was not."
                }
            }
        },
        "RecordWithReverse": {
            "description": "The saved record, plus what happened to its PTR record when \
                `update_ptr=true` was given (the `reverse` member is absent otherwise).",
            "allOf": [
                { "$ref": "#/components/schemas/Record" },
                {
                    "type": "object",
                    "properties": {
                        "reverse": { "$ref": "#/components/schemas/ReverseOutcome" }
                    }
                }
            ]
        }
    })
}

/// The whole configuration and a runtime settings update.
///
/// Each section's fields are described in `docs/API.md` under Configuration
/// and published in full here only where this document already names them
/// (`dnstap`, `log_export`); the rest are typed as objects rather than guessed
/// at. `SettingsUpdate` refuses unknown sections, so a misspelled one is a
/// `400` rather than a silent no-op.
fn settings_schemas() -> Value {
    let section_doc = "A settings section; its fields are listed in docs/API.md \
        under Configuration.";
    let sections = |partial: bool| {
        let mut map = Map::new();
        for name in [
            "server",
            "recursive",
            "authoritative",
            "dot",
            "doh",
            "doq",
            "api",
            "policy",
            "rate_limit",
            "logging",
            "ai",
            "display",
            "web",
            "updates",
            "syslog",
            "ecs",
            "alerts",
            "rrl",
            "block_page",
            "ddr",
            "accounts",
            "reports",
            "dhcp",
        ] {
            map.insert(
                name.to_string(),
                json!({ "type": "object", "description": section_doc }),
            );
        }
        map.insert("log_export".to_string(), schema_ref("LogExportSettings"));
        map.insert("dnstap".to_string(), schema_ref("DnstapSettings"));
        if partial {
            map.insert(
                "dns64".to_string(),
                json!({ "type": "object", "description": section_doc }),
            );
        }
        map
    };
    let mut config = sections(false);
    config.insert(
        "networks".to_string(),
        json!({
            "type": "array",
            "description": "Named networks, referenced by split horizon and policy.",
            "items": { "type": "object" }
        }),
    );
    config.insert(
        "rpz".to_string(),
        json!({
            "type": "array",
            "description": "Response policy zones, in match order.",
            "items": { "type": "object" }
        }),
    );
    let mut update = sections(true);
    update.insert(
        "networks".to_string(),
        json!({ "type": "array", "items": { "type": "object" } }),
    );
    update.insert(
        "rpz".to_string(),
        json!({
            "type": "array",
            "description": "Replaces the response policy zone list, in order.",
            "items": { "type": "object" }
        }),
    );
    json!({
        "Config": {
            "type": "object",
            "description": "The whole running configuration, in the shape of the TOML \
                file. Secrets read back as `[redacted]`: TSIG key secrets, the alert \
                SMTP password and the log-export authorization.",
            "properties": config
        },
        "SettingsUpdate": {
            "type": "object",
            "description": "A runtime settings update: only the sections and fields \
                present are changed. Most sections are partial (omitted fields keep \
                their value), but a whole-section payload - `syslog`, `log_export`, \
                `dnstap`, `rrl`, `block_page`, `ddr`, `accounts`, `reports`, `alerts`, \
                `dns64`, `ecs`, `updates`, `dhcp` - replaces that section. \
                `authorization: [redacted]` and `smtp_password: [redacted]` keep the \
                stored secrets. An unknown section name is refused with `400`.",
            "additionalProperties": false,
            "properties": update
        },
        "ReloadRequested": {
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": { "type": "string", "enum": ["reload requested"] }
            }
        }
    })
}

/// The `update_ptr` / `create_reverse_zone` query flags of the record writes.
fn reverse_parameters() -> Value {
    json!([
        {
            "name": "update_ptr",
            "in": "query",
            "required": false,
            "schema": { "type": "boolean", "default": false },
            "description": "Keep the PTR record of an A or AAAA record in step."
        },
        {
            "name": "create_reverse_zone",
            "in": "query",
            "required": false,
            "schema": { "type": "boolean", "default": false },
            "description": "With `update_ptr`, create the reverse zone (a /24 for IPv4, \
                a /64 for IPv6) when no hosted zone covers the address."
        }
    ])
}

/// Zones and zone aliases.
fn zones_operation(path: &str, method: &str) -> Option<Value> {
    let zone = schema_ref("Zone");
    let not_found = json!({ "description": "No such zone." });
    let secondary = json!({
        "description": "A secondary zone is read-only.",
        "content": { "application/json": { "schema": schema_ref("Error") } }
    });
    let conflict = json!({
        "description": "The change conflicts with what the server already has.",
        "content": { "application/json": { "schema": schema_ref("Error") } }
    });
    match (method, path) {
        ("get", "/zones") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every hosted zone, with its DNSSEC state and secondary settings.",
                    json!({ "type": "array", "items": schema_ref("ZoneView") }),
                )
            }
        })),
        ("post", "/zones") => Some(json!({
            "requestBody": request_body(
                schema_ref("CreateZoneInput"),
                "The new zone. The response is the stored zone.",
                true,
            ),
            "responses": {
                "201": json_response("The zone was created.", zone),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": conflict
            }
        })),
        ("get", "/zones/defaults") => Some(json!({
            "responses": {
                "200": json_response(
                    "The SOA values a new zone would get, with where each came from.",
                    schema_ref("ZoneDefaults"),
                )
            }
        })),
        ("delete", "/zones/{id}") => Some(json!({
            "responses": {
                "204": empty_response("The zone and its records are gone."),
                "404": not_found,
                "409": json!({
                    "description": "The zone was added by a catalog zone: remove it \
                        there, or stop following the catalog.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("put", "/zones/{id}/enabled") => Some(json!({
            "requestBody": request_body(
                schema_ref("ZoneEnabledInput"),
                "Stop or resume serving the zone, keeping its records.",
                true,
            ),
            "responses": {
                "200": json_response("The zone, as stored.", zone),
                "404": not_found
            }
        })),
        ("put", "/zones/{id}/soa") => Some(json!({
            "requestBody": request_body(
                schema_ref("UpdateZoneSoaInput"),
                "The SOA fields to change; omitted fields keep their value.",
                true,
            ),
            "responses": {
                "200": json_response("The zone with its new SOA.", zone),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found,
                "409": secondary
            }
        })),
        ("post", "/zones/import") => Some(json!({
            "requestBody": request_body(
                schema_ref("ImportRequest"),
                "The zone name and a BIND zone file, SOA included.",
                true,
            ),
            "responses": {
                "201": json_response("The zone was created from the zone file.", zone),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("get", "/zones/{id}/export") => Some(json!({
            "responses": {
                "200": {
                    "description": "The zone as a BIND zone file, including SOA and every \
                        record. Disabled records appear as `; disabled:` comments, so an \
                        export round-trips through the import endpoint.",
                    "content": { "text/plain": { "schema": { "type": "string" } } }
                },
                "404": not_found
            }
        })),
        ("post", "/zones/{id}/sign") => Some(json!({
            "requestBody": request_body(
                schema_ref("SignZoneBody"),
                "Which denial-of-existence proof to use; omitted keeps the zone's choice.",
                false,
            ),
            "responses": {
                "204": empty_response("The zone is signed."),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found,
                "409": secondary
            }
        })),
        ("post", "/zones/{id}/unsign") => Some(json!({
            "responses": {
                "204": empty_response("The zone's keys and signatures are gone."),
                "404": not_found,
                "409": secondary
            }
        })),
        ("get", "/zone-aliases") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every zone alias, by name.",
                    json!({ "type": "array", "items": schema_ref("ZoneAlias") }),
                )
            }
        })),
        ("put", "/zones/{id}/aliases") => Some(json!({
            "requestBody": request_body(
                schema_ref("ZoneAliasesInput"),
                "The complete alias list; an empty list removes them all.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "The aliases now stored for the zone.",
                    json!({ "type": "array", "items": schema_ref("ZoneAlias") }),
                ),
                "404": not_found,
                "409": json!({
                    "description": "The alias is the published catalog zone.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        _ => None,
    }
}

/// Records, their staged state, weights, health checks and PTR upkeep.
fn records_operation(path: &str, method: &str) -> Option<Value> {
    let record = schema_ref("Record");
    let input = schema_ref("RecordInput");
    let not_found = json!({ "description": "No such record in this zone." });
    let secondary = json!({
        "description": "The zone is a secondary zone (read-only).",
        "content": { "application/json": { "schema": schema_ref("Error") } }
    });
    match (method, path) {
        ("get", "/zones/{id}/records") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every record in the zone, disabled ones included.",
                    json!({ "type": "array", "items": record }),
                )
            }
        })),
        ("put", "/zones/{id}/records") => Some(json!({
            "parameters": reverse_parameters(),
            "requestBody": request_body(
                input,
                "The record to add. Adding an existing name and type adds a second \
                    record, which is how round-robin and failover sets are built.",
                true,
            ),
            "responses": {
                "200": json_response("The record as stored.", schema_ref("RecordWithReverse")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": secondary
            }
        })),
        ("put", "/zones/{id}/records/{rid}") => Some(json!({
            "parameters": reverse_parameters(),
            "requestBody": request_body(
                input,
                "The new content of the record. The record keeps its id.",
                true,
            ),
            "responses": {
                "200": json_response("The record as stored.", schema_ref("RecordWithReverse")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found,
                "409": secondary
            }
        })),
        ("delete", "/zones/{id}/records/{rid}") => Some(json!({
            "parameters": reverse_parameters(),
            "responses": {
                "200": json_response(
                    "Only with `update_ptr=true`: what happened to the PTR record.",
                    json!({
                        "type": "object",
                        "required": ["reverse"],
                        "properties": { "reverse": schema_ref("ReverseOutcome") }
                    }),
                ),
                "204": empty_response(
                    "The record is gone (and its PTR with it, with `update_ptr`).",
                ),
                "404": not_found,
                "409": secondary
            }
        })),
        ("put", "/zones/{id}/records/{rid}/disabled") => Some(json!({
            "parameters": reverse_parameters(),
            "requestBody": request_body(
                schema_ref("RecordDisabledInput"),
                "Stage or re-enable the record. The zone serial is bumped either way.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "The record id and its new state.",
                    schema_ref("RecordDisabledResponse"),
                ),
                "404": not_found,
                "409": secondary
            }
        })),
        ("get", "/record-weights") => Some(json!({
            "responses": {
                "200": json_response(
                    "The load-balancing weight of every weighted A or AAAA record, by \
                        record id.",
                    json!({ "type": "object", "additionalProperties": { "type": "integer" } }),
                )
            }
        })),
        ("put", "/zones/{id}/records/{rid}/weight") => Some(json!({
            "requestBody": request_body(
                schema_ref("RecordWeightInput"),
                "The weight to store; 0 takes the record out of load balancing.",
                true,
            ),
            "responses": {
                "200": json_response("The weight as stored.", schema_ref("RecordWeight")),
                "400": json!({
                    "description": "Only A and AAAA records can be load-balanced.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "404": not_found,
                "409": secondary
            }
        })),
        ("get", "/health-checks") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every health check with its record and whether it is passing.",
                    json!({ "type": "array", "items": schema_ref("HealthStatus") }),
                )
            }
        })),
        ("put", "/zones/{id}/records/{rid}/health") => Some(json!({
            "requestBody": request_body(
                schema_ref("HealthCheckInput"),
                "The check to put on the record; an existing check is replaced.",
                true,
            ),
            "responses": {
                "200": json_response("The check as stored.", schema_ref("HealthCheck")),
                "400": json!({
                    "description": "Only A and AAAA records can be checked, or the \
                        check's fields are refused.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "404": not_found,
                "409": secondary
            }
        })),
        ("delete", "/zones/{id}/records/{rid}/health") => Some(json!({
            "responses": {
                "204": empty_response(
                    "The check is gone; the record is served whatever its state.",
                ),
                "404": json!({
                    "description": "No such record, or the record has no health check.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        _ => None,
    }
}

/// The whole configuration and runtime settings updates.
fn settings_operation(path: &str, method: &str) -> Option<Value> {
    let config = schema_ref("Config");
    match (method, path) {
        ("get", "/config") => Some(json!({
            "responses": {
                "200": json_response(
                    "The running configuration, with secrets read back as `[redacted]`.",
                    config,
                )
            }
        })),
        ("get", "/config/defaults") => Some(json!({
            "responses": {
                "200": json_response(
                    "The built-in defaults, in the same shape as `GET /api/config`.",
                    config,
                )
            }
        })),
        ("put", "/config") => Some(json!({
            "requestBody": request_body(
                schema_ref("SettingsUpdate"),
                "The sections and fields to change. Listener, policy and resolver \
                    settings apply at once; the response is the stored configuration.",
                true,
            ),
            "responses": {
                "200": json_response("The configuration as stored after the update.", config),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("post", "/config") => Some(json!({
            "responses": {
                "202": json_response(
                    "The re-read was requested: the file watcher applies it and reports \
                        failures in the log.",
                    schema_ref("ReloadRequested"),
                ),
                "409": json!({
                    "description": "Live reload is unavailable: no config file, or \
                        reloading is disabled.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        _ => None,
    }
}

/// Sign-in, sessions, two-factor, API tokens and console accounts.
fn auth_schemas() -> Value {
    let role = json!({ "type": "string", "enum": ["admin", "viewer"] });
    json!({
        "LoginInput": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": { "type": "string" },
                "password": { "type": "string" },
                "code": {
                    "type": "string",
                    "default": "",
                    "description": "The authenticator app's code, or a recovery code, for an \
                        account with two-factor login."
                }
            }
        },
        "Session": {
            "type": "object",
            "description": "A signed-in session. The same token is set as the `session` \
                cookie, and is accepted as `Authorization: Bearer`.",
            "required": ["token", "username", "role", "expires_in_secs"],
            "properties": {
                "token": { "type": "string" },
                "username": { "type": "string" },
                "role": { "$ref": "#/components/schemas/Role" },
                "expires_in_secs": {
                    "type": "integer",
                    "description": "Session lifetime (`api.session_ttl_secs`)."
                }
            }
        },
        "Role": role,
        "DisplaySettings": {
            "type": "object",
            "description": "Date, time and theme choices. An empty field means the \
                server default (`display` in the configuration) applies.",
            "required": ["time_zone", "date_format", "time_format", "theme"],
            "properties": {
                "time_zone": {
                    "type": "string",
                    "description": "`system`, `UTC`, or an IANA zone name such as \
                        `Europe/London`."
                },
                "date_format": {
                    "type": "string",
                    "description": "`system`, `dmy`, `mdy`, `ymd` or `d_mon_y`."
                },
                "time_format": { "type": "string", "description": "`system`, `24h` or `12h`." },
                "theme": { "type": "string", "description": "`system`, `light` or `dark`." }
            }
        },
        "Me": {
            "type": "object",
            "description": "The presented session's identity, with the account's own \
                display preferences and the server's defaults.",
            "required": [
                "username", "role", "expires_at_secs", "preferences",
                "display_defaults", "api_token"
            ],
            "properties": {
                "username": { "type": "string" },
                "role": { "$ref": "#/components/schemas/Role" },
                "expires_at_secs": { "type": "integer", "description": "UNIX seconds." },
                "preferences": {
                    "nullable": true,
                    "description": "The account's preferences; null for accounts defined \
                        in the configuration file, which have nowhere to store them.",
                    "allOf": [{ "$ref": "#/components/schemas/DisplaySettings" }]
                },
                "display_defaults": { "$ref": "#/components/schemas/DisplaySettings" },
                "api_token": {
                    "type": "boolean",
                    "description": "True when signed in with a personal API token rather \
                        than a password login."
                }
            }
        },
        "Preferences": {
            "type": "object",
            "required": ["preferences"],
            "properties": {
                "preferences": { "$ref": "#/components/schemas/DisplaySettings" }
            }
        },
        "ColumnsInput": {
            "type": "object",
            "description": "Hide columns of one table in the signed-in user's own view.",
            "required": ["table", "hidden"],
            "properties": {
                "table": {
                    "type": "string",
                    "description": "The table, e.g. `query-log`: up to 64 lowercase \
                        letters, digits, `-` and `_`."
                },
                "hidden": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "The hidden columns (up to 50); empty shows them all again."
                }
            }
        },
        "Columns": {
            "type": "object",
            "description": "Hidden columns, by table.",
            "required": ["columns"],
            "properties": {
                "columns": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            }
        },
        "ChangePasswordInput": {
            "type": "object",
            "required": ["current_password", "new_password"],
            "properties": {
                "current_password": { "type": "string" },
                "new_password": {
                    "type": "string",
                    "description": "8-128 characters, and different from the current one."
                }
            }
        },
        "PasswordInput": {
            "type": "object",
            "description": "The signed-in account's password, confirming a credential change.",
            "properties": {
                "password": { "type": "string", "default": "" }
            }
        },
        "CodeInput": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "default": "",
                    "description": "The code from the authenticator app."
                }
            }
        },
        "TwoFactorStatus": {
            "type": "object",
            "required": ["enabled", "recovery_codes_left"],
            "properties": {
                "enabled": { "type": "boolean" },
                "recovery_codes_left": { "type": "integer" }
            }
        },
        "TwoFactorSetup": {
            "type": "object",
            "description": "A new secret, pending until `POST /api/auth/two-factor/enable` \
                confirms a code.",
            "required": ["secret", "uri"],
            "properties": {
                "secret": { "type": "string" },
                "uri": {
                    "type": "string",
                    "description": "The `otpauth://` URI to render as a QR code."
                }
            }
        },
        "RecoveryCodes": {
            "type": "object",
            "description": "Recovery codes, shown only in this response.",
            "required": ["recovery_codes"],
            "properties": {
                "recovery_codes": { "type": "array", "items": { "type": "string" } }
            }
        },
        "ApiTokenInput": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "A label, up to 64 characters."
                },
                "read_only": {
                    "type": "boolean",
                    "default": false,
                    "description": "Limit the token to reading, whatever the account's role."
                },
                "expires_in_days": {
                    "type": "integer",
                    "default": 0,
                    "maximum": 3650,
                    "description": "Days until the token stops working; 0 or absent: never."
                }
            }
        },
        "ApiToken": {
            "type": "object",
            "description": "A personal API token. Only its hash is stored; the token \
                itself appears once, in the response that created it.",
            "required": [
                "id", "username", "name", "read_only",
                "created_at", "last_used_at", "expires_at"
            ],
            "properties": {
                "id": { "type": "string" },
                "username": { "type": "string" },
                "name": { "type": "string" },
                "read_only": { "type": "boolean" },
                "created_at": { "type": "integer", "description": "UNIX seconds." },
                "last_used_at": { "type": "integer", "description": "UNIX seconds; 0 = never." },
                "expires_at": { "type": "integer", "description": "UNIX seconds; 0 = never." }
            }
        },
        "CreatedApiToken": {
            "description": "The stored token plus its secret, shown only here.",
            "allOf": [
                { "$ref": "#/components/schemas/ApiToken" },
                {
                    "type": "object",
                    "required": ["token"],
                    "properties": {
                        "token": { "type": "string", "description": "The `dgl_...` secret." }
                    }
                }
            ]
        },
        "SetupStatus": {
            "type": "object",
            "required": ["setup_pending", "auth_required", "token_auth"],
            "properties": {
                "setup_pending": {
                    "type": "boolean",
                    "description": "Console auth is on, no account exists yet, and no static \
                        `api_token` is configured."
                },
                "auth_required": { "type": "boolean" },
                "token_auth": {
                    "type": "boolean",
                    "description": "A static `api.api_token` is configured."
                }
            }
        },
        "SetupInput": {
            "type": "object",
            "description": "The first administrator account, created once.",
            "required": ["username", "password"],
            "properties": {
                "username": {
                    "type": "string",
                    "description": "1-64 characters, no whitespace."
                },
                "password": { "type": "string", "description": "8-128 characters." },
                "first_name": { "type": "string", "default": "" },
                "last_name": { "type": "string", "default": "" },
                "email": { "type": "string", "default": "" }
            }
        },
        "ConsoleUser": {
            "type": "object",
            "description": "A console account, with its password material redacted.",
            "required": [
                "username", "role", "enabled", "first_name", "last_name", "email",
                "created_at", "preferences", "two_factor", "password_hash"
            ],
            "properties": {
                "username": { "type": "string" },
                "role": { "$ref": "#/components/schemas/Role" },
                "enabled": { "type": "boolean" },
                "first_name": { "type": "string" },
                "last_name": { "type": "string" },
                "email": { "type": "string" },
                "created_at": { "type": "string", "description": "RFC 3339 timestamp." },
                "preferences": { "$ref": "#/components/schemas/DisplaySettings" },
                "two_factor": {
                    "type": "boolean",
                    "description": "Whether the account signs in with an authenticator \
                        code as well as its password."
                },
                "last_login_at": {
                    "type": ["string", "null"],
                    "description": "RFC 3339 time of the latest successful password sign-in."
                },
                "password_hash": {
                    "type": "string",
                    "enum": ["[redacted]"],
                    "description": "Always `[redacted]` over the API."
                }
            }
        },
        "CreateUserInput": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": { "type": "string", "description": "1-64 characters, no whitespace." },
                "password": { "type": "string", "description": "8-128 characters." },
                "role": {
                    "type": "string",
                    "enum": ["admin", "viewer"],
                    "default": "admin"
                },
                "first_name": { "type": "string" },
                "last_name": { "type": "string" },
                "email": { "type": "string" }
            }
        },
        "UpdateUserInput": {
            "type": "object",
            "description": "Only the members present change. A password, role or \
                `enabled` change revokes that account's live sessions.",
            "properties": {
                "password": { "type": "string", "description": "A new password, 8-128 characters." },
                "role": { "type": "string", "enum": ["admin", "viewer"] },
                "enabled": { "type": "boolean" },
                "first_name": { "type": "string" },
                "last_name": { "type": "string" },
                "email": { "type": "string" }
            }
        }
    })
}

/// Sign-in, sessions, two-factor, API tokens and console accounts.
fn auth_operation(path: &str, method: &str) -> Option<Value> {
    let session = schema_ref("Session");
    let forbidden = json!({ "$ref": "#/components/responses/Forbidden" });
    let password = schema_ref("PasswordInput");
    let not_authenticated = json!({
        "description": "Not signed in.",
        "content": { "application/json": { "schema": schema_ref("Error") } }
    });
    let wrong_password = json!({
        "description": "The password is incorrect.",
        "content": { "application/json": { "schema": schema_ref("Error") } }
    });
    let recovery_codes = json_response(
        "The new recovery codes; they are shown only here.",
        schema_ref("RecoveryCodes"),
    );
    match (method, path) {
        ("post", "/auth/login") => Some(json!({
            "requestBody": request_body(
                schema_ref("LoginInput"),
                "The account's credentials, plus the authenticator code when the account \
                    uses two-factor login.",
                true,
            ),
            "responses": {
                "200": {
                    "description": "Signed in. The token is also set as the `session` \
                        cookie, accepted on subsequent calls.",
                    "headers": {
                        "Set-Cookie": {
                            "schema": { "type": "string" },
                            "description": "`session=<token>; HttpOnly; SameSite=Lax`, secure \
                                when the request arrived over HTTPS."
                        }
                    },
                    "content": { "application/json": { "schema": session } }
                },
                "401": {
                    "description": "Invalid username or password, or the two-factor code \
                        was missing or wrong. When the account uses two-factor login the \
                        body carries `two_factor: true` and the console shows the code field.",
                    "content": { "application/json": { "schema": {
                        "type": "object",
                        "required": ["error", "two_factor"],
                        "properties": {
                            "error": { "type": "string" },
                            "two_factor": { "type": "boolean" }
                        }
                    }}}
                },
                "429": {
                    "description": "Too many failed attempts from this address; \
                        `Retry-After` says how long to wait.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }
            }
        })),
        ("post", "/auth/logout") => Some(json!({
            "responses": {
                "204": {
                    "description": "The session is revoked and its cookie cleared.",
                    "headers": {
                        "Set-Cookie": {
                            "schema": { "type": "string" },
                            "description": "`session=; Max-Age=0`."
                        }
                    }
                }
            }
        })),
        ("get", "/auth/me") => Some(json!({
            "responses": {
                "200": json_response(
                    "The signed-in identity, its preferences and the server's defaults.",
                    schema_ref("Me"),
                ),
                "401": not_authenticated
            }
        })),
        ("put", "/auth/preferences") => Some(json!({
            "requestBody": request_body(
                schema_ref("DisplaySettings"),
                "The user's own date, time and theme choices. An empty field means the \
                    server default applies.",
                true,
            ),
            "responses": {
                "200": json_response("The preferences as stored.",
                    schema_ref("Preferences")),
                "401": not_authenticated,
                "409": json!({
                    "description": "Accounts defined in the configuration file cannot store \
                        preferences.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("get", "/auth/columns") => Some(json!({
            "responses": {
                "200": json_response(
                    "The signed-in user's hidden table columns.",
                    schema_ref("Columns"),
                ),
                "401": not_authenticated
            }
        })),
        ("put", "/auth/columns") => Some(json!({
            "requestBody": request_body(
                schema_ref("ColumnsInput"),
                "The columns to hide in one table; an empty list shows them all again.",
                true,
            ),
            "responses": {
                "200": json_response("Every table's hidden columns, as stored.",
                    schema_ref("Columns")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "401": not_authenticated
            }
        })),
        ("post", "/auth/password") => Some(json!({
            "requestBody": request_body(
                schema_ref("ChangePasswordInput"),
                "The current password and the new one.",
                true,
            ),
            "responses": {
                "204": empty_response(
                    "The password changed; every other session of the account is revoked.",
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "401": not_authenticated,
                "403": forbidden
            }
        })),
        ("get", "/auth/two-factor") => Some(json!({
            "responses": {
                "200": json_response(
                    "Whether the account uses two-factor login, and how many recovery \
                        codes it has left.",
                    schema_ref("TwoFactorStatus"),
                ),
                "401": not_authenticated
            }
        })),
        ("post", "/auth/two-factor/setup") => Some(json!({
            "requestBody": request_body(
                password,
                "The account's password, confirming the credential change.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "A new secret and its `otpauth://` URI. Nothing changes until a code \
                        is confirmed with `/enable`.",
                    schema_ref("TwoFactorSetup"),
                ),
                "401": wrong_password
            }
        })),
        ("post", "/auth/two-factor/enable") => Some(json!({
            "requestBody": request_body(
                schema_ref("CodeInput"),
                "A code from the authenticator app, proving the app works.",
                true,
            ),
            "responses": {
                "200": recovery_codes,
                "400": json!({
                    "description": "Setup was not started, or the code is not right.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "401": not_authenticated
            }
        })),
        ("post", "/auth/two-factor/recovery-codes") => Some(json!({
            "requestBody": request_body(
                password,
                "The account's password; the old codes stop working.",
                true,
            ),
            "responses": {
                "200": recovery_codes,
                "400": json!({
                    "description": "Two-factor login is not on.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "401": wrong_password
            }
        })),
        ("post", "/auth/two-factor/disable") => Some(json!({
            "requestBody": request_body(
                password,
                "The account's password, confirming the credential change.",
                true,
            ),
            "responses": {
                "204": empty_response("Two-factor login is off for the signed-in account."),
                "401": wrong_password
            }
        })),
        ("get", "/auth/tokens") => Some(json!({
            "responses": {
                "200": json_response(
                    "The signed-in account's API tokens, newest first.",
                    json!({ "type": "array", "items": schema_ref("ApiToken") }),
                ),
                "401": not_authenticated
            }
        })),
        ("post", "/auth/tokens") => Some(json!({
            "requestBody": request_body(
                schema_ref("ApiTokenInput"),
                "The token's label, scope and lifetime.",
                true,
            ),
            "responses": {
                "201": json_response(
                    "The token was created. This response is the only place its secret \
                        appears.",
                    schema_ref("CreatedApiToken"),
                ),
                "400": json!({
                    "description": "The name is missing or too long, the lifetime is over \
                        3650 days, or the account already has 50 tokens.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "401": not_authenticated
            }
        })),
        ("delete", "/auth/tokens/{id}") => Some(json!({
            "responses": {
                "204": empty_response("The token is revoked."),
                "404": json!({
                    "description": "No such token for this account.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("get", "/auth/setup") => Some(json!({
            "responses": {
                "200": json_response(
                    "Whether the one-time admin setup is still pending.",
                    schema_ref("SetupStatus"),
                )
            }
        })),
        ("post", "/auth/setup") => Some(json!({
            "requestBody": request_body(
                schema_ref("SetupInput"),
                "The first administrator account.",
                true,
            ),
            "responses": {
                "200": {
                    "description": "The account was created and signed in. Its token is \
                        also set as the `session` cookie.",
                    "headers": {
                        "Set-Cookie": {
                            "schema": { "type": "string" },
                            "description": "`session=<token>; HttpOnly; SameSite=Lax`."
                        }
                    },
                    "content": { "application/json": { "schema": session } }
                },
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": json!({
                    "description": "Setup is not available: an account already exists, \
                        console auth is disabled, or a static `api_token` manages auth.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("get", "/users") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every console account, with password material redacted.",
                    json!({ "type": "array", "items": schema_ref("ConsoleUser") }),
                )
            }
        })),
        ("post", "/users") => Some(json!({
            "requestBody": request_body(
                schema_ref("CreateUserInput"),
                "The account to create; it is enabled from the start.",
                true,
            ),
            "responses": {
                "200": json_response("The account as stored.",
                    schema_ref("ConsoleUser")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": json!({
                    "description": "The username already exists.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("patch", "/users/{username}") => Some(json!({
            "requestBody": request_body(
                schema_ref("UpdateUserInput"),
                "The fields to change; omitted fields keep their value.",
                true,
            ),
            "responses": {
                "200": json_response("The account as stored.",
                    schema_ref("ConsoleUser")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": json!({
                    "description": "No such account.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "409": json!({
                    "description": "The change would remove the last enabled admin account.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("delete", "/users/{username}") => Some(json!({
            "responses": {
                "204": empty_response("The account and its live sessions are gone."),
                "404": json!({
                    "description": "No such account.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                }),
                "409": json!({
                    "description": "The account is the last enabled admin: deleting it \
                        would lock the console.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("delete", "/users/{username}/two-factor") => Some(json!({
            "responses": {
                "204": empty_response(
                    "Two-factor login is off; the account signs in with its password \
                        alone until it sets it up again.",
                ),
                "404": json!({
                    "description": "No such account.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        _ => None,
    }
}

/// Remote blocklist sources, filtering groups, the policy checks and RPZ.
fn policy_schemas() -> Value {
    let block_response = json!({
        "description": "What a blocked query is answered with: `{kind}` alone for \
            `nx_domain`, `refused` and `no_data`, or `{kind: \"redirect\", address}`.",
        "oneOf": [
            {
                "type": "object",
                "required": ["kind"],
                "properties": { "kind": { "type": "string", "enum": ["nx_domain", "refused", "no_data"] } }
            },
            {
                "type": "object",
                "required": ["kind", "address"],
                "properties": {
                    "kind": { "type": "string", "enum": ["redirect"] },
                    "address": { "type": "string", "description": "The address to answer with." }
                }
            }
        ]
    });
    json!({
        "BlocklistSourceConfig": {
            "type": "object",
            "description": "One remote blocklist: where to fetch it, how it is written, \
                and who it applies to.",
            "required": ["name", "url"],
            "properties": {
                "name": { "type": "string", "description": "Unique, used by logs and groups." },
                "url": { "type": "string", "description": "An HTTP(S) URL." },
                "format": {
                    "type": "string",
                    "enum": ["domains", "wildcard", "hosts", "adblock", "rpz"],
                    "default": "domains"
                },
                "refresh_secs": {
                    "type": "integer",
                    "format": "int64",
                    "default": 86400,
                    "description": "How often to re-fetch the source."
                },
                "enabled": { "type": "boolean", "default": true },
                "scope": {
                    "type": "string",
                    "enum": ["everyone", "groups", "dot"],
                    "default": "everyone",
                    "description": "`everyone` blocks for all clients; `groups` only for \
                        the client groups that select it. `dot` is accepted for sources \
                        saved by older versions."
                }
            }
        },
        "BlocklistSourceStatus": {
            "type": "object",
            "description": "A configured source with its last fetch.",
            "required": ["name", "url", "enabled", "format", "scope", "refresh_secs", "domains"],
            "properties": {
                "name": { "type": "string" },
                "url": { "type": "string" },
                "enabled": { "type": "boolean" },
                "format": {
                    "type": "string",
                    "enum": ["domains", "wildcard", "hosts", "adblock", "rpz"]
                },
                "scope": { "type": "string" },
                "refresh_secs": { "type": "integer", "format": "int64" },
                "last_fetch": {
                    "type": ["integer", "null"],
                    "description": "Seconds since the last successful fetch."
                },
                "last_fetch_at": { "type": ["string", "null"], "description": "RFC 3339." },
                "domains": { "type": "integer", "description": "Domains this source contributes." },
                "last_error": { "type": ["string", "null"] }
            }
        },
        "BlocklistSources": {
            "type": "object",
            "required": ["sources", "total_domains"],
            "properties": {
                "sources": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/BlocklistSourceStatus" }
                },
                "total_domains": {
                    "type": "integer",
                    "description": "Domains in the live remote blocklist."
                }
            }
        },
        "BlocklistSourcesInput": {
            "type": "object",
            "description": "The complete desired source list; it replaces what is configured. \
                The list is validated, persisted and applied live, so a saved source starts \
                (or stops) blocking within seconds.",
            "additionalProperties": false,
            "required": ["sources"],
            "properties": {
                "sources": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/BlocklistSourceConfig" }
                },
                "renames": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Sources renamed in this edit (old name to new), so the \
                        client groups that select them follow the rename."
                }
            }
        },
        "BlocklistSourcesApplied": {
            "type": "object",
            "required": ["applied", "sources", "total_domains"],
            "properties": {
                "applied": { "type": "boolean" },
                "sources": { "type": "integer", "description": "Sources now configured." },
                "total_domains": { "type": "integer" }
            }
        },
        "BlocklistValidateResult": {
            "type": "object",
            "description": "Whether a candidate URL really is the declared blocklist \
                format. Returned with `200` either way, so the console can tell wrong \
                content from an unreachable URL.",
            "required": ["ok", "format", "domains"],
            "properties": {
                "ok": { "type": "boolean" },
                "format": {
                    "type": "string",
                    "enum": ["domains", "wildcard", "hosts", "adblock", "rpz", "auto"],
                    "description": "The format detected (or the one declared)."
                },
                "domains": { "type": "integer" },
                "sample": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "A few of the domains parsed."
                },
                "reason": {
                    "type": "string",
                    "description": "Why the content was refused, when `ok` is false."
                }
            }
        },
        "BlocklistRefresh": {
            "type": "object",
            "required": ["refreshed", "total_domains"],
            "properties": {
                "refreshed": { "type": "boolean" },
                "total_domains": { "type": "integer" }
            }
        },
        "BlockResponse": block_response,
        "BlockingGroup": {
            "type": "object",
            "description": "One Advanced Blocking group: client networks and the rules \
                applied to their queries. The first matching group decides.",
            "required": ["id", "name", "enabled", "clients", "response"],
            "properties": {
                "id": { "type": "string", "description": "Primary key (UUID)." },
                "name": { "type": "string" },
                "enabled": { "type": "boolean" },
                "clients": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Client networks (CIDR), network names, listener names \
                        or `account:<name>`. Empty means every client."
                },
                "allow": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Allowed domains (exact or `*.suffix`), overriding the \
                        block rules."
                },
                "block": { "type": "array", "items": { "type": "string" }, "description": "Blocked domains (exact or `*.suffix`)." },
                "allow_regex": { "type": "array", "items": { "type": "string" }, "description": "Regexes whose matches are never blocked." },
                "block_regex": { "type": "array", "items": { "type": "string" }, "description": "Regexes whose matches are blocked." },
                "blocklists": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Names of the `groups`-scoped blocklist sources this \
                        group blocks with."
                },
                "response": block_response.clone(),
                "ai_mode": {
                    "type": ["string", "null"],
                    "enum": ["train", "enforce", null],
                    "description": "How AI threat auto-blocking applies to these clients; \
                        null follows the global `ai.mode`."
                },
                "safe_search": { "type": "boolean" },
                "youtube_restricted": { "type": "boolean" },
                "schedule": {
                    "type": "array",
                    "description": "When the group applies; empty means always. Outside \
                        its windows the group is skipped as if it did not exist.",
                    "items": { "type": "object" }
                },
                "blocked_services": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Service ids (e.g. `tiktok`)."
                },
                "blocked_categories": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "AI content labels (e.g. `gambling`) blocked for these \
                        clients, whatever `ai_mode` says."
                },
                "blocked_security": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Security category ids (e.g. `dynamic_dns`)."
                },
                "blocked_tlds": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Top-level domains whose every name is blocked."
                },
                "block_local_addresses": {
                    "type": "boolean",
                    "description": "Block answers carrying private, loopback or link-local \
                        addresses for public names (DNS rebinding protection)."
                },
                "limit_payloads": {
                    "type": "boolean",
                    "description": "Block answers with unusually large payloads."
                }
            }
        },
        "BlockingGroupInput": {
            "type": "object",
            "description": "A group to create or update. With `id` the group is updated \
                under that id, so it can be renamed; without one, a group with the same \
                name is updated in place, else created.",
            "required": ["name"],
            "properties": {
                "id": {
                    "type": "string",
                    "description": "The group being edited, when it is being renamed."
                },
                "name": { "type": "string" },
                "enabled": { "type": "boolean", "default": true },
                "clients": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Client networks (CIDR), network names, listener names \
                        or `account:<name>`. Empty means every client."
                },
                "allow": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Allowed domains (exact or `*.suffix`)."
                },
                "block": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Blocked domains (exact or `*.suffix`)."
                },
                "allow_regex": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Regexes whose matches are never blocked, matched anywhere in the \
                        name (unless anchored), ignoring case. Blank patterns are dropped."
                },
                "block_regex": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Regexes whose matches are blocked, matched anywhere in the \
                        name (unless anchored), ignoring case. Blank patterns are dropped."
                },
                "blocklists": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Names of the `groups`-scoped blocklist sources this \
                        group blocks with."
                },
                "response": block_response.clone(),
                "ai_mode": {
                    "type": ["string", "null"],
                    "enum": ["train", "enforce", null],
                    "description": "How AI threat auto-blocking applies to these clients; \
                        null follows the global `ai.mode`."
                },
                "safe_search": { "type": "boolean", "default": false },
                "youtube_restricted": { "type": "boolean", "default": false },
                "schedule": {
                    "type": "array",
                    "description": "When the group applies; empty means always.",
                    "items": { "type": "object" }
                },
                "blocked_services": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Service ids (e.g. `tiktok`)."
                },
                "blocked_categories": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "AI content labels blocked for these clients."
                },
                "blocked_security": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Security category ids (e.g. `dynamic_dns`)."
                },
                "blocked_tlds": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Top-level domains whose every name is blocked."
                },
                "block_local_addresses": { "type": "boolean", "default": false },
                "limit_payloads": { "type": "boolean", "default": false }
            }
        },
        "MoveGroupInput": {
            "type": "object",
            "additionalProperties": false,
            "required": ["direction"],
            "properties": {
                "direction": { "type": "string", "enum": ["up", "down"] }
            }
        },
        "BlockingTestInput": {
            "type": "object",
            "description": "Evaluate one `{client, domain}` pair against the live groups.",
            "required": ["client", "domain"],
            "properties": {
                "client": { "type": "string", "description": "The client IP to evaluate as." },
                "domain": { "type": "string" },
                "listener": {
                    "type": "string",
                    "enum": ["dot", "doh", "doq"],
                    "description": "Evaluate as an encrypted listener; omitted for plain DNS."
                },
                "account": {
                    "type": "string",
                    "description": "Evaluate as this DNS account; omitted for none."
                }
            }
        },
        "BlockingVerdict": {
            "type": "object",
            "description": "Whether the tested pair is blocked, and why.",
            "required": [
                "client", "domain", "blocked", "action", "reason",
                "ai_mode", "safe_search", "youtube_restricted", "scheduled_off"
            ],
            "properties": {
                "client": { "type": "string" },
                "domain": { "type": "string" },
                "blocked": { "type": "boolean" },
                "action": {
                    "type": "string",
                    "description": "The action taken: `allow`, `block`, or the group's \
                        block response."
                },
                "reason": { "type": "string" },
                "group": { "type": ["string", "null"], "description": "The deciding group." },
                "ai_mode": { "type": "string", "enum": ["train", "enforce"] },
                "ai_group": {
                    "type": ["string", "null"],
                    "description": "The group that set `ai_mode`; null when the global \
                        mode applies."
                },
                "safe_search": { "type": "boolean" },
                "youtube_restricted": { "type": "boolean" },
                "safe_search_target": {
                    "type": ["string", "null"],
                    "description": "The safe address the domain would be answered with."
                },
                "scheduled_off": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Groups covering the client that are outside their \
                        schedule now."
                }
            }
        },
        "ExplainCheck": {
            "type": "object",
            "description": "One check in the order queries meet it, and what it does with \
                the domain.",
            "required": ["source", "result", "detail"],
            "properties": {
                "source": { "type": "string", "description": "The check's source, e.g. `allowlist`." },
                "result": {
                    "type": "string",
                    "description": "`allow`, `block`, `none` or `rewrite`."
                },
                "detail": { "type": "string" },
                "matched": { "type": ["string", "null"], "description": "What matched." },
                "group": { "type": ["string", "null"] },
                "action": { "type": ["string", "null"] }
            }
        },
        "ExplainReport": {
            "type": "object",
            "description": "Why a domain is (or is not) blocked for a device: the verdict \
                the server gives, every check in order, and the latest logged blocks of \
                the domain.",
            "required": ["domain", "client", "qtype", "verdict", "checks", "recent"],
            "properties": {
                "domain": { "type": "string" },
                "client": { "type": "string", "description": "The device's address." },
                "client_name": { "type": ["string", "null"], "description": "Its device name, when it has one." },
                "qtype": { "type": "string" },
                "listener": { "type": ["string", "null"] },
                "verdict": {
                    "type": "object",
                    "description": "`{blocked: true, source, group, matched, reason, action}` \
                        when blocked, `{blocked: false, source, reason}` when not.",
                    "required": ["blocked", "reason"],
                    "properties": {
                        "blocked": { "type": "boolean" },
                        "source": { "type": ["string", "null"] },
                        "group": { "type": ["string", "null"] },
                        "matched": { "type": ["string", "null"] },
                        "reason": { "type": "string" },
                        "action": { "type": "string" }
                    }
                },
                "checks": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/ExplainCheck" }
                },
                "recent": {
                    "type": "array",
                    "description": "The latest logged blocks of the domain, newest first.",
                    "items": { "type": "object" }
                }
            }
        },
        "ServiceCatalogue": {
            "type": "object",
            "required": ["services"],
            "properties": {
                "services": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "name", "category", "domains"],
                        "properties": {
                            "id": { "type": "string", "description": "Stored in a group's `blocked_services`." },
                            "name": { "type": "string" },
                            "category": { "type": "string" },
                            "domains": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Each also covers its subdomains."
                            }
                        }
                    }
                }
            }
        },
        "SecurityCatalogue": {
            "type": "object",
            "required": ["categories"],
            "properties": {
                "categories": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "name", "description", "section"],
                        "properties": {
                            "id": { "type": "string", "description": "Stored in a group's `blocked_security`." },
                            "name": { "type": "string" },
                            "description": { "type": "string" },
                            "section": { "type": "string", "description": "The console section it is listed in." },
                            "detector": {
                                "type": ["object", "null"],
                                "description": "How membership is decided, for categories \
                                    judged by examining the answer."
                            },
                            "feed": {
                                "type": ["object", "null"],
                                "description": "The maintained list the category is built from."
                            },
                            "feed_status": {
                                "description": "That feed's download state, so the console \
                                    can say when a list has not been downloaded yet or failed."
                            }
                        }
                    }
                }
            }
        },
        "RpzZoneStatus": {
            "type": "object",
            "description": "One response policy zone's state.",
            "required": ["name", "enabled", "source", "policy", "loaded", "rules", "hits"],
            "properties": {
                "name": { "type": "string" },
                "enabled": { "type": "boolean" },
                "source": {
                    "type": "string",
                    "description": "`local` (rules typed in), `url` (a fetched zone file) or \
                        `transfer` (an AXFR feed)."
                },
                "policy": {
                    "type": "string",
                    "description": "What matching rules do: `given` (each rule's action), \
                        `disabled`, `nxdomain`, `nodata`, `passthru`, `drop` or `tcp_only`."
                },
                "loaded": { "type": "boolean", "description": "Whether rules are in force." },
                "rules": {
                    "type": "object",
                    "description": "Rule counts by trigger type."
                },
                "serial": { "type": ["integer", "null"] },
                "last_loaded": { "type": ["string", "null"], "description": "RFC 3339." },
                "last_checked": { "type": ["string", "null"], "description": "RFC 3339." },
                "last_error": {
                    "type": ["string", "null"],
                    "description": "Why the last load failed; the previous rules stay in force."
                },
                "hits": { "type": "integer", "description": "Matches since start." }
            }
        },
        "RpzStatus": {
            "type": "object",
            "required": ["zones"],
            "properties": {
                "zones": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/RpzZoneStatus" }
                }
            }
        },
        "RpzTestInput": {
            "type": "object",
            "required": ["client", "domain"],
            "properties": {
                "client": { "type": "string", "description": "An IP address." },
                "domain": { "type": "string" }
            }
        },
        "RpzTestResult": {
            "type": "object",
            "description": "Which zones match a query, in order; the first that is not \
                log-only acts.",
            "required": ["client", "domain", "allowlisted", "matches"],
            "properties": {
                "client": { "type": "string" },
                "domain": { "type": "string" },
                "allowlisted": { "type": "boolean" },
                "matches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["zone", "trigger", "action"],
                        "properties": {
                            "zone": { "type": "string" },
                            "trigger": { "type": "string", "description": "For logs, e.g. `QNAME *.bad.example`." },
                            "action": { "type": "string", "description": "The rule's action." }
                        }
                    }
                }
            }
        },
        "AlertTestInput": {
            "type": "object",
            "description": "The alert settings to try, as on the form (saved or not); \
                omitted, the saved ones. The test is delivered whether or not alerts are \
                switched on yet.",
            "properties": {
                "alerts": { "type": "object", "description": "The `[alerts]` section." }
            }
        }
    })
}

/// The AI scanner's status, verdicts, threats and overrides.
fn ai_schemas() -> Value {
    json!({
        "AiStatus": {
            "type": "object",
            "description": "The scanner's settings, the pipelines actually running per \
                channel, and its verdict and block counters.",
            "required": [
                "enabled", "mode", "backend", "status_counts", "blockable_counts",
                "snapshot_len"
            ],
            "properties": {
                "enabled": { "type": "boolean" },
                "mode": { "type": "string", "enum": ["train", "enforce"] },
                "backend": { "type": "string", "description": "`fasttext` or `heuristic`." },
                "content_backend": { "type": "string", "description": "The categorization channel." },
                "threat_backend": { "type": "string", "description": "The threat channel." },
                "workers": { "type": "integer" },
                "scan_interval_secs": { "type": "integer" },
                "expire_check_secs": { "type": "integer" },
                "confidence_floor": { "type": "number", "description": "The threat channel's floor." },
                "category_confidence_floor": { "type": "number" },
                "category_ttl_secs": { "type": "integer" },
                "threat_ttl_secs": { "type": "integer" },
                "block_threshold": { "type": "number" },
                "auto_block_categories": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "backend_categories": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "The labels the loaded backend can emit."
                },
                "status_counts": {
                    "type": "object",
                    "additionalProperties": { "type": "integer" },
                    "description": "Verdicts by status: `pending`, `classified`, `skipped`, `stale`."
                },
                "blockable_counts": {
                    "type": "object",
                    "description": "Domains that qualify for auto-blocking, by category: \
                        blocked in enforce mode, what would be in train mode."
                },
                "snapshot_len": {
                    "type": "integer",
                    "description": "Domains in the current auto-block snapshot."
                }
            }
        },
        "AiVerdict": {
            "type": "object",
            "description": "The scanner's verdict for one domain on one channel.",
            "required": [
                "domain", "channel", "category", "severity", "status", "confidence",
                "backend", "evidence", "observations", "overridden", "category_overridden"
            ],
            "properties": {
                "domain": { "type": "string" },
                "channel": {
                    "type": "string",
                    "enum": ["content", "threat"],
                    "description": "`content` is the categorization pass, `threat` the \
                        malicious-domain pass."
                },
                "category": {
                    "type": "string",
                    "description": "The label; empty when there is no verdict yet."
                },
                "severity": {
                    "type": "string",
                    "description": "`info`, `threat`, `disputed` (a threat the verifier \
                        disagreed with, never auto-blocked) or empty."
                },
                "status": {
                    "type": "string",
                    "description": "`pending`, `classified`, `skipped` or `stale`."
                },
                "confidence": { "type": "number" },
                "backend": { "type": "string" },
                "evidence": { "type": "string" },
                "observations": {
                    "type": "integer",
                    "description": "How many scan cycles the domain appeared in the query log."
                },
                "overridden": {
                    "type": "boolean",
                    "description": "The domain has an operator `allow` override (it is exempt)."
                },
                "category_overridden": {
                    "type": "boolean",
                    "description": "The category is the operator's label, not the model's."
                },
                "classified_at": { "type": ["string", "null"], "description": "RFC 3339." },
                "expires_at": { "type": ["string", "null"], "description": "RFC 3339." }
            }
        },
        "AiVerdictPage": {
            "type": "object",
            "required": ["entries", "total", "per_page", "page"],
            "properties": {
                "entries": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/AiVerdict" }
                },
                "total": { "type": "integer" },
                "per_page": { "type": "integer" },
                "page": { "type": "integer" }
            }
        },
        "AiThreat": {
            "description": "A verdict from the threat channel, with whether it is blocked \
                now and whether a group blocks its category.",
            "allOf": [
                { "$ref": "#/components/schemas/AiVerdict" },
                {
                    "type": "object",
                    "required": ["blocked", "category_blocked"],
                    "properties": {
                        "blocked": {
                            "type": "boolean",
                            "description": "In the current block snapshot, i.e. actually \
                                auto-blocked in enforce mode."
                        },
                        "category_blocked": {
                            "type": "boolean",
                            "description": "A filtering group blocks the category the domain \
                                carries, so it is blocked for that group's clients in either mode."
                        }
                    }
                }
            ]
        },
        "AiThreatPage": {
            "type": "object",
            "required": ["entries", "total", "per_page", "page"],
            "properties": {
                "entries": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/AiThreat" }
                },
                "total": { "type": "integer" },
                "per_page": { "type": "integer" },
                "page": { "type": "integer" }
            }
        },
        "AiOverrideInput": {
            "type": "object",
            "required": ["domain", "action"],
            "properties": {
                "domain": { "type": "string" },
                "action": {
                    "type": "string",
                    "enum": ["allow", "clear", "category", "clear_category"],
                    "description": "`allow` exempts the domain (and its subdomains); `clear` \
                        removes that; `category` relabels it; `clear_category` drops the label."
                },
                "category": {
                    "type": "string",
                    "default": "",
                    "description": "The operator's label, for `action = \"category\"`."
                },
                "reason": { "type": "string", "default": "", "description": "Shown in the console." }
            }
        },
        "AiOverrideApplied": {
            "type": "object",
            "required": ["domain", "action"],
            "properties": {
                "domain": { "type": "string" },
                "action": { "type": "string" },
                "category": { "type": "string", "description": "Present for `category`." }
            }
        },
        "AiOverrides": {
            "type": "object",
            "required": ["overrides"],
            "properties": {
                "overrides": {
                    "type": "array",
                    "description": "Exempted domains, newest first.",
                    "items": {
                        "type": "object",
                        "required": ["domain", "action", "reason"],
                        "properties": {
                            "domain": { "type": "string" },
                            "action": { "type": "string" },
                            "reason": { "type": "string" },
                            "created_at": { "type": ["string", "null"], "description": "RFC 3339." }
                        }
                    }
                }
            }
        },
        "AiModelStatus": {
            "type": "object",
            "description": "The installed AI model files and the release their bundle came \
                from. Embeds the shared update state, so a models update can be followed here.",
            "required": ["models_dir", "files", "state"],
            "properties": {
                "models_dir": { "type": ["string", "null"] },
                "files": {
                    "type": "array",
                    "description": "Each installed file with its presence, size and sha256.",
                    "items": { "type": "object" }
                },
                "bundle": {
                    "description": "The release the bundle came from; absent when the \
                        install predates the marker."
                },
                "state": {
                    "description": "The shared update state; poll until `done`/`error`."
                }
            }
        },
        "AiRescan": {
            "type": "object",
            "required": ["requested"],
            "properties": { "requested": { "type": "boolean" } }
        },
        "ModelsUpdate": {
            "type": "object",
            "required": ["started", "pid"],
            "properties": {
                "started": { "type": "boolean" },
                "pid": { "type": "integer", "description": "The privileged apply process." }
            }
        }
    })
}

/// The recursive cache, the resolver dashboard and the local root zone.
fn resolver_schemas() -> Value {
    json!({
        "CacheStatus": {
            "type": "object",
            "required": [
                "enabled", "mode", "capacity", "tracked_names", "hits", "misses",
                "prefetch_enabled", "serve_stale_secs"
            ],
            "properties": {
                "enabled": { "type": "boolean", "description": "Whether recursion is on." },
                "mode": {
                    "type": ["string", "null"],
                    "description": "`recursive` or `forwarding`; null when recursion is off. \
                        Recursive mode cannot flush one name from the recursor's own cache."
                },
                "capacity": { "type": "integer", "description": "Cache entries." },
                "tracked_names": { "type": "integer" },
                "hits": { "type": "integer" },
                "misses": { "type": "integer" },
                "prefetch_enabled": { "type": "boolean" },
                "serve_stale_secs": { "type": "integer" }
            }
        },
        "ResolverStats": {
            "type": "object",
            "description": "How lookups were routed and how they ended, since the server \
                started.",
            "required": [
                "enabled", "dnssec_validation", "opportunistic_encryption", "local_root",
                "client_policies", "conditional_zones", "stub_zones", "queries",
                "dnssec_validated", "stats"
            ],
            "properties": {
                "enabled": { "type": "boolean" },
                "mode": { "type": ["string", "null"], "description": "`recursive` or `forwarding`." },
                "dnssec_validation": { "type": "boolean" },
                "opportunistic_encryption": { "type": "boolean" },
                "local_root": {
                    "type": "object",
                    "required": ["enabled", "serving"],
                    "properties": {
                        "enabled": { "type": "boolean" },
                        "serving": { "type": "boolean" },
                        "serial": { "type": ["integer", "null"] }
                    }
                },
                "client_policies": { "type": "integer", "description": "Enabled client policies." },
                "conditional_zones": { "type": "integer" },
                "stub_zones": { "type": "integer" },
                "queries": { "type": "integer" },
                "dnssec_validated": { "type": "integer" },
                "stats": {
                    "type": "object",
                    "description": "A latency histogram and counters by transport and outcome."
                }
            }
        },
        "LocalRootStatus": {
            "type": "object",
            "description": "The local root zone (RFC 8806): whether it is enabled and \
                served, its size and the last refresh outcome.",
            "required": ["enabled", "serving", "records", "tlds"],
            "properties": {
                "enabled": { "type": "boolean" },
                "serving": {
                    "type": "boolean",
                    "description": "A verified, unexpired copy is being served to the resolver."
                },
                "serial": { "type": ["integer", "null"] },
                "records": { "type": "integer" },
                "tlds": { "type": "integer" },
                "last_checked": { "type": ["string", "null"], "description": "RFC 3339." },
                "expires": {
                    "type": ["string", "null"],
                    "description": "After this the copy is no longer used (RFC 3339)."
                },
                "source": {
                    "type": ["string", "null"],
                    "description": "The server the copy came from, or `cache` after a restart."
                },
                "last_error": { "type": ["string", "null"] },
                "last_error_at": { "type": ["string", "null"], "description": "RFC 3339." }
            }
        },
        "FlushNameInput": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "type": {
                    "type": "string",
                    "description": "One record type (`A`, `AAAA`, ...); omitted flushes the \
                        common types."
                }
            }
        },
        "FlushNameResult": {
            "type": "object",
            "required": ["name", "complete"],
            "properties": {
                "name": { "type": "string" },
                "complete": {
                    "type": "boolean",
                    "description": "False when recursive mode still holds its own copy; \
                        flush the whole cache for that."
                }
            }
        }
    })
}

/// The `[policy]` checks, filtering groups, blocklist sources and RPZ.
fn policy_operation(path: &str, method: &str) -> Option<Value> {
    let error = schema_ref("Error");
    let not_configured = json!({
        "description": "No blocklist sources are configured.",
        "content": { "application/json": { "schema": error } }
    });
    let groups = json!({ "type": "array", "items": schema_ref("BlockingGroup") });
    match (method, path) {
        ("get", "/policy/services") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every service a group can block, grouped by category.",
                    schema_ref("ServiceCatalogue"),
                )
            }
        })),
        ("get", "/policy/security") => Some(json!({
            "responses": {
                "200": json_response(
                    "The security categories a filtering group can block, each feed-backed \
                        one with its download state.",
                    schema_ref("SecurityCatalogue"),
                )
            }
        })),
        ("get", "/policy/blocklist/sources") => Some(json!({
            "responses": {
                "200": json_response(
                    "Each source with its last fetch, and the live domain total.",
                    schema_ref("BlocklistSources"),
                ),
                "404": not_configured
            }
        })),
        ("put", "/policy/blocklist/sources") => Some(json!({
            "requestBody": request_body(
                schema_ref("BlocklistSourcesInput"),
                "The complete source list, applied live.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "The list was saved and applied; the background refresher takes over \
                        from here.",
                    schema_ref("BlocklistSourcesApplied"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "500": json!({
                    "description": "The blocklist manager is unavailable, so the sources \
                        could not be applied.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/policy/blocklist/sources/validate") => Some(json!({
            "parameters": [
                {
                    "name": "url",
                    "in": "query",
                    "required": true,
                    "schema": { "type": "string" },
                    "description": "The candidate source URL (http or https)."
                },
                {
                    "name": "format",
                    "in": "query",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "enum": ["domains", "wildcard", "hosts", "adblock", "rpz", "auto", "detect"]
                    },
                    "description": "The declared format; empty or `auto` detects it from \
                        the content."
                }
            ],
            "responses": {
                "200": json_response(
                    "The verdict: `ok` with the format and domain count, or `ok: false` \
                        and a reason when the content does not match.",
                    schema_ref("BlocklistValidateResult"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "502": json!({
                    "description": "The URL could not be fetched.",
                    "content": { "application/json": { "schema": error } }
                }),
                "503": json!({
                    "description": "The blocklist client is unavailable.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/policy/blocklist/sources") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every enabled source was re-fetched and published.",
                    schema_ref("BlocklistRefresh"),
                ),
                "404": not_configured,
                "502": json!({
                    "description": "A source could not be fetched.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/policy/blocking") => Some(json!({
            "responses": {
                "200": json_response("Every group, in evaluation order.", groups)
            }
        })),
        ("post", "/policy/blocking") => Some(json!({
            "requestBody": request_body(
                schema_ref("BlockingGroupInput"),
                "The group to create or update. Unknown service, category or TLD ids, and \
                    invalid regexes or schedules, are refused.",
                true,
            ),
            "responses": {
                "200": json_response("The group as stored.", schema_ref("BlockingGroup")),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("delete", "/policy/blocking/{id}") => Some(json!({
            "responses": {
                "204": empty_response("The group is gone and the engine rebuilt."),
                "404": json!({
                    "description": "No such group.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/policy/blocking/{id}/move") => Some(json!({
            "requestBody": request_body(
                schema_ref("MoveGroupInput"),
                "Which way to move the group in the evaluation order.",
                true,
            ),
            "responses": {
                "200": json_response("Every group, in its new order.", groups),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": json!({
                    "description": "No such group.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/policy/blocking/test") => Some(json!({
            "requestBody": request_body(
                schema_ref("BlockingTestInput"),
                "The pair to evaluate, optionally as a listener or DNS account.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "Whether the query is blocked and why, as the live engine decides it.",
                    schema_ref("BlockingVerdict"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("get", "/policy/explain") => Some(json!({
            "parameters": [
                {
                    "name": "domain",
                    "in": "query",
                    "required": true,
                    "schema": { "type": "string" }
                },
                {
                    "name": "client",
                    "in": "query",
                    "required": true,
                    "schema": { "type": "string" },
                    "description": "An IP address, or a device name from the devices list."
                },
                {
                    "name": "qtype",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "default": "A" },
                    "description": "The query type: Filter AAAA only touches `AAAA`."
                },
                {
                    "name": "listener",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["dot", "doh", "doq"] },
                    "description": "The encrypted listener asked on; omitted for plain DNS."
                },
                {
                    "name": "account",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "The DNS account asked as; omitted for none."
                }
            ],
            "responses": {
                "200": json_response(
                    "The verdict, every check in the order queries meet them, and the \
                        latest logged blocks of the domain.",
                    schema_ref("ExplainReport"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("get", "/rpz") => Some(json!({
            "responses": {
                "200": json_response("Each response policy zone's state.",
                    schema_ref("RpzStatus"))
            }
        })),
        ("post", "/rpz") => Some(json!({
            "responses": {
                "202": empty_response("Every fetched or transferred zone is being checked now."),
                "404": json!({
                    "description": "Response policy zones are not available.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/rpz/test") => Some(json!({
            "requestBody": request_body(
                schema_ref("RpzTestInput"),
                "The client address and domain to test.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "Which zones match, in order, and whether the domain is allowlisted.",
                    schema_ref("RpzTestResult"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("post", "/alerts/test") => Some(json!({
            "requestBody": request_body(
                schema_ref("AlertTestInput"),
                "The alert settings to try; omitted, the saved ones. The test is delivered \
                    whether or not alerts are switched on yet.",
                false,
            ),
            "responses": {
                "200": json_response(
                    "The test alert reached every configured destination.",
                    schema_ref("Sent"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "502": json!({
                    "description": "A destination refused or could not be reached.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        _ => None,
    }
}

/// The AI scanner.
fn ai_operation(path: &str, method: &str) -> Option<Value> {
    let error = schema_ref("Error");
    let ai_unavailable = json!({
        "description": "The AI scanner is not enabled or has no model loaded.",
        "content": { "application/json": { "schema": error } }
    });
    let page_parameters = |extra: Value| -> Value {
        let mut parameters = extra;
        if let Some(parameters) = parameters.as_array_mut() {
            parameters.extend([
                json!({
                    "name": "page",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "default": 1 }
                }),
                json!({
                    "name": "per_page",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "default": 50, "maximum": 500 }
                }),
                json!({
                    "name": "q",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Domain substring search."
                }),
            ]);
        }
        parameters
    };
    match (method, path) {
        ("get", "/ai/status") => Some(json!({
            "responses": {
                "200": json_response(
                    "The scanner's settings, backends and counters.",
                    schema_ref("AiStatus"),
                ),
                "404": ai_unavailable
            }
        })),
        ("get", "/ai/verdicts") => Some(json!({
            "parameters": page_parameters(json!([
                {
                    "name": "status",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["pending", "classified", "skipped", "stale"] }
                },
                {
                    "name": "category",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Category substring filter."
                },
                {
                    "name": "severity",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["info", "threat", "disputed"] }
                },
                {
                    "name": "exemption",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["exempt", "not_exempt"] }
                },
                {
                    "name": "label",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["set", "scanner"] },
                    "description": "`set`: categories the operator set; `scanner`: the scanner's own."
                },
                {
                    "name": "channel",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["content", "threat"], "default": "content" }
                }
            ])),
            "responses": {
                "200": json_response("One page of verdicts.", schema_ref("AiVerdictPage")),
                "404": ai_unavailable
            }
        })),
        ("get", "/ai/threats") => Some(json!({
            "parameters": page_parameters(json!([
                {
                    "name": "category",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" }
                },
                {
                    "name": "severity",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["threat", "disputed"] }
                },
                {
                    "name": "exemption",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string", "enum": ["exempt", "not_exempt"] }
                }
            ])),
            "responses": {
                "200": json_response(
                    "One page of threat verdicts, highest confidence first.",
                    schema_ref("AiThreatPage"),
                ),
                "404": ai_unavailable
            }
        })),
        ("post", "/ai/override") => Some(json!({
            "requestBody": request_body(
                schema_ref("AiOverrideInput"),
                "The override to install or remove.",
                true,
            ),
            "responses": {
                "200": json_response("The override was applied.",
                    schema_ref("AiOverrideApplied")),
                "404": json!({
                    "description": "Nothing to clear: no such override exists.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/ai/overrides") => Some(json!({
            "responses": {
                "200": json_response(
                    "The exempted domains (an exemption also covers subdomains), newest first.",
                    schema_ref("AiOverrides"),
                ),
                "404": ai_unavailable
            }
        })),
        ("post", "/ai/rescan") => Some(json!({
            "responses": {
                "200": json_response(
                    "The scanner was woken for an immediate cycle.",
                    schema_ref("AiRescan"),
                ),
                "404": ai_unavailable
            }
        })),
        ("get", "/ai/threats/export") => Some(json!({
            "parameters": json!([{
                "name": "format",
                "in": "query",
                "required": false,
                "schema": { "type": "string", "enum": ["csv", "list"] }
            }]),
            "responses": {
                "200": json!({
                    "description": "The active threat list, exactly the rows the block snapshot is built from: `list` is one domain per line, `csv` adds the label, confidence and re-check time.",
                    "content": {
                        "text/plain": { "schema": { "type": "string" } },
                        "text/csv": { "schema": { "type": "string" } }
                    }
                }),
                "400": json!({
                    "description": "`format` is neither `csv` nor `list`.",
                    "content": { "application/json": { "schema": error } }
                }),
                "404": ai_unavailable
            }
        })),
        ("get", "/ai/explain") => Some(json!({
            "parameters": json!([{
                "name": "domain",
                "in": "query",
                "required": true,
                "schema": { "type": "string" }
            }]),
            "responses": {
                "200": json!({
                    "description": "Why one domain is or is not blocked: both channels' verdicts, the operator's overrides, the label category blocking matches, the groups that block it, and plain-language reasons."
                }),
                "400": json!({
                    "description": "`domain` is missing or not a classifiable name.",
                    "content": { "application/json": { "schema": error } }
                }),
                "404": ai_unavailable
            }
        })),
        ("get", "/ai/corrections") => Some(json!({
            "parameters": json!([{
                "name": "format",
                "in": "query",
                "required": false,
                "schema": { "type": "string", "enum": ["csv"] }
            }]),
            "responses": {
                "200": json!({
                    "description": "Every operator correction (exemptions, not-a-threat marks and category relabels), newest first; `?format=csv` downloads it as training data."
                }),
                "404": ai_unavailable
            }
        })),
        ("post", "/ai/retrain") => Some(json!({
            "responses": {
                "200": json!({
                    "description": "Retrained from the scanner's confident verdicts and the operator's corrections, and loaded into the running scanner."
                }),
                "404": ai_unavailable,
                "500": json!({
                    "description": "Not enough training data, or the candidate did worse on held-out corrections than the model in use; the current model was kept.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/ai/model-status") => Some(json!({
            "responses": {
                "200": json_response(
                    "The installed model files and the shared update state.",
                    schema_ref("AiModelStatus"),
                )
            }
        })),
        ("post", "/ai/update-models") => Some(json!({
            "responses": {
                "202": json_response(
                    "The models-only update began. Poll `/ai/model-status` until `done`/`error`.",
                    schema_ref("ModelsUpdate"),
                ),
                "500": json!({
                    "description": "The running binary could not be located, or the update \
                        could not start.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        _ => None,
    }
}

/// The recursive cache, the resolver dashboard and the local root zone.
fn resolver_operation(path: &str, method: &str) -> Option<Value> {
    let error = schema_ref("Error");
    match (method, path) {
        ("get", "/cache") => Some(json!({
            "responses": {
                "200": json_response(
                    "The cache's configuration and runtime counters.",
                    schema_ref("CacheStatus"),
                )
            }
        })),
        ("post", "/cache/clear") => Some(json!({
            "responses": {
                "204": empty_response("Every cache entry is gone.")
            }
        })),
        ("post", "/cache/flush") => Some(json!({
            "requestBody": request_body(
                schema_ref("FlushNameInput"),
                "The name to remove, and optionally one record type.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "Whether the name is completely gone.",
                    schema_ref("FlushNameResult"),
                ),
                "400": json!({
                    "description": "The name is empty, or the flush was refused.",
                    "content": { "application/json": { "schema": error } }
                }),
                "409": json!({
                    "description": "Recursion is disabled, so there is no cache.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/resolver") => Some(json!({
            "responses": {
                "200": json_response(
                    "The resolver dashboard: routing, outcomes, latency and DNSSEC share.",
                    schema_ref("ResolverStats"),
                )
            }
        })),
        ("get", "/local-root") => Some(json!({
            "responses": {
                "200": json_response(
                    "The local root zone's state.",
                    schema_ref("LocalRootStatus"),
                )
            }
        })),
        ("post", "/local-root/refresh") => Some(json!({
            "responses": {
                "202": empty_response(
                    "The sources are being checked now instead of waiting for the interval.",
                ),
                "409": json!({
                    "description": "The local root zone is not enabled.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        _ => None,
    }
}

/// Managed certificates, split horizon, named networks, DNS accounts, devices
/// and DHCP.
fn admin_schemas() -> Value {
    let nullable_string = json!({ "type": ["string", "null"] });
    json!({
        "CertificateInput": {
            "type": "object",
            "description": "Create a self-signed certificate (omit both PEM fields) or \
                upload one. Uploading with an existing name replaces that entry.",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "1-64 characters of letters, digits, `.`, `_` or `-`, \
                        with no leading or trailing dot."
                },
                "server_name": {
                    "type": "string",
                    "description": "The CN/SAN used for a generated certificate."
                },
                "cert_pem": { "type": "string", "description": "PEM certificate chain." },
                "key_pem": {
                    "type": "string",
                    "description": "PEM private key; must accompany `cert_pem`."
                }
            }
        },
        "Certificate": {
            "type": "object",
            "description": "A managed certificate. PEM material is never returned; the \
                details are read from the certificate itself and are null when it cannot \
                be parsed.",
            "required": ["name", "server_name", "created_at", "in_use"],
            "properties": {
                "name": { "type": "string" },
                "server_name": { "type": "string" },
                "created_at": { "type": "string" },
                "in_use": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Listeners referencing it: `DoT`, `DoH`, `DoQ`, `Web Console`."
                },
                "subject": nullable_string.clone(),
                "issuer": nullable_string.clone(),
                "self_signed": { "type": ["boolean", "null"] },
                "names": {
                    "type": ["array", "null"],
                    "items": { "type": "string" },
                    "description": "Every name the certificate covers."
                },
                "not_before": { "type": ["string", "null"], "description": "RFC 3339." },
                "not_after": { "type": ["string", "null"], "description": "RFC 3339." },
                "acme": {
                    "description": "Present when the certificate is issued by ACME.",
                    "oneOf": [
                        { "$ref": "#/components/schemas/AcmeInfo" },
                        { "type": "null" }
                    ]
                }
            }
        },
        "AcmeInfo": {
            "type": "object",
            "description": "An ACME issuance: the domains asked for and how it went.",
            "required": ["domains", "challenge", "status", "last_error", "last_attempt"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The certificate's name; present on an issuance request."
                },
                "domains": { "type": "array", "items": { "type": "string" } },
                "challenge": {
                    "type": "string",
                    "description": "`http`, `dns` or `cloudflare`."
                },
                "status": {
                    "type": "string",
                    "description": "`pending` while an issuance is running, else the stored \
                        status (`valid`, `error`, ...)."
                },
                "last_error": { "type": "string" },
                "last_attempt": { "type": "integer", "description": "UNIX seconds; 0 = never." }
            }
        },
        "AcmeCertificateInput": {
            "type": "object",
            "description": "Request a certificate from the ACME CA. Issuing runs in the \
                background; the certificate list shows how it went.",
            "required": ["name", "domains"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "1-64 characters of letters, digits, `.`, `_` or `-`."
                },
                "domains": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "The names to certify."
                },
                "challenge": {
                    "type": "string",
                    "enum": ["http", "dns", "cloudflare"],
                    "default": "http",
                    "description": "`cloudflare` needs an API token in the Let's Encrypt \
                        settings."
                }
            }
        },
        "AcmeSettings": {
            "type": "object",
            "description": "The Let's Encrypt (ACME) settings.",
            "required": [
                "email", "directory", "agree_terms", "ca_certificate",
                "renew_days", "cloudflare_api_token"
            ],
            "properties": {
                "email": {
                    "type": "string",
                    "description": "Contact address for the CA account (expiry warnings)."
                },
                "directory": {
                    "type": "string",
                    "description": "The CA's directory URL; empty means Let's Encrypt."
                },
                "agree_terms": {
                    "type": "boolean",
                    "description": "The CA's terms of service were accepted; issuing is \
                        refused until they are."
                },
                "ca_certificate": {
                    "type": "string",
                    "description": "PEM root to trust for a private CA (empty: the system's roots)."
                },
                "renew_days": {
                    "type": "integer",
                    "description": "Renew this many days before expiry; 0 uses the default (30)."
                },
                "cloudflare_api_token": {
                    "type": "string",
                    "description": "Write-only: reads back as `[redacted]`, and sending \
                        `[redacted]` keeps the stored token."
                }
            }
        },
        "AcmeSettingsResponse": {
            "type": "object",
            "required": ["settings", "directory_url", "lets_encrypt", "lets_encrypt_staging"],
            "properties": {
                "settings": { "$ref": "#/components/schemas/AcmeSettings" },
                "directory_url": { "type": "string", "description": "The directory in effect." },
                "lets_encrypt": { "type": "string", "description": "The production directory URL." },
                "lets_encrypt_staging": { "type": "string", "description": "The staging URL." }
            }
        },
        "NamedNetwork": {
            "type": "object",
            "description": "A named set of addresses, referenced by split horizon, policy, \
                groups and the transfer gates instead of repeating CIDRs.",
            "required": ["name", "cidrs"],
            "properties": {
                "name": { "type": "string" },
                "cidrs": { "type": "array", "items": { "type": "string" } },
                "description": { "type": "string" }
            }
        },
        "NetworkView": {
            "description": "A network with what uses it.",
            "allOf": [
                { "$ref": "#/components/schemas/NamedNetwork" },
                {
                    "type": "object",
                    "required": ["used_by", "builtin", "description"],
                    "properties": {
                        "used_by": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "The settings and rules that name it."
                        },
                        "builtin": {
                            "type": "boolean",
                            "description": "One of the built-in networks (e.g. `LAN`)."
                        },
                        "description": { "type": "string" }
                    }
                }
            ]
        },
        "NetworksResponse": {
            "type": "object",
            "required": ["networks"],
            "properties": {
                "networks": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/NetworkView" }
                }
            }
        },
        "NetworkInput": {
            "type": "object",
            "additionalProperties": false,
            "description": "Add a network, or change one. A different `name` renames it and \
                every reference to it.",
            "required": ["name", "cidrs"],
            "properties": {
                "original_name": {
                    "type": "string",
                    "description": "The network being edited; absent for a new one."
                },
                "name": { "type": "string" },
                "cidrs": { "type": "array", "items": { "type": "string" } },
                "description": { "type": "string", "default": "" }
            }
        },
        "SplitHorizonNetworkInput": {
            "type": "object",
            "description": "The older form of `POST /api/networks`: add a named network, or \
                change the addresses of the one with the same name.",
            "required": ["name", "cidrs"],
            "properties": {
                "name": { "type": "string" },
                "cidrs": { "type": "array", "items": { "type": "string" } }
            }
        },
        "SplitHorizonRecord": {
            "type": "object",
            "description": "One synthesized answer in zone-file presentation format: `A` to \
                `10.0.0.5`, `MX` to `10 mail.example.com.`, `TXT` to `\"hello world\"`.",
            "required": ["rtype", "content"],
            "properties": {
                "rtype": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "TXT", "CNAME", "SRV"]
                },
                "content": { "type": "string" }
            }
        },
        "SplitHorizonEntry": {
            "type": "object",
            "description": "Clients in `networks` receive `records` for `domain` instead of \
                the normal answer. Entries for one domain are ordered; the first match wins.",
            "required": [
                "id", "domain", "networks", "ips", "records", "ttl", "disabled", "position"
            ],
            "properties": {
                "id": { "type": "string", "description": "Primary key (UUID)." },
                "domain": { "type": "string", "description": "Fully qualified, no trailing dot." },
                "networks": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Network names and/or literal CIDRs; empty means every client."
                },
                "ips": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Kept for compatibility: always the A/AAAA subset of `records`."
                },
                "records": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/SplitHorizonRecord" }
                },
                "ttl": { "type": "integer", "description": "TTL of the synthesized answers." },
                "disabled": {
                    "type": "boolean",
                    "description": "Skipped while true, kept for later use."
                },
                "position": {
                    "type": "integer",
                    "description": "Ordering among entries for the same domain."
                },
                "last_modified_at": { "type": ["string", "null"], "description": "RFC 3339." },
                "last_used_at": {
                    "type": ["string", "null"],
                    "description": "When this entry last served an answer (RFC 3339)."
                }
            }
        },
        "SplitHorizonEntryInput": {
            "type": "object",
            "description": "`records` is the canonical form; `ips` alone still works and is \
                converted to A/AAAA records, and `records` wins when both are given.",
            "required": ["domain", "networks"],
            "properties": {
                "domain": { "type": "string" },
                "networks": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Network names and/or literal CIDRs; a name that does not \
                        exist is refused, since it would never match."
                },
                "ips": {
                    "type": "array",
                    "items": { "type": "string" },
                    "default": []
                },
                "records": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/SplitHorizonRecord" },
                    "default": []
                },
                "ttl": { "type": "integer", "default": 60 },
                "disabled": { "type": "boolean", "default": false }
            }
        },
        "SplitHorizonView": {
            "type": "object",
            "required": ["networks", "entries"],
            "properties": {
                "networks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "name", "cidrs"],
                        "properties": {
                            "id": { "type": "string" },
                            "name": { "type": "string" },
                            "cidrs": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                },
                "entries": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/SplitHorizonEntry" }
                }
            }
        },
        "MoveDirection": {
            "type": "string",
            "enum": ["up", "down"],
            "description": "`up` moves earlier (higher precedence), `down` later."
        },
        "SplitHorizonMoveInput": {
            "type": "object",
            "required": ["direction"],
            "properties": { "direction": { "$ref": "#/components/schemas/MoveDirection" } }
        },
        "Moved": {
            "type": "object",
            "required": ["moved"],
            "properties": {
                "moved": {
                    "type": "boolean",
                    "description": "False when the entry is already at the edge of its domain's order."
                }
            }
        },
        "DnsAccount": {
            "type": "object",
            "description": "A DNS account: devices are recognised by the client ID in the \
                host name they reach DoT/DoQ at, or in the DoH URL path, wherever they connect from.",
            "required": ["id", "name", "client_id", "enabled", "created_at"],
            "properties": {
                "id": { "type": "string" },
                "name": {
                    "type": "string",
                    "description": "Unique ignoring case; what filtering groups refer to."
                },
                "client_id": {
                    "type": "string",
                    "description": "The DNS label devices put in front of the account domain."
                },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "description": "RFC 3339." },
                "last_seen_at": {
                    "type": ["string", "null"],
                    "description": "RFC 3339 time of the last query seen (to the minute)."
                }
            }
        },
        "AccountView": {
            "description": "An account with how a device connects as it.",
            "allOf": [
                { "$ref": "#/components/schemas/DnsAccount" },
                {
                    "type": "object",
                    "required": ["hostname", "doh_path"],
                    "properties": {
                        "hostname": {
                            "type": "string",
                            "description": "The DoT/DoQ host name (`<client id>.<domain>`); \
                                empty while no account domain is set."
                        },
                        "doh_path": {
                            "type": "string",
                            "description": "The DoH URL path (`<endpoint>/<client id>`)."
                        }
                    }
                }
            ]
        },
        "DnsAccountInput": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "client_id": {
                    "type": "string",
                    "default": "",
                    "description": "Empty keeps the current ID, or generates one for a new \
                        account."
                },
                "enabled": { "type": "boolean", "default": true }
            }
        },
        "AccountsResponse": {
            "type": "object",
            "required": ["settings", "accounts"],
            "properties": {
                "settings": {
                    "type": "object",
                    "required": ["domain", "require"],
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Client IDs go under this name; the listeners' \
                                certificate must cover `*.<domain>`. Empty turns account \
                                recognition off."
                        },
                        "require": {
                            "type": "boolean",
                            "description": "Refuse encrypted queries that name no known, \
                                enabled account. Plain DNS is not affected."
                        }
                    }
                },
                "accounts": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/AccountView" }
                }
            }
        },
        "Device": {
            "type": "object",
            "description": "A device seen in the query log, holding a DHCP lease or named \
                by hand.",
            "required": [
                "address", "mac", "name", "source", "manual_name",
                "queries", "blocked", "last_seen"
            ],
            "properties": {
                "address": { "type": "string" },
                "mac": { "type": "string", "description": "From its DHCP lease; empty when unknown." },
                "name": { "type": "string", "description": "The name shown; empty when there is none." },
                "source": {
                    "type": "string",
                    "enum": ["manual", "dhcp", "reverse_dns"],
                    "description": "Where `name` came from."
                },
                "manual_name": { "type": "string", "description": "The name given by hand, if any." },
                "queries": { "type": "integer" },
                "blocked": { "type": "integer" },
                "last_seen": {
                    "type": "string",
                    "description": "RFC 3339; empty when it has not asked anything in the period."
                }
            }
        },
        "DevicesResponse": {
            "type": "object",
            "required": ["hours", "query_log_enabled", "devices"],
            "properties": {
                "hours": { "type": "integer", "description": "The window actually used." },
                "query_log_enabled": {
                    "type": "boolean",
                    "description": "False when the query log is off, so the list is empty."
                },
                "devices": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/Device" }
                }
            }
        },
        "DeviceNameInput": {
            "type": "object",
            "description": "Name a device (by its MAC address when one is given, else by its \
                IP address), or forget its name.",
            "required": ["address"],
            "properties": {
                "address": { "type": "string", "description": "An IP address." },
                "mac": { "type": "string", "default": "", "description": "A MAC address, when known." },
                "name": {
                    "type": "string",
                    "default": "",
                    "description": "The name to keep; empty forgets it."
                }
            }
        },
        "DhcpStatus": {
            "type": "object",
            "required": ["supported", "v4", "v6", "server_duid"],
            "properties": {
                "supported": { "type": "boolean", "description": "Whether this platform can serve DHCP." },
                "v4": {
                    "type": "string",
                    "description": "`Off`, `Listening on UDP port 67`, or why it is not listening."
                },
                "v6": { "type": "string" },
                "server_duid": { "type": "string", "description": "This server's DHCPv6 DUID, hex." }
            }
        },
        "DhcpInterface": {
            "type": "object",
            "required": ["name", "index", "addresses"],
            "properties": {
                "name": { "type": "string" },
                "index": { "type": "integer" },
                "addresses": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "With their prefix length, e.g. `192.168.1.2/24`."
                }
            }
        },
        "DhcpLease": {
            "type": "object",
            "required": [
                "address", "scope", "client_id", "hw_address", "hostname",
                "state", "expires", "dns_name", "dns_records", "updated_at"
            ],
            "properties": {
                "address": { "type": "string" },
                "scope": { "type": "string", "description": "The scope's name." },
                "client_id": {
                    "type": "string",
                    "description": "Client identifier or MAC (v4), DUID and IAID (v6), in hex."
                },
                "hw_address": { "type": "string", "description": "MAC address or DUID." },
                "hostname": { "type": "string" },
                "state": {
                    "type": "string",
                    "enum": ["offered", "bound", "declined", "released"]
                },
                "expires": { "type": "integer", "description": "UNIX seconds." },
                "dns_name": { "type": "string", "description": "The name registered; empty for none." },
                "dns_records": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Ids of the DNS records registered for the lease."
                },
                "updated_at": { "type": "string", "description": "RFC 3339." }
            }
        },
        "DhcpView": {
            "type": "object",
            "required": ["status", "interfaces", "leases"],
            "properties": {
                "status": { "$ref": "#/components/schemas/DhcpStatus" },
                "interfaces": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/DhcpInterface" }
                },
                "leases": {
                    "type": "array",
                    "description": "By address, IPv4 first.",
                    "items": { "$ref": "#/components/schemas/DhcpLease" }
                }
            }
        }
    })
}

/// Managed certificates and ACME, split horizon and named networks, DNS
/// accounts, devices and DHCP.
fn admin_operation(path: &str, method: &str) -> Option<Value> {
    let error = schema_ref("Error");
    let not_found = |what: &str| {
        json!({
            "description": what,
            "content": { "application/json": { "schema": schema_ref("Error") } }
        })
    };
    let in_use = json!({
        "description": "The certificate is selected by a listener; change the listener first.",
        "content": { "application/json": { "schema": error } }
    });
    match (method, path) {
        ("get", "/certificates") => Some(json!({
            "responses": {
                "200": json_response(
                    "Every managed certificate (metadata only; PEM is never returned), \
                        including ACME issuance that is still pending.",
                    json!({ "type": "array", "items": schema_ref("Certificate") }),
                )
            }
        })),
        ("post", "/certificates") => Some(json!({
            "requestBody": request_body(
                schema_ref("CertificateInput"),
                "The certificate to generate or upload. Listeners using the name are \
                    rebuilt, so new material applies at once.",
                true,
            ),
            "responses": {
                "200": json_response("The certificate as stored.",
                    schema_ref("Certificate")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": json!({
                    "description": "A certificate with that name already exists, or the \
                        material is refused.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("delete", "/certificates/{name}") => Some(json!({
            "responses": {
                "204": empty_response("The certificate is gone."),
                "404": not_found("Certificate not found."),
                "409": in_use
            }
        })),
        ("post", "/certificates/acme") => Some(json!({
            "requestBody": request_body(
                schema_ref("AcmeCertificateInput"),
                "The names to certify and the challenge to use.",
                true,
            ),
            "responses": {
                "202": json_response(
                    "Issuance started in the background; the certificate list shows how it went.",
                    schema_ref("AcmeInfo"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "409": json!({
                    "description": "A certificate with that name already exists.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/certificates/{name}/renew") => Some(json!({
            "responses": {
                "202": empty_response("Renewal started in the background."),
                "404": not_found("That name is not an ACME certificate."),
                "409": json!({
                    "description": "The certificate is already being requested.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/acme") => Some(json!({
            "responses": {
                "200": json_response(
                    "The ACME settings, with the API token redacted, and the directories in \
                        use.",
                    schema_ref("AcmeSettingsResponse"),
                )
            }
        })),
        ("put", "/acme") => Some(json!({
            "requestBody": request_body(
                schema_ref("AcmeSettings"),
                "The settings to save. An API token of `[redacted]` keeps the stored one.",
                true,
            ),
            "responses": {
                "200": json_response("The settings as stored.",
                    schema_ref("AcmeSettingsResponse")),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("get", "/split-horizon") => Some(json!({
            "responses": {
                "200": json_response(
                    "The named networks and every split-horizon entry.",
                    schema_ref("SplitHorizonView"),
                )
            }
        })),
        ("post", "/split-horizon/networks") => Some(json!({
            "requestBody": request_body(
                schema_ref("SplitHorizonNetworkInput"),
                "Add a named network, or change the addresses of the one with the same name.",
                true,
            ),
            "responses": {
                "200": json_response("The network as stored.",
                    schema_ref("NamedNetwork")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": json_response(
                    "The network being edited does not exist.",
                    schema_ref("Error"),
                ),
                "409": json!({
                    "description": "A network with that name already exists.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("delete", "/split-horizon/networks/{name}") => Some(json!({
            "responses": {
                "204": empty_response("The network is gone."),
                "404": not_found("No network with that name."),
                "409": json!({
                    "description": "The network is still used; `used_by` names what uses it.",
                    "content": { "application/json": { "schema": json!({
                        "type": "object",
                        "required": ["error", "used_by"],
                        "properties": {
                            "error": { "type": "string" },
                            "used_by": { "type": "array", "items": { "type": "string" } }
                        }
                    }) } }
                })
            }
        })),
        ("post", "/split-horizon/entries") => Some(json!({
            "requestBody": request_body(
                schema_ref("SplitHorizonEntryInput"),
                "The entry to add; it is appended after existing entries for the same domain.",
                true,
            ),
            "responses": {
                "201": json_response("The entry as stored.",
                    schema_ref("SplitHorizonEntry")),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("put", "/split-horizon/entries/{id}") => Some(json!({
            "requestBody": request_body(
                schema_ref("SplitHorizonEntryInput"),
                "The entry's new content.",
                true,
            ),
            "responses": {
                "200": json_response("The entry as stored.",
                    schema_ref("SplitHorizonEntry")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found("Entry not found.")
            }
        })),
        ("delete", "/split-horizon/entries/{id}") => Some(json!({
            "responses": {
                "204": empty_response("The entry is gone."),
                "404": not_found("Entry not found.")
            }
        })),
        ("post", "/split-horizon/entries/{id}/move") => Some(json!({
            "requestBody": request_body(
                schema_ref("SplitHorizonMoveInput"),
                "Which way to move the entry within its domain's order.",
                true,
            ),
            "responses": {
                "200": json_response(
                    "Whether the entry moved: false when it is already at the edge.",
                    schema_ref("Moved"),
                ),
                "404": not_found("Entry not found.")
            }
        })),
        ("get", "/networks") => Some(json!({
            "responses": {
                "200": json_response(
                    "The built-in and configured networks, each with what uses it.",
                    schema_ref("NetworksResponse"),
                )
            }
        })),
        ("post", "/networks") => Some(json!({
            "requestBody": request_body(
                schema_ref("NetworkInput"),
                "Add a network, or change (and rename) one. Everything that names networks \
                    picks the change up at once.",
                true,
            ),
            "responses": {
                "200": json_response("The network as stored.",
                    schema_ref("NamedNetwork")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found("The network being edited does not exist."),
                "409": json!({
                    "description": "A network with that name already exists.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("delete", "/networks/{name}") => Some(json!({
            "responses": {
                "204": empty_response("The network is gone."),
                "404": not_found("No network with that name."),
                "409": json!({
                    "description": "The network is still used; `used_by` names what uses it.",
                    "content": { "application/json": { "schema": json!({
                        "type": "object",
                        "required": ["error", "used_by"],
                        "properties": {
                            "error": { "type": "string" },
                            "used_by": { "type": "array", "items": { "type": "string" } }
                        }
                    }) } }
                })
            }
        })),
        ("get", "/accounts") => Some(json!({
            "responses": {
                "200": json_response(
                    "The account settings, every account, and how each one connects.",
                    schema_ref("AccountsResponse"),
                )
            }
        })),
        ("post", "/accounts") => Some(json!({
            "requestBody": request_body(
                schema_ref("DnsAccountInput"),
                "The account to create; an empty `client_id` is generated.",
                true,
            ),
            "responses": {
                "201": json_response("The account as stored.",
                    schema_ref("AccountView")),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("put", "/accounts/{id}") => Some(json!({
            "requestBody": request_body(
                schema_ref("DnsAccountInput"),
                "Rename, enable or disable the account, or change its client ID.",
                true,
            ),
            "responses": {
                "200": json_response("The account as stored.",
                    schema_ref("AccountView")),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": not_found("No such account.")
            }
        })),
        ("post", "/accounts/{id}/new-id") => Some(json!({
            "responses": {
                "200": json_response(
                    "The account with a new random client ID; the old one stops working.",
                    schema_ref("AccountView"),
                ),
                "404": not_found("No such account.")
            }
        })),
        ("delete", "/accounts/{id}") => Some(json!({
            "responses": {
                "204": empty_response(
                    "The account is gone, and it is dropped from filtering groups.",
                ),
                "404": not_found("No such account.")
            }
        })),
        ("get", "/devices") => Some(json!({
            "parameters": [{
                "name": "hours",
                "in": "query",
                "required": false,
                "schema": { "type": "integer", "default": 168, "minimum": 1, "maximum": 2160 },
                "description": "How far back to look, in hours (clamped to 1-2160)."
            }],
            "responses": {
                "200": json_response(
                    "The devices seen in the period (default a week), with their names.",
                    schema_ref("DevicesResponse"),
                ),
                "500": json!({
                    "description": "The devices could not be listed.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("put", "/devices/name") => Some(json!({
            "requestBody": request_body(
                schema_ref("DeviceNameInput"),
                "The device to name, and the name to keep (empty forgets it).",
                true,
            ),
            "responses": {
                "204": empty_response("The name is stored (or forgotten)."),
                "400": { "$ref": "#/components/responses/BadRequest" }
            }
        })),
        ("get", "/dhcp") => Some(json!({
            "responses": {
                "200": json_response(
                    "The DHCP server's status, the interfaces it can serve and the leases.",
                    schema_ref("DhcpView"),
                ),
                "404": json!({
                    "description": "DHCP is not available on this deployment.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("delete", "/dhcp/leases/{address}") => Some(json!({
            "responses": {
                "204": empty_response("The lease is forgotten and its DNS names removed."),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "404": json!({
                    "description": "DHCP is unavailable, or there is no lease for that address.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        _ => None,
    }
}

/// Reports, backup and restore, in-place updates and the audit log.
fn maintenance_schemas() -> Value {
    json!({
        "ReportQuery": {
            "type": "object",
            "description": "What the summary covers; every field is optional.",
            "properties": {
                "hours": {
                    "type": "integer",
                    "default": 24,
                    "minimum": 1,
                    "maximum": 2160,
                    "description": "How far back to look, in hours (clamped to 1-2160)."
                },
                "client": {
                    "type": "string",
                    "description": "Only this client's queries; empty or absent counts every client."
                },
                "top": {
                    "type": "integer",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 100,
                    "description": "How many entries each ranked list holds."
                }
            }
        },
        "QueryLogReport": {
            "type": "object",
            "description": "A summary of the query log for a period: totals, the ranked \
                lists the Reports page draws, and the time series behind its charts. Every \
                ranked list is most-frequent first.",
            "required": [
                "since", "queries", "blocked", "clients_seen", "clients", "top_domains",
                "top_blocked", "timeline", "outcomes", "rcodes", "block_sources",
                "block_rules", "failing", "qtypes", "protocols", "latency",
                "latency_buckets", "slowest", "new_names_total", "new_names", "zones"
            ],
            "properties": {
                "since": { "type": "string", "description": "RFC 3339: the start of the period." },
                "queries": { "type": "integer" },
                "blocked": { "type": "integer" },
                "clients_seen": { "type": "integer", "description": "Distinct clients." },
                "clients": {
                    "type": "array",
                    "description": "The most active clients.",
                    "items": { "$ref": "#/components/schemas/ClientActivity" }
                },
                "top_domains": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "top_blocked": {
                    "type": "array",
                    "description": "The most blocked names, each with what blocked it most.",
                    "items": { "$ref": "#/components/schemas/BlockedName" }
                },
                "timeline": {
                    "type": "array",
                    "description": "Queries per UTC hour, oldest first; hours with none are \
                        left out.",
                    "items": { "$ref": "#/components/schemas/HourCount" }
                },
                "outcomes": {
                    "type": "array",
                    "description": "Queries by outcome (`recursive`, `authoritative`, \
                        `split_horizon`, `blocked`, `rate_limited`, `error`).",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "rcodes": {
                    "type": "array",
                    "description": "Queries by response code (`NOERROR`, `NXDOMAIN`, ...); \
                        empty when none was recorded.",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "block_sources": {
                    "type": "array",
                    "description": "Blocked queries by what blocked them (a rule source such \
                        as `group` or `rpz`); empty for blocks logged before reasons were kept.",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "block_rules": {
                    "type": "array",
                    "description": "The blocking rules that blocked most.",
                    "items": { "$ref": "#/components/schemas/BlockRuleCount" }
                },
                "failing": {
                    "type": "array",
                    "description": "The names that failed most: NXDOMAIN, SERVFAIL or REFUSED \
                        answers the server gave, not counting its own blocks or rate limiting.",
                    "items": { "$ref": "#/components/schemas/FailingName" }
                },
                "qtypes": {
                    "type": "array",
                    "description": "Queries by record type (`A`, `AAAA`, `HTTPS`, ...).",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "protocols": {
                    "type": "array",
                    "description": "Queries by transport (`udp`, `tcp`, `tls`, `https`, \
                        `quic`, `h3`).",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "latency": {
                    "description": "Response times of resolved queries, cache hits included.",
                    "$ref": "#/components/schemas/LatencySummary"
                },
                "latency_buckets": {
                    "type": "array",
                    "description": "Resolved queries by response time, in the fixed order \
                        `under_10`, `10_50`, `50_200`, `200_1000`, `over_1000` milliseconds.",
                    "items": { "$ref": "#/components/schemas/NameCount" }
                },
                "slowest": {
                    "type": "array",
                    "description": "The slowest names to resolve, asked at least three \
                        times, slowest first.",
                    "items": { "$ref": "#/components/schemas/SlowName" }
                },
                "new_names_total": {
                    "type": "integer",
                    "description": "How many names were asked for the first time in the \
                        period, as far back as the query log is kept."
                },
                "new_names": {
                    "type": "array",
                    "description": "The most recent of those, newest first.",
                    "items": { "$ref": "#/components/schemas/NewName" }
                },
                "zones": {
                    "type": "array",
                    "description": "Queries answered from each hosted zone; a zone's aliases \
                        count towards it.",
                    "items": { "$ref": "#/components/schemas/ZoneTraffic" }
                }
            }
        },
        "ClientActivity": {
            "type": "object",
            "required": ["client", "queries", "blocked", "last_seen"],
            "properties": {
                "client": { "type": "string" },
                "queries": { "type": "integer" },
                "blocked": { "type": "integer" },
                "last_seen": { "type": "string", "description": "RFC 3339." }
            }
        },
        "NameCount": {
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": { "type": "string" },
                "count": { "type": "integer" }
            }
        },
        "BlockedName": {
            "type": "object",
            "required": ["name", "count", "source"],
            "properties": {
                "name": { "type": "string" },
                "count": { "type": "integer" },
                "source": {
                    "type": "string",
                    "description": "What blocked the dominant share; empty for blocks logged \
                        before reasons were kept."
                },
                "group": {
                    "type": ["string", "null"],
                    "description": "The filtering group that decided, when known."
                },
                "matched": {
                    "type": ["string", "null"],
                    "description": "The blocklist entry or list that matched, when known."
                }
            }
        },
        "BlockRuleCount": {
            "type": "object",
            "required": ["source", "count"],
            "properties": {
                "source": { "type": "string" },
                "group": { "type": ["string", "null"] },
                "matched": { "type": ["string", "null"] },
                "count": { "type": "integer" }
            }
        },
        "FailingName": {
            "type": "object",
            "required": ["name", "rcode", "count"],
            "properties": {
                "name": { "type": "string" },
                "rcode": { "type": "string" },
                "count": { "type": "integer" }
            }
        },
        "LatencySummary": {
            "type": "object",
            "description": "Response times in milliseconds, over the queries that were resolved.",
            "required": ["queries", "average_ms", "median_ms", "p95_ms", "max_ms"],
            "properties": {
                "queries": { "type": "integer", "description": "How many queries the figures cover." },
                "average_ms": { "type": "integer" },
                "median_ms": { "type": "integer" },
                "p95_ms": { "type": "integer" },
                "max_ms": { "type": "integer" }
            }
        },
        "SlowName": {
            "type": "object",
            "required": ["name", "queries", "average_ms", "max_ms"],
            "properties": {
                "name": { "type": "string" },
                "queries": { "type": "integer" },
                "average_ms": { "type": "integer" },
                "max_ms": { "type": "integer" }
            }
        },
        "NewName": {
            "type": "object",
            "required": ["name", "first_seen", "queries", "blocked"],
            "properties": {
                "name": { "type": "string" },
                "first_seen": { "type": "string", "description": "RFC 3339." },
                "queries": { "type": "integer" },
                "blocked": { "type": "integer" }
            }
        },
        "ZoneTraffic": {
            "type": "object",
            "required": ["zone", "queries", "nxdomain"],
            "properties": {
                "zone": { "type": "string" },
                "queries": { "type": "integer" },
                "nxdomain": {
                    "type": "integer",
                    "description": "Of those, how many were answered NXDOMAIN (a name the zone \
                        does not have)."
                }
            }
        },
        "HourCount": {
            "type": "object",
            "required": ["hour", "queries", "blocked"],
            "properties": {
                "hour": { "type": "string", "description": "RFC 3339: the start of the hour, UTC." },
                "queries": { "type": "integer" },
                "blocked": { "type": "integer" }
            }
        },
        "ReportsResponse": {
            "type": "object",
            "required": ["hours", "query_log_enabled", "report"],
            "properties": {
                "hours": { "type": "integer", "description": "The period actually used." },
                "query_log_enabled": {
                    "type": "boolean",
                    "description": "False when the query log is off, so every figure is zero."
                },
                "report": { "$ref": "#/components/schemas/QueryLogReport" }
            }
        },
        "ReportSettings": {
            "type": "object",
            "description": "The scheduled report's settings.",
            "required": ["enabled", "frequency", "weekday", "hour", "top"],
            "properties": {
                "enabled": { "type": "boolean" },
                "frequency": {
                    "type": "string",
                    "enum": ["daily", "weekly"],
                    "description": "`daily` covers the last 24 hours, `weekly` the last 7 days."
                },
                "weekday": {
                    "type": "string",
                    "description": "`weekly` only: the day it goes out, `mon` to `sun`."
                },
                "hour": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 23,
                    "description": "The hour it goes out, in the display time zone."
                },
                "top": {
                    "type": "integer",
                    "description": "How many domains and devices each list in the report shows."
                }
            }
        },
        "SendReportInput": {
            "type": "object",
            "description": "Settings to use for this send instead of the saved ones.",
            "properties": {
                "reports": { "$ref": "#/components/schemas/ReportSettings" }
            }
        },
        "ReportSent": {
            "type": "object",
            "required": ["sent"],
            "properties": { "sent": { "type": "boolean" } }
        },
        "BackupInfo": {
            "type": "object",
            "description": "What a backup file holds, read from the file itself.",
            "required": [
                "created_at", "app_version", "zones", "records", "users",
                "certificates", "query_logs", "ai_overrides"
            ],
            "properties": {
                "created_at": { "type": "integer", "description": "UNIX seconds." },
                "app_version": { "type": "string", "description": "The server version that made it." },
                "zones": { "type": "integer" },
                "records": { "type": "integer" },
                "users": { "type": "integer" },
                "certificates": { "type": "integer" },
                "query_logs": { "type": "integer" },
                "ai_overrides": { "type": "integer" }
            }
        },
        "RestoreStatus": {
            "type": "object",
            "required": ["pending"],
            "properties": {
                "pending": {
                    "description": "The restore waiting for a restart, or null when none is staged.",
                    "oneOf": [
                        { "$ref": "#/components/schemas/BackupInfo" },
                        { "type": "null" }
                    ]
                }
            }
        },
        "UpdateState": {
            "type": "object",
            "description": "The updater's progress snapshot, written to a temp-dir state file \
                so a poll after the restart still reports the run's outcome.",
            "required": [
                "phase", "pid", "started_at", "message", "exit_code", "automatic"
            ],
            "properties": {
                "phase": {
                    "type": "string",
                    "description": "`\"\"` (idle), `preparing`, `downloading`, `cloning`, \
                        `building`, `installing`, `applying`, `restarting`, `rolling_back`, \
                        `done` or `error`."
                },
                "pid": { "type": "integer", "description": "The helper's process id; 0 when unknown." },
                "started_at": { "type": "string" },
                "message": { "type": "string" },
                "exit_code": { "type": "integer", "description": "The helper's exit status; 0 while running." },
                "automatic": {
                    "type": "boolean",
                    "description": "True only for an opt-in scheduled stable-release installation."
                }
            }
        },
        "UpdateInfo": {
            "type": "object",
            "required": [
                "version", "install_script", "has_config_file", "has_systemd", "can_update",
                "gates", "update_command", "preserves", "note", "state", "checks_enabled",
                "check_interval_secs"
            ],
            "properties": {
                "version": { "type": "string", "description": "The running server's version." },
                "install_script": { "type": "string", "description": "The one-line installer's URL." },
                "has_config_file": {
                    "type": "boolean",
                    "description": "Whether the server was started with a config file."
                },
                "has_systemd": {
                    "type": "boolean",
                    "description": "Whether the systemd unit is installed."
                },
                "can_update": {
                    "type": "boolean",
                    "description": "Whether this host can run the installer in place; when \
                        false the console shows `update_command` to run by hand."
                },
                "gates": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Human-readable reasons an in-place update is unavailable; \
                        empty when it is."
                },
                "latest_release": {
                    "type": ["string", "null"],
                    "description": "The latest published release, e.g. `1.0.2`; null when no \
                        check has succeeded or the host cannot self-update."
                },
                "updater_outdated": {
                    "type": ["boolean", "null"],
                    "description": "Whether the running binary is older than the latest release."
                },
                "updater_bootstrap_required": {
                    "type": ["boolean", "null"],
                    "description": "Whether the installed updater predates in-place updates, so \
                        the installer must be run once by hand first."
                },
                "update_command": { "type": "string", "description": "The manual equivalent." },
                "preserves": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "What an update keeps: configuration, zones, certificates, database."
                },
                "note": { "type": "string" },
                "state": { "$ref": "#/components/schemas/UpdateState" },
                "checks_enabled": {
                    "type": "boolean",
                    "description": "Whether automatic release checks are on. The release data \
                        here is a pure cache read either way, so a manual check fills it."
                },
                "check_interval_secs": { "type": "integer" },
                "latest_checked_secs_ago": {
                    "type": ["integer", "null"],
                    "description": "Seconds since the release cache was last refreshed."
                }
            }
        },
        "UpdateStatus": {
            "type": "object",
            "required": ["version", "can_update", "gates", "state", "log"],
            "properties": {
                "version": { "type": "string" },
                "can_update": { "type": "boolean" },
                "gates": { "type": "array", "items": { "type": "string" } },
                "state": { "$ref": "#/components/schemas/UpdateState" },
                "log": {
                    "type": "string",
                    "description": "The tail of the updater's output (at most 8 KiB), for live \
                        progress."
                }
            }
        },
        "UpdateCheck": {
            "type": "object",
            "required": ["latest_release", "checked_now", "fetched", "retry_after_secs"],
            "properties": {
                "latest_release": { "type": ["string", "null"] },
                "updater_outdated": { "type": ["boolean", "null"] },
                "updater_bootstrap_required": { "type": ["boolean", "null"] },
                "checked_now": {
                    "type": "boolean",
                    "description": "False when the request arrived inside the throttle window \
                        and was answered from the cache."
                },
                "fetched": {
                    "type": "boolean",
                    "description": "Whether this attempt reached GitHub; false when the host \
                        was unreachable or rate-limited, in which case the cache keeps its \
                        last-known value."
                },
                "retry_after_secs": {
                    "type": ["integer", "null"],
                    "description": "Seconds until the throttle window lifts; set only when \
                        throttled."
                }
            }
        },
        "UpdateStarted": {
            "type": "object",
            "required": ["started", "pid"],
            "properties": {
                "started": { "type": "boolean" },
                "pid": { "type": "integer", "description": "The detached updater's process id." }
            }
        },
        "Dismissed": {
            "type": "object",
            "required": ["dismissed"],
            "properties": { "dismissed": { "type": "boolean" } }
        },
        "PreflightCheck": {
            "type": "object",
            "required": ["name", "ok", "message"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The check (`platform`, `update_service`, `disk_space`, \
                        `network`, ...)."
                },
                "ok": { "type": "boolean" },
                "message": { "type": "string", "description": "What the check found." },
                "fix": {
                    "type": "string",
                    "description": "For a failed check: what to do about it (absent when there \
                        is nothing to say)."
                },
                "fix_commands": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "For a failed check: commands to run as root (absent when \
                        there are none)."
                }
            }
        },
        "PreflightResult": {
            "type": "object",
            "required": ["ready", "checks"],
            "properties": {
                "ready": { "type": "boolean", "description": "Whether every check passed." },
                "checks": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/PreflightCheck" }
                }
            }
        },
        "AuditEntry": {
            "type": "object",
            "description": "One write operation, as the audit log records it.",
            "required": [
                "id", "ts", "username", "via", "client", "action", "method", "path", "status"
            ],
            "properties": {
                "id": {
                    "type": "integer",
                    "description": "Descending; pass one as `before_id` to page further back."
                },
                "ts": { "type": "integer", "description": "UNIX seconds." },
                "username": { "type": "string" },
                "via": {
                    "type": "string",
                    "description": "How the caller signed in: `session`, `api_token`, \
                        `static_token`, `open` (authentication turned off), or `password` for \
                        a sign-in."
                },
                "client": { "type": "string", "description": "The caller's address." },
                "action": { "type": "string", "description": "What was done, in words (\"Created zone\")." },
                "method": { "type": "string" },
                "path": { "type": "string" },
                "status": { "type": "integer", "description": "HTTP status of the response." }
            }
        }
    })
}

/// Reports, backup and restore, in-place updates and the audit log.
fn maintenance_operation(path: &str, method: &str) -> Option<Value> {
    let error = schema_ref("Error");
    match (method, path) {
        ("get", "/reports") => Some(json!({
            "parameters": [
                {
                    "name": "hours",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "default": 24, "minimum": 1, "maximum": 2160 },
                    "description": "How far back to look (clamped to 1-2160)."
                },
                {
                    "name": "client",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Only this client's queries."
                },
                {
                    "name": "top",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "default": 20, "minimum": 1, "maximum": 100 },
                    "description": "How many entries each ranked list holds."
                }
            ],
            "responses": {
                "200": json_response(
                    "The summary, the period it covers and whether the query log was on.",
                    schema_ref("ReportsResponse"),
                ),
                "500": json!({
                    "description": "The query log could not be read.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/reports/send") => Some(json!({
            "requestBody": {
                "required": false,
                "description": "Settings to use instead of the saved ones. Omit the body to \
                    send with the saved settings.",
                "content": { "application/json": { "schema": schema_ref("SendReportInput") } }
            },
            "responses": {
                "200": json_response("The report was sent.", schema_ref("ReportSent")),
                "400": json!({
                    "description": "The settings are incomplete (no destination or no query log).",
                    "content": { "application/json": { "schema": error } }
                }),
                "502": json!({
                    "description": "A destination could not be reached or refused the report.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/backup/restore") => Some(json!({
            "responses": {
                "200": json_response(
                    "The restore waiting for the next restart, or null when none is staged.",
                    schema_ref("RestoreStatus"),
                )
            }
        })),
        ("post", "/backup/restore") => Some(json!({
            "requestBody": {
                "required": true,
                "description": "The backup file itself, byte for byte as `GET /api/backup` \
                    produced it.",
                "content": { "application/octet-stream": {
                    "schema": { "type": "string", "format": "binary" }
                }}
            },
            "responses": {
                "200": json_response(
                    "The backup checked out and is staged: it replaces the database on the \
                        next restart. Nothing changes until then.",
                    schema_ref("RestoreStatus"),
                ),
                "400": json!({
                    "description": "The file is not a backup this server can restore, or the \
                        server runs on an in-memory database, which cannot be replaced.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("delete", "/backup/restore") => Some(json!({
            "responses": {
                "204": empty_response(
                    "The staged restore is gone; the database is untouched.",
                ),
                "404": json!({
                    "description": "No restore was staged.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/update") => Some(json!({
            "responses": {
                "200": json_response(
                    "The version, whether this host can be updated in place, the reasons it \
                        cannot, the latest known release and the command that does it by hand.",
                    schema_ref("UpdateInfo"),
                )
            }
        })),
        ("get", "/update/status") => Some(json!({
            "responses": {
                "200": json_response(
                    "The updater's progress and a tail of its output; safe to poll, and still \
                        meaningful after a restart.",
                    schema_ref("UpdateStatus"),
                )
            }
        })),
        ("get", "/update/preflight") => Some(json!({
            "responses": {
                "200": json_response(
                    "One result per check, each with what to fix when it failed.",
                    schema_ref("PreflightResult"),
                )
            }
        })),
        ("post", "/update/start") => Some(json!({
            "responses": {
                "202": json_response(
                    "The update began. Only that: follow `/api/update/status` for progress and \
                        to detect the restart.",
                    schema_ref("UpdateStarted"),
                ),
                "409": json!({
                    "description": "This host cannot be updated in place, or an update is \
                        already running.",
                    "content": { "application/json": { "schema": error } }
                }),
                "500": json!({
                    "description": "The updater could not be started, or the running binary \
                        could not be located.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/update/check") => Some(json!({
            "responses": {
                "200": json_response(
                    "The result of one release check. A request inside the throttle window is \
                        answered from the cache with `retry_after_secs` rather than failing.",
                    schema_ref("UpdateCheck"),
                ),
                "409": json!({
                    "description": "This host cannot self-update, so there is nothing to check.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("post", "/update/dismiss") => Some(json!({
            "responses": {
                "200": json_response(
                    "The recorded run state is cleared, so the console stops showing the last \
                        result.",
                    schema_ref("Dismissed"),
                ),
                "409": json!({
                    "description": "An update run is active and cannot be dismissed.",
                    "content": { "application/json": { "schema": error } }
                })
            }
        })),
        ("get", "/audit") => Some(json!({
            "parameters": [
                {
                    "name": "before_id",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "format": "int64" },
                    "description": "Only entries older than this id (paging)."
                },
                {
                    "name": "user",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Only this user's entries."
                },
                {
                    "name": "q",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Only entries whose action, method or path contains this text."
                },
                {
                    "name": "limit",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "integer", "default": 100, "minimum": 1 },
                    "description": "How many entries to return (100 unless asked otherwise)."
                }
            ],
            "responses": {
                "200": json_response(
                    "The matching entries, newest first; pass the last `id` as `before_id` for \
                        the next page.",
                    json!({ "type": "array", "items": schema_ref("AuditEntry") }),
                )
            }
        })),
        _ => None,
    }
}

/// The endpoints whose request and response bodies this document publishes.
fn documented_operation(path: &str, method: &str) -> Option<Value> {
    auth_operation(path, method)
        .or_else(|| admin_operation(path, method))
        .or_else(|| policy_operation(path, method))
        .or_else(|| ai_operation(path, method))
        .or_else(|| resolver_operation(path, method))
        .or_else(|| zones_operation(path, method))
        .or_else(|| records_operation(path, method))
        .or_else(|| settings_operation(path, method))
        .or_else(|| diagnostics_operation(path, method))
        .or_else(|| maintenance_operation(path, method))
}

/// Health, status, the query sinks and the backup download.
fn diagnostics_operation(path: &str, method: &str) -> Option<Value> {
    let settings_body = |schema: Value| {
        request_body(
            schema,
            "The settings to try, as on the console form (saved or not); omitted, the \
                saved ones.",
            false,
        )
    };
    match (method, path) {
        ("get", "/health") => Some(json!({
            "responses": {
                "200": json_response("The server is up.", schema_ref("Health"))
            }
        })),
        ("get", "/status") => Some(json!({
            "responses": {
                "200": json_response(
                    "Counts, listener state, setup state and the cached release data.",
                    schema_ref("Status"),
                ),
                "500": json!({
                    "description": "The counts could not be read.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("get", "/openapi.json") => Some(json!({
            "responses": {
                "200": json_response("This document.", json!({ "type": "object" }))
            }
        })),
        ("get", "/metrics/prometheus") => Some(json!({
            "responses": {
                "200": {
                    "description": "Prometheus text exposition format.",
                    "content": { "text/plain": { "schema": { "type": "string" } } }
                }
            }
        })),
        ("get", "/log-export") => Some(json!({
            "responses": {
                "200": json_response(
                    "Counters since the server started.",
                    schema_ref("LogExportStatus"),
                )
            }
        })),
        ("post", "/log-export/test") => Some(json!({
            "requestBody": settings_body(schema_ref("LogExportTestInput")),
            "responses": {
                "200": json_response(
                    "The endpoint accepted the sample query.",
                    schema_ref("Sent"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "502": json!({
                    "description": "The endpoint refused or could not be reached.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("post", "/dnstap/test") => Some(json!({
            "requestBody": settings_body(schema_ref("DnstapTestInput")),
            "responses": {
                "200": json_response(
                    "The collector completed the handshake and took the sample event.",
                    schema_ref("Sent"),
                ),
                "400": { "$ref": "#/components/responses/BadRequest" },
                "502": json!({
                    "description": "The collector was unreachable or refused the handshake.",
                    "content": { "application/json": { "schema": schema_ref("Error") } }
                })
            }
        })),
        ("get", "/backup") => Some(json!({
            "responses": {
                "200": {
                    "description": "The database backup, as a download.",
                    "content": { "application/octet-stream": {
                        "schema": { "type": "string", "format": "binary" }
                    }}
                }
            }
        })),
        _ => None,
    }
}
/// An `operationId` clients can name: `get_zones_id_records`.
fn operation_id(method: &str, path: &str) -> String {
    let mut id = format!("{method}_");
    let mut last_underscore = false;
    for c in path.chars() {
        if c.is_ascii_alphanumeric() {
            id.push(c.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore && !id.ends_with('_') {
            id.push('_');
            last_underscore = true;
        }
    }
    id.trim_end_matches('_').to_string()
}

/// The `{name}` placeholders in a path, as OpenAPI path parameters. Every one
/// must be declared or the document is invalid.
fn path_parameters(path: &str) -> Vec<Value> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        names.push(&after[..close]);
        rest = &after[close + 1..];
    }
    names
        .into_iter()
        .map(|name| {
            json!({
                "name": name,
                "in": "path",
                "required": true,
                "schema": { "type": "string" }
            })
        })
        .collect()
}

/// One operation object: tag, summary, parameters, security and responses.
fn operation(path: &str, method: &str, summary: &str) -> Value {
    let mut op = json!({
        "tags": [tag_for(path)],
        "summary": summary,
        "operationId": operation_id(method, path),
        "responses": {
            "200": {
                "description": "Success.",
                "content": { "application/json": { "schema": {} } }
            },
            "400": { "$ref": "#/components/responses/BadRequest" },
            "401": { "$ref": "#/components/responses/Unauthorized" },
            "403": { "$ref": "#/components/responses/Forbidden" }
        }
    });
    // Login and setup run before a session exists, and health is how a
    // monitor checks the server without one.
    if OPEN_PATHS.contains(&path) {
        op["security"] = json!([]);
    }
    if let Some(details) = documented_operation(path, method) {
        if let (Some(op), Some(details)) = (op.as_object_mut(), details.as_object()) {
            for (key, value) in details {
                if key == "responses" {
                    merge_responses(op, value, path == "/health");
                } else {
                    op.insert(key.clone(), value.clone());
                }
            }
        }
    }
    // The path parameters come last: an endpoint that documents its own query
    // flags supplies a `parameters` array, which must not drop them.
    let mut parameters = op["parameters"].as_array().cloned().unwrap_or_default();
    for path_parameter in path_parameters(path) {
        let declared = parameters.iter().any(|parameter| {
            parameter["in"] == "path" && parameter["name"] == path_parameter["name"]
        });
        if !declared {
            parameters.push(path_parameter);
        }
    }
    if !parameters.is_empty() {
        op["parameters"] = Value::Array(parameters);
    }
    op
}

/// Add the documented statuses to the generic set, so an endpoint described
/// in full still says it answers `401`. `/health` is the exception: it is
/// reachable without a session and answers nothing but `200`, so its
/// documented responses stand alone.
fn merge_responses(op: &mut Map<String, Value>, documented: &Value, replace: bool) {
    let Some(documented) = documented.as_object() else {
        return;
    };
    if replace {
        op.insert("responses".to_string(), Value::Object(documented.clone()));
        return;
    }
    // A documented success status replaces the generic `200`: an endpoint that
    // answers `204` or `201` must not also advertise a body it never sends.
    let documented_success = documented.keys().any(|status| status.starts_with('2'));
    let Some(responses) = op
        .get_mut("responses")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };
    if documented_success && !documented.contains_key("200") {
        responses.remove("200");
    }
    for (status, response) in documented {
        responses.insert(status.clone(), response.clone());
    }
}

/// The whole OpenAPI document.
pub fn document() -> Value {
    let mut paths = Map::new();
    for (path, operations) in PATHS {
        let mut item = Map::new();
        for (method, summary) in *operations {
            item.insert((*method).to_string(), operation(path, method, summary));
        }
        paths.insert((*path).to_string(), Value::Object(item));
    }
    let mut tags: Vec<&str> = PATHS.iter().map(|(path, _)| tag_for(path)).collect();
    tags.sort_unstable();
    tags.dedup();
    let tags: Vec<Value> = tags
        .into_iter()
        .map(|name| json!({ "name": name }))
        .collect();
    json!({
        // 3.1 rather than 3.0: the schemas use JSON Schema 2020-12 types, where a
        // nullable field is `"type": ["string", "null"]`.
        "openapi": "3.1.0",
        "info": {
            "title": "Daygle DNS API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The console's REST API. Prose for every endpoint is in \
                docs/API.md; this document is generated from the routes the server \
                serves. Send an API token as `Authorization: Bearer <token>`, or \
                sign in with `POST /api/auth/login` for the session cookie.",
            "license": { "name": "See LICENSE" }
        },
        "servers": [
            { "url": "/api", "description": "This server" }
        ],
        "tags": tags,
        "paths": paths,
        "components": components(),
        "security": [
            { "bearerAuth": [] },
            { "sessionCookie": [] }
        ]
    })
}

/// `GET /api/openapi.json`: the document, as JSON.
pub async fn serve() -> Response {
    let body = serde_json::to_string_pretty(&document()).unwrap_or_else(|_| "{}".to_string());
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths served by `router()` that are not part of the API: the console's
    /// own bundle and the ACME challenge answer the CA fetches over plain HTTP.
    const NON_API: &[&str] = &["/", "/{*path}", "/.well-known/acme-challenge/{token}"];

    /// The routes `router()` registers, read out of `lib.rs` itself: a
    /// hand-kept copy in a test would drift exactly like a hand-kept schema.
    fn router_routes() -> Vec<(String, Vec<String>)> {
        let source = include_str!("lib.rs");
        let mut routes = Vec::new();
        let mut rest = source;
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let chunk_end = rest.find(".route(").unwrap_or(rest.len());
            let chunk = &rest[..chunk_end];
            let Some(quote) = chunk.find('"') else {
                continue;
            };
            let after = &chunk[quote + 1..];
            let Some(end) = after.find('"') else { continue };
            let path = after[..end].to_string();
            let mut methods = Vec::new();
            for method in ["get", "post", "put", "patch", "delete"] {
                if has_call(chunk, method) {
                    methods.push(method.to_string());
                }
            }
            routes.push((path, methods));
        }
        routes
    }

    /// Whether `chunk` calls `method(` as a function, rather than merely
    /// containing those letters inside another word.
    fn has_call(chunk: &str, method: &str) -> bool {
        let mut from = 0;
        while let Some(at) = chunk[from..].find(method) {
            let start = from + at;
            let before = chunk[..start].chars().next_back();
            let after = chunk[start + method.len()..].trim_start();
            if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') && after.starts_with('(') {
                return true;
            }
            from = start + method.len();
        }
        false
    }

    #[test]
    fn every_served_path_is_documented() {
        let documented: Vec<&str> = PATHS.iter().map(|(path, _)| *path).collect();
        let served = router_routes();
        let mut missing: Vec<&str> = served
            .iter()
            .filter(|(path, _)| {
                !NON_API.contains(&path.as_str()) && !documented.contains(&path.as_str())
            })
            .map(|(path, _)| path.as_str())
            .collect();
        missing.sort_unstable();
        assert!(
            missing.is_empty(),
            "router() serves these paths but PATHS does not name them: {missing:?}"
        );
    }

    #[test]
    fn every_documented_path_is_served() {
        let served = router_routes();
        let mut phantom: Vec<&str> = PATHS
            .iter()
            .map(|(path, _)| *path)
            .filter(|path| !served.iter().any(|(served, _)| served == path))
            .collect();
        phantom.sort_unstable();
        assert!(
            phantom.is_empty(),
            "PATHS names these paths but router() does not serve them: {phantom:?}"
        );
    }

    #[test]
    fn the_table_matches_the_router_methods() {
        let routes = router_routes();
        for (path, operations) in PATHS {
            let Some((_, served)) = routes.iter().find(|(p, _)| p == path).cloned() else {
                continue; // covered by every_documented_path_is_served
            };
            let mut documented: Vec<&str> = operations.iter().map(|(method, _)| *method).collect();
            let mut served = served;
            documented.sort_unstable();
            served.sort();
            assert_eq!(
                documented, served,
                "PATHS and router() disagree about the methods of {path}"
            );
        }
    }

    #[test]
    fn path_parameters_are_declared() {
        let document = document();
        for (path, operations) in PATHS {
            for (method, _) in *operations {
                let op = &document["paths"][path][method];
                let declared: Vec<&str> = op["parameters"]
                    .as_array()
                    .map(|params| {
                        params
                            .iter()
                            .filter_map(|p| p["name"].as_str())
                            .filter(|name| !name.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                for placeholder in path.split('{').skip(1) {
                    let name = placeholder.split('}').next().unwrap_or("");
                    assert!(
                        declared.contains(&name),
                        "{method} {path} does not declare the path parameter '{name}'"
                    );
                }
            }
        }
    }

    #[test]
    fn the_schema_is_served_by_this_module() {
        assert!(
            include_str!("lib.rs").contains(".route(\"/openapi.json\", get(openapi::serve))"),
            "router() must serve GET /api/openapi.json from openapi::serve"
        );
    }

    /// Shape checks a generated client depends on: every operation named,
    /// summarised, tagged and answering with a success status, and no two
    /// operations sharing an id.
    #[test]
    fn the_document_is_well_formed() {
        let document = document();
        assert!(document["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.")));
        assert!(document["info"]["version"].as_str().is_some());
        let mut tags = Vec::new();
        for tag in document["tags"].as_array().unwrap() {
            let name = tag["name"].as_str().unwrap_or("");
            assert!(!name.is_empty(), "top-level tag must have a nonempty name");
            assert!(!tags.contains(&name), "duplicate top-level tag {name}");
            tags.push(name);
        }
        let mut ids = Vec::new();
        for (path, item) in document["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                assert!(
                    !op["summary"].as_str().unwrap_or("").is_empty(),
                    "{method} {path} has no summary"
                );
                let tag = op["tags"][0].as_str().unwrap_or("");
                assert!(!tag.is_empty(), "{method} {path} has no tag");
                assert!(
                    tags.contains(&tag),
                    "{method} {path} has undeclared tag {tag}"
                );
                let id = op["operationId"].as_str().unwrap_or("");
                assert!(!id.is_empty(), "{method} {path} has no operationId");
                assert!(!ids.contains(&id), "two operations share the id {id}");
                ids.push(id);
                let responses = op["responses"].as_object().unwrap();
                assert!(
                    responses.keys().any(|status| status.starts_with('2')),
                    "{method} {path} declares no success response"
                );
                let generic_200 = op["responses"]["200"]["description"] == "Success.";
                let other_success = responses
                    .keys()
                    .any(|status| status != "200" && status.starts_with('2'));
                assert!(
                    !(generic_200 && other_success),
                    "{method} {path} keeps a generic 200 beside its documented success status"
                );
            }
        }
    }

    /// An operation behind `require_auth` that describes its own responses
    /// must still say what an unauthenticated caller gets.
    #[test]
    fn authenticated_operations_declare_unauthorized() {
        let document = document();
        for (path, operations) in PATHS {
            if OPEN_PATHS.contains(path) {
                continue;
            }
            for (method, _) in *operations {
                let unauthorized = &document["paths"][path][method]["responses"]["401"];
                assert!(
                    unauthorized.is_object(),
                    "{method} {path} does not declare 401"
                );
            }
        }
    }

    #[test]
    fn every_reference_resolves() {
        let document = document();
        let schemas = &document["components"]["schemas"];
        let responses = &document["components"]["responses"];
        fn refs(value: &Value, found: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    for (key, value) in map {
                        if key == "$ref" {
                            if let Some(target) = value.as_str() {
                                found.push(target.to_string());
                            }
                        } else {
                            refs(value, found);
                        }
                    }
                }
                Value::Array(items) => items.iter().for_each(|item| refs(item, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        refs(&document, &mut found);
        for target in found {
            let name = target
                .strip_prefix("#/components/schemas/")
                .and_then(|name| schemas.get(name).map(|_| ()))
                .or_else(|| {
                    target
                        .strip_prefix("#/components/responses/")
                        .and_then(|name| responses.get(name).map(|_| ()))
                });
            assert!(name.is_some(), "unresolved reference {target}");
        }
    }
}
