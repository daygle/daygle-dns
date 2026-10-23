//! SQLite-backed zone and record storage.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{Timelike, Utc};
use hickory_proto::rr::{RData, RecordType};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{
    DynamicUpdate, MoveDirection, Record, RecordInput, SigningKeyRecord, SplitHorizonEntry,
    SplitHorizonEntryInput, SplitHorizonNetwork, SplitHorizonNetworkInput, SplitHorizonRecord,
    Zone, ZoneInput,
};
use crate::validate_name;
use daygle_dns_core::blocking::{BlockingGroup, BlockingGroupInput};
use daygle_dns_core::config::{DisplaySettings, Role};
use daygle_dns_core::error::{DaygleError, Result};

/// Every zone paired with its records and signing keys, as consumed by the
/// catalog builder.
pub type CatalogData = Vec<(Zone, Vec<Record>, Vec<SigningKeyRecord>)>;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS zones (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    primary_ns     TEXT NOT NULL,
    admin_mailbox  TEXT NOT NULL,
    serial         INTEGER NOT NULL DEFAULT 1,
    refresh        INTEGER NOT NULL DEFAULT 3600,
    retry          INTEGER NOT NULL DEFAULT 600,
    expire         INTEGER NOT NULL DEFAULT 86400,
    minimum        INTEGER NOT NULL DEFAULT 3600,
    created_at     TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    last_modified_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS records (
    id       TEXT PRIMARY KEY,
    zone_id  TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    rtype    TEXT NOT NULL,
    content  TEXT NOT NULL,
    ttl      INTEGER NOT NULL DEFAULT 3600,
    priority INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    last_modified_at TEXT NOT NULL DEFAULT '',
    last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);
CREATE INDEX IF NOT EXISTS idx_records_name ON records(name);

CREATE TABLE IF NOT EXISTS dnssec_keys (
    id         TEXT PRIMARY KEY,
    zone_id    TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    algorithm  INTEGER NOT NULL,
    key_der    BLOB NOT NULL,
    state      TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone ON dnssec_keys(zone_id);

-- Health checks on A/AAAA records (no foreign key: editing a record
-- re-inserts its row, which must not drop the check; orphans are cleared at
-- start-up and ignored when read).
CREATE TABLE IF NOT EXISTS health_checks (
    record_id      TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    path           TEXT NOT NULL DEFAULT '',
    host           TEXT NOT NULL DEFAULT '',
    interval_secs  INTEGER NOT NULL DEFAULT 30
);

-- Zones added by a consumed catalog zone (RFC 9432), and which catalog.
CREATE TABLE IF NOT EXISTS catalog_members (
    zone_id  TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    catalog  TEXT NOT NULL
);

-- The published catalog zone's serial, and a digest of the member list it
-- was last bumped for.
CREATE TABLE IF NOT EXISTS catalog_state (
    name    TEXT PRIMARY KEY,
    digest  TEXT NOT NULL,
    serial  INTEGER NOT NULL
);

-- How a signed zone proves names and types do not exist (NSEC or NSEC3).
CREATE TABLE IF NOT EXISTS zone_dnssec (
    zone_id  TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    nsec3    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS secondary_zones (
    zone_id      TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    masters      TEXT NOT NULL,
    refresh_secs INTEGER NOT NULL DEFAULT 3600,
    last_transfer TEXT
);

CREATE TABLE IF NOT EXISTS split_horizon_networks (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE,
    cidrs TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS split_horizon_entries (
    id       TEXT PRIMARY KEY,
    domain   TEXT NOT NULL,
    networks TEXT NOT NULL,
    ips      TEXT NOT NULL,
    records  TEXT NOT NULL DEFAULT '[]',
    ttl      INTEGER NOT NULL DEFAULT 60,
    disabled INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL DEFAULT 0,
    last_modified_at TEXT,
    last_used_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_split_horizon_domain ON split_horizon_entries(domain);

CREATE TABLE IF NOT EXISTS tsig_keys (
    name       TEXT PRIMARY KEY,
    algorithm  TEXT NOT NULL,
    secret     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stub_zones (
    name         TEXT PRIMARY KEY,
    nss          TEXT NOT NULL DEFAULT '[]',
    refresh_secs INTEGER NOT NULL DEFAULT 3600,
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_refresh TEXT
);

CREATE TABLE IF NOT EXISTS blocking_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    clients     TEXT NOT NULL DEFAULT '[]',
    allow       TEXT NOT NULL DEFAULT '[]',
    block       TEXT NOT NULL DEFAULT '[]',
    allow_regex TEXT NOT NULL DEFAULT '[]',
    block_regex TEXT NOT NULL DEFAULT '[]',
    blocklists  TEXT NOT NULL DEFAULT '[]',
    response    TEXT NOT NULL DEFAULT '{"kind":"nx_domain"}',
    position    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS console_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    enabled       INTEGER NOT NULL DEFAULT 1,
    first_name    TEXT NOT NULL DEFAULT '',
    last_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    time_zone     TEXT NOT NULL DEFAULT '',
    date_format   TEXT NOT NULL DEFAULT '',
    time_format   TEXT NOT NULL DEFAULT '',
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS console_user_two_factor (
    username        TEXT PRIMARY KEY REFERENCES console_users(username) ON DELETE CASCADE,
    secret          TEXT NOT NULL DEFAULT '',
    pending_secret  TEXT NOT NULL DEFAULT '',
    recovery_hashes TEXT NOT NULL DEFAULT '[]',
    last_step       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS console_sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES console_users(username) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL REFERENCES console_users(username) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    read_only    INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT NOT NULL,
    via      TEXT NOT NULL,
    client   TEXT NOT NULL DEFAULT '',
    action   TEXT NOT NULL,
    method   TEXT NOT NULL,
    path     TEXT NOT NULL,
    status   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (ts DESC);

CREATE TABLE IF NOT EXISTS tls_certificates (
    name        TEXT PRIMARY KEY,
    server_name TEXT NOT NULL DEFAULT '',
    cert_pem    TEXT NOT NULL,
    key_pem     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_certificates (
    name         TEXT PRIMARY KEY,
    domains      TEXT NOT NULL DEFAULT '[]',
    challenge    TEXT NOT NULL DEFAULT 'http',
    status       TEXT NOT NULL DEFAULT 'pending',
    last_error   TEXT NOT NULL DEFAULT '',
    last_attempt INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runtime_settings (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    client     TEXT NOT NULL,
    qname      TEXT NOT NULL,
    qtype      TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    rcode      TEXT,
    elapsed_ms INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_query_logs_ts ON query_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_query_logs_qname ON query_logs (qname);
CREATE INDEX IF NOT EXISTS idx_query_logs_client ON query_logs (client);
"#;

/// SQLite-backed storage for zones and records.
///
/// The store owns a [`rusqlite::Connection`] behind a mutex; every operation
/// is short so the coarse-grained lock is acceptable and keeps the API simple.
/// The server performs bulk reads only at startup / on zone changes, and the
/// [`crate::AuthorityCatalog`] keeps the hot path in memory.
#[derive(Clone)]
pub struct ZoneStore {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for ZoneStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneStore").finish_non_exhaustive()
    }
}

impl ZoneStore {
    /// Open (or create) the database at `path`. An in-memory database is used
    /// when `path` is `":memory:"`.
    pub fn open(path: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let conn = Connection::open(path)?;
            restrict_permissions(Path::new(path))?;
            conn
        };
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init()?;
        Ok(store)
    }

    /// Lock the internal SQLite connection. Converts mutex-poison into
    /// [`DaygleError::Internal`] so callers never need to handle it.
    fn lock_conn(&self) -> std::result::Result<std::sync::MutexGuard<'_, Connection>, DaygleError> {
        self.conn
            .lock()
            .map_err(|e| DaygleError::Internal(format!("database lock poisoned: {e}")))
    }

    /// Run `f` with the connection locked (for whole-database operations
    /// such as backups).
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.lock_conn()?;
        f(&conn)
    }

    fn init(&self) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute_batch(SCHEMA)?;
        migrate_zone_metadata(&conn)?;
        migrate_record_metadata(&conn)?;
        migrate_split_horizon_records(&conn)?;
        migrate_split_horizon_timestamps(&conn)?;
        migrate_dnssec_keys(&conn)?;
        migrate_console_user_profile(&conn)?;
        migrate_blocking_group_lists(&conn)?;
        // SQLite ships with foreign-key enforcement off (per connection), so
        // the schema's `ON DELETE CASCADE` never fired and deleting a zone
        // left its records, DNSSEC private keys and secondary state behind.
        // Purge what earlier versions orphaned, then turn enforcement on (the
        // migrations above run first: they copy rows between tables and must
        // not trip over legacy orphans).
        conn.execute_batch(
            "DELETE FROM records WHERE zone_id NOT IN (SELECT id FROM zones);
             DELETE FROM dnssec_keys WHERE zone_id NOT IN (SELECT id FROM zones);
             DELETE FROM zone_dnssec WHERE zone_id NOT IN (SELECT id FROM zones);
             DELETE FROM catalog_members WHERE zone_id NOT IN (SELECT id FROM zones);
             DELETE FROM health_checks WHERE record_id NOT IN (SELECT id FROM records);
             DELETE FROM secondary_zones WHERE zone_id NOT IN (SELECT id FROM zones);
             PRAGMA foreign_keys = ON;",
        )?;
        Ok(())
    }

    // ---- Zones -----------------------------------------------------------

    /// List all zones ordered by name.
    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at, enabled, last_modified_at
             FROM zones ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_zone)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_zone(&self, id: &str) -> Result<Option<Zone>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at, enabled, last_modified_at
             FROM zones WHERE id = ?1",
            [id],
            row_to_zone,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn find_zone_by_name(&self, name: &str) -> Result<Option<Zone>> {
        let normalized = normalize_fqdn(name);
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at, enabled, last_modified_at
             FROM zones WHERE name = ?1",
            [&normalized],
            row_to_zone,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Create a zone, synthesizing an SOA and a default NS record.
    pub fn create_zone(&self, input: &ZoneInput) -> Result<Zone> {
        let name = normalize_fqdn(&input.name);
        validate_name(&name, false)?;

        let primary_ns = input
            .primary_ns
            .clone()
            .unwrap_or_else(|| format!("ns1.{name}."));
        let admin_mailbox = input
            .admin_mailbox
            .clone()
            .unwrap_or_else(|| format!("admin.{name}."));

        let now = Utc::now().to_rfc3339();
        let zone = Zone {
            id: Uuid::new_v4().to_string(),
            name,
            primary_ns,
            admin_mailbox,
            serial: input.serial.unwrap_or(1),
            refresh: input.refresh.unwrap_or(3600),
            retry: input.retry.unwrap_or(600),
            expire: input.expire.unwrap_or(86400),
            minimum: input.minimum.unwrap_or(3600),
            created_at: now.clone(),
            enabled: true,
            last_modified_at: now,
        };

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO zones (id, name, primary_ns, admin_mailbox, serial,
                                refresh, retry, expire, minimum, created_at, enabled, last_modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                zone.id,
                zone.name,
                zone.primary_ns,
                zone.admin_mailbox,
                zone.serial,
                zone.refresh,
                zone.retry,
                zone.expire,
                zone.minimum,
                zone.created_at,
                zone.enabled,
                zone.last_modified_at,
            ],
        )
        .map_err(map_unique_violation)?;

        // Default NS record pointing at the primary nameserver's host.
        let ns_host = zone.primary_ns.trim_end_matches('.');
        let ns_record = RecordInput {
            name: "@".to_string(),
            rtype: "NS".to_string(),
            content: format!("{ns_host}."),
            ttl: zone.minimum.max(3600),
            priority: 0,
            disabled: false,
        };
        insert_record_in_tx(&tx, &zone.id, &zone.name, &ns_record)?;
        let last_modified_at = Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE zones SET last_modified_at = ?2 WHERE id = ?1",
            params![zone.id, last_modified_at],
        )?;
        tx.commit()?;

        Ok(Zone {
            last_modified_at,
            ..zone
        })
    }

    pub fn delete_zone(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM zones WHERE id = ?1", [id])?;
        Ok(changed > 0)
    }

    /// Update the SOA serial (and refresh/retry timers if provided).
    pub fn bump_serial(&self, id: &str) -> Result<u32> {
        let conn = self.lock_conn()?;
        bump_serial_in(&conn, id)
    }

    /// Replace the SOA metadata (mname, rname, serial, and timers) of a zone
    /// with values learned from a zone transfer.
    // The parameters are the individual SOA fields; grouping them into a struct
    // would only add indirection at the single transfer call site.
    #[allow(clippy::too_many_arguments)]
    pub fn set_zone_soa(
        &self,
        id: &str,
        primary_ns: &str,
        admin_mailbox: &str,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE zones SET primary_ns = ?2, admin_mailbox = ?3, serial = ?4,
                             refresh = ?5, retry = ?6, expire = ?7, minimum = ?8,
                             last_modified_at = ?9
             WHERE id = ?1",
            params![
                id,
                primary_ns,
                admin_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                Utc::now().to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Err(DaygleError::NotFound(format!("zone {id}")));
        }
        Ok(())
    }

    /// Enable or disable a zone while retaining its data and configuration.
    pub fn set_zone_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE zones SET enabled = ?2, last_modified_at = ?3 WHERE id = ?1 AND enabled != ?2",
            params![id, enabled, Utc::now().to_rfc3339()],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM zones WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    // ---- Secondary zones --------------------------------------------------

    /// Mark a zone as secondary, replacing its master list and refresh interval.
    pub fn set_secondary(
        &self,
        zone_id: &str,
        masters: &[String],
        refresh_secs: u64,
    ) -> Result<()> {
        let masters = serde_json::to_string(masters)
            .map_err(|e| DaygleError::Database(format!("encode masters: {e}")))?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO secondary_zones (zone_id, masters, refresh_secs, last_transfer)
             VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT(zone_id) DO UPDATE SET masters = ?2, refresh_secs = ?3",
            params![zone_id, masters, refresh_secs as i64],
        )?;
        Ok(())
    }

    /// List all secondary zones with their metadata.
    pub fn list_secondary(&self) -> Result<Vec<crate::model::SecondaryZone>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT zone_id, masters, refresh_secs, last_transfer
             FROM secondary_zones ORDER BY zone_id",
        )?;
        let rows = stmt.query_map([], |row| {
            let masters_json: String = row.get(1)?;
            let masters: Vec<String> = serde_json::from_str(&masters_json).unwrap_or_default();
            Ok(crate::model::SecondaryZone {
                zone_id: row.get(0)?,
                masters,
                refresh_secs: row.get::<_, i64>(2)? as u64,
                last_transfer: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Record a successful transfer timestamp for a secondary zone.
    pub fn touch_secondary(&self, zone_id: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE secondary_zones SET last_transfer = ?2 WHERE zone_id = ?1",
            params![zone_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Remove secondary metadata (the zone itself is kept).
    pub fn unset_secondary(&self, zone_id: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM secondary_zones WHERE zone_id = ?1", [zone_id])?;
        Ok(())
    }

    // ---- Stub zones -------------------------------------------------------

    /// Insert or update a stub zone. `nss` may be empty while the
    /// nameservers are still being learned.
    pub fn set_stub(
        &self,
        name: &str,
        nss: &[String],
        refresh_secs: u64,
        enabled: bool,
    ) -> Result<()> {
        let nss = serde_json::to_string(nss)
            .map_err(|e| DaygleError::Database(format!("encode nss: {e}")))?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO stub_zones (name, nss, refresh_secs, enabled, last_refresh)
             VALUES (?1, ?2, ?3, ?4, NULL)
             ON CONFLICT(name) DO UPDATE SET nss = ?2, refresh_secs = ?3, enabled = ?4",
            params![name, nss, refresh_secs as i64, enabled as i64],
        )?;
        Ok(())
    }

    /// All stub zones with their metadata.
    pub fn list_stubs(&self) -> Result<Vec<crate::model::StubZone>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, nss, refresh_secs, enabled, last_refresh
             FROM stub_zones ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            let nss_json: String = row.get(1)?;
            Ok(crate::model::StubZone {
                name: row.get(0)?,
                nss: serde_json::from_str(&nss_json).unwrap_or_default(),
                refresh_secs: row.get::<_, i64>(2)? as u64,
                enabled: row.get::<_, i64>(3)? != 0,
                last_refresh: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Record a successful NS refresh for a stub zone.
    pub fn touch_stub(&self, name: &str, nss: &[String]) -> Result<()> {
        let nss = serde_json::to_string(nss)
            .map_err(|e| DaygleError::Database(format!("encode nss: {e}")))?;
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE stub_zones SET nss = ?2, last_refresh = ?3 WHERE name = ?1",
            params![name, nss, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Remove a stub zone entirely (stub rows are standalone; nothing else
    /// references them).
    pub fn unset_stub(&self, name: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        Ok(conn.execute("DELETE FROM stub_zones WHERE name = ?1", [name])? > 0)
    }

    // ---- Advanced blocking groups ----------------------------------------

    /// All Advanced Blocking groups, ordered by `position` then name.
    pub fn list_blocking_groups(&self) -> Result<Vec<BlockingGroup>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, enabled, clients, allow, block, allow_regex, block_regex,
                    response, position, blocklists
             FROM blocking_groups ORDER BY position, name",
        )?;
        let rows = stmt.query_map([], row_to_blocking_group)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Fetch a single blocking group by id.
    pub fn get_blocking_group(&self, id: &str) -> Result<Option<BlockingGroup>> {
        let conn = self.lock_conn()?;
        let group = conn
            .query_row(
                "SELECT id, name, enabled, clients, allow, block, allow_regex, block_regex,
                        response, position, blocklists
                 FROM blocking_groups WHERE id = ?1",
                [id],
                row_to_blocking_group,
            )
            .optional()?;
        Ok(group)
    }

    /// Create a blocking group, or update one in place (its id and position
    /// are preserved): the group with `input.id` when given (which may rename
    /// it), else the one with the same name.
    pub fn upsert_blocking_group(&self, input: &BlockingGroupInput) -> Result<BlockingGroup> {
        let name = input.name.trim().to_string();
        if name.is_empty() {
            return Err(DaygleError::InvalidRecord(
                "blocking group name is empty".to_string(),
            ));
        }
        let clients = encode_json(&input.clients, "clients")?;
        let allow = encode_json(&input.allow, "allow")?;
        let block = encode_json(&input.block, "block")?;
        let allow_regex = encode_json(&input.allow_regex, "allow_regex")?;
        let block_regex = encode_json(&input.block_regex, "block_regex")?;
        let blocklists = encode_json(&input.blocklists, "blocklists")?;
        let response = serde_json::to_string(&input.response)
            .map_err(|e| DaygleError::Database(format!("encode response: {e}")))?;
        let conn = self.lock_conn()?;
        if let Some(id) = &input.id {
            let duplicate: bool = conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM blocking_groups WHERE name = ?1 AND id != ?2)",
                params![name, id],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(DaygleError::InvalidRecord(format!(
                    "a blocking group named '{name}' already exists"
                )));
            }
            let updated = conn.execute(
                "UPDATE blocking_groups SET name = ?2, enabled = ?3, clients = ?4,
                    allow = ?5, block = ?6, allow_regex = ?7, block_regex = ?8,
                    response = ?9, blocklists = ?10
                 WHERE id = ?1",
                params![
                    id,
                    name,
                    input.enabled as i64,
                    clients,
                    allow,
                    block,
                    allow_regex,
                    block_regex,
                    response,
                    blocklists,
                ],
            )?;
            drop(conn);
            if updated == 0 {
                return Err(DaygleError::NotFound(format!("blocking group {id}")));
            }
            return self
                .get_blocking_group(id)?
                .ok_or_else(|| DaygleError::NotFound(format!("blocking group {id}")));
        }
        let id = Uuid::new_v4().to_string();
        // New rows land after every existing group; updates keep their spot.
        conn.execute(
            "INSERT INTO blocking_groups
                (id, name, enabled, clients, allow, block, allow_regex, block_regex,
                 response, blocklists, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 (SELECT COALESCE(MAX(position), -1) + 1 FROM blocking_groups))
             ON CONFLICT(name) DO UPDATE SET
                enabled = ?3, clients = ?4, allow = ?5, block = ?6,
                allow_regex = ?7, block_regex = ?8, response = ?9, blocklists = ?10",
            params![
                id,
                name,
                input.enabled as i64,
                clients,
                allow,
                block,
                allow_regex,
                block_regex,
                response,
                blocklists,
            ],
        )?;
        drop(conn);
        self.list_blocking_groups()?
            .into_iter()
            .find(|g| g.name == name)
            .ok_or_else(|| {
                DaygleError::Internal("blocking group vanished after upsert".to_string())
            })
    }

    /// The stored settings that name the network `name` (any case): split
    /// horizon entries and client groups, labelled for the console.
    pub fn network_users(&self, name: &str) -> Result<Vec<String>> {
        let named = |list: &[String]| {
            list.iter()
                .any(|e| e.trim().eq_ignore_ascii_case(name.trim()))
        };
        let mut users = Vec::new();
        for entry in self.list_split_horizon_entries()? {
            if named(&entry.networks) {
                users.push(format!("Split horizon '{}'", entry.domain));
            }
        }
        for group in self.list_blocking_groups()? {
            if named(&group.clients) {
                users.push(format!("Client group '{}'", group.name));
            }
        }
        Ok(users)
    }

    /// Point the stored references to the network `old` (any case) at
    /// `new`: split horizon entries and client groups.
    pub fn rename_network_refs(&self, old: &str, new: &str) -> Result<()> {
        let rename = |list: &[String]| -> Option<Vec<String>> {
            let hit = list
                .iter()
                .any(|e| e.trim().eq_ignore_ascii_case(old.trim()));
            hit.then(|| {
                list.iter()
                    .map(|e| {
                        if e.trim().eq_ignore_ascii_case(old.trim()) {
                            new.to_string()
                        } else {
                            e.clone()
                        }
                    })
                    .collect()
            })
        };
        let entries = self.list_split_horizon_entries()?;
        let groups = self.list_blocking_groups()?;
        let conn = self.lock_conn()?;
        for entry in entries {
            if let Some(networks) = rename(&entry.networks) {
                conn.execute(
                    "UPDATE split_horizon_entries SET networks = ?2 WHERE id = ?1",
                    params![entry.id, encode_json(&networks, "networks")?],
                )?;
            }
        }
        for group in groups {
            if let Some(clients) = rename(&group.clients) {
                conn.execute(
                    "UPDATE blocking_groups SET clients = ?2 WHERE id = ?1",
                    params![group.id, encode_json(&clients, "clients")?],
                )?;
            }
        }
        Ok(())
    }

    /// Delete a blocking group by id. Returns whether a row was removed.
    pub fn delete_blocking_group(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        Ok(conn.execute("DELETE FROM blocking_groups WHERE id = ?1", [id])? > 0)
    }

    // ---- Records ---------------------------------------------------------

    /// List records for a zone.
    pub fn list_records(&self, zone_id: &str) -> Result<Vec<Record>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at, last_used_at
             FROM records WHERE zone_id = ?1 ORDER BY name, rtype",
        )?;
        let rows = stmt.query_map([zone_id], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All records across all zones (used to rebuild the in-memory catalog).
    pub fn list_all_records(&self) -> Result<Vec<Record>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at, last_used_at
             FROM records ORDER BY zone_id, name, rtype",
        )?;
        let rows = stmt.query_map([], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_record(&self, id: &str) -> Result<Option<Record>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at, last_used_at
             FROM records WHERE id = ?1",
            [id],
            row_to_record,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Mark stored records at an owner name as used after a successful
    /// authoritative answer. Only the first answer per record and minute is
    /// written, but the stored timestamp retains that answer's exact time.
    pub fn mark_records_used(&self, name: &str, rtype: &str, used_at: &str) -> Result<usize> {
        let parsed = chrono::DateTime::parse_from_rfc3339(used_at)
            .map_err(|e| DaygleError::Internal(format!("invalid record-use timestamp: {e}")))?;
        let minute_start = parsed
            .with_second(0)
            .and_then(|time| time.with_nanosecond(0))
            .ok_or_else(|| DaygleError::Internal("invalid record-use minute".to_string()))?
            .to_rfc3339();
        let used_at = parsed.to_rfc3339();
        let conn = self.lock_conn()?;
        Ok(conn.execute(
            "UPDATE records SET last_used_at = ?3
             WHERE name = ?1 AND disabled = 0
               AND (rtype = ?2 OR rtype = 'CNAME' OR (?2 IN ('A', 'AAAA') AND rtype = 'ALIAS') OR ?2 = 'ANY')
               AND (last_used_at IS NULL OR julianday(last_used_at) < julianday(?4))",
            params![
                name.trim_end_matches('.').to_ascii_lowercase(),
                rtype.to_ascii_uppercase(),
                used_at,
                minute_start,
            ],
        )?)
    }

    /// Insert or update a record, returning the stored record. The zone serial
    /// is bumped in the same transaction so secondaries and IXFR/AXFR clients
    /// detect the change.
    pub fn upsert_record(&self, zone_id: &str, input: &RecordInput) -> Result<Record> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let record = insert_record_in_tx(&tx, zone_id, &zone.name, input)?;
        bump_serial_in(&tx, zone_id)?;
        tx.commit()?;
        Ok(record)
    }

    /// Enable or disable an existing record (Technitium-style staging):
    /// disabled records stay in the database for later re-enable but are
    /// skipped when the serving catalog is rebuilt. The zone serial is bumped
    /// in the same transaction.
    pub fn set_record_disabled(&self, id: &str, disabled: bool) -> Result<bool> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let state: Option<(String, bool)> = tx
            .query_row(
                "SELECT zone_id, disabled FROM records WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        let Some((zone_id, was_disabled)) = state else {
            return Ok(false);
        };
        if was_disabled == disabled {
            return Ok(true);
        }
        tx.execute(
            "UPDATE records SET disabled = ?2, last_modified_at = ?3 WHERE id = ?1",
            params![id, disabled as i64, Utc::now().to_rfc3339()],
        )?;
        bump_serial_in(&tx, &zone_id)?;
        tx.commit()?;
        Ok(true)
    }

    /// Render a zone (SOA + every record, including disabled ones marked with
    /// a `; disabled` comment) as a BIND-style zone file.
    pub fn export_zone_file(&self, zone_id: &str) -> Result<String> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let records = self.list_records(zone_id)?;
        Ok(render_zone_file(&zone, &records))
    }

    /// Delete a record by id. When a record is removed, the owning zone's
    /// serial is bumped in the same transaction (matching [`Self::upsert_record`]),
    /// so callers no longer need a separate [`Self::bump_serial`]. The zone's
    /// last-modified timestamp is updated at the same time.
    pub fn delete_record(&self, id: &str) -> Result<bool> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let zone_id: Option<String> = tx
            .query_row("SELECT zone_id FROM records WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(zone_id) = zone_id else {
            return Ok(false);
        };
        tx.execute("DELETE FROM records WHERE id = ?1", [id])?;
        bump_serial_in(&tx, &zone_id)?;
        tx.commit()?;
        Ok(true)
    }

    /// Replace an existing record in place, keeping its id and staged
    /// (disabled) state. The old row is removed and the new one validated and
    /// inserted in one transaction, so a rejected value leaves the original
    /// untouched. Returns `None` when no record with `record_id` exists in
    /// `zone_id`.
    pub fn replace_record(
        &self,
        zone_id: &str,
        record_id: &str,
        input: &RecordInput,
    ) -> Result<Option<Record>> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let prior: Option<(bool, Option<String>)> = tx
            .query_row(
                "SELECT disabled, last_used_at FROM records WHERE id = ?1 AND zone_id = ?2",
                params![record_id, zone_id],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get(1)?)),
            )
            .optional()?;
        let Some((disabled, last_used_at)) = prior else {
            return Ok(None);
        };
        tx.execute("DELETE FROM records WHERE id = ?1", [record_id])?;
        let input = RecordInput {
            disabled,
            ..input.clone()
        };
        let mut record = insert_record_in_tx(&tx, zone_id, &zone.name, &input)?;
        let last_modified_at = Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE records SET id = ?1, last_modified_at = ?3, last_used_at = ?4 WHERE id = ?2",
            params![record_id, record.id, last_modified_at, last_used_at],
        )?;
        record.id = record_id.to_string();
        record.last_modified_at = last_modified_at;
        record.last_used_at = last_used_at;
        bump_serial_in(&tx, zone_id)?;
        tx.commit()?;
        Ok(Some(record))
    }

    /// Apply a batch of RFC 2136 dynamic-update changes to a zone atomically.
    ///
    /// All additions, deletions, and the optional SOA rewrite happen in one
    /// transaction: either every change lands or none do. When no explicit
    /// SOA is supplied, the zone serial is bumped (RFC 2136 §3.4.2.2 requires
    /// the serial to increase on any successful update).
    pub fn apply_dynamic_updates(&self, zone_id: &str, update: &DynamicUpdate) -> Result<()> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;

        for del in &update.deletes {
            let name = normalize_fqdn(&del.name);
            let mut sql = "DELETE FROM records WHERE zone_id = ?1 AND name = ?2".to_string();
            let mut values: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(zone_id.to_string()), Box::new(name)];
            if let Some(rtype) = &del.rtype {
                sql.push_str(" AND rtype = ?");
                values.push(Box::new(rtype.to_ascii_uppercase()));
            }
            if let Some(content) = &del.content {
                sql.push_str(" AND content = ?");
                values.push(Box::new(content.clone()));
            }
            let mut stmt = tx.prepare(&sql)?;
            stmt.execute(rusqlite::params_from_iter(
                values.iter().map(|v| v.as_ref()),
            ))?;
        }

        for add in &update.adds {
            insert_record_in_tx(&tx, zone_id, &zone.name, add)?;
        }

        match &update.soa {
            Some(soa) => {
                let changed = tx.execute(
                    "UPDATE zones SET primary_ns = ?2, admin_mailbox = ?3, serial = ?4,
                                     refresh = ?5, retry = ?6, expire = ?7, minimum = ?8,
                                     last_modified_at = ?9
                     WHERE id = ?1",
                    params![
                        zone_id,
                        soa.primary_ns,
                        soa.admin_mailbox,
                        soa.serial,
                        soa.refresh,
                        soa.retry,
                        soa.expire,
                        soa.minimum,
                        Utc::now().to_rfc3339(),
                    ],
                )?;
                if changed == 0 {
                    return Err(DaygleError::NotFound(format!("zone {zone_id}")));
                }
            }
            None => {
                let next = zone.serial.wrapping_add(1).max(1);
                tx.execute(
                    "UPDATE zones SET serial = ?2, last_modified_at = ?3 WHERE id = ?1",
                    params![zone_id, next, Utc::now().to_rfc3339()],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Bulk import: replace all records of a zone (keeping the zone row).
    pub fn replace_records(&self, zone_id: &str, records: &[RecordInput]) -> Result<()> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM records WHERE zone_id = ?1", [zone_id])?;
        for record in records {
            insert_record_in_tx(&tx, zone_id, &zone.name, record)?;
        }
        tx.execute(
            "UPDATE zones SET last_modified_at = ?2 WHERE id = ?1",
            params![zone_id, Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn count_zones(&self) -> Result<u64> {
        let conn = self.lock_conn()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM zones", [], |r| {
            Ok(r.get::<_, i64>(0)? as u64)
        })?)
    }

    pub fn count_records(&self) -> Result<u64> {
        let conn = self.lock_conn()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM records", [], |r| {
            Ok(r.get::<_, i64>(0)? as u64)
        })?)
    }

    // ---- Split horizon ---------------------------------------------------

    /// List all split-horizon networks ordered by name.
    pub fn list_split_horizon_networks(&self) -> Result<Vec<SplitHorizonNetwork>> {
        let conn = self.lock_conn()?;
        let mut stmt =
            conn.prepare("SELECT id, name, cidrs FROM split_horizon_networks ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            let cidrs: Vec<String> =
                serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default();
            Ok(SplitHorizonNetwork {
                id: row.get(0)?,
                name: row.get(1)?,
                cidrs,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Create a split-horizon network, or update the CIDRs of an existing
    /// network with the same name (the id is kept stable on update).
    pub fn upsert_split_horizon_network(
        &self,
        input: &SplitHorizonNetworkInput,
    ) -> Result<SplitHorizonNetwork> {
        validate_split_horizon_network(input)?;
        let name = input.name.trim().to_string();
        if name.is_empty() {
            return Err(DaygleError::InvalidRecord(
                "split-horizon network name is empty".to_string(),
            ));
        }
        let cidrs = serde_json::to_string(&input.cidrs)
            .map_err(|e| DaygleError::Database(format!("encode cidrs: {e}")))?;
        let id = Uuid::new_v4().to_string();
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO split_horizon_networks (id, name, cidrs)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET cidrs = ?3",
            params![id, name, cidrs],
        )?;
        drop(conn);
        self.list_split_horizon_networks()?
            .into_iter()
            .find(|n| n.name == name)
            .ok_or_else(|| DaygleError::Internal("network vanished after upsert".to_string()))
    }

    /// Delete a split-horizon network by name. Entries that referenced it are
    /// kept but simply never match until the name is recreated.
    pub fn delete_split_horizon_network(&self, name: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM split_horizon_networks WHERE name = ?1", [name])?;
        Ok(changed > 0)
    }

    /// Move a blocking group one place up (`-1`) or down (`1`) in the
    /// evaluation order. Returns false when the group does not exist; moving
    /// past either end is a no-op.
    pub fn move_blocking_group(&self, id: &str, delta: i64) -> Result<bool> {
        let mut ids: Vec<String> = self
            .list_blocking_groups()?
            .into_iter()
            .map(|g| g.id)
            .collect();
        let Some(from) = ids.iter().position(|g| g == id) else {
            return Ok(false);
        };
        let to = from as i64 + delta;
        if to < 0 || to >= ids.len() as i64 {
            return Ok(true);
        }
        ids.swap(from, to as usize);
        // Renumber everything, which also repairs duplicate positions.
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        for (position, group) in ids.iter().enumerate() {
            tx.execute(
                "UPDATE blocking_groups SET position = ?2 WHERE id = ?1",
                params![group, position as i64],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// List all split-horizon entries ordered by domain then position.
    pub fn list_split_horizon_entries(&self) -> Result<Vec<SplitHorizonEntry>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, networks, ips, records, ttl, disabled, position,
                    last_modified_at, last_used_at
             FROM split_horizon_entries ORDER BY domain, position",
        )?;
        let rows = stmt.query_map([], |row| {
            let networks: Vec<String> =
                serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default();
            let ips: Vec<String> =
                serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default();
            let mut records: Vec<SplitHorizonRecord> =
                serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default();
            // Rows written before typed records existed carry ips only;
            // derive the A/AAAA records so callers always see both in sync.
            if records.is_empty() && !ips.is_empty() {
                records = ips_to_records(&ips);
            }
            Ok(SplitHorizonEntry {
                id: row.get(0)?,
                domain: row.get(1)?,
                networks,
                ips,
                records,
                ttl: row.get(5)?,
                disabled: row.get::<_, i64>(6)? != 0,
                position: row.get(7)?,
                last_modified_at: row.get(8)?,
                last_used_at: row.get(9)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Create a split-horizon entry. Entries for the same domain are ordered
    /// by position (first match wins), so new entries go to the end.
    pub fn create_split_horizon_entry(
        &self,
        input: &SplitHorizonEntryInput,
    ) -> Result<SplitHorizonEntry> {
        let domain = normalize_fqdn(&input.domain);
        validate_split_horizon_entry(&domain, input)?;
        let (ips, records) = canonicalize_split_horizon_records(input)?;
        let networks = serde_json::to_string(&input.networks)
            .map_err(|e| DaygleError::Database(format!("encode networks: {e}")))?;
        let ips_json = serde_json::to_string(&ips)
            .map_err(|e| DaygleError::Database(format!("encode ips: {e}")))?;
        let records_json = serde_json::to_string(&records)
            .map_err(|e| DaygleError::Database(format!("encode records: {e}")))?;

        let conn = self.lock_conn()?;
        let next_position: i64 = conn.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM split_horizon_entries
                 WHERE domain = ?1",
            [&domain],
            |r| r.get(0),
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let entry = SplitHorizonEntry {
            id: Uuid::new_v4().to_string(),
            domain,
            networks: input.networks.clone(),
            ips,
            records,
            ttl: input.ttl,
            disabled: input.disabled,
            position: next_position,
            last_modified_at: Some(now.clone()),
            last_used_at: None,
        };
        conn.execute(
            "INSERT INTO split_horizon_entries
                (id, domain, networks, ips, records, ttl, disabled, position, last_modified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.id,
                entry.domain,
                networks,
                ips_json,
                records_json,
                entry.ttl as i64,
                entry.disabled as i64,
                entry.position,
                now,
            ],
        )?;
        Ok(entry)
    }

    /// Update an existing split-horizon entry by id, keeping its position.
    pub fn update_split_horizon_entry(
        &self,
        id: &str,
        input: &SplitHorizonEntryInput,
    ) -> Result<Option<SplitHorizonEntry>> {
        let domain = normalize_fqdn(&input.domain);
        validate_split_horizon_entry(&domain, input)?;
        let (ips, records) = canonicalize_split_horizon_records(input)?;
        let networks = serde_json::to_string(&input.networks)
            .map_err(|e| DaygleError::Database(format!("encode networks: {e}")))?;
        let ips_json = serde_json::to_string(&ips)
            .map_err(|e| DaygleError::Database(format!("encode ips: {e}")))?;
        let records_json = serde_json::to_string(&records)
            .map_err(|e| DaygleError::Database(format!("encode records: {e}")))?;
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE split_horizon_entries
             SET domain = ?2, networks = ?3, ips = ?4, records = ?5, ttl = ?6, disabled = ?7,
                 last_modified_at = ?8
             WHERE id = ?1",
            params![
                id,
                domain,
                networks,
                ips_json,
                records_json,
                input.ttl as i64,
                input.disabled as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        drop(conn);
        self.list_split_horizon_entries()?
            .into_iter()
            .find(|e| e.id == id)
            .ok_or_else(|| DaygleError::Internal("entry vanished after update".to_string()))
            .map(Some)
    }

    /// Delete a split-horizon entry by id.
    pub fn delete_split_horizon_entry(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM split_horizon_entries WHERE id = ?1", [id])?;
        Ok(changed > 0)
    }

    /// Mark a split-horizon entry as having served an answer. Only the first
    /// use per minute is written, but the stored timestamp keeps that use's
    /// exact time (the same coalescing as [`Self::mark_records_used`]).
    pub fn mark_split_horizon_used(&self, id: &str, used_at: &str) -> Result<usize> {
        let parsed = chrono::DateTime::parse_from_rfc3339(used_at)
            .map_err(|e| DaygleError::Internal(format!("invalid record-use timestamp: {e}")))?;
        let minute_start = parsed
            .with_second(0)
            .and_then(|time| time.with_nanosecond(0))
            .ok_or_else(|| DaygleError::Internal("invalid record-use minute".to_string()))?
            .to_rfc3339();
        let used_at = parsed.to_rfc3339();
        let conn = self.lock_conn()?;
        Ok(conn.execute(
            "UPDATE split_horizon_entries SET last_used_at = ?2
             WHERE id = ?1
               AND (last_used_at IS NULL OR julianday(last_used_at) < julianday(?3))",
            params![id, used_at, minute_start],
        )?)
    }

    /// Move a split-horizon entry one position up or down within the ordering
    /// of its domain by swapping its `position` with the adjacent entry's.
    ///
    /// The caller must reload the catalog afterwards for the change to take
    /// effect. Entries of other domains are never affected.
    pub fn move_split_horizon_entry(
        &self,
        id: &str,
        direction: MoveDirection,
    ) -> Result<MoveResult> {
        let conn = self.lock_conn()?;
        let domain: Option<String> = conn
            .query_row(
                "SELECT domain FROM split_horizon_entries WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(domain) = domain else {
            return Ok(MoveResult::NotFound);
        };

        let mut stmt = conn.prepare(
            "SELECT id, position FROM split_horizon_entries WHERE domain = ?1
             ORDER BY position, id",
        )?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([&domain], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;

        let Some(idx) = rows.iter().position(|(rid, _)| rid == id) else {
            return Ok(MoveResult::NotFound);
        };
        let swap_idx = match direction {
            MoveDirection::Up => idx.checked_sub(1),
            MoveDirection::Down => Some(idx + 1),
        };
        let Some(swap_idx) = swap_idx else {
            return Ok(MoveResult::AtBoundary);
        };
        if swap_idx >= rows.len() {
            return Ok(MoveResult::AtBoundary);
        }

        conn.execute(
            "UPDATE split_horizon_entries SET position = ?2 WHERE id = ?1",
            params![rows[idx].0, rows[swap_idx].1],
        )?;
        conn.execute(
            "UPDATE split_horizon_entries SET position = ?2 WHERE id = ?1",
            params![rows[swap_idx].0, rows[idx].1],
        )?;
        Ok(MoveResult::Moved)
    }

    // ---- TSIG keys (RFC 8945) -------------------------------------------

    /// List all stored TSIG keys, oldest first.
    pub fn list_tsig_keys(&self) -> Result<Vec<crate::model::TsigKeyRecord>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, algorithm, secret, created_at FROM tsig_keys ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(crate::model::TsigKeyRecord {
                name: row.get(0)?,
                algorithm: row.get(1)?,
                secret: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Store or replace a TSIG key.
    pub fn store_tsig_key(&self, name: &str, algorithm: &str, secret_b64: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO tsig_keys (name, algorithm, secret, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET algorithm = ?2, secret = ?3",
            params![name, algorithm, secret_b64, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Delete a TSIG key.
    pub fn delete_tsig_key(&self, name: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM tsig_keys WHERE name = ?1", [name])?;
        Ok(changed > 0)
    }

    // ---- Health checks ---------------------------------------------------

    /// Every health check on an existing A or AAAA record, with the record.
    pub fn list_health_checks(&self) -> Result<Vec<(crate::model::HealthCheck, Record)>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT r.id, r.zone_id, r.name, r.rtype, r.content, r.ttl, r.priority, r.disabled,
                    r.last_modified_at, r.last_used_at,
                    h.kind, h.port, h.path, h.host, h.interval_secs
             FROM health_checks h JOIN records r ON r.id = h.record_id
             WHERE r.rtype IN ('A', 'AAAA')
             ORDER BY r.name",
        )?;
        let rows = stmt.query_map([], |row| {
            let record = row_to_record(row)?;
            Ok((
                crate::model::HealthCheck {
                    record_id: record.id.clone(),
                    kind: row.get(10)?,
                    port: row.get(11)?,
                    path: row.get(12)?,
                    host: row.get(13)?,
                    interval_secs: row.get(14)?,
                },
                record,
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Add or replace the health check on a record.
    pub fn set_health_check(&self, check: &crate::model::HealthCheck) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO health_checks (record_id, kind, port, path, host, interval_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(record_id) DO UPDATE SET kind = excluded.kind, port = excluded.port,
                 path = excluded.path, host = excluded.host,
                 interval_secs = excluded.interval_secs",
            params![
                check.record_id,
                check.kind,
                check.port,
                check.path,
                check.host,
                check.interval_secs
            ],
        )?;
        Ok(())
    }

    /// Remove a record's health check. Returns whether it had one.
    pub fn delete_health_check(&self, record_id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        Ok(conn.execute(
            "DELETE FROM health_checks WHERE record_id = ?1",
            [record_id],
        )? > 0)
    }

    // ---- Catalog zones (RFC 9432) ----------------------------------------

    /// Record that `catalog` added the zone `zone_id`.
    pub fn add_catalog_member(&self, zone_id: &str, catalog: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO catalog_members (zone_id, catalog) VALUES (?1, ?2)
             ON CONFLICT(zone_id) DO UPDATE SET catalog = excluded.catalog",
            params![zone_id, catalog],
        )?;
        Ok(())
    }

    /// Every zone added by a consumed catalog: zone id → catalog name.
    pub fn catalog_members(&self) -> Result<std::collections::HashMap<String, String>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare("SELECT zone_id, catalog FROM catalog_members")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The serial of the published catalog zone `name` for a member list
    /// with this `digest`: bumped (and `true` returned) when the list
    /// changed since last time.
    pub fn catalog_serial(&self, name: &str, digest: &str) -> Result<(u32, bool)> {
        let conn = self.lock_conn()?;
        let current: Option<(String, u32)> = conn
            .query_row(
                "SELECT digest, serial FROM catalog_state WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match current {
            Some((d, serial)) if d == digest => Ok((serial, false)),
            current => {
                // Start from the time, so a catalog that is turned off and
                // on again (or renamed back) still moves forward.
                let now = u32::try_from(chrono::Utc::now().timestamp()).unwrap_or(u32::MAX);
                let serial = current
                    .map(|(_, s)| s.wrapping_add(1))
                    .unwrap_or(now)
                    .max(1);
                conn.execute(
                    "INSERT INTO catalog_state (name, digest, serial) VALUES (?1, ?2, ?3)
                     ON CONFLICT(name) DO UPDATE SET digest = excluded.digest,
                         serial = excluded.serial",
                    params![name, digest, serial],
                )?;
                Ok((serial, true))
            }
        }
    }

    // ---- DNSSEC signing keys --------------------------------------------

    /// Whether a signed zone uses NSEC3 (rather than NSEC) for denial of
    /// existence.
    pub fn zone_nsec3(&self, zone_id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let nsec3: Option<bool> = conn
            .query_row(
                "SELECT nsec3 FROM zone_dnssec WHERE zone_id = ?1",
                [zone_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(nsec3.unwrap_or(false))
    }

    /// Choose NSEC3 (`true`) or NSEC for a zone's denial of existence.
    pub fn set_zone_nsec3(&self, zone_id: &str, nsec3: bool) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO zone_dnssec (zone_id, nsec3) VALUES (?1, ?2)
             ON CONFLICT(zone_id) DO UPDATE SET nsec3 = excluded.nsec3",
            rusqlite::params![zone_id, nsec3],
        )?;
        Ok(())
    }

    /// List every stored signing key for a zone (active and retired), oldest
    /// first.
    pub fn list_signing_keys(&self, zone_id: &str) -> Result<Vec<SigningKeyRecord>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, algorithm, key_der, state, created_at
             FROM dnssec_keys WHERE zone_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map([zone_id], row_to_key)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Store a new signing key created now; returns its id.
    pub fn store_signing_key(
        &self,
        zone_id: &str,
        algorithm: u8,
        key_der: &[u8],
    ) -> Result<String> {
        self.store_signing_key_created(zone_id, algorithm, key_der, Utc::now())
    }

    /// Store a new signing key with an explicit creation timestamp (used for
    /// rollover bookkeeping and imports); returns its id.
    pub fn store_signing_key_created(
        &self,
        zone_id: &str,
        algorithm: u8,
        key_der: &[u8],
        created_at: chrono::DateTime<Utc>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO dnssec_keys (id, zone_id, algorithm, key_der, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5)",
            params![
                id,
                zone_id,
                algorithm as i64,
                key_der,
                created_at.to_rfc3339()
            ],
        )?;
        Ok(id)
    }

    /// Move a key between states (`active` <-> `retired`).
    pub fn set_key_state(&self, key_id: &str, state: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE dnssec_keys SET state = ?2 WHERE id = ?1",
            params![key_id, state],
        )?;
        Ok(changed > 0)
    }

    /// Rewrite a key's creation timestamp (used to backfill/import keys with
    /// known creation dates).
    pub fn set_key_created_at(
        &self,
        key_id: &str,
        created_at: chrono::DateTime<Utc>,
    ) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE dnssec_keys SET created_at = ?2 WHERE id = ?1",
            params![key_id, created_at.to_rfc3339()],
        )?;
        Ok(changed > 0)
    }

    /// Delete a single key row.
    pub fn delete_key(&self, key_id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM dnssec_keys WHERE id = ?1", [key_id])?;
        Ok(changed > 0)
    }

    /// True when the zone has at least one signing key (of any state).
    pub fn get_signing_key(&self, zone_id: &str) -> Result<Option<(u8, Vec<u8>)>> {
        Ok(self
            .list_signing_keys(zone_id)?
            .into_iter()
            .next()
            .map(|k| (k.algorithm, k.key_der)))
    }

    /// Delete every signing key for a zone (used by "unsign zone").
    pub fn delete_signing_key(&self, zone_id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM dnssec_keys WHERE zone_id = ?1", [zone_id])?;
        Ok(changed > 0)
    }

    /// All zones paired with their records and every signing key, for the
    /// catalog builder.
    pub fn load_catalog_data(&self) -> Result<CatalogData> {
        let zones = self.list_zones()?;
        let records = self.list_all_records()?;
        let mut out = Vec::with_capacity(zones.len());
        for zone in zones {
            let recs = records
                .iter()
                .filter(|r| r.zone_id == zone.id)
                .cloned()
                .collect::<Vec<_>>();
            let keys = self.list_signing_keys(&zone.id)?;
            out.push((zone, recs, keys));
        }
        Ok(out)
    }
}

fn row_to_zone(row: &rusqlite::Row<'_>) -> rusqlite::Result<Zone> {
    Ok(Zone {
        id: row.get(0)?,
        name: row.get(1)?,
        primary_ns: row.get(2)?,
        admin_mailbox: row.get(3)?,
        serial: row.get(4)?,
        refresh: row.get(5)?,
        retry: row.get(6)?,
        expire: row.get(7)?,
        minimum: row.get(8)?,
        created_at: row.get(9)?,
        enabled: row.get::<_, i64>(10)? != 0,
        last_modified_at: row.get(11)?,
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        zone_id: row.get(1)?,
        name: row.get(2)?,
        rtype: row.get(3)?,
        content: row.get(4)?,
        ttl: row.get(5)?,
        priority: row.get(6)?,
        disabled: row.get::<_, i64>(7)? != 0,
        last_modified_at: row.get(8)?,
        last_used_at: row.get(9)?,
    })
}

fn row_to_key(row: &rusqlite::Row<'_>) -> rusqlite::Result<SigningKeyRecord> {
    Ok(SigningKeyRecord {
        id: row.get(0)?,
        zone_id: row.get(1)?,
        algorithm: row.get::<_, i64>(2)? as u8,
        key_der: row.get(3)?,
        state: row.get(4)?,
        created_at: row.get(5)?,
    })
}

/// JSON-encode a list column, mapping serialization errors to `DaygleError`.
fn encode_json(value: &[String], field: &str) -> Result<String> {
    serde_json::to_string(value).map_err(|e| DaygleError::Database(format!("encode {field}: {e}")))
}

/// Decode a JSON string list column, falling back to empty on malformed data.
fn decode_list(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Vec<String>> {
    Ok(serde_json::from_str(&row.get::<_, String>(idx)?).unwrap_or_default())
}

/// Build a [`BlockingGroup`] from a `blocking_groups` row. Malformed JSON
/// list/response columns fall back to safe defaults rather than erroring.
fn row_to_blocking_group(row: &rusqlite::Row<'_>) -> rusqlite::Result<BlockingGroup> {
    let response = serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default();
    Ok(BlockingGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        clients: decode_list(row, 3)?,
        allow: decode_list(row, 4)?,
        block: decode_list(row, 5)?,
        allow_regex: decode_list(row, 6)?,
        block_regex: decode_list(row, 7)?,
        blocklists: decode_list(row, 10)?,
        response,
        position: row.get(9)?,
    })
}

/// Build a [`ConsoleUser`] from a `console_users` row.
fn row_to_console_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsoleUser> {
    let role: String = row.get(2)?;
    Ok(ConsoleUser {
        username: row.get(0)?,
        password_hash: row.get(1)?,
        role: match role.as_str() {
            "viewer" => Role::Viewer,
            _ => Role::Admin,
        },
        enabled: row.get::<_, i64>(3)? != 0,
        first_name: row.get(4)?,
        last_name: row.get(5)?,
        email: row.get(6)?,
        created_at: row.get(7)?,
        preferences: DisplaySettings {
            time_zone: row.get(8)?,
            date_format: row.get(9)?,
            time_format: row.get(10)?,
        },
        two_factor: row.get(11)?,
        last_login_at: row.get(12)?,
    })
}

/// A console account (no password): what the admin UI and login responses see.
#[derive(Debug, Clone, Serialize)]
pub struct ConsoleUser {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub created_at: String,
    /// The account's own date and time display choices. An empty field
    /// means the server default (`display` in the configuration) applies.
    pub preferences: DisplaySettings,
    /// Whether the account signs in with a code from an authenticator app
    /// as well as its password.
    pub two_factor: bool,
    /// RFC 3339 time of the most recent successful password sign-in.
    pub last_login_at: Option<String>,
}

impl ConsoleUser {
    /// The account as the admin UI should see it: password material redacted.
    pub fn redacted(&self) -> Self {
        Self {
            password_hash: "[redacted]".to_string(),
            ..self.clone()
        }
    }
}

/// Input for creating or updating a console account.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConsoleUserInput {
    pub password_hash: String,
    pub role: Role,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub email: String,
}

/// A TLS certificate managed from the console (created as self-signed or
/// uploaded), stored PEM-encoded in the database. Listeners reference one by
/// `name`; the server materializes it to disk before binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificate {
    pub name: String,
    /// Subject/display name (the CN / SAN used when generated self-signed).
    pub server_name: String,
    /// PEM certificate chain (leaf first).
    pub cert_pem: String,
    /// PEM private key.
    pub key_pem: String,
    pub created_at: String,
}

fn row_to_tls_certificate(row: &rusqlite::Row<'_>) -> rusqlite::Result<TlsCertificate> {
    Ok(TlsCertificate {
        name: row.get(0)?,
        server_name: row.get(1)?,
        cert_pem: row.get(2)?,
        key_pem: row.get(3)?,
        created_at: row.get(4)?,
    })
}

// ---- TLS certificates (console-managed) ---------------------------------

impl ZoneStore {
    /// List every managed TLS certificate ordered by name.
    pub fn list_tls_certificates(&self) -> Result<Vec<TlsCertificate>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, server_name, cert_pem, key_pem, created_at
             FROM tls_certificates ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_tls_certificate)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_tls_certificate(&self, name: &str) -> Result<Option<TlsCertificate>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT name, server_name, cert_pem, key_pem, created_at
             FROM tls_certificates WHERE name = ?1",
            [name],
            row_to_tls_certificate,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Insert or replace a managed TLS certificate (keyed by `name`).
    pub fn put_tls_certificate(&self, cert: &TlsCertificate) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO tls_certificates (name, server_name, cert_pem, key_pem, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                server_name = excluded.server_name,
                cert_pem    = excluded.cert_pem,
                key_pem     = excluded.key_pem,
                created_at  = excluded.created_at",
            params![
                cert.name,
                cert.server_name,
                cert.cert_pem,
                cert.key_pem,
                cert.created_at
            ],
        )?;
        Ok(())
    }

    /// Delete a managed TLS certificate by name (and stop renewing it, if
    /// it came from an ACME CA). Returns whether one existed.
    pub fn delete_tls_certificate(&self, name: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let n = conn.execute("DELETE FROM tls_certificates WHERE name = ?1", [name])?;
        let acme = conn.execute("DELETE FROM acme_certificates WHERE name = ?1", [name])?;
        Ok(n > 0 || acme > 0)
    }
}

/// A certificate issued and renewed by an ACME CA such as Let's Encrypt.
/// Its key and chain live in `tls_certificates` under the same name once
/// issued.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeCertificate {
    pub name: String,
    pub domains: Vec<String>,
    /// How control of the names is proven: `http` (HTTP-01, served by the
    /// web console) or `dns` (DNS-01, a TXT record in a zone hosted here).
    pub challenge: String,
    /// `pending` (being issued), `valid` or `failed`.
    pub status: String,
    pub last_error: String,
    /// UNIX time of the last issue or renewal attempt.
    pub last_attempt: i64,
}

fn row_to_acme_certificate(row: &rusqlite::Row<'_>) -> rusqlite::Result<AcmeCertificate> {
    let domains: String = row.get(1)?;
    Ok(AcmeCertificate {
        name: row.get(0)?,
        domains: serde_json::from_str(&domains).unwrap_or_default(),
        challenge: row.get(2)?,
        status: row.get(3)?,
        last_error: row.get(4)?,
        last_attempt: row.get(5)?,
    })
}

impl ZoneStore {
    pub fn list_acme_certificates(&self) -> Result<Vec<AcmeCertificate>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, domains, challenge, status, last_error, last_attempt
             FROM acme_certificates ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_acme_certificate)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_acme_certificate(&self, name: &str) -> Result<Option<AcmeCertificate>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT name, domains, challenge, status, last_error, last_attempt
             FROM acme_certificates WHERE name = ?1",
            [name],
            row_to_acme_certificate,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Insert or replace an ACME certificate's settings and state.
    pub fn put_acme_certificate(&self, cert: &AcmeCertificate) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO acme_certificates (name, domains, challenge, status, last_error, last_attempt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
                domains = excluded.domains, challenge = excluded.challenge,
                status = excluded.status, last_error = excluded.last_error,
                last_attempt = excluded.last_attempt",
            params![
                cert.name,
                serde_json::to_string(&cert.domains).expect("strings serialize"),
                cert.challenge,
                cert.status,
                cert.last_error,
                cert.last_attempt
            ],
        )?;
        Ok(())
    }

    /// Record the outcome of an issue or renewal attempt.
    pub fn set_acme_certificate_status(
        &self,
        name: &str,
        status: &str,
        last_error: &str,
        last_attempt: i64,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE acme_certificates SET status = ?2, last_error = ?3, last_attempt = ?4
             WHERE name = ?1",
            params![name, status, last_error, last_attempt],
        )?;
        Ok(())
    }
}

// ---- Two-factor login --------------------------------------------------

/// An account's two-factor state. `secret` is set once two-factor login is
/// on; `pending_secret` while it is being set up (until a first code
/// confirms the authenticator app has it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwoFactor {
    pub secret: String,
    pub pending_secret: String,
    /// Hashes of the unused recovery codes.
    pub recovery_hashes: Vec<String>,
    /// Time step of the last code accepted (a code works once).
    pub last_step: u64,
}

impl ZoneStore {
    pub fn get_two_factor(&self, username: &str) -> Result<Option<TwoFactor>> {
        let conn = self.lock_conn()?;
        let row: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT secret, pending_secret, recovery_hashes, last_step
                 FROM console_user_two_factor WHERE username = ?1",
                [username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        Ok(
            row.map(|(secret, pending_secret, hashes, last_step)| TwoFactor {
                secret,
                pending_secret,
                recovery_hashes: serde_json::from_str(&hashes).unwrap_or_default(),
                last_step: last_step.max(0) as u64,
            }),
        )
    }

    /// Start setting up two-factor login: keep `secret` until a code
    /// confirms it. Two-factor login already on stays on meanwhile.
    pub fn set_two_factor_pending(&self, username: &str, secret: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO console_user_two_factor (username, pending_secret) VALUES (?1, ?2)
             ON CONFLICT(username) DO UPDATE SET pending_secret = excluded.pending_secret",
            params![username, secret],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                DaygleError::NotFound(format!("user '{username}'"))
            }
            other => other.into(),
        })?;
        Ok(())
    }

    /// Turn two-factor login on with the pending secret, confirmed by the
    /// code for `step`, and these recovery code hashes.
    pub fn enable_two_factor(
        &self,
        username: &str,
        step: u64,
        recovery_hashes: &[String],
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        let n = conn.execute(
            "UPDATE console_user_two_factor
             SET secret = pending_secret, pending_secret = '', recovery_hashes = ?2, last_step = ?3
             WHERE username = ?1 AND pending_secret != ''",
            params![
                username,
                serde_json::to_string(recovery_hashes).expect("strings serialize"),
                step as i64
            ],
        )?;
        if n == 0 {
            return Err(DaygleError::Config(
                "start two-factor setup first".to_string(),
            ));
        }
        Ok(())
    }

    /// Replace the recovery codes.
    pub fn set_two_factor_recovery(
        &self,
        username: &str,
        recovery_hashes: &[String],
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE console_user_two_factor SET recovery_hashes = ?2 WHERE username = ?1",
            params![
                username,
                serde_json::to_string(recovery_hashes).expect("strings serialize")
            ],
        )?;
        Ok(())
    }

    /// Record that the code for `step` was used. False when it (or a later
    /// one) already was: a code works once, even when two sign-ins race.
    pub fn use_two_factor_step(&self, username: &str, step: u64) -> Result<bool> {
        let conn = self.lock_conn()?;
        Ok(conn.execute(
            "UPDATE console_user_two_factor SET last_step = ?2
             WHERE username = ?1 AND last_step < ?2",
            params![username, step as i64],
        )? > 0)
    }

    /// Use up the recovery code with this hash. False when it is not one of
    /// the account's unused codes.
    pub fn use_two_factor_recovery_code(&self, username: &str, hash: &str) -> Result<bool> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT recovery_hashes FROM console_user_two_factor WHERE username = ?1",
                [username],
                |r| r.get(0),
            )
            .optional()?;
        let mut hashes: Vec<String> = stored
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let before = hashes.len();
        hashes.retain(|h| h != hash);
        if hashes.len() == before {
            return Ok(false);
        }
        tx.execute(
            "UPDATE console_user_two_factor SET recovery_hashes = ?2 WHERE username = ?1",
            params![
                username,
                serde_json::to_string(&hashes).expect("strings serialize")
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Turn two-factor login off (and drop any setup in progress). Returns
    /// whether it was on.
    pub fn disable_two_factor(&self, username: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let was_on: bool = conn
            .query_row(
                "SELECT secret != '' FROM console_user_two_factor WHERE username = ?1",
                [username],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);
        conn.execute(
            "DELETE FROM console_user_two_factor WHERE username = ?1",
            [username],
        )?;
        Ok(was_on)
    }
}

// ---- Login sessions and API tokens ---------------------------------------

/// A stored login session (the token itself is never stored, only its
/// hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub token_hash: String,
    pub username: String,
    pub role: Role,
    /// UNIX seconds.
    pub expires_at: i64,
}

/// A personal API token: a long-lived credential for scripts, made by a
/// signed-in account for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiToken {
    pub id: String,
    pub username: String,
    pub name: String,
    #[serde(skip)]
    pub token_hash: String,
    /// Limited to reading, whatever the account's role.
    pub read_only: bool,
    /// UNIX seconds; `last_used_at` 0 = never, `expires_at` 0 = never.
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
}

fn role_from_str(role: &str) -> Role {
    if role == Role::Viewer.as_str() {
        Role::Viewer
    } else {
        Role::Admin
    }
}

fn row_to_api_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiToken> {
    Ok(ApiToken {
        id: row.get(0)?,
        username: row.get(1)?,
        name: row.get(2)?,
        token_hash: row.get(3)?,
        read_only: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
        last_used_at: row.get(6)?,
        expires_at: row.get(7)?,
    })
}

const API_TOKEN_COLUMNS: &str =
    "id, username, name, token_hash, read_only, created_at, last_used_at, expires_at";

impl ZoneStore {
    pub fn put_session(&self, session: &StoredSession) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO console_sessions (token_hash, username, role, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                session.token_hash,
                session.username,
                session.role.as_str(),
                session.expires_at
            ],
        )?;
        Ok(())
    }

    /// Unexpired sessions (expired ones are deleted).
    pub fn load_sessions(&self, now: i64) -> Result<Vec<StoredSession>> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM console_sessions WHERE expires_at <= ?1", [now])?;
        let mut stmt =
            conn.prepare("SELECT token_hash, username, role, expires_at FROM console_sessions")?;
        let rows = stmt.query_map([], |r| {
            let role: String = r.get(2)?;
            Ok(StoredSession {
                token_hash: r.get(0)?,
                username: r.get(1)?,
                role: role_from_str(&role),
                expires_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn delete_session(&self, token_hash: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "DELETE FROM console_sessions WHERE token_hash = ?1",
            [token_hash],
        )?;
        Ok(())
    }

    /// Delete `username`'s sessions, except the one with `keep_hash`.
    pub fn delete_user_sessions(&self, username: &str, keep_hash: Option<&str>) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "DELETE FROM console_sessions WHERE username = ?1 AND token_hash != ?2",
            params![username, keep_hash.unwrap_or("")],
        )?;
        Ok(())
    }

    pub fn create_api_token(&self, token: &ApiToken) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            &format!("INSERT INTO api_tokens ({API_TOKEN_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
            params![
                token.id,
                token.username,
                token.name,
                token.token_hash,
                token.read_only as i64,
                token.created_at,
                token.last_used_at,
                token.expires_at
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                DaygleError::NotFound(format!("user '{}'", token.username))
            }
            other => other.into(),
        })?;
        Ok(())
    }

    /// `username`'s tokens, newest first.
    pub fn list_api_tokens(&self, username: &str) -> Result<Vec<ApiToken>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {API_TOKEN_COLUMNS} FROM api_tokens WHERE username = ?1
             ORDER BY created_at DESC, name"
        ))?;
        let rows = stmt.query_map([username], row_to_api_token)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn find_api_token(&self, token_hash: &str) -> Result<Option<ApiToken>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            &format!("SELECT {API_TOKEN_COLUMNS} FROM api_tokens WHERE token_hash = ?1"),
            [token_hash],
            row_to_api_token,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Note that the token was used (at most once a minute).
    pub fn touch_api_token(&self, id: &str, now: i64) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE api_tokens SET last_used_at = ?2 WHERE id = ?1 AND last_used_at < ?2 - 60",
            params![id, now],
        )?;
        Ok(())
    }

    /// Delete one of `username`'s tokens. Returns whether it existed.
    pub fn delete_api_token(&self, username: &str, id: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        Ok(conn.execute(
            "DELETE FROM api_tokens WHERE id = ?1 AND username = ?2",
            params![id, username],
        )? > 0)
    }
}

// ---- Audit log ------------------------------------------------------------

/// One change made through the API (or a sign-in): who, how, what, and
/// whether it worked. Request bodies are never kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    /// UNIX seconds.
    pub ts: i64,
    pub username: String,
    /// How the caller signed in: `session`, `api_token`, `static_token`,
    /// `open` (authentication turned off), or `password` for a sign-in.
    pub via: String,
    pub client: String,
    /// What was done, in words ("Created zone", "Signed in"...).
    pub action: String,
    pub method: String,
    pub path: String,
    /// HTTP status of the response.
    pub status: u16,
}

/// Filters for [`ZoneStore::search_audit_log`].
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Only entries older than this id (paging).
    pub before_id: Option<i64>,
    pub username: Option<String>,
    /// Matches the action or path.
    pub text: Option<String>,
    pub limit: u32,
}

/// Audit entries older than this are dropped.
const AUDIT_KEEP_SECS: i64 = 365 * 86_400;

impl ZoneStore {
    pub fn add_audit_entry(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO audit_log (ts, username, via, client, action, method, path, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.ts,
                entry.username,
                entry.via,
                entry.client,
                entry.action,
                entry.method,
                entry.path,
                entry.status
            ],
        )?;
        // Trim now and then rather than on every write.
        if conn.last_insert_rowid() % 500 == 0 {
            conn.execute(
                "DELETE FROM audit_log WHERE ts < ?1",
                [entry.ts - AUDIT_KEEP_SECS],
            )?;
        }
        Ok(())
    }

    /// Newest first.
    pub fn search_audit_log(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let conn = self.lock_conn()?;
        let mut sql = String::from(
            "SELECT id, ts, username, via, client, action, method, path, status
             FROM audit_log WHERE 1 = 1",
        );
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(before) = query.before_id {
            sql.push_str(" AND id < ?");
            values.push(Box::new(before));
        }
        if let Some(user) = query.username.as_ref().filter(|u| !u.is_empty()) {
            sql.push_str(" AND username = ?");
            values.push(Box::new(user.clone()));
        }
        if let Some(text) = query.text.as_ref().filter(|t| !t.is_empty()) {
            sql.push_str(" AND (action LIKE ? OR path LIKE ?)");
            let pattern = format!("%{}%", text.replace(['%', '_'], ""));
            values.push(Box::new(pattern.clone()));
            values.push(Box::new(pattern));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        values.push(Box::new(i64::from(query.limit.clamp(1, 1000))));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(values.iter().map(|v| v.as_ref())),
            |r| {
                Ok(AuditEntry {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    username: r.get(2)?,
                    via: r.get(3)?,
                    client: r.get(4)?,
                    action: r.get(5)?,
                    method: r.get(6)?,
                    path: r.get(7)?,
                    status: r.get::<_, i64>(8)? as u16,
                })
            },
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

// ---- Console users (login accounts) ------------------------------------

impl ZoneStore {
    /// List every console account ordered by username.
    pub fn list_console_users(&self) -> Result<Vec<ConsoleUser>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT username, password_hash, role, enabled, first_name, last_name, email, created_at,
                    time_zone, date_format, time_format,
                    EXISTS(SELECT 1 FROM console_user_two_factor t
                           WHERE t.username = console_users.username AND t.secret != ''),
                    last_login_at
             FROM console_users ORDER BY username",
        )?;
        let rows = stmt.query_map([], row_to_console_user)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Number of console accounts (enabled or not). Cheaper than listing
    /// them for callers that only need to know whether any exist.
    pub fn count_console_users(&self) -> Result<usize> {
        let conn = self.lock_conn()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM console_users", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Count enabled admin accounts (used by the last-admin guard).
    pub fn count_enabled_admins(&self) -> Result<usize> {
        let conn = self.lock_conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM console_users WHERE role = 'admin' AND enabled = 1",
            [],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    pub fn get_console_user(&self, username: &str) -> Result<Option<ConsoleUser>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT username, password_hash, role, enabled, first_name, last_name, email, created_at,
                    time_zone, date_format, time_format,
                    EXISTS(SELECT 1 FROM console_user_two_factor t
                           WHERE t.username = console_users.username AND t.secret != ''),
                    last_login_at
             FROM console_users WHERE username = ?1",
            [username],
            row_to_console_user,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Create a console account. The password must already be hashed.
    pub fn create_console_user(
        &self,
        username: &str,
        input: &ConsoleUserInput,
    ) -> Result<ConsoleUser> {
        validate_username(username)?;
        let user = ConsoleUser {
            username: username.to_string(),
            password_hash: input.password_hash.clone(),
            role: input.role,
            enabled: input.enabled,
            first_name: input.first_name.clone(),
            last_name: input.last_name.clone(),
            email: input.email.clone(),
            created_at: Utc::now().to_rfc3339(),
            preferences: DisplaySettings {
                time_zone: String::new(),
                date_format: String::new(),
                time_format: String::new(),
            },
            two_factor: false,
            last_login_at: None,
        };
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO console_users (username, password_hash, role, enabled, first_name, last_name, email, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(username) DO UPDATE SET
                password_hash = excluded.password_hash,
                role = excluded.role,
                enabled = excluded.enabled,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                email = excluded.email,
                created_at = excluded.created_at",
            params![
                user.username,
                user.password_hash,
                user.role.as_str(),
                user.enabled as i64,
                user.first_name,
                user.last_name,
                user.email,
                user.created_at
            ],
        )?;
        Ok(user)
    }

    /// Record a successful interactive login for an existing console user.
    pub fn touch_console_user_login(&self, username: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        let changed = conn.execute(
            "UPDATE console_users SET last_login_at = ?2 WHERE username = ?1",
            params![username, Utc::now().to_rfc3339()],
        )?;
        if changed == 0 {
            return Err(DaygleError::NotFound(format!("user '{username}'")));
        }
        Ok(())
    }

    /// Store a console account's own display preferences (empty fields
    /// fall back to the server default).
    pub fn set_console_user_preferences(
        &self,
        username: &str,
        preferences: &DisplaySettings,
    ) -> Result<()> {
        preferences
            .check(true)
            .map_err(DaygleError::InvalidRecord)?;
        let conn = self.lock_conn()?;
        let n = conn.execute(
            "UPDATE console_users SET time_zone = ?2, date_format = ?3, time_format = ?4
             WHERE username = ?1",
            params![
                username,
                preferences.time_zone,
                preferences.date_format,
                preferences.time_format
            ],
        )?;
        if n == 0 {
            return Err(DaygleError::NotFound(format!("user '{username}'")));
        }
        Ok(())
    }

    /// Set a console account's stored password hash.
    pub fn set_console_user_password(&self, username: &str, password_hash: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        let n = conn.execute(
            "UPDATE console_users SET password_hash = ?2 WHERE username = ?1",
            params![username, password_hash],
        )?;
        if n == 0 {
            return Err(DaygleError::Config(format!("user '{username}' not found")));
        }
        Ok(())
    }

    /// Update a console account's profile fields (first name, last name,
    /// email). Pass `None` to leave a field unchanged.
    pub fn set_console_user_profile(
        &self,
        username: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        email: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        let n = conn.execute(
            "UPDATE console_users
             SET first_name = COALESCE(?2, first_name),
                 last_name  = COALESCE(?3, last_name),
                 email      = COALESCE(?4, email)
             WHERE username = ?1",
            params![username, first_name, last_name, email],
        )?;
        if n == 0 {
            return Err(DaygleError::Config(format!("user '{username}' not found")));
        }
        Ok(())
    }

    /// Change a console account's role.
    ///
    /// Refuses to demote the last enabled admin to a non-admin role, which
    /// would otherwise lock the operator out of the console.
    pub fn set_console_user_role(&self, username: &str, role: Role) -> Result<()> {
        let conn = self.lock_conn()?;
        if role != Role::Admin {
            // Only enforce when demoting FROM admin; other role transitions
            // (viewer -> editor, etc.) are unaffected.
            let current: String = conn
                .query_row(
                    "SELECT role FROM console_users WHERE username = ?1",
                    [username],
                    |r| r.get(0),
                )
                .map_err(|_| DaygleError::Config(format!("user '{username}' not found")))?;
            if current == Role::Admin.as_str() {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM console_users WHERE role = 'admin' AND enabled = 1",
                    [],
                    |r| r.get(0),
                )?;
                if count <= 1 {
                    return Err(DaygleError::Config(
                        "cannot demote the last enabled admin".to_string(),
                    ));
                }
            }
        }
        let n = conn.execute(
            "UPDATE console_users SET role = ?2 WHERE username = ?1",
            params![username, role.as_str()],
        )?;
        if n == 0 {
            return Err(DaygleError::Config(format!("user '{username}' not found")));
        }
        Ok(())
    }

    /// Enable or disable a console account. Disabled accounts cannot log in.
    ///
    /// Refuses to disable an enabled admin when no other enabled admin exists.
    pub fn set_console_user_enabled(&self, username: &str, enabled: bool) -> Result<()> {
        let conn = self.lock_conn()?;
        if !enabled {
            let (role, was_enabled): (String, i64) = conn
                .query_row(
                    "SELECT role, enabled FROM console_users WHERE username = ?1",
                    [username],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| DaygleError::Config(format!("user '{username}' not found")))?;
            if role == Role::Admin.as_str() && was_enabled != 0 {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM console_users WHERE role = 'admin' AND enabled = 1",
                    [],
                    |r| r.get(0),
                )?;
                if count <= 1 {
                    return Err(DaygleError::Config(
                        "cannot disable the last enabled admin".to_string(),
                    ));
                }
            }
        }
        let n = conn.execute(
            "UPDATE console_users SET enabled = ?2 WHERE username = ?1",
            params![username, enabled as i64],
        )?;
        if n == 0 {
            return Err(DaygleError::Config(format!("user '{username}' not found")));
        }
        Ok(())
    }

    /// Delete a console account. Returns whether a row was removed.
    ///
    /// Refuses to delete the last enabled admin.
    pub fn delete_console_user(&self, username: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT role, enabled FROM console_users WHERE username = ?1",
                [username],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((role, was_enabled)) = row else {
            return Err(DaygleError::Config(format!("user '{username}' not found")));
        };
        if role == Role::Admin.as_str() && was_enabled != 0 {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM console_users WHERE role = 'admin' AND enabled = 1",
                [],
                |r| r.get(0),
            )?;
            if count <= 1 {
                return Err(DaygleError::Config(
                    "cannot delete the last enabled admin".to_string(),
                ));
            }
        }
        let n = conn.execute("DELETE FROM console_users WHERE username = ?1", [username])?;
        Ok(n > 0)
    }

    /// The email of the earliest-created enabled administrator that has
    /// one (normally the account made at first-run setup), or `None`.
    pub fn first_admin_email(&self) -> Result<Option<String>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT email FROM console_users
             WHERE role = 'admin' AND enabled = 1 AND TRIM(email) != ''
             ORDER BY created_at, username LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map(|e| e.map(|e| e.trim().to_string()))
        .map_err(Into::into)
    }

    /// The username of the first enabled admin, or `None` (used to guard
    /// against demoting/disabling/deleting the last admin).
    pub fn first_enabled_admin(&self) -> Result<Option<String>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT username FROM console_users
             WHERE role = 'admin' AND enabled = 1 ORDER BY created_at, username LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(Into::into)
    }
}

fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > 64 || username.contains(char::is_whitespace) {
        return Err(DaygleError::Config(
            "username must be 1-64 characters with no whitespace".to_string(),
        ));
    }
    Ok(())
}

// ---- Runtime settings (DB-backed overlay) -------------------------------

impl ZoneStore {
    /// Read the DB-backed runtime settings, deserialized into `T`.
    /// `Ok(None)` when nothing has been persisted yet (first boot).
    pub fn get_runtime_settings<T: serde::de::DeserializeOwned>(&self) -> Result<Option<T>> {
        let conn = self.lock_conn()?;
        let text: Option<String> = conn
            .query_row(
                "SELECT value FROM runtime_settings WHERE name = 'runtime'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match text {
            None => Ok(None),
            Some(text) => serde_json::from_str(&text).map(Some).map_err(|e| {
                DaygleError::Config(format!("stored runtime settings are invalid: {e}"))
            }),
        }
    }

    /// Persist the DB-backed runtime settings, replacing any previous value.
    /// A setting stored on its own (beside the runtime overlay) under
    /// `name`, such as the ACME settings and account.
    pub fn get_named_setting<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>> {
        let conn = self.lock_conn()?;
        let text: Option<String> = conn
            .query_row(
                "SELECT value FROM runtime_settings WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        text.map(|text| {
            serde_json::from_str(&text).map_err(|e| {
                DaygleError::Config(format!("stored setting '{name}' is invalid: {e}"))
            })
        })
        .transpose()
    }

    pub fn put_named_setting<T: serde::Serialize>(&self, name: &str, value: &T) -> Result<()> {
        if name == "runtime" {
            return Err(DaygleError::Config(
                "'runtime' is the settings overlay".into(),
            ));
        }
        let text = serde_json::to_string(value)
            .map_err(|e| DaygleError::Config(format!("cannot serialize setting '{name}': {e}")))?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO runtime_settings (name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, text],
        )?;
        Ok(())
    }

    pub fn put_runtime_settings<T: serde::Serialize>(&self, settings: &T) -> Result<()> {
        let text = serde_json::to_string(settings)
            .map_err(|e| DaygleError::Config(format!("cannot serialize settings: {e}")))?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO runtime_settings (name, value) VALUES ('runtime', ?1)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![text],
        )?;
        Ok(())
    }
}

// ---- Query logs (searchable per-query history) ---------------------------

/// One recorded query: a row of the searchable query log.
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogRow {
    pub id: i64,
    /// RFC 3339 timestamp.
    pub ts: String,
    pub client: String,
    pub qname: String,
    pub qtype: String,
    /// Transport: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`.
    pub protocol: String,
    /// Outcome classification (`authoritative`, `recursive`, `blocked`, ...).
    pub outcome: String,
    /// Response code (`NOERROR`, `NXDOMAIN`, ...) when known.
    pub rcode: Option<String>,
    pub elapsed_ms: i64,
}

/// Filters for [`ZoneStore::search_query_logs`]; `None`/empty means unfiltered.
#[derive(Debug, Clone, Default)]
pub struct QueryLogFilter {
    pub client: Option<String>,
    /// Exact qname, or a `*`-wildcard / substring pattern.
    pub qname: Option<String>,
    pub qtype: Option<String>,
    pub protocol: Option<String>,
    pub outcome: Option<String>,
    pub rcode: Option<String>,
    /// Inclusive lower bound (RFC 3339).
    pub from: Option<String>,
    /// Inclusive upper bound (RFC 3339).
    pub to: Option<String>,
    /// 1-based page (default 1).
    pub page: Option<u32>,
    /// Rows per page (default 50; capped at 500, or 10 000 for an export).
    pub per_page: Option<u32>,
}

/// Escape a LIKE pattern so user input matches literally, then translate a
/// leading or trailing `*` into a `%` wildcard. Plain input becomes a
/// substring match, matching how the GUI search box feels.
fn qname_like_pattern(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return "%".to_string();
    }
    let escaped = trimmed
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    if let Some(stripped) = escaped.strip_prefix('*') {
        format!("%{}", stripped)
    } else if let Some(stripped) = escaped.strip_suffix('*') {
        format!("{}%", stripped)
    } else {
        format!("%{}%", escaped)
    }
}

impl ZoneStore {
    /// Append one query-log entry.
    pub fn insert_query_log(&self, entry: &QueryLogRow) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO query_logs (ts, client, qname, qtype, protocol, outcome, rcode, elapsed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.ts,
                entry.client,
                entry.qname,
                entry.qtype,
                entry.protocol,
                entry.outcome,
                entry.rcode,
                entry.elapsed_ms,
            ],
        )?;
        Ok(())
    }

    /// Append many entries in one transaction (the background writer's bulk path).
    pub fn insert_query_logs(&self, entries: &[QueryLogRow]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        for entry in entries {
            tx.execute(
                "INSERT INTO query_logs (ts, client, qname, qtype, protocol, outcome, rcode, elapsed_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    entry.ts,
                    entry.client,
                    entry.qname,
                    entry.qtype,
                    entry.protocol,
                    entry.outcome,
                    entry.rcode,
                    entry.elapsed_ms,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Largest page [`Self::search_query_logs`] returns (the console's paged
    /// view).
    pub const QUERY_LOG_MAX_PAGE: u32 = 500;
    /// Largest page [`Self::export_query_logs`] returns (CSV export).
    pub const QUERY_LOG_MAX_EXPORT: u32 = 10_000;

    /// Search the query log with filters and pagination. Returns the page of
    /// rows (newest first) plus the total count under the same filter.
    pub fn search_query_logs(&self, filter: &QueryLogFilter) -> Result<(Vec<QueryLogRow>, u64)> {
        self.query_logs_page(filter, Self::QUERY_LOG_MAX_PAGE)
    }

    /// Like [`Self::search_query_logs`], with the larger export page cap so a
    /// CSV export is not silently cut to one console page.
    pub fn export_query_logs(&self, filter: &QueryLogFilter) -> Result<(Vec<QueryLogRow>, u64)> {
        self.query_logs_page(filter, Self::QUERY_LOG_MAX_EXPORT)
    }

    fn query_logs_page(
        &self,
        filter: &QueryLogFilter,
        max_per_page: u32,
    ) -> Result<(Vec<QueryLogRow>, u64)> {
        let mut wheres: Vec<String> = vec![];
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];
        if let Some(client) = filter
            .client
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            params_vec.push(Box::new(client.to_string()));
            wheres.push(format!("client = ?{}", params_vec.len()));
        }
        if let Some(qname) = filter
            .qname
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            params_vec.push(Box::new(qname_like_pattern(qname)));
            wheres.push(format!("qname LIKE ?{} ESCAPE '\\'", params_vec.len()));
        }
        for (value, column) in [
            (filter.qtype.as_deref(), "qtype"),
            (filter.protocol.as_deref(), "protocol"),
            (filter.outcome.as_deref(), "outcome"),
            (filter.rcode.as_deref(), "rcode"),
        ] {
            if let Some(v) = value.map(str::trim).filter(|s| !s.is_empty()) {
                params_vec.push(Box::new(v.to_string()));
                wheres.push(format!("{column} = ?{}", params_vec.len()));
            }
        }
        if let Some(from) = filter
            .from
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            params_vec.push(Box::new(from.to_string()));
            wheres.push(format!("ts >= ?{}", params_vec.len()));
        }
        if let Some(to) = filter
            .to
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            params_vec.push(Box::new(to.to_string()));
            wheres.push(format!("ts <= ?{}", params_vec.len()));
        }
        let where_clause = if wheres.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", wheres.join(" AND "))
        };

        let per_page = filter.per_page.unwrap_or(50).clamp(1, max_per_page);
        let page = filter.page.unwrap_or(1).max(1);
        let offset = (page - 1).saturating_mul(per_page);

        let params_ref: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        let conn = self.lock_conn()?;
        let count: u64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM query_logs {where_clause}"),
            rusqlite::params_from_iter(params_ref.iter().copied()),
            |r| r.get::<_, i64>(0),
        )? as u64;
        let mut stmt = conn.prepare(&format!(
            "SELECT id, ts, client, qname, qtype, protocol, outcome, rcode, elapsed_ms
             FROM query_logs {where_clause}
             ORDER BY id DESC LIMIT {per_page} OFFSET {offset}"
        ))?;
        let rows = stmt
            .query_map(
                rusqlite::params_from_iter(params_ref.iter().copied()),
                |r| {
                    Ok(QueryLogRow {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        client: r.get(2)?,
                        qname: r.get(3)?,
                        qtype: r.get(4)?,
                        protocol: r.get(5)?,
                        outcome: r.get(6)?,
                        rcode: r.get(7)?,
                        elapsed_ms: r.get(8)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, count))
    }

    /// Delete every query-log row (the console's Clear button). Returns the
    /// number of deleted rows.
    pub fn clear_query_logs(&self) -> Result<usize> {
        let conn = self.lock_conn()?;
        Ok(conn.execute("DELETE FROM query_logs", [])?)
    }

    /// Distinct query names logged at or after `since_epoch` (UNIX seconds),
    /// most recently queried first, capped at `limit`. Used by the AI
    /// scanner to harvest domains from live traffic; the query log's `ts`
    /// index keeps the time window cheap even on large logs.
    pub fn distinct_recent_query_names(&self, since_epoch: i64, limit: u32) -> Result<Vec<String>> {
        let cutoff = chrono::DateTime::<Utc>::from_timestamp(since_epoch, 0)
            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
            .to_rfc3339();
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT qname FROM query_logs
             WHERE ts >= ?1
             GROUP BY qname
             ORDER BY MAX(ts) DESC
             LIMIT ?2",
        )?;
        let names = stmt
            .query_map(params![cutoff, limit as i64], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(names)
    }

    /// Enforce the retention cap by deleting rows beyond the newest `max`
    /// (0 disables the cap). Called opportunistically by the log writer.
    pub fn trim_query_logs(&self, max: usize) -> Result<usize> {
        if max == 0 {
            return Ok(0);
        }
        let conn = self.lock_conn()?;
        // The id of the row just past the kept window: everything at or below
        // it is surplus. (A single DELETE with subqueries on the same table is
        // unsafe here: SQLite may re-evaluate them mid-scan as rows vanish.)
        let cutoff: Option<i64> = conn
            .query_row(
                "SELECT id FROM query_logs ORDER BY id DESC LIMIT 1 OFFSET ?1",
                [max as i64],
                |r| r.get(0),
            )
            .optional()?;
        match cutoff {
            Some(cutoff) => Ok(conn.execute("DELETE FROM query_logs WHERE id <= ?1", [cutoff])?),
            None => Ok(0),
        }
    }
}

/// Render a zone as a BIND-style zone file (used by the export API).
///
/// The SOA is emitted from the zone row; every record follows in
/// presentation format. Disabled records are included as comments (with a
/// `; disabled` marker) so an export captures the *full* zone state and can
/// be re-imported as a backup.
fn render_zone_file(zone: &Zone, records: &[Record]) -> String {
    let mut out = String::with_capacity(1024 + records.len() * 64);
    out.push_str(&format!(
        "; zone file exported by daygle-dns for {}\n",
        zone.name
    ));
    out.push_str(&format!("$ORIGIN {}.\n", zone.name));
    out.push_str(&format!("$TTL {}\n", zone.minimum.max(300)));

    out.push_str(&format!(
        "{}. {} IN SOA {} {} (\n\t{}\t; serial\n\t{}\t; refresh\n\t{}\t; retry\n\t{}\t; expire\n\t{}\t; minimum\n)\n",
        zone.name,
        zone.minimum.max(300),
        zone.primary_ns,
        zone.admin_mailbox,
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum,
    ));

    for record in records {
        let name = format!("{}.", record.name.trim_end_matches('.'));
        let line = format!(
            "{} {} IN {} {}\n",
            name, record.ttl, record.rtype, record.content
        );
        if record.disabled {
            out.push_str("; disabled: ");
            out.push_str(line.trim_end());
            out.push('\n');
        } else {
            out.push_str(&line);
        }
    }
    out
}

fn bump_serial_in(conn: &Connection, zone_id: &str) -> Result<u32> {
    let current: u32 = conn
        .query_row("SELECT serial FROM zones WHERE id = ?1", [zone_id], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
    let next = current.wrapping_add(1).max(1);
    conn.execute(
        "UPDATE zones SET serial = ?2, last_modified_at = ?3 WHERE id = ?1",
        params![zone_id, next, Utc::now().to_rfc3339()],
    )?;
    Ok(next)
}

fn insert_record_in_tx(
    tx: &rusqlite::Transaction<'_>,
    zone_id: &str,
    zone_name: &str,
    input: &RecordInput,
) -> Result<Record> {
    let rtype = input.rtype.to_ascii_uppercase();
    if !crate::model::KNOWN_RECORD_TYPES.contains(&rtype.as_str()) {
        return Err(DaygleError::InvalidRecord(format!(
            "unsupported record type '{}'",
            input.rtype
        )));
    }

    let name = qualify_name(&input.name, zone_name)?;
    validate_name(&name, false)?;

    // Reject content the catalog could not serve: it parses records with the
    // same presentation-format parser and would otherwise skip them silently.
    let mut content = input.content.trim().to_string();
    if rtype == "ALIAS" {
        content = check_alias(tx, zone_id, &name, &content)?;
    } else {
        let rr_type = rtype
            .parse::<RecordType>()
            .map_err(|e| DaygleError::InvalidRecord(format!("record type '{rtype}': {e}")))?;
        RData::try_from_str(rr_type, &content).map_err(|e| {
            DaygleError::InvalidRecord(format!("invalid {rtype} record '{content}': {e}"))
        })?;
        if matches!(rtype.as_str(), "A" | "AAAA" | "CNAME") && !input.disabled {
            let alias: i64 = tx.query_row(
                "SELECT COUNT(*) FROM records
                 WHERE zone_id = ?1 AND name = ?2 AND rtype = 'ALIAS' AND disabled = 0",
                params![zone_id, name],
                |r| r.get(0),
            )?;
            if alias > 0 {
                return Err(DaygleError::InvalidRecord(format!(
                    "{name} has an ALIAS record, which supplies its addresses: remove it to add {rtype} records"
                )));
            }
        }
    }

    let record = Record {
        id: Uuid::new_v4().to_string(),
        zone_id: zone_id.to_string(),
        name,
        rtype,
        content,
        ttl: input.ttl,
        priority: input.priority,
        disabled: input.disabled,
        last_modified_at: Utc::now().to_rfc3339(),
        last_used_at: None,
    };
    tx.execute(
        "INSERT INTO records (id, zone_id, name, rtype, content, ttl, priority, disabled, last_modified_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            &record.id,
            &record.zone_id,
            &record.name,
            &record.rtype,
            &record.content,
            record.ttl,
            record.priority,
            record.disabled as i64,
            &record.last_modified_at,
            record.last_used_at.as_deref(),
        ],
    )?;
    Ok(record)
}

/// Check an ALIAS record (a name whose A and AAAA answers are looked up from
/// its target when asked) and return its target in stored form
/// (lowercase, trailing dot). ALIAS answers are made at query time, so they
/// cannot be DNSSEC-signed; they are kept out of signed zones.
fn check_alias(
    tx: &rusqlite::Transaction<'_>,
    zone_id: &str,
    name: &str,
    target: &str,
) -> Result<String> {
    let target = target.trim().trim_end_matches('.').to_ascii_lowercase();
    validate_name(&target, false).map_err(|_| {
        DaygleError::InvalidRecord(format!("ALIAS target '{target}' is not a domain name"))
    })?;
    if target == name {
        return Err(DaygleError::InvalidRecord(
            "an ALIAS cannot point to itself".to_string(),
        ));
    }
    let signed: i64 = tx.query_row(
        "SELECT COUNT(*) FROM dnssec_keys WHERE zone_id = ?1",
        [zone_id],
        |r| r.get(0),
    )?;
    if signed > 0 {
        return Err(DaygleError::InvalidRecord(
            "ALIAS records cannot be used in a DNSSEC-signed zone: their answers are made when asked and cannot be signed".to_string(),
        ));
    }
    let clash: Option<String> = tx
        .query_row(
            "SELECT rtype FROM records
             WHERE zone_id = ?1 AND name = ?2 AND rtype IN ('A', 'AAAA', 'CNAME', 'ALIAS')
             LIMIT 1",
            params![zone_id, name],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(rtype) = clash {
        return Err(DaygleError::InvalidRecord(if rtype == "ALIAS" {
            format!("{name} already has an ALIAS record")
        } else {
            format!("{name} has {rtype} records: an ALIAS supplies the addresses itself, so remove them first")
        }));
    }
    Ok(format!("{target}."))
}

/// Resolve `@`, bare relative names, and trailing dots against the zone name.
pub fn qualify_name(owner: &str, zone_name: &str) -> Result<String> {
    let owner = owner.trim();
    let zone = zone_name.trim().trim_end_matches('.');
    // The bare zone name is the apex too: the console's edit form fills in a
    // stored record's full name, which for an apex record is the zone itself.
    let resolved = if owner == "@" || owner.is_empty() || owner.eq_ignore_ascii_case(zone) {
        zone.to_string()
    } else if let Some(stripped) = owner.strip_suffix('.') {
        stripped.to_string()
    } else if owner.ends_with(&format!(".{zone}")) {
        owner.to_string()
    } else {
        format!("{owner}.{zone}")
    };
    Ok(resolved.to_ascii_lowercase())
}

/// Normalize an FQDN: trim, strip a single trailing dot, lowercase.
pub fn normalize_fqdn(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Result of [`ZoneStore::move_split_horizon_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveResult {
    /// The entry was swapped with its neighbour.
    Moved,
    /// The entry is already at the edge of its domain's ordering.
    AtBoundary,
    /// No entry with the given id exists.
    NotFound,
}

/// Validate a split-horizon network payload: every CIDR must parse.
fn validate_split_horizon_network(input: &SplitHorizonNetworkInput) -> Result<()> {
    for cidr in &input.cidrs {
        cidr.parse::<ipnet::IpNet>()
            .map_err(|e| DaygleError::InvalidRecord(format!("split-horizon CIDR '{cidr}': {e}")))?;
    }
    Ok(())
}

/// Validate a split-horizon entry payload. `domain` must already be
/// normalized (lowercase, no trailing dot). Record content validation happens
/// in [`canonicalize_split_horizon_records`].
fn validate_split_horizon_entry(domain: &str, _input: &SplitHorizonEntryInput) -> Result<()> {
    validate_name(domain, false)
}

/// Convert an `ips`-style list (IPv4/IPv6 addresses) into A/AAAA records.
fn ips_to_records(ips: &[String]) -> Vec<SplitHorizonRecord> {
    ips.iter()
        .filter_map(|ip| {
            if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                Some(SplitHorizonRecord {
                    rtype: "A".to_string(),
                    content: v4.to_string(),
                })
            } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
                Some(SplitHorizonRecord {
                    rtype: "AAAA".to_string(),
                    content: v6.to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Maximum number of records allowed in a single split-horizon entry.
/// Prevents unbounded memory allocation from adversarial input.
const MAX_SPLIT_HORIZON_RECORDS: usize = 1024;

/// Build the canonical `(ips, records)` pair for an entry input. `records` is
/// authoritative when provided; otherwise `ips` is converted to A/AAAA
/// records. Every record is validated: the type must be supported and the
/// content must parse as that type's RDATA in zone-file presentation format
/// (TXT values are auto-quoted). The returned `ips` is always the A/AAAA
/// subset of the canonical records.
fn canonicalize_split_horizon_records(
    input: &SplitHorizonEntryInput,
) -> Result<(Vec<String>, Vec<SplitHorizonRecord>)> {
    let records = if input.records.is_empty() {
        // The legacy `ips` path: every address must parse - reject junk
        // instead of silently dropping it.
        for ip in &input.ips {
            ip.parse::<std::net::IpAddr>()
                .map_err(|e| DaygleError::InvalidRecord(format!("split-horizon IP '{ip}': {e}")))?;
        }
        ips_to_records(&input.ips)
    } else {
        input.records.clone()
    };

    if records.len() > MAX_SPLIT_HORIZON_RECORDS {
        return Err(DaygleError::InvalidRecord(format!(
            "split-horizon entry has {} records, maximum is {}",
            records.len(),
            MAX_SPLIT_HORIZON_RECORDS,
        )));
    }

    // Grown on push rather than pre-sized from the request: the bound above
    // already caps it, and the allocation never trusts a client-supplied length.
    let mut canonical = Vec::new();
    for record in &records {
        let rtype = record.rtype.trim().to_ascii_uppercase();
        if !crate::model::SPLIT_HORIZON_RECORD_TYPES.contains(&rtype.as_str()) {
            return Err(DaygleError::InvalidRecord(format!(
                "unsupported split-horizon record type '{rtype}'"
            )));
        }
        let rr_type = rtype
            .parse::<RecordType>()
            .map_err(|e| DaygleError::InvalidRecord(format!("record type '{rtype}': {e}")))?;
        let content = if rtype == "TXT" && !record.content.trim_start().starts_with('"') {
            format!("\"{}\"", record.content.trim())
        } else {
            record.content.trim().to_string()
        };
        RData::try_from_str(rr_type, &content).map_err(|e| {
            DaygleError::InvalidRecord(format!("invalid {rtype} record '{content}': {e}"))
        })?;
        canonical.push(SplitHorizonRecord { rtype, content });
    }

    let ips = canonical
        .iter()
        .filter(|r| r.rtype == "A" || r.rtype == "AAAA")
        .map(|r| r.content.clone())
        .collect();
    Ok((ips, canonical))
}

/// Add per-record last-modified/last-used metadata to older databases.
fn migrate_record_metadata(conn: &Connection) -> Result<()> {
    for (column, definition) in [
        ("last_modified_at", "TEXT NOT NULL DEFAULT ''"),
        ("last_used_at", "TEXT"),
    ] {
        let has: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('records') WHERE name = ?1
             )",
            [column],
            |row| row.get(0),
        )?;
        if !has {
            conn.execute(
                &format!("ALTER TABLE records ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    conn.execute(
        "UPDATE records SET last_modified_at = (
            SELECT zones.created_at FROM zones WHERE zones.id = records.zone_id
         ) WHERE last_modified_at = ''",
        [],
    )?;
    Ok(())
}

/// Add zone enablement and modification metadata to older databases.
/// Add zone enablement and modification metadata to older databases.
fn migrate_zone_metadata(conn: &Connection) -> Result<()> {
    for (column, definition) in [
        ("enabled", "INTEGER NOT NULL DEFAULT 1"),
        ("last_modified_at", "TEXT NOT NULL DEFAULT ''"),
    ] {
        let has: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('zones') WHERE name = ?1
             )",
            [column],
            |r| r.get(0),
        )?;
        if !has {
            conn.execute(
                &format!("ALTER TABLE zones ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    conn.execute(
        "UPDATE zones SET last_modified_at = created_at WHERE last_modified_at = ''",
        [],
    )?;
    Ok(())
}

/// Add the `last_modified_at` / `last_used_at` columns to
/// `split_horizon_entries` for databases created before entry usage was
/// tracked. Existing rows keep NULL (shown as never / unknown).
fn migrate_split_horizon_timestamps(conn: &Connection) -> Result<()> {
    for column in ["last_modified_at", "last_used_at"] {
        let has: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('split_horizon_entries') WHERE name = ?1
             )",
            [column],
            |r| r.get(0),
        )?;
        if !has {
            conn.execute(
                &format!("ALTER TABLE split_horizon_entries ADD COLUMN {column} TEXT"),
                [],
            )?;
        }
    }
    Ok(())
}

/// Add the `records` column to `split_horizon_entries` for databases created
/// before typed records existed. Rows written with only `ips` keep working:
/// the A/AAAA records are derived on read.
fn migrate_split_horizon_records(conn: &Connection) -> Result<()> {
    let has_records: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('split_horizon_entries') WHERE name = 'records'
         )",
        [],
        |r| r.get(0),
    )?;
    if !has_records {
        conn.execute(
            "ALTER TABLE split_horizon_entries ADD COLUMN records TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(())
}

/// Add the `blocklists` column (remote blocklist sources a group selects) to
/// `blocking_groups` for databases created before it existed.
fn migrate_blocking_group_lists(conn: &Connection) -> Result<()> {
    let has: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('blocking_groups') WHERE name = 'blocklists'
         )",
        [],
        |r| r.get(0),
    )?;
    if !has {
        conn.execute(
            "ALTER TABLE blocking_groups ADD COLUMN blocklists TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(())
}

/// Add the personal profile columns (`first_name`, `last_name`, `email`) and
/// display preference columns to `console_users` for databases created
/// before they existed.
fn migrate_console_user_profile(conn: &Connection) -> Result<()> {
    for (column, default) in [
        ("first_name", "''"),
        ("last_name", "''"),
        ("email", "''"),
        ("time_zone", "''"),
        ("date_format", "''"),
        ("time_format", "''"),
    ] {
        let has: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('console_users') WHERE name = ?1
             )",
            [column],
            |r| r.get(0),
        )?;
        if !has {
            conn.execute(
                &format!(
                    "ALTER TABLE console_users ADD COLUMN {column} TEXT NOT NULL DEFAULT {default}"
                ),
                [],
            )?;
        }
    }
    let has_last_login: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('console_users') WHERE name = 'last_login_at'
         )",
        [],
        |r| r.get(0),
    )?;
    if !has_last_login {
        conn.execute(
            "ALTER TABLE console_users ADD COLUMN last_login_at TEXT",
            [],
        )?;
    }
    Ok(())
}

/// Convert a pre-rollover `dnssec_keys` table (one key per zone, `zone_id`
/// primary key) to the multi-key schema. Existing keys are kept as `active`;
/// their ids are synthesized and their original `created_at` is preserved so
/// rollover timing continues from the key's real age.
fn migrate_dnssec_keys(conn: &Connection) -> Result<()> {
    let has_id: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('dnssec_keys') WHERE name = 'id'
         )",
        [],
        |r| r.get(0),
    )?;
    if has_id {
        return Ok(());
    }
    conn.execute_batch(
        "BEGIN;
         ALTER TABLE dnssec_keys RENAME TO dnssec_keys_legacy;
         DROP INDEX IF EXISTS idx_dnssec_keys_zone;
         CREATE TABLE dnssec_keys (
             id         TEXT PRIMARY KEY,
             zone_id    TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
             algorithm  INTEGER NOT NULL,
             key_der    BLOB NOT NULL,
             state      TEXT NOT NULL DEFAULT 'active',
             created_at TEXT NOT NULL
         );
         CREATE INDEX idx_dnssec_keys_zone ON dnssec_keys(zone_id);
         INSERT INTO dnssec_keys (id, zone_id, algorithm, key_der, state, created_at)
             SELECT lower(hex(randomblob(16))), zone_id, algorithm, key_der,
                    'active', created_at
             FROM dnssec_keys_legacy;
         DROP TABLE dnssec_keys_legacy;
         COMMIT;",
    )?;
    Ok(())
}

/// Make the database file readable by its owner only. It holds console
/// password hashes, TLS and DNSSEC private keys and TSIG secrets, and SQLite
/// otherwise creates it (and its journals, which inherit the file's mode)
/// with the process umask - typically world-readable.
fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(perms.mode() & 0o700);
            std::fs::set_permissions(path, perms)?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn map_unique_violation(e: rusqlite::Error) -> DaygleError {
    match &e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            DaygleError::AlreadyExists("zone already exists".to_string())
        }
        other => DaygleError::Database(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ZoneStore {
        ZoneStore::open(":memory:").unwrap()
    }

    #[test]
    fn query_log_export_is_not_capped_at_one_console_page() {
        let s = store();
        let rows: Vec<QueryLogRow> = (0..600)
            .map(|i| QueryLogRow {
                id: 0,
                ts: "2026-10-19T00:00:00Z".to_string(),
                client: "10.0.0.1".to_string(),
                qname: format!("host{i}.example"),
                qtype: "A".to_string(),
                protocol: "udp".to_string(),
                outcome: "recursive".to_string(),
                rcode: Some("NOERROR".to_string()),
                elapsed_ms: 1,
            })
            .collect();
        s.insert_query_logs(&rows).unwrap();
        let filter = QueryLogFilter {
            per_page: Some(ZoneStore::QUERY_LOG_MAX_EXPORT),
            ..Default::default()
        };
        let (page, total) = s.search_query_logs(&filter).unwrap();
        assert_eq!((page.len(), total), (500, 600));
        let (export, total) = s.export_query_logs(&filter).unwrap();
        assert_eq!((export.len(), total), (600, 600));
    }

    #[test]
    fn blocking_group_crud_roundtrip() {
        use daygle_dns_core::blocking::{BlockResponse, BlockingGroupInput};
        let s = store();
        let created = s
            .upsert_blocking_group(&BlockingGroupInput {
                id: None,
                name: "  Kids  ".to_string(),
                enabled: true,
                clients: vec!["192.168.1.0/24".to_string()],
                allow: vec!["school.test".to_string()],
                block: vec!["*.games.test".to_string()],
                allow_regex: vec![],
                block_regex: vec![r"^ad".to_string()],
                blocklists: vec![],
                response: BlockResponse::Redirect("0.0.0.0".parse().unwrap()),
            })
            .unwrap();
        assert_eq!(created.name, "Kids");
        assert_eq!(created.block, vec!["*.games.test".to_string()]);
        assert_eq!(
            created.response,
            BlockResponse::Redirect("0.0.0.0".parse().unwrap())
        );

        // Upsert by the same name updates in place (id and position preserved).
        let updated = s
            .upsert_blocking_group(&BlockingGroupInput {
                id: None,
                name: "Kids".to_string(),
                enabled: false,
                clients: vec![],
                allow: vec![],
                block: vec!["*.social.test".to_string()],
                allow_regex: vec![],
                block_regex: vec![],
                blocklists: vec![],
                response: BlockResponse::NxDomain,
            })
            .unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.position, created.position);
        assert!(!updated.enabled);
        assert_eq!(s.list_blocking_groups().unwrap().len(), 1);

        assert_eq!(
            s.get_blocking_group(&created.id).unwrap().unwrap().id,
            created.id
        );
        assert!(s.delete_blocking_group(&created.id).unwrap());
        assert!(s.list_blocking_groups().unwrap().is_empty());
        assert!(!s.delete_blocking_group(&created.id).unwrap());
    }

    #[test]
    fn blocking_groups_rename_by_id_and_reorder() {
        use daygle_dns_core::blocking::BlockingGroupInput;
        let s = store();
        let input = |id: Option<String>, name: &str| BlockingGroupInput {
            id,
            name: name.to_string(),
            enabled: true,
            clients: vec![],
            allow: vec![],
            block: vec![],
            allow_regex: vec![],
            block_regex: vec![],
            blocklists: vec![],
            response: Default::default(),
        };
        let a = s.upsert_blocking_group(&input(None, "A")).unwrap();
        let b = s.upsert_blocking_group(&input(None, "B")).unwrap();

        // Renaming by id updates the same group instead of adding one.
        let renamed = s
            .upsert_blocking_group(&input(Some(a.id.clone()), "Kids"))
            .unwrap();
        assert_eq!(renamed.id, a.id);
        let names: Vec<String> = s
            .list_blocking_groups()
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect();
        assert_eq!(names, vec!["Kids", "B"]);
        // ...but not onto another group's name, nor for a missing id.
        assert!(s
            .upsert_blocking_group(&input(Some(a.id.clone()), "B"))
            .is_err());
        assert!(s
            .upsert_blocking_group(&input(Some("nope".into()), "C"))
            .is_err());

        // Reorder: B moves above Kids; moving past the top is a no-op.
        assert!(s.move_blocking_group(&b.id, -1).unwrap());
        assert!(s.move_blocking_group(&b.id, -1).unwrap());
        let names: Vec<String> = s
            .list_blocking_groups()
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect();
        assert_eq!(names, vec!["B", "Kids"]);
        assert!(!s.move_blocking_group("nope", 1).unwrap());
    }

    #[test]
    fn console_user_last_login_starts_empty_and_persists_after_touch() {
        let s = store();
        let user = s
            .create_console_user("login-user", &console_admin("login-user"))
            .unwrap();
        assert_eq!(user.last_login_at, None);
        assert_eq!(
            s.get_console_user("login-user")
                .unwrap()
                .unwrap()
                .last_login_at,
            None
        );

        s.touch_console_user_login("login-user").unwrap();
        let logged_in = s.get_console_user("login-user").unwrap().unwrap();
        assert!(logged_in.last_login_at.is_some());
        assert_eq!(
            s.list_console_users().unwrap()[0].last_login_at,
            logged_in.last_login_at
        );
        assert!(s.touch_console_user_login("missing").is_err());
    }

    #[test]
    fn creates_and_lists_zones() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "Example.COM.".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        assert_eq!(zone.name, "example.com");
        assert!(!zone.last_modified_at.is_empty());
        assert_eq!(
            s.get_zone(&zone.id).unwrap().unwrap().last_modified_at,
            zone.last_modified_at
        );
        assert!(zone.enabled);
        assert_eq!(s.list_zones().unwrap().len(), 1);
        assert_eq!(s.count_zones().unwrap(), 1);
    }

    #[test]
    fn toggling_zone_enablement_updates_state_and_last_modified() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();

        assert!(s.set_zone_enabled(&zone.id, false).unwrap());
        let disabled = s.get_zone(&zone.id).unwrap().unwrap();
        assert!(!disabled.enabled);
        assert!(disabled.last_modified_at >= zone.last_modified_at);

        // Repeating the current state is a successful no-op, not a new edit.
        let unchanged_timestamp = disabled.last_modified_at.clone();
        assert!(s.set_zone_enabled(&zone.id, false).unwrap());
        assert_eq!(
            s.get_zone(&zone.id).unwrap().unwrap().last_modified_at,
            unchanged_timestamp
        );

        assert!(s.set_zone_enabled(&zone.id, true).unwrap());
        assert!(s.get_zone(&zone.id).unwrap().unwrap().enabled);
        assert!(!s.set_zone_enabled("missing", true).unwrap());
    }

    #[test]
    fn duplicate_zone_is_rejected() {
        let s = store();
        let input = ZoneInput {
            name: "example.com".to_string(),
            ..zone_input_defaults()
        };
        s.create_zone(&input).unwrap();
        assert!(matches!(
            s.create_zone(&input),
            Err(DaygleError::AlreadyExists(_))
        ));
    }

    #[test]
    fn deleting_a_zone_cascades_to_its_dependents() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        s.set_secondary(&zone.id, &["192.0.2.53".to_string()], 3600)
            .unwrap();
        assert!(s.count_records().unwrap() > 0, "zone creation adds records");

        assert!(s.delete_zone(&zone.id).unwrap());
        assert_eq!(
            s.count_records().unwrap(),
            0,
            "records must not be orphaned"
        );
        assert!(s.list_secondary().unwrap().is_empty());
    }

    #[test]
    fn count_console_users_tracks_accounts() {
        let s = store();
        assert_eq!(s.count_console_users().unwrap(), 0);
        s.create_console_user("alice", &console_admin("alice"))
            .unwrap();
        assert_eq!(s.count_console_users().unwrap(), 1);
    }

    #[test]
    fn upsert_and_delete_records() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();

        let record = s
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "www".to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.1".to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
        assert_eq!(record.name, "www.example.com");

        // Default NS record plus our A record.
        let records = s.list_records(&zone.id).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.rtype == "NS"));
        assert!(records.iter().any(|r| r.rtype == "A"));

        assert!(s.delete_record(&record.id).unwrap());
        assert_eq!(s.list_records(&zone.id).unwrap().len(), 1);
    }

    #[test]
    fn record_changes_bump_the_zone_serial() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                serial: Some(10),
                ..zone_input_defaults()
            })
            .unwrap();

        let record = s
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "www".to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.1".to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
        // Adding a record must advance the serial so secondaries notice.
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, 11);

        // Deleting a record advances it again, in the delete's own transaction.
        assert!(s.delete_record(&record.id).unwrap());
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, 12);

        // Deleting a non-existent record neither succeeds nor bumps the serial.
        assert!(!s.delete_record("does-not-exist").unwrap());
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, 12);
    }

    #[test]
    fn record_usage_updates_matching_enabled_rrsets_without_bumping_serial() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                serial: Some(10),
                ..zone_input_defaults()
            })
            .unwrap();
        let input = |name: &str, rtype: &str, content: &str, disabled| RecordInput {
            name: name.to_string(),
            rtype: rtype.to_string(),
            content: content.to_string(),
            ttl: 300,
            priority: 0,
            disabled,
        };
        let a = s
            .upsert_record(&zone.id, &input("www", "A", "192.0.2.1", false))
            .unwrap();
        let cname = s
            .upsert_record(
                &zone.id,
                &input("alias", "CNAME", "target.example.com.", false),
            )
            .unwrap();
        let disabled = s
            .upsert_record(&zone.id, &input("www", "AAAA", "2001:db8::1", true))
            .unwrap();
        let unrelated = s
            .upsert_record(&zone.id, &input("mail", "A", "192.0.2.2", false))
            .unwrap();
        let serial = s.get_zone(&zone.id).unwrap().unwrap().serial;

        assert_eq!(
            s.mark_records_used("WWW.example.com.", "a", "2026-10-20T12:34:56Z")
                .unwrap(),
            1
        );
        assert_eq!(
            s.get_record(&a.id)
                .unwrap()
                .unwrap()
                .last_used_at
                .as_deref(),
            Some("2026-10-20T12:34:56+00:00")
        );
        assert_eq!(
            s.mark_records_used("www.example.com", "A", "2026-10-20T12:34:59Z")
                .unwrap(),
            0,
            "same-minute queries do not rewrite the timestamp"
        );
        assert_eq!(s.get_record(&cname.id).unwrap().unwrap().last_used_at, None);
        assert_eq!(
            s.get_record(&disabled.id).unwrap().unwrap().last_used_at,
            None
        );
        assert_eq!(
            s.get_record(&unrelated.id).unwrap().unwrap().last_used_at,
            None
        );

        // CNAME queries match the CNAME, while ANY marks each enabled RRset
        // at that owner. Usage metadata never changes the DNS serial.
        assert_eq!(
            s.mark_records_used("alias.example.com", "TXT", "2026-10-20T12:35:30Z")
                .unwrap(),
            1
        );
        assert_eq!(
            s.get_record(&cname.id)
                .unwrap()
                .unwrap()
                .last_used_at
                .as_deref(),
            Some("2026-10-20T12:35:30+00:00")
        );
        assert_eq!(
            s.mark_records_used("www.example.com", "ANY", "2026-10-20T12:36:10Z")
                .unwrap(),
            1
        );
        assert_eq!(
            s.get_record(&a.id)
                .unwrap()
                .unwrap()
                .last_used_at
                .as_deref(),
            Some("2026-10-20T12:36:10+00:00")
        );
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, serial);
    }

    #[test]
    fn serial_bumps() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                serial: Some(41),
                ..zone_input_defaults()
            })
            .unwrap();
        assert_eq!(s.bump_serial(&zone.id).unwrap(), 42);
        assert_eq!(s.bump_serial(&zone.id).unwrap(), 43);
    }

    #[test]
    fn record_validation_rejects_bad_type() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        let err = s
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "www".to_string(),
                    rtype: "BOGUS".to_string(),
                    content: "x".to_string(),
                    ttl: 60,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap_err();
        assert!(matches!(err, DaygleError::InvalidRecord(_)));
    }

    #[test]
    fn extended_record_types_round_trip() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        let samples = [
            ("HTTPS", "1 . alpn=h2,h3"),
            ("SVCB", "1 svc.example.com. port=8443"),
            (
                "DS",
                "12345 13 2 3F2A6B1C9D8E7F60514233241506F7E8D9C0B1A2938475665748392A1B0C0D0E",
            ),
            (
                "TLSA",
                "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6",
            ),
            (
                "SSHFP",
                "4 2 9F6B2C1D0E3A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            ),
            (
                "NAPTR",
                "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com.",
            ),
        ];
        for (rtype, content) in samples {
            let record = s
                .upsert_record(
                    &zone.id,
                    &RecordInput {
                        name: "svc".to_string(),
                        rtype: rtype.to_string(),
                        content: content.to_string(),
                        ttl: 300,
                        priority: 0,
                        disabled: false,
                    },
                )
                .unwrap_or_else(|e| panic!("{rtype} '{content}' rejected: {e}"));
            assert_eq!(record.rtype, rtype);

            // Secondary zones store the transferred RDATA's display form, so
            // it must parse back to the same data.
            let rr_type = rtype.parse::<RecordType>().unwrap();
            let rdata = RData::try_from_str(rr_type, content).unwrap();
            let reparsed = RData::try_from_str(rr_type, &rdata.to_string())
                .unwrap_or_else(|e| panic!("{rtype} display form '{rdata}' does not reparse: {e}"));
            assert_eq!(rdata, reparsed, "{rtype} round trip");
        }
    }

    #[test]
    fn qualify_name_treats_the_bare_zone_name_as_the_apex() {
        assert_eq!(
            qualify_name("example.com", "example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            qualify_name("Example.COM", "example.com").unwrap(),
            "example.com"
        );
        assert_eq!(qualify_name("@", "example.com").unwrap(), "example.com");
        assert_eq!(
            qualify_name("www", "example.com").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            qualify_name("www.example.com", "example.com").unwrap(),
            "www.example.com"
        );
    }

    #[test]
    fn replace_record_updates_in_place() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        let input = |content: &str| RecordInput {
            name: "www".to_string(),
            rtype: "A".to_string(),
            content: content.to_string(),
            ttl: 300,
            priority: 0,
            disabled: false,
        };
        let original = s.upsert_record(&zone.id, &input("192.0.2.1")).unwrap();
        assert!(!original.last_modified_at.is_empty());
        assert_eq!(original.last_used_at, None);
        let last_used_at = "2026-10-20T12:00:00+00:00";
        assert_eq!(
            s.mark_records_used("www.example.com", "A", last_used_at)
                .unwrap(),
            1
        );
        s.set_record_disabled(&original.id, true).unwrap();
        let serial = s.get_zone(&zone.id).unwrap().unwrap().serial;

        let replaced = s
            .replace_record(&zone.id, &original.id, &input("192.0.2.2"))
            .unwrap()
            .expect("record exists");
        assert_eq!(replaced.id, original.id);
        assert!(replaced.disabled, "staged state is kept");
        assert!(replaced.last_modified_at >= original.last_modified_at);
        assert_eq!(replaced.last_used_at.as_deref(), Some(last_used_at));

        let a_records: Vec<_> = s
            .list_records(&zone.id)
            .unwrap()
            .into_iter()
            .filter(|r| r.rtype == "A")
            .collect();
        assert_eq!(a_records.len(), 1, "edit must not leave a duplicate");
        assert_eq!(a_records[0].content, "192.0.2.2");
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, serial + 1);

        // A rejected value leaves the original untouched.
        assert!(s
            .replace_record(&zone.id, &original.id, &input("not-an-ip"))
            .is_err());
        let after = s.list_records(&zone.id).unwrap();
        assert!(after
            .iter()
            .any(|r| r.id == original.id && r.content == "192.0.2.2"));

        // Unknown ids report None.
        assert!(s
            .replace_record(&zone.id, "missing", &input("192.0.2.3"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn record_validation_rejects_unparseable_content() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        for (rtype, content) in [
            ("A", "not-an-ip"),
            ("TLSA", "3 1 1 nothex"),
            ("DS", "12345"),
        ] {
            let err = s
                .upsert_record(
                    &zone.id,
                    &RecordInput {
                        name: "www".to_string(),
                        rtype: rtype.to_string(),
                        content: content.to_string(),
                        ttl: 60,
                        priority: 0,
                        disabled: false,
                    },
                )
                .unwrap_err();
            assert!(
                matches!(err, DaygleError::InvalidRecord(_)),
                "{rtype} '{content}' must be rejected"
            );
        }
    }

    #[test]
    fn applies_dynamic_updates_atomically() {
        use crate::model::{DeleteSpec, SoaUpdate};

        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        let serial_before = zone.serial;

        let mut plan = DynamicUpdate {
            adds: vec![RecordInput {
                name: "host.example.com.".to_string(),
                rtype: "A".to_string(),
                content: "192.0.2.55".to_string(),
                ttl: 120,
                priority: 0,
                disabled: false,
            }],
            deletes: vec![DeleteSpec {
                name: "www.example.com".to_string(),
                rtype: Some("TXT".to_string()),
                content: None,
            }],
            soa: None,
        };

        // Deleting a non-existent RRset is fine; the add lands and serial bumps.
        s.apply_dynamic_updates(&zone.id, &plan).unwrap();
        let records = s.list_records(&zone.id).unwrap();
        assert!(records.iter().any(|r| {
            r.name == "host.example.com" && r.rtype == "A" && r.content == "192.0.2.55"
        }));
        assert_eq!(
            s.get_zone(&zone.id).unwrap().unwrap().serial,
            serial_before + 1
        );

        // Deleting the RRset we just added works and bumps the serial again.
        plan.deletes = vec![DeleteSpec {
            name: "host.example.com".to_string(),
            rtype: Some("A".to_string()),
            content: None,
        }];
        plan.adds.clear();
        s.apply_dynamic_updates(&zone.id, &plan).unwrap();
        let records = s.list_records(&zone.id).unwrap();
        assert!(!records
            .iter()
            .any(|r| r.name == "host.example.com" && r.rtype == "A"));

        // An explicit SOA rewrite is applied and keeps its serial.
        let soa = SoaUpdate {
            primary_ns: "ns1.example.com.".to_string(),
            admin_mailbox: "admin.example.com.".to_string(),
            serial: 42,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        };
        s.apply_dynamic_updates(
            &zone.id,
            &DynamicUpdate {
                adds: vec![],
                deletes: vec![],
                soa: Some(soa),
            },
        )
        .unwrap();
        let zone = s.get_zone(&zone.id).unwrap().unwrap();
        assert_eq!(zone.serial, 42);
        assert_eq!(zone.primary_ns, "ns1.example.com.");
        assert_eq!(zone.minimum, 300);
    }

    #[test]
    fn dynamic_update_failure_rolls_back() {
        use crate::model::DeleteSpec;

        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();
        let serial_before = s.get_zone(&zone.id).unwrap().unwrap().serial;

        // A valid add followed by an invalid add must leave no trace.
        let plan = DynamicUpdate {
            adds: vec![
                RecordInput {
                    name: "ok.example.com.".to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.10".to_string(),
                    ttl: 60,
                    priority: 0,
                    disabled: false,
                },
                RecordInput {
                    name: "bad.example.com.".to_string(),
                    rtype: "BOGUS".to_string(),
                    content: "x".to_string(),
                    ttl: 60,
                    priority: 0,
                    disabled: false,
                },
            ],
            deletes: vec![],
            soa: None,
        };
        assert!(s.apply_dynamic_updates(&zone.id, &plan).is_err());

        let records = s.list_records(&zone.id).unwrap();
        assert!(!records.iter().any(|r| r.name == "ok.example.com"));
        assert_eq!(s.get_zone(&zone.id).unwrap().unwrap().serial, serial_before);
        let _ = DeleteSpec::default();
    }

    #[test]
    fn qualifies_relative_names() {
        assert_eq!(qualify_name("@", "example.com").unwrap(), "example.com");
        assert_eq!(
            qualify_name("www", "example.com").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            qualify_name("a.b.example.com.", "example.com").unwrap(),
            "a.b.example.com"
        );
        assert_eq!(
            qualify_name("WWW", "EXAMPLE.COM").unwrap(),
            "www.example.com"
        );
    }

    #[test]
    fn split_horizon_network_crud() {
        let s = store();
        let net = s
            .upsert_split_horizon_network(&SplitHorizonNetworkInput {
                name: "LAN".to_string(),
                cidrs: vec!["192.168.20.0/24".to_string(), "10.0.0.0/8".to_string()],
            })
            .unwrap();
        assert_eq!(net.name, "LAN");
        assert_eq!(net.cidrs.len(), 2);

        // Upsert by name updates the CIDRs but keeps the id stable.
        let updated = s
            .upsert_split_horizon_network(&SplitHorizonNetworkInput {
                name: "LAN".to_string(),
                cidrs: vec!["192.168.20.0/24".to_string()],
            })
            .unwrap();
        assert_eq!(updated.id, net.id);
        assert_eq!(updated.cidrs, vec!["192.168.20.0/24".to_string()]);

        // A malformed CIDR is rejected.
        assert!(matches!(
            s.upsert_split_horizon_network(&SplitHorizonNetworkInput {
                name: "Bad".to_string(),
                cidrs: vec!["not-a-cidr".to_string()],
            }),
            Err(DaygleError::InvalidRecord(_))
        ));

        assert!(s.delete_split_horizon_network("LAN").unwrap());
        assert!(!s.delete_split_horizon_network("LAN").unwrap());
        assert!(s.list_split_horizon_networks().unwrap().is_empty());
    }

    #[test]
    fn split_horizon_entry_crud() {
        let s = store();
        let a = s
            .create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "www.example.com.".to_string(),
                networks: vec!["LAN".to_string()],
                ips: vec!["10.0.0.5".to_string()],
                records: vec![],
                ttl: 30,
                disabled: false,
            })
            .unwrap();
        assert_eq!(a.domain, "www.example.com");
        assert_eq!(a.position, 0);

        let b = s
            .create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "www.example.com".to_string(),
                networks: vec![],
                ips: vec!["10.0.0.6".to_string(), "fd00::1".to_string()],
                records: vec![],
                ttl: 60,
                disabled: false,
            })
            .unwrap();
        assert_eq!(b.position, 1);

        // Update by id keeps position and rewrites the fields.
        let updated = s
            .update_split_horizon_entry(
                &a.id,
                &SplitHorizonEntryInput {
                    domain: "www.example.com".to_string(),
                    networks: vec!["VPN".to_string()],
                    ips: vec!["10.0.0.7".to_string()],
                    records: vec![],
                    ttl: 120,
                    disabled: true,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.position, 0);
        assert_eq!(updated.ips, vec!["10.0.0.7".to_string()]);
        assert!(updated.disabled);

        // A malformed IP is rejected; a missing id yields None.
        assert!(matches!(
            s.create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "x.example.com".to_string(),
                networks: vec![],
                ips: vec!["999.1.1.1".to_string()],
                records: vec![],
                ttl: 60,
                disabled: false,
            }),
            Err(DaygleError::InvalidRecord(_))
        ));
        assert!(s
            .update_split_horizon_entry(
                "missing",
                &SplitHorizonEntryInput {
                    domain: "x.example.com".to_string(),
                    networks: vec![],
                    ips: vec!["10.0.0.1".to_string()],
                    records: vec![],
                    ttl: 60,
                    disabled: false,
                },
            )
            .unwrap()
            .is_none());

        assert!(s.delete_split_horizon_entry(&a.id).unwrap());
        assert_eq!(s.list_split_horizon_entries().unwrap().len(), 1);
    }

    #[test]
    fn split_horizon_typed_records_are_canonicalized() {
        use crate::model::SplitHorizonRecord;

        let s = store();
        let entry = s
            .create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "mail.example.com".to_string(),
                networks: vec![],
                ips: vec![],
                records: vec![
                    SplitHorizonRecord {
                        rtype: "mx".to_string(),
                        content: "10 mailhost.example.com.".to_string(),
                    },
                    SplitHorizonRecord {
                        rtype: "TXT".to_string(),
                        content: "v=spf1 -all".to_string(), // auto-quoted below
                    },
                    SplitHorizonRecord {
                        rtype: "A".to_string(),
                        content: "10.0.0.5".to_string(),
                    },
                    SplitHorizonRecord {
                        rtype: "SRV".to_string(),
                        content: "0 5 5060 sip.example.com.".to_string(),
                    },
                    SplitHorizonRecord {
                        rtype: "CNAME".to_string(),
                        content: "target.example.com.".to_string(),
                    },
                ],
                ttl: 60,
                disabled: false,
            })
            .unwrap();

        // `ips` holds only the A/AAAA subset of the canonical records.
        assert_eq!(entry.ips, vec!["10.0.0.5".to_string()]);
        assert_eq!(entry.records.len(), 5);
        let mx = entry.records.iter().find(|r| r.rtype == "MX").unwrap();
        assert_eq!(mx.content, "10 mailhost.example.com.");
        let txt = entry.records.iter().find(|r| r.rtype == "TXT").unwrap();
        assert_eq!(txt.content, "\"v=spf1 -all\""); // auto-quoted

        // Relisted from the database: both stay in sync.
        let listed = s.list_split_horizon_entries().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].records, entry.records);
        assert_eq!(listed[0].ips, entry.ips);

        // Unsupported types and malformed content are rejected.
        assert!(matches!(
            s.create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "x.example.com".to_string(),
                networks: vec![],
                ips: vec![],
                records: vec![SplitHorizonRecord {
                    rtype: "BOGUS".to_string(),
                    content: "x".to_string(),
                }],
                ttl: 60,
                disabled: false,
            }),
            Err(DaygleError::InvalidRecord(_))
        ));
        assert!(matches!(
            s.create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "x.example.com".to_string(),
                networks: vec![],
                ips: vec![],
                records: vec![SplitHorizonRecord {
                    rtype: "A".to_string(),
                    content: "not-an-ip".to_string(),
                }],
                ttl: 60,
                disabled: false,
            }),
            Err(DaygleError::InvalidRecord(_))
        ));

        // An ips-only input still works and is converted to A/AAAA records.
        let legacy = s
            .create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: "legacy.example.com".to_string(),
                networks: vec![],
                ips: vec!["10.0.0.9".to_string()],
                records: vec![],
                ttl: 60,
                disabled: false,
            })
            .unwrap();
        assert_eq!(legacy.records.len(), 1);
        assert_eq!(legacy.records[0].rtype, "A");
        assert_eq!(legacy.records[0].content, "10.0.0.9");
    }

    #[test]
    fn split_horizon_entry_reorder_swaps_positions() {
        use crate::model::MoveDirection;
        use crate::store::MoveResult;

        let s = store();
        let mk = |ip: &str, domain: &str| {
            s.create_split_horizon_entry(&SplitHorizonEntryInput {
                domain: domain.to_string(),
                networks: vec![],
                ips: vec![ip.to_string()],
                records: vec![],
                ttl: 60,
                disabled: false,
            })
            .unwrap()
        };
        let a = mk("10.0.0.1", "a.example.com");
        let b = mk("10.0.0.2", "a.example.com");
        let c = mk("10.0.0.3", "a.example.com");
        let other = mk("10.0.0.9", "b.example.com");

        let pos = |id: &str| {
            s.list_split_horizon_entries()
                .unwrap()
                .into_iter()
                .find(|e| e.id == id)
                .unwrap()
                .position
        };
        assert_eq!(pos(&a.id), 0);
        assert_eq!(pos(&b.id), 1);
        assert_eq!(pos(&c.id), 2);
        assert_eq!(pos(&other.id), 0); // separate ordering per domain

        // Move the middle entry up: b,a,c.
        assert_eq!(
            s.move_split_horizon_entry(&b.id, MoveDirection::Up)
                .unwrap(),
            MoveResult::Moved
        );
        assert!(pos(&b.id) < pos(&a.id));
        assert!(pos(&a.id) < pos(&c.id));

        // The other domain is untouched.
        assert_eq!(pos(&other.id), 0);

        // Edges report AtBoundary without changing anything.
        assert_eq!(
            s.move_split_horizon_entry(&b.id, MoveDirection::Up)
                .unwrap(),
            MoveResult::AtBoundary
        );
        assert_eq!(
            s.move_split_horizon_entry(&c.id, MoveDirection::Down)
                .unwrap(),
            MoveResult::AtBoundary
        );
        assert_eq!(pos(&b.id), 0);
        assert_eq!(pos(&c.id), 2);

        // Move the last entry up: b,c,a.
        assert_eq!(
            s.move_split_horizon_entry(&c.id, MoveDirection::Up)
                .unwrap(),
            MoveResult::Moved
        );
        assert!(pos(&c.id) < pos(&a.id));

        // Unknown ids are reported as NotFound.
        assert_eq!(
            s.move_split_horizon_entry("nope", MoveDirection::Up)
                .unwrap(),
            MoveResult::NotFound
        );
    }

    #[test]
    fn signing_key_lifecycle_and_legacy_migration() {
        let s = store();
        let zone = s
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..zone_input_defaults()
            })
            .unwrap();

        // No keys yet.
        assert!(s.list_signing_keys(&zone.id).unwrap().is_empty());

        // Two keys can coexist (rollover double-signing state).
        let k1 = s.store_signing_key(&zone.id, 13, b"der-1").unwrap();
        let k2 = s
            .store_signing_key_created(
                &zone.id,
                13,
                b"der-2",
                Utc::now() - chrono::Duration::hours(48),
            )
            .unwrap();
        assert_ne!(k1, k2);

        let keys = s.list_signing_keys(&zone.id).unwrap();
        assert_eq!(keys.len(), 2);
        // Oldest first: the backdated key is returned first.
        assert_eq!(keys[0].id, k2);
        assert!(keys[0].is_active());

        // State transitions.
        assert!(s.set_key_state(&k2, "retired").unwrap());
        let keys = s.list_signing_keys(&zone.id).unwrap();
        assert!(keys.iter().find(|k| k.id == k2).unwrap().is_retired());

        // Timestamp rewrite (import/backfill).
        assert!(s
            .set_key_created_at(&k2, Utc::now() - chrono::Duration::hours(96))
            .unwrap());

        // Single-key deletion leaves the other key.
        assert!(s.delete_key(&k2).unwrap());
        let keys = s.list_signing_keys(&zone.id).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, k1);

        // Deleting every key for the zone ("unsign").
        assert!(s.delete_signing_key(&zone.id).unwrap());
        assert!(s.list_signing_keys(&zone.id).unwrap().is_empty());
    }

    #[test]
    fn legacy_single_key_schema_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("legacy.db");

        // Build a database with the pre-rollover schema: one key per zone,
        // keyed by zone_id, no id/state columns.
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE zones (
                     id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                     primary_ns TEXT NOT NULL, admin_mailbox TEXT NOT NULL,
                     serial INTEGER NOT NULL, refresh INTEGER NOT NULL,
                     retry INTEGER NOT NULL, expire INTEGER NOT NULL,
                     minimum INTEGER NOT NULL, created_at TEXT NOT NULL
                 );
                 CREATE TABLE dnssec_keys (
                     zone_id TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
                     algorithm INTEGER NOT NULL, key_der BLOB NOT NULL,
                     created_at TEXT NOT NULL
                 );
                 INSERT INTO zones VALUES ('z1', 'example.com', 'ns1.example.com.',
                     'admin.example.com.', 1, 3600, 600, 86400, 300, '2024-01-01T00:00:00Z');
                 INSERT INTO dnssec_keys VALUES ('z1', 13, x'de726572',
                     '2020-05-05T00:00:00+00:00');",
            )
            .unwrap();
        }

        // Opening through ZoneStore migrates in place.
        let s = ZoneStore::open(db.to_string_lossy().as_ref()).unwrap();
        let keys = s.list_signing_keys("z1").unwrap();
        assert_eq!(keys.len(), 1, "legacy key preserved");
        let key = &keys[0];
        assert_eq!(key.algorithm, 13);
        assert_eq!(key.key_der, b"\xde\x72\x65\x72");
        assert!(key.is_active(), "legacy key imported as active");
        // The original creation timestamp survives so rollover timing
        // continues from the key's real age.
        assert_eq!(key.created_at, "2020-05-05T00:00:00+00:00");
        assert!(key.id.len() == 32, "synthesized hex id");

        // The migrated store accepts new keys immediately.
        let _ = s.store_signing_key("z1", 13, b"der-new").unwrap();
        assert_eq!(s.list_signing_keys("z1").unwrap().len(), 2);
    }

    #[test]
    fn tls_certificate_crud_roundtrip() {
        let s = store();
        assert!(s.list_tls_certificates().unwrap().is_empty());
        assert!(s.get_tls_certificate("lan").unwrap().is_none());

        let cert = TlsCertificate {
            name: "lan".to_string(),
            server_name: "dns.home.test".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        };
        s.put_tls_certificate(&cert).unwrap();

        let got = s.get_tls_certificate("lan").unwrap().expect("stored");
        assert_eq!(got.cert_pem, cert.cert_pem);
        assert_eq!(got.server_name, "dns.home.test");
        assert_eq!(s.list_tls_certificates().unwrap().len(), 1);

        // Upsert by name replaces the material.
        let replacement = TlsCertificate {
            created_at: cert.created_at.clone(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----".to_string(),
            ..cert.clone()
        };
        s.put_tls_certificate(&replacement).unwrap();
        assert_eq!(
            s.get_tls_certificate("lan").unwrap().unwrap().cert_pem,
            replacement.cert_pem
        );
        assert_eq!(s.list_tls_certificates().unwrap().len(), 1);

        assert!(s.delete_tls_certificate("lan").unwrap());
        assert!(!s.delete_tls_certificate("lan").unwrap());
        assert!(s.list_tls_certificates().unwrap().is_empty());
    }

    fn zone_input_defaults() -> ZoneInput {
        ZoneInput {
            name: String::new(),
            primary_ns: None,
            admin_mailbox: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum: None,
        }
    }

    fn console_admin(_name: &str) -> ConsoleUserInput {
        ConsoleUserInput {
            password_hash: "not-a-real-hash".to_string(),
            role: Role::Admin,
            enabled: true,
            first_name: String::new(),
            last_name: String::new(),
            email: String::new(),
        }
    }

    fn console_viewer(_name: &str) -> ConsoleUserInput {
        ConsoleUserInput {
            role: Role::Viewer,
            enabled: true,
            first_name: String::new(),
            last_name: String::new(),
            email: String::new(),
            password_hash: "not-a-real-hash".to_string(),
        }
    }

    /// The last-enabled-admin store methods used to self-deadlock: they called
    /// `count_enabled_admins()` while already holding the connection mutex.
    /// Run each on a helper thread and fail instead of hanging if it regresses.
    #[test]
    fn admin_writes_do_not_deadlock_on_the_lock() {
        let s = store();
        s.create_console_user("admin", &console_admin("admin"))
            .unwrap();
        s.create_console_user("root2", &console_admin("root2"))
            .unwrap();
        s.create_console_user("auditor", &console_viewer("auditor"))
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            let _ = tx.send(("delete", s2.delete_console_user("root2")));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(("delete", Ok(true))) => {}
            Ok(("delete", Err(e))) => panic!("delete failed: {e:?}"),
            Ok(_) => panic!("unexpected result"),
            Err(_) => panic!("delete_console_user deadlocked"),
        }
        assert!(s.count_enabled_admins().unwrap() == 1);

        // With only one enabled admin left, disabling it is refused (the
        // guard must return an error, not deadlock).
        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            let _ = tx.send(("disable", s2.set_console_user_enabled("admin", false)));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(("disable", Err(_))) => {}
            Ok(("disable", Ok(()))) => panic!("last enabled admin unexpectedly disabled"),
            Ok(_) => panic!("unexpected result"),
            Err(_) => panic!("set_console_user_enabled deadlocked"),
        }
        assert!(s.count_enabled_admins().unwrap() == 1);
    }

    #[test]
    fn last_enabled_admin_table_ops_are_rejected_without_deadlock() {
        let s = store();
        s.create_console_user("admin", &console_admin("admin"))
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            let _ = tx.send(("delete", s2.delete_console_user("admin")));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(("delete", Err(_))) => {}
            Ok(("delete", Ok(_))) => panic!("last admin unexpectedly deleted"),
            Ok(_) => panic!("unexpected result"),
            Err(_) => panic!("delete_console_user deadlocked"),
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            let _ = tx.send(("demote", s2.set_console_user_role("admin", Role::Viewer)));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(("demote", Err(_))) => {}
            Ok(("demote", Ok(()))) => panic!("last admin unexpectedly demoted"),
            Ok(_) => panic!("unexpected result"),
            Err(_) => panic!("set_console_user_role deadlocked"),
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let s2 = s.clone();
        std::thread::spawn(move || {
            let _ = tx.send(("disable", s2.set_console_user_enabled("admin", false)));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(("disable", Err(_))) => {}
            Ok(("disable", Ok(()))) => panic!("last admin unexpectedly disabled"),
            Ok(_) => panic!("unexpected result"),
            Err(_) => panic!("set_console_user_enabled deadlocked"),
        }

        // A viewer can still be removed freely, and an admin stays enabled.
        s.create_console_user("auditor", &console_viewer("auditor"))
            .unwrap();
        assert!(s.clone().delete_console_user("auditor").unwrap());
    }
}
