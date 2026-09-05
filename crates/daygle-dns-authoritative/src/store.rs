//! SQLite-backed zone and record storage.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{Utc};
use serde::{Deserialize, Serialize};
use hickory_proto::rr::{RData, RecordType};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::model::{
    DynamicUpdate, MoveDirection, Record, RecordInput, SigningKeyRecord, SplitHorizonEntry,
    SplitHorizonEntryInput, SplitHorizonNetwork, SplitHorizonNetworkInput,
    SplitHorizonRecord, Zone, ZoneInput,
};
use crate::validate_name;
use daygle_dns_core::blocking::{BlockingGroup, BlockingGroupInput};
use daygle_dns_core::config::Role;
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
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id       TEXT PRIMARY KEY,
    zone_id  TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    rtype    TEXT NOT NULL,
    content  TEXT NOT NULL,
    ttl      INTEGER NOT NULL DEFAULT 3600,
    priority INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0
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
    position INTEGER NOT NULL DEFAULT 0
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
    created_at    TEXT NOT NULL
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
            Connection::open(path)?
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
        self.conn.lock().map_err(|e| DaygleError::Internal(format!("database lock poisoned: {e}")))
    }

    fn init(&self) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute_batch(SCHEMA)?;
        migrate_split_horizon_records(&conn)?;
        migrate_dnssec_keys(&conn)?;
        migrate_console_user_profile(&conn)?;
        Ok(())
    }

    // ---- Zones -----------------------------------------------------------

    /// List all zones ordered by name.
    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at
             FROM zones ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_zone)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_zone(&self, id: &str) -> Result<Option<Zone>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at
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
                    retry, expire, minimum, created_at
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
            created_at: Utc::now().to_rfc3339(),
        };

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO zones (id, name, primary_ns, admin_mailbox, serial,
                                refresh, retry, expire, minimum, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
        tx.commit()?;

        Ok(zone)
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
                             refresh = ?5, retry = ?6, expire = ?7, minimum = ?8
             WHERE id = ?1",
            params![id, primary_ns, admin_mailbox, serial, refresh, retry, expire, minimum],
        )?;
        if changed == 0 {
            return Err(DaygleError::NotFound(format!("zone {id}")));
        }
        Ok(())
    }

    // ---- Secondary zones --------------------------------------------------

    /// Mark a zone as secondary, replacing its master list and refresh interval.
    pub fn set_secondary(&self, zone_id: &str, masters: &[String], refresh_secs: u64) -> Result<()> {
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
    pub fn set_stub(&self, name: &str, nss: &[String], refresh_secs: u64, enabled: bool) -> Result<()> {
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
                    response, position
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
                        response, position
                 FROM blocking_groups WHERE id = ?1",
                [id],
                row_to_blocking_group,
            )
            .optional()?;
        Ok(group)
    }

    /// Create a blocking group, or update the one with the same name in place
    /// (its id and position are preserved on update).
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
        let response = serde_json::to_string(&input.response)
            .map_err(|e| DaygleError::Database(format!("encode response: {e}")))?;
        let id = Uuid::new_v4().to_string();
        let conn = self.lock_conn()?;
        // New rows land after every existing group; updates keep their spot.
        conn.execute(
            "INSERT INTO blocking_groups
                (id, name, enabled, clients, allow, block, allow_regex, block_regex,
                 response, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                 (SELECT COALESCE(MAX(position), -1) + 1 FROM blocking_groups))
             ON CONFLICT(name) DO UPDATE SET
                enabled = ?3, clients = ?4, allow = ?5, block = ?6,
                allow_regex = ?7, block_regex = ?8, response = ?9",
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
            ],
        )?;
        drop(conn);
        self.list_blocking_groups()?
            .into_iter()
            .find(|g| g.name == name)
            .ok_or_else(|| DaygleError::Internal("blocking group vanished after upsert".to_string()))
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
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records WHERE zone_id = ?1 ORDER BY name, rtype",
        )?;
        let rows = stmt.query_map([zone_id], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All records across all zones (used to rebuild the in-memory catalog).
    pub fn list_all_records(&self) -> Result<Vec<Record>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records ORDER BY zone_id, name, rtype",
        )?;
        let rows = stmt.query_map([], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_record(&self, id: &str) -> Result<Option<Record>> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records WHERE id = ?1",
            [id],
            row_to_record,
        )
        .optional()
        .map_err(Into::into)
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
        let zone_id: Option<String> = tx
            .query_row("SELECT zone_id FROM records WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(zone_id) = zone_id else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE records SET disabled = ?2 WHERE id = ?1",
            params![id, disabled as i64],
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
    /// so callers no longer need a separate [`Self::bump_serial`].
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

    /// Apply a batch of RFC 2136 dynamic-update changes to a zone atomically.
    ///
    /// All additions, deletions, and the optional SOA rewrite happen in one
    /// transaction: either every change lands or none do. When no explicit
    /// SOA is supplied, the zone serial is bumped (RFC 2136 §3.4.2.2 requires
    /// the serial to increase on any successful update).
    pub fn apply_dynamic_updates(
        &self,
        zone_id: &str,
        update: &DynamicUpdate,
    ) -> Result<()> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;

        for del in &update.deletes {
            let name = normalize_fqdn(&del.name);
            let mut sql =
                "DELETE FROM records WHERE zone_id = ?1 AND name = ?2".to_string();
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
            stmt.execute(rusqlite::params_from_iter(values.iter().map(|v| v.as_ref())))?;
        }

        for add in &update.adds {
            insert_record_in_tx(&tx, zone_id, &zone.name, add)?;
        }

        match &update.soa {
            Some(soa) => {
                let changed = tx.execute(
                    "UPDATE zones SET primary_ns = ?2, admin_mailbox = ?3, serial = ?4,
                                     refresh = ?5, retry = ?6, expire = ?7, minimum = ?8
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
                    ],
                )?;
                if changed == 0 {
                    return Err(DaygleError::NotFound(format!("zone {zone_id}")));
                }
            }
            None => {
                let next = zone.serial.wrapping_add(1).max(1);
                tx.execute(
                    "UPDATE zones SET serial = ?2 WHERE id = ?1",
                    params![zone_id, next],
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
        tx.commit()?;
        Ok(())
    }

    pub fn count_zones(&self) -> Result<u64> {
        let conn = self.lock_conn()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM zones", [], |r| Ok(r.get::<_, i64>(0)? as u64))?)
    }

    pub fn count_records(&self) -> Result<u64> {
        let conn = self.lock_conn()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM records", [], |r| Ok(r.get::<_, i64>(0)? as u64))?)
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
        let changed = conn.execute(
            "DELETE FROM split_horizon_networks WHERE name = ?1",
            [name],
        )?;
        Ok(changed > 0)
    }

    /// List all split-horizon entries ordered by domain then position.
    pub fn list_split_horizon_entries(&self) -> Result<Vec<SplitHorizonEntry>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, networks, ips, records, ttl, disabled, position
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
        let next_position: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM split_horizon_entries
                 WHERE domain = ?1",
                [&domain],
                |r| r.get(0),
            )?;
        let entry = SplitHorizonEntry {
            id: Uuid::new_v4().to_string(),
            domain,
            networks: input.networks.clone(),
            ips,
            records,
            ttl: input.ttl,
            disabled: input.disabled,
            position: next_position,
        };
        conn.execute(
            "INSERT INTO split_horizon_entries
                (id, domain, networks, ips, records, ttl, disabled, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.id,
                entry.domain,
                networks,
                ips_json,
                records_json,
                entry.ttl as i64,
                entry.disabled as i64,
                entry.position,
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
             SET domain = ?2, networks = ?3, ips = ?4, records = ?5, ttl = ?6, disabled = ?7
             WHERE id = ?1",
            params![
                id,
                domain,
                networks,
                ips_json,
                records_json,
                input.ttl as i64,
                input.disabled as i64,
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
    pub fn store_tsig_key(
        &self,
        name: &str,
        algorithm: &str,
        secret_b64: &str,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO tsig_keys (name, algorithm, secret, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET algorithm = ?2, secret = ?3",
            params![
                name,
                algorithm,
                secret_b64,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Delete a TSIG key.
    pub fn delete_tsig_key(&self, name: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let changed = conn.execute("DELETE FROM tsig_keys WHERE name = ?1", [name])?;
        Ok(changed > 0)
    }

    // ---- DNSSEC signing keys --------------------------------------------

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
            params![id, zone_id, algorithm as i64, key_der, created_at.to_rfc3339()],
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
    serde_json::to_string(value)
        .map_err(|e| DaygleError::Database(format!("encode {field}: {e}")))
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
        response,
        position: row.get(9)?,
    })
}

/// Increment a zone's SOA serial by one (wrapping, never landing on 0).
/// Works against either a plain [`Connection`] or a transaction (which derefs
/// to `Connection`), so the bump can share the caller's transaction.
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

// ---- Console users (login accounts) ------------------------------------

impl ZoneStore {
    /// List every console account ordered by username.
    pub fn list_console_users(&self) -> Result<Vec<ConsoleUser>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT username, password_hash, role, enabled, first_name, last_name, email, created_at
             FROM console_users ORDER BY username",
        )?;
        let rows = stmt.query_map([], row_to_console_user)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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
            "SELECT username, password_hash, role, enabled, first_name, last_name, email, created_at
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
    pub fn set_console_user_role(&self, username: &str, role: Role) -> Result<()> {
        let conn = self.lock_conn()?;
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
    pub fn set_console_user_enabled(&self, username: &str, enabled: bool) -> Result<()> {
        let conn = self.lock_conn()?;
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
    pub fn delete_console_user(&self, username: &str) -> Result<bool> {
        let conn = self.lock_conn()?;
        let n = conn.execute("DELETE FROM console_users WHERE username = ?1", [username])?;
        Ok(n > 0)
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
            Some(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| {
                    DaygleError::Config(format!("stored runtime settings are invalid: {e}"))
                }),
        }
    }

    /// Persist the DB-backed runtime settings, replacing any previous value.
    pub fn put_runtime_settings<T: serde::Serialize>(&self, settings: &T) -> Result<()> {
        let text =
            serde_json::to_string(settings)
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
    /// Rows per page (default 50, max 500).
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

    /// Search the query log with filters and pagination. Returns the page of
    /// rows (newest first) plus the total count under the same filter.
    pub fn search_query_logs(&self, filter: &QueryLogFilter) -> Result<(Vec<QueryLogRow>, u64)> {
        let mut wheres: Vec<String> = vec![];
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];
        if let Some(client) = filter.client.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            params_vec.push(Box::new(client.to_string()));
            wheres.push(format!("client = ?{}", params_vec.len()));
        }
        if let Some(qname) = filter.qname.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
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
        if let Some(from) = filter.from.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            params_vec.push(Box::new(from.to_string()));
            wheres.push(format!("ts >= ?{}", params_vec.len()));
        }
        if let Some(to) = filter.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            params_vec.push(Box::new(to.to_string()));
            wheres.push(format!("ts <= ?{}", params_vec.len()));
        }
        let where_clause = if wheres.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", wheres.join(" AND "))
        };

        let per_page = filter.per_page.unwrap_or(50).clamp(1, 500);
        let page = filter.page.unwrap_or(1).max(1);
        let offset = (page - 1).saturating_mul(per_page);

        let params_ref: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
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
        "UPDATE zones SET serial = ?2 WHERE id = ?1",
        params![zone_id, next],
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

    let record = Record {
        id: Uuid::new_v4().to_string(),
        zone_id: zone_id.to_string(),
        name,
        rtype,
        content: input.content.trim().to_string(),
        ttl: input.ttl,
        priority: input.priority,
        disabled: input.disabled,
    };
    tx.execute(
        "INSERT INTO records (id, zone_id, name, rtype, content, ttl, priority, disabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            record.id,
            record.zone_id,
            record.name,
            record.rtype,
            record.content,
            record.ttl,
            record.priority,
            record.disabled as i64,
        ],
    )?;
    Ok(record)
}

/// Resolve `@`, bare relative names, and trailing dots against the zone name.
pub fn qualify_name(owner: &str, zone_name: &str) -> Result<String> {
    let owner = owner.trim();
    let zone = zone_name.trim().trim_end_matches('.');
    let resolved = if owner == "@" || owner.is_empty() {
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
    name.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
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
        cidr.parse::<ipnet::IpNet>().map_err(|e| {
            DaygleError::InvalidRecord(format!("split-horizon CIDR '{cidr}': {e}"))
        })?;
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

/// Build the canonical `(ips, records)` pair for an entry input. `records` is
/// authoritative when provided; otherwise `ips` is converted to A/AAAA
/// records. Every record is validated: the type must be supported and the
/// content must parse as that type's RDATA in zone-file presentation format
/// (TXT values are auto-quoted). The returned `ips` is always the A/AAAA
/// subset of the canonical records.
/// Maximum number of records allowed in a single split-horizon entry.
/// Prevents unbounded memory allocation from adversarial input.
const MAX_SPLIT_HORIZON_RECORDS: usize = 1024;

fn canonicalize_split_horizon_records(
    input: &SplitHorizonEntryInput,
) -> Result<(Vec<String>, Vec<SplitHorizonRecord>)> {
    let records = if input.records.is_empty() {
        // The legacy `ips` path: every address must parse - reject junk
        // instead of silently dropping it.
        for ip in &input.ips {
            ip.parse::<std::net::IpAddr>().map_err(|e| {
                DaygleError::InvalidRecord(format!("split-horizon IP '{ip}': {e}"))
            })?;
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

    let mut canonical = Vec::with_capacity(records.len());
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

/// Add the personal profile columns (`first_name`, `last_name`, `email`) to
/// `console_users` for databases created before user profiles existed.
fn migrate_console_user_profile(conn: &Connection) -> Result<()> {
    for (column, default) in [
        ("first_name", "''"),
        ("last_name", "''"),
        ("email", "''"),
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
                &format!("ALTER TABLE console_users ADD COLUMN {column} TEXT NOT NULL DEFAULT {default}"),
                [],
            )?;
        }
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
    fn blocking_group_crud_roundtrip() {
        use daygle_dns_core::blocking::{BlockResponse, BlockingGroupInput};
        let s = store();
        let created = s
            .upsert_blocking_group(&BlockingGroupInput {
                name: "  Kids  ".to_string(),
                enabled: true,
                clients: vec!["192.168.1.0/24".to_string()],
                allow: vec!["school.test".to_string()],
                block: vec!["*.games.test".to_string()],
                allow_regex: vec![],
                block_regex: vec![r"^ad".to_string()],
                response: BlockResponse::Redirect("0.0.0.0".parse().unwrap()),
            })
            .unwrap();
        assert_eq!(created.name, "Kids");
        assert_eq!(created.block, vec!["*.games.test".to_string()]);
        assert_eq!(created.response, BlockResponse::Redirect("0.0.0.0".parse().unwrap()));

        // Upsert by the same name updates in place (id and position preserved).
        let updated = s
            .upsert_blocking_group(&BlockingGroupInput {
                name: "Kids".to_string(),
                enabled: false,
                clients: vec![],
                allow: vec![],
                block: vec!["*.social.test".to_string()],
                allow_regex: vec![],
                block_regex: vec![],
                response: BlockResponse::NxDomain,
            })
            .unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.position, created.position);
        assert!(!updated.enabled);
        assert_eq!(s.list_blocking_groups().unwrap().len(), 1);

        assert_eq!(s.get_blocking_group(&created.id).unwrap().unwrap().id, created.id);
        assert!(s.delete_blocking_group(&created.id).unwrap());
        assert!(s.list_blocking_groups().unwrap().is_empty());
        assert!(!s.delete_blocking_group(&created.id).unwrap());
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
        assert_eq!(s.list_zones().unwrap().len(), 1);
        assert_eq!(s.count_zones().unwrap(), 1);
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
        assert_eq!(
            s.get_zone(&zone.id).unwrap().unwrap().serial,
            serial_before
        );
        let _ = DeleteSpec::default();
    }

    #[test]
    fn qualifies_relative_names() {
        assert_eq!(qualify_name("@", "example.com").unwrap(), "example.com");
        assert_eq!(qualify_name("www", "example.com").unwrap(), "www.example.com");
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
            s.move_split_horizon_entry(&b.id, MoveDirection::Up).unwrap(),
            MoveResult::Moved
        );
        assert!(pos(&b.id) < pos(&a.id));
        assert!(pos(&a.id) < pos(&c.id));

        // The other domain is untouched.
        assert_eq!(pos(&other.id), 0);

        // Edges report AtBoundary without changing anything.
        assert_eq!(
            s.move_split_horizon_entry(&b.id, MoveDirection::Up).unwrap(),
            MoveResult::AtBoundary
        );
        assert_eq!(
            s.move_split_horizon_entry(&c.id, MoveDirection::Down).unwrap(),
            MoveResult::AtBoundary
        );
        assert_eq!(pos(&b.id), 0);
        assert_eq!(pos(&c.id), 2);

        // Move the last entry up: b,c,a.
        assert_eq!(
            s.move_split_horizon_entry(&c.id, MoveDirection::Up).unwrap(),
            MoveResult::Moved
        );
        assert!(pos(&c.id) < pos(&a.id));

        // Unknown ids are reported as NotFound.
        assert_eq!(
            s.move_split_horizon_entry("nope", MoveDirection::Up).unwrap(),
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
}
