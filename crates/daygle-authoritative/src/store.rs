//! SQLite-backed zone and record storage.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::model::{
    DynamicUpdate, Record, RecordInput, SplitHorizonEntry, SplitHorizonEntryInput,
    SplitHorizonNetwork, SplitHorizonNetworkInput, Zone, ZoneInput,
};
use crate::validate_name;
use daygle_core::error::{DaygleError, Result};

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
    zone_id    TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    algorithm  INTEGER NOT NULL,
    key_der    BLOB NOT NULL,
    created_at TEXT NOT NULL
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
    ttl      INTEGER NOT NULL DEFAULT 60,
    disabled INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_split_horizon_domain ON split_horizon_entries(domain);
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

    fn init(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    // ---- Zones -----------------------------------------------------------

    /// List all zones ordered by name.
    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, primary_ns, admin_mailbox, serial, refresh,
                    retry, expire, minimum, created_at
             FROM zones ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_zone)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_zone(&self, id: &str) -> Result<Option<Zone>> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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

        let mut conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM zones WHERE id = ?1", [id])?;
        Ok(changed > 0)
    }

    /// Update the SOA serial (and refresh/retry timers if provided).
    pub fn bump_serial(&self, id: &str) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let current: u32 =
            conn.query_row("SELECT serial FROM zones WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {id}")))?;
        let next = current.wrapping_add(1).max(1);
        conn.execute("UPDATE zones SET serial = ?2 WHERE id = ?1", params![id, next])?;
        Ok(next)
    }

    /// Replace the SOA metadata (mname, rname, serial, and timers) of a zone
    /// with values learned from a zone transfer.
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE secondary_zones SET last_transfer = ?2 WHERE zone_id = ?1",
            params![zone_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Remove secondary metadata (the zone itself is kept).
    pub fn unset_secondary(&self, zone_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM secondary_zones WHERE zone_id = ?1", [zone_id])?;
        Ok(())
    }

    // ---- Records ---------------------------------------------------------

    /// List records for a zone.
    pub fn list_records(&self, zone_id: &str) -> Result<Vec<Record>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records WHERE zone_id = ?1 ORDER BY name, rtype",
        )?;
        let rows = stmt.query_map([zone_id], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All records across all zones (used to rebuild the in-memory catalog).
    pub fn list_all_records(&self) -> Result<Vec<Record>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records ORDER BY zone_id, name, rtype",
        )?;
        let rows = stmt.query_map([], row_to_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_record(&self, id: &str) -> Result<Option<Record>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, zone_id, name, rtype, content, ttl, priority, disabled
             FROM records WHERE id = ?1",
            [id],
            row_to_record,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Insert or update a record, returning the stored record.
    pub fn upsert_record(&self, zone_id: &str, input: &RecordInput) -> Result<Record> {
        let zone = self
            .get_zone(zone_id)?
            .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let record = insert_record_in_tx(&tx, zone_id, &zone.name, input)?;
        tx.commit()?;
        Ok(record)
    }

    pub fn delete_record(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM records WHERE id = ?1", [id])?;
        Ok(changed > 0)
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
        let mut conn = self.conn.lock().unwrap();
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM records WHERE zone_id = ?1", [zone_id])?;
        for record in records {
            insert_record_in_tx(&tx, zone_id, &zone.name, record)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn count_zones(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM zones", [], |r| Ok(r.get::<_, i64>(0)? as u64))?)
    }

    pub fn count_records(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM records", [], |r| Ok(r.get::<_, i64>(0)? as u64))?)
    }

    // ---- Split horizon ---------------------------------------------------

    /// List all split-horizon networks ordered by name.
    pub fn list_split_horizon_networks(&self) -> Result<Vec<SplitHorizonNetwork>> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "DELETE FROM split_horizon_networks WHERE name = ?1",
            [name],
        )?;
        Ok(changed > 0)
    }

    /// List all split-horizon entries ordered by domain then position.
    pub fn list_split_horizon_entries(&self) -> Result<Vec<SplitHorizonEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, domain, networks, ips, ttl, disabled, position
             FROM split_horizon_entries ORDER BY domain, position",
        )?;
        let rows = stmt.query_map([], |row| {
            let networks: Vec<String> =
                serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default();
            let ips: Vec<String> =
                serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default();
            Ok(SplitHorizonEntry {
                id: row.get(0)?,
                domain: row.get(1)?,
                networks,
                ips,
                ttl: row.get(4)?,
                disabled: row.get::<_, i64>(5)? != 0,
                position: row.get(6)?,
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
        let networks = serde_json::to_string(&input.networks)
            .map_err(|e| DaygleError::Database(format!("encode networks: {e}")))?;
        let ips = serde_json::to_string(&input.ips)
            .map_err(|e| DaygleError::Database(format!("encode ips: {e}")))?;

        let conn = self.conn.lock().unwrap();
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
            ips: input.ips.clone(),
            ttl: input.ttl,
            disabled: input.disabled,
            position: next_position,
        };
        conn.execute(
            "INSERT INTO split_horizon_entries
                (id, domain, networks, ips, ttl, disabled, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.id,
                entry.domain,
                networks,
                ips,
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
        let networks = serde_json::to_string(&input.networks)
            .map_err(|e| DaygleError::Database(format!("encode networks: {e}")))?;
        let ips = serde_json::to_string(&input.ips)
            .map_err(|e| DaygleError::Database(format!("encode ips: {e}")))?;
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE split_horizon_entries
             SET domain = ?2, networks = ?3, ips = ?4, ttl = ?5, disabled = ?6
             WHERE id = ?1",
            params![
                id,
                domain,
                networks,
                ips,
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
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM split_horizon_entries WHERE id = ?1", [id])?;
        Ok(changed > 0)
    }

    // ---- DNSSEC signing keys --------------------------------------------

    /// A stored signing key: `(algorithm, pkcs8_der_bytes)`.
    pub fn get_signing_key(&self, zone_id: &str) -> Result<Option<(u8, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT algorithm, key_der FROM dnssec_keys WHERE zone_id = ?1",
            [zone_id],
            |row| Ok((row.get::<_, i64>(0)? as u8, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn store_signing_key(
        &self,
        zone_id: &str,
        algorithm: u8,
        key_der: &[u8],
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO dnssec_keys (zone_id, algorithm, key_der, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(zone_id) DO UPDATE SET algorithm = ?2, key_der = ?3",
            params![zone_id, algorithm as i64, key_der, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn delete_signing_key(&self, zone_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM dnssec_keys WHERE zone_id = ?1", [zone_id])?;
        Ok(changed > 0)
    }

    /// All zones paired with their records and optional signing key, for the
    /// catalog builder.
    pub fn load_catalog_data(&self) -> Result<Vec<(Zone, Vec<Record>, Option<(u8, Vec<u8>)>)>> {
        let zones = self.list_zones()?;
        let records = self.list_all_records()?;
        let mut out = Vec::with_capacity(zones.len());
        for zone in zones {
            let recs = records
                .iter()
                .filter(|r| r.zone_id == zone.id)
                .cloned()
                .collect::<Vec<_>>();
            let key = self.get_signing_key(&zone.id)?;
            out.push((zone, recs, key));
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
/// normalized (lowercase, no trailing dot); every IP must parse.
fn validate_split_horizon_entry(domain: &str, input: &SplitHorizonEntryInput) -> Result<()> {
    validate_name(domain, false)?;
    for ip in &input.ips {
        ip.parse::<std::net::IpAddr>().map_err(|e| {
            DaygleError::InvalidRecord(format!("split-horizon IP '{ip}': {e}"))
        })?;
    }
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
                    ttl: 60,
                    disabled: false,
                },
            )
            .unwrap()
            .is_none());

        assert!(s.delete_split_horizon_entry(&a.id).unwrap());
        assert_eq!(s.list_split_horizon_entries().unwrap().len(), 1);
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
