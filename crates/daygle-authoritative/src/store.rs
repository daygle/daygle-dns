//! SQLite-backed zone and record storage.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::model::{Record, RecordInput, Zone, ZoneInput};
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
        Ok(conn.query_row("SELECT COUNT(*) FROM zones", [], |r| r.get(0))?)
    }

    pub fn count_records(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))?)
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
