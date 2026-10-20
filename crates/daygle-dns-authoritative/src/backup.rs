//! Backup and restore of the server's database.
//!
//! A backup is a single SQLite file: a consistent copy of the main database
//! (zones, records, DNSSEC keys, settings, console users, certificates,
//! blocking groups, split horizon, ...) made with `VACUUM INTO`, plus the
//! AI scanner's operator overrides (from `ai.db`; its verdicts are a cache
//! and are not kept) and a `backup_info` row describing it. Query logs are
//! left out unless asked for.
//!
//! Restoring never swaps the database under a running server. The backup is
//! checked and staged next to the database as `<database>.restore`, and the
//! next start moves the current database aside (as
//! `<database>.before-restore-<time>`) and opens the backup in its place.

use std::path::{Path, PathBuf};

use daygle_dns_core::error::{DaygleError, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

use crate::store::ZoneStore;

/// Version of the backup layout (the `backup_info.format` column).
const FORMAT: i64 = 1;

/// Tables a file must have to be a Daygle DNS backup.
const REQUIRED_TABLES: &[&str] = &[
    "backup_info",
    "zones",
    "records",
    "console_users",
    "runtime_settings",
];

/// What a backup holds, for the console and before a restore.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BackupInfo {
    /// Unix time the backup was made.
    pub created_at: i64,
    /// Version of the server that made it.
    pub app_version: String,
    pub zones: i64,
    pub records: i64,
    pub users: i64,
    pub certificates: i64,
    pub query_logs: i64,
    pub ai_overrides: i64,
}

/// Where a restore is staged for `database`.
pub fn pending_restore_path(database: &str) -> PathBuf {
    PathBuf::from(format!("{database}.restore"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn db_err(context: &str, e: impl std::fmt::Display) -> DaygleError {
    DaygleError::Database(format!("{context}: {e}"))
}

impl ZoneStore {
    /// Write a backup to `dest` (which must not exist). `ai_database` is the
    /// AI scanner's database, whose operator overrides are included when the
    /// file exists.
    pub fn backup_to(
        &self,
        dest: &Path,
        include_query_logs: bool,
        ai_database: Option<&Path>,
    ) -> Result<BackupInfo> {
        let dest_text = dest
            .to_str()
            .ok_or_else(|| DaygleError::Config("backup path is not valid UTF-8".into()))?;
        // A consistent copy, taken under the store's lock.
        self.with_conn(|conn| {
            conn.execute("VACUUM INTO ?1", params![dest_text])
                .map_err(|e| db_err("cannot copy the database", e))?;
            Ok(())
        })?;
        let result = finish_backup(dest, include_query_logs, ai_database);
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }
}

fn finish_backup(
    dest: &Path,
    include_query_logs: bool,
    ai_database: Option<&Path>,
) -> Result<BackupInfo> {
    restrict(dest);
    let conn = Connection::open(dest).map_err(|e| db_err("cannot open the backup", e))?;
    if !include_query_logs {
        conn.execute("DELETE FROM query_logs", [])
            .map_err(|e| db_err("cannot leave out query logs", e))?;
    }
    conn.execute_batch(
        "CREATE TABLE backup_ai_overrides (
             domain     TEXT PRIMARY KEY,
             action     TEXT NOT NULL,
             reason     TEXT NOT NULL DEFAULT '',
             created_at INTEGER NOT NULL
         );",
    )
    .map_err(|e| db_err("cannot write the backup", e))?;
    if let Some(ai) = ai_database.filter(|p| p.exists()) {
        let ai_text = ai.to_str().unwrap_or_default();
        conn.execute(
            "ATTACH DATABASE ?1 AS ai",
            params![format!("file:{ai_text}?mode=ro")],
        )
        .map_err(|e| db_err("cannot read the AI database", e))?;
        let has_overrides: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM ai.sqlite_master WHERE type = 'table' AND name = 'ai_overrides'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);
        if has_overrides {
            conn.execute(
                "INSERT INTO backup_ai_overrides SELECT domain, action, reason, created_at
                 FROM ai.ai_overrides",
                [],
            )
            .map_err(|e| db_err("cannot copy AI overrides", e))?;
        }
        conn.execute("DETACH DATABASE ai", [])
            .map_err(|e| db_err("cannot read the AI database", e))?;
    }
    conn.execute_batch(
        "CREATE TABLE backup_info (
             format      INTEGER NOT NULL,
             app_version TEXT NOT NULL,
             created_at  INTEGER NOT NULL
         );",
    )
    .map_err(|e| db_err("cannot write the backup", e))?;
    conn.execute(
        "INSERT INTO backup_info (format, app_version, created_at) VALUES (?1, ?2, ?3)",
        params![FORMAT, env!("CARGO_PKG_VERSION"), now()],
    )
    .map_err(|e| db_err("cannot write the backup", e))?;
    if !include_query_logs {
        conn.execute("VACUUM", [])
            .map_err(|e| db_err("cannot compact the backup", e))?;
    }
    describe(&conn)
}

/// Check that `path` is an intact Daygle DNS backup and say what it holds.
pub fn check_backup(path: &Path) -> Result<BackupInfo> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| DaygleError::Config("the file is not a Daygle DNS backup".into()))?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|_| DaygleError::Config("the file is not a Daygle DNS backup".into()))?;
    if integrity != "ok" {
        return Err(DaygleError::Config(format!(
            "the backup is damaged: {integrity}"
        )));
    }
    for table in REQUIRED_TABLES {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |r| r.get(0),
            )
            .map_err(|e| db_err("cannot read the backup", e))?;
        if found == 0 {
            return Err(DaygleError::Config(
                "the file is not a Daygle DNS backup".into(),
            ));
        }
    }
    let format: i64 = conn
        .query_row("SELECT format FROM backup_info", [], |r| r.get(0))
        .map_err(|e| db_err("cannot read the backup", e))?;
    if format > FORMAT {
        return Err(DaygleError::Config(
            "the backup was made by a newer version of Daygle DNS: update this server first".into(),
        ));
    }
    describe(&conn)
}

fn describe(conn: &Connection) -> Result<BackupInfo> {
    let count = |table: &str| -> Result<i64> {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |r| r.get(0),
            )
            .map_err(|e| db_err("cannot read the backup", e))?;
        if exists == 0 {
            return Ok(0);
        }
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .map_err(|e| db_err("cannot read the backup", e))
    };
    let (created_at, app_version) = conn
        .query_row("SELECT created_at, app_version FROM backup_info", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|e| db_err("cannot read the backup", e))?;
    Ok(BackupInfo {
        created_at,
        app_version,
        zones: count("zones")?,
        records: count("records")?,
        users: count("console_users")?,
        certificates: count("tls_certificates")?,
        query_logs: count("query_logs")?,
        ai_overrides: count("backup_ai_overrides")?,
    })
}

/// Check the backup at `backup` and stage it to replace `database` on the
/// next start. Replaces any restore already staged.
pub fn stage_restore(database: &str, backup: &Path) -> Result<BackupInfo> {
    let info = check_backup(backup)?;
    let staged = pending_restore_path(database);
    let partial = PathBuf::from(format!("{database}.restore.partial"));
    std::fs::copy(backup, &partial)?;
    restrict(&partial);
    std::fs::rename(&partial, &staged)?;
    Ok(info)
}

/// The restore staged for `database`, if any.
pub fn pending_restore(database: &str) -> Option<BackupInfo> {
    let staged = pending_restore_path(database);
    staged
        .exists()
        .then(|| check_backup(&staged).ok())
        .flatten()
}

/// Drop the restore staged for `database`. Returns whether there was one.
pub fn cancel_restore(database: &str) -> Result<bool> {
    match std::fs::remove_file(pending_restore_path(database)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// At start-up, before the database is opened: put a staged restore in
/// place. The current database (and its journal files) moves aside, and
/// its new name is returned. A staged file that no longer checks out is
/// renamed `<database>.restore.rejected` and the database is left alone.
pub fn apply_pending_restore(database: &str) -> Result<Option<PathBuf>> {
    let staged = pending_restore_path(database);
    if !staged.exists() {
        return Ok(None);
    }
    if let Err(e) = check_backup(&staged) {
        std::fs::rename(&staged, format!("{database}.restore.rejected"))?;
        return Err(DaygleError::Config(format!(
            "the staged restore was not applied: {e}"
        )));
    }
    let aside = PathBuf::from(format!("{database}.before-restore-{}", now()));
    if Path::new(database).exists() {
        std::fs::rename(database, &aside)?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let file = format!("{database}{suffix}");
        if Path::new(&file).exists() {
            std::fs::rename(&file, format!("{}{suffix}", aside.display()))?;
        }
    }
    std::fs::rename(&staged, database)?;
    Ok(Some(aside))
}

impl ZoneStore {
    /// After a restore: move the backup's AI overrides into `ai_database`
    /// (replacing the ones there) and drop the backup-only tables. Does
    /// nothing for a database that was not restored from a backup.
    pub fn finish_restore(&self, ai_database: &Path) -> Result<usize> {
        self.with_conn(|conn| {
            let restored: Option<i64> = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'backup_ai_overrides'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| db_err("cannot read the database", e))?;
            if restored.unwrap_or(0) == 0 {
                return Ok(0);
            }
            let ai_text = ai_database
                .to_str()
                .ok_or_else(|| DaygleError::Config("AI database path is not valid UTF-8".into()))?;
            if let Some(parent) = ai_database.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            conn.execute("ATTACH DATABASE ?1 AS ai", params![ai_text])
                .map_err(|e| db_err("cannot open the AI database", e))?;
            let moved = (|| -> rusqlite::Result<usize> {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS ai.ai_overrides (
                         domain     TEXT PRIMARY KEY,
                         action     TEXT NOT NULL,
                         reason     TEXT NOT NULL DEFAULT '',
                         created_at INTEGER NOT NULL
                     );
                     DELETE FROM ai.ai_overrides;",
                )?;
                let n = conn.execute(
                    "INSERT INTO ai.ai_overrides SELECT domain, action, reason, created_at
                     FROM backup_ai_overrides",
                    [],
                )?;
                conn.execute_batch(
                    "DROP TABLE backup_ai_overrides;
                     DROP TABLE IF EXISTS backup_info;",
                )?;
                Ok(n)
            })();
            let _ = conn.execute("DETACH DATABASE ai", []);
            moved.map_err(|e| db_err("cannot restore AI overrides", e))
        })
    }
}

/// Backups hold private keys and password hashes: owner-only.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ZoneInput;

    #[test]
    fn backup_stage_and_restore_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("daygle-dns.db");
        let db_text = db.to_str().unwrap();
        let ai = dir.path().join("ai.db");
        {
            let ai_conn = Connection::open(&ai).unwrap();
            ai_conn
                .execute_batch(
                    "CREATE TABLE ai_overrides (domain TEXT PRIMARY KEY, action TEXT NOT NULL,
                         reason TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
                     INSERT INTO ai_overrides VALUES ('good.example', 'allow', 'mine', 1);",
                )
                .unwrap();
        }
        let store = ZoneStore::open(db_text).unwrap();
        store
            .create_zone(&ZoneInput {
                name: "kept.test".into(),
                ..Default::default()
            })
            .unwrap();

        let backup = dir.path().join("backup.db");
        let info = store.backup_to(&backup, false, Some(&ai)).unwrap();
        assert_eq!(info.zones, 1);
        assert_eq!(info.ai_overrides, 1);
        assert_eq!(info.query_logs, 0);
        assert_eq!(check_backup(&backup).unwrap(), info);

        // Changes after the backup are undone by the restore.
        store
            .create_zone(&ZoneInput {
                name: "later.test".into(),
                ..Default::default()
            })
            .unwrap();
        Connection::open(&ai)
            .unwrap()
            .execute("DELETE FROM ai_overrides", [])
            .unwrap();
        stage_restore(db_text, &backup).unwrap();
        assert_eq!(pending_restore(db_text).unwrap().zones, 1);
        drop(store);

        let aside = apply_pending_restore(db_text).unwrap().unwrap();
        assert!(aside.exists());
        assert!(pending_restore(db_text).is_none());
        let store = ZoneStore::open(db_text).unwrap();
        assert_eq!(store.finish_restore(&ai).unwrap(), 1);
        let names: Vec<String> = store
            .list_zones()
            .unwrap()
            .into_iter()
            .map(|z| z.name)
            .collect();
        assert_eq!(names, ["kept.test"]);
        let overrides: i64 = Connection::open(&ai)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM ai_overrides", [], |r| r.get(0))
            .unwrap();
        assert_eq!(overrides, 1);
        // Only once.
        assert_eq!(store.finish_restore(&ai).unwrap(), 0);
        assert!(apply_pending_restore(db_text).unwrap().is_none());
    }

    #[test]
    fn rejects_files_that_are_not_backups() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.db");
        std::fs::write(&junk, b"not a database at all").unwrap();
        assert!(check_backup(&junk).is_err());
        // A plain database (not made by backup_to) is refused too.
        let plain = dir.path().join("plain.db");
        drop(ZoneStore::open(plain.to_str().unwrap()).unwrap());
        assert!(check_backup(&plain)
            .unwrap_err()
            .to_string()
            .contains("not a Daygle DNS backup"));
        let db = dir.path().join("daygle-dns.db");
        assert!(stage_restore(db.to_str().unwrap(), &plain).is_err());
        assert!(!pending_restore_path(db.to_str().unwrap()).exists());
        assert!(!cancel_restore(db.to_str().unwrap()).unwrap());
    }
}
