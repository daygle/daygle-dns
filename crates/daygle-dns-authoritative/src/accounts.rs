//! DNS accounts: devices recognised by the client ID in the host name they
//! reach the encrypted listeners at (`<client id>.<accounts.domain>`), or in
//! the DoH URL path (`/dns-query/<client id>`).
//!
//! Filtering groups name an account with a `account:<name>` client entry, so
//! renaming an account rewrites those entries and deleting one removes them.

use daygle_dns_core::error::{DaygleError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::store::ZoneStore;

/// The client-list entry prefix that names an account in a filtering group.
pub const ACCOUNT_ENTRY_PREFIX: &str = "account:";

/// Length of a generated client ID: 12 characters of `[a-z0-9]` (about 62
/// bits), so IDs cannot be guessed.
const GENERATED_ID_LEN: usize = 12;

/// One DNS account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAccount {
    pub id: String,
    /// Display name, unique ignoring case; what filtering groups refer to.
    pub name: String,
    /// The DNS label devices put in front of the account domain.
    pub client_id: String,
    pub enabled: bool,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339 time of the last query seen from it (to the minute).
    pub last_seen_at: Option<String>,
}

/// Create or change an account.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsAccountInput {
    pub name: String,
    /// Empty: keep the current ID, or generate one for a new account.
    #[serde(default)]
    pub client_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

const COLUMNS: &str = "id, name, client_id, enabled, created_at, last_seen_at";

fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<DnsAccount> {
    Ok(DnsAccount {
        id: row.get(0)?,
        name: row.get(1)?,
        client_id: row.get(2)?,
        enabled: row.get::<_, i64>(3)? != 0,
        created_at: row.get(4)?,
        last_seen_at: row.get(5)?,
    })
}

/// A valid account name: 1-64 characters, none of them a control
/// character, `,` or `:` (it is written into `account:<name>` entries of
/// comma-separated client lists).
pub fn validate_account_name(name: &str) -> Result<()> {
    let bad = |why: &str| Err(DaygleError::Config(format!("account name {why}")));
    if name.is_empty() {
        return bad("is required");
    }
    if name.chars().count() > 64 {
        return bad("is longer than 64 characters");
    }
    if name.chars().any(|c| c.is_control() || c == ',' || c == ':') {
        return bad("cannot contain ',' or ':'");
    }
    Ok(())
}

/// A valid client ID: one DNS label of lowercase letters, digits and
/// hyphens (not first or last), 1-63 characters.
pub fn validate_client_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 63
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(DaygleError::Config(format!(
            "client ID '{id}' must be one DNS label: lowercase letters, digits and hyphens"
        )))
    }
}

/// A random client ID.
pub fn generate_client_id() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..GENERATED_ID_LEN)
        .map(|_| ALPHABET[rand::random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Create the accounts table and the query log's account column.
pub(crate) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS dns_accounts (
             id           TEXT PRIMARY KEY,
             name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
             client_id    TEXT NOT NULL UNIQUE,
             enabled      INTEGER NOT NULL DEFAULT 1,
             created_at   TEXT NOT NULL,
             last_seen_at TEXT
         );",
    )?;
    let has_column: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('query_logs') WHERE name = 'account')",
        [],
        |row| row.get(0),
    )?;
    if !has_column {
        conn.execute("ALTER TABLE query_logs ADD COLUMN account TEXT", [])?;
    }
    Ok(())
}

/// Rewrite every filtering group's `account:<old>` client entry to
/// `account:<new>`, or drop it when `new` is `None`.
fn rewrite_group_entries(conn: &Connection, old: &str, new: Option<&str>) -> Result<()> {
    let old_entry = format!("{ACCOUNT_ENTRY_PREFIX}{old}").to_lowercase();
    let groups: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT id, clients FROM blocking_groups")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for (id, clients) in groups {
        let Ok(entries) = serde_json::from_str::<Vec<String>>(&clients) else {
            continue;
        };
        if !entries.iter().any(|e| e.trim().to_lowercase() == old_entry) {
            continue;
        }
        let rewritten: Vec<String> = entries
            .into_iter()
            .filter_map(|e| {
                if e.trim().to_lowercase() != old_entry {
                    return Some(e);
                }
                new.map(|name| format!("{ACCOUNT_ENTRY_PREFIX}{name}"))
            })
            .collect();
        // A group left with no clients would cover every client: one that
        // only named the deleted account is turned off instead.
        conn.execute(
            "UPDATE blocking_groups
             SET clients = ?2, enabled = CASE WHEN ?3 THEN 0 ELSE enabled END
             WHERE id = ?1",
            params![
                id,
                serde_json::to_string(&rewritten).expect("strings serialize"),
                rewritten.is_empty(),
            ],
        )?;
    }
    Ok(())
}

/// Refuse `name` when another account (not `except`) has it, ignoring
/// case the way filtering groups match names (Unicode lowercase; SQLite's
/// `NOCASE` only folds ASCII, so `Éva` and `éva` would both get in).
fn ensure_name_free(conn: &Connection, name: &str, except: Option<&str>) -> Result<()> {
    let folded = name.to_lowercase();
    let mut stmt = conn.prepare("SELECT id, name FROM dns_accounts")?;
    let taken = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(std::result::Result::ok)
        .any(|(id, other)| Some(id.as_str()) != except && other.to_lowercase() == folded);
    if taken {
        return Err(DaygleError::Config(format!(
            "an account named '{name}' already exists"
        )));
    }
    Ok(())
}

fn constraint_error(e: rusqlite::Error, name: &str, client_id: &str) -> DaygleError {
    match e {
        rusqlite::Error::SqliteFailure(f, Some(msg))
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            if msg.contains("client_id") {
                DaygleError::Config(format!("client ID '{client_id}' is already in use"))
            } else {
                DaygleError::Config(format!("an account named '{name}' already exists"))
            }
        }
        other => other.into(),
    }
}

impl ZoneStore {
    /// Every account, by name.
    pub fn list_dns_accounts(&self) -> Result<Vec<DnsAccount>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {COLUMNS} FROM dns_accounts ORDER BY name COLLATE NOCASE"
            ))?;
            let rows = stmt.query_map([], row_to_account)?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        })
    }

    pub fn get_dns_account(&self, id: &str) -> Result<Option<DnsAccount>> {
        self.with_conn(|conn| {
            conn.query_row(
                &format!("SELECT {COLUMNS} FROM dns_accounts WHERE id = ?1"),
                [id],
                row_to_account,
            )
            .optional()
            .map_err(Into::into)
        })
    }

    /// Create an account; an empty client ID gets a random one.
    pub fn create_dns_account(&self, input: &DnsAccountInput) -> Result<DnsAccount> {
        let name = input.name.trim().to_string();
        validate_account_name(&name)?;
        let client_id = match input.client_id.trim().to_ascii_lowercase() {
            id if id.is_empty() => generate_client_id(),
            id => id,
        };
        validate_client_id(&client_id)?;
        let account = DnsAccount {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            client_id,
            enabled: input.enabled,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_seen_at: None,
        };
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            ensure_name_free(&tx, &account.name, None)?;
            tx.execute(
                "INSERT INTO dns_accounts (id, name, client_id, enabled, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    account.id,
                    account.name,
                    account.client_id,
                    account.enabled,
                    account.created_at
                ],
            )
            .map_err(|e| constraint_error(e, &account.name, &account.client_id))?;
            tx.commit()?;
            Ok(())
        })?;
        Ok(account)
    }

    /// Change an account. A new name is carried into the filtering groups
    /// that name the account; an empty client ID keeps the current one.
    pub fn update_dns_account(&self, id: &str, input: &DnsAccountInput) -> Result<DnsAccount> {
        let name = input.name.trim().to_string();
        validate_account_name(&name)?;
        let requested_id = input.client_id.trim().to_ascii_lowercase();
        if !requested_id.is_empty() {
            validate_client_id(&requested_id)?;
        }
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let current = tx
                .query_row(
                    &format!("SELECT {COLUMNS} FROM dns_accounts WHERE id = ?1"),
                    [id],
                    row_to_account,
                )
                .optional()?
                .ok_or_else(|| DaygleError::NotFound(format!("account '{id}'")))?;
            ensure_name_free(&tx, &name, Some(id))?;
            let client_id = if requested_id.is_empty() {
                current.client_id.clone()
            } else {
                requested_id.clone()
            };
            tx.execute(
                "UPDATE dns_accounts SET name = ?2, client_id = ?3, enabled = ?4 WHERE id = ?1",
                params![id, name, client_id, input.enabled],
            )
            .map_err(|e| constraint_error(e, &name, &client_id))?;
            if current.name != name {
                rewrite_group_entries(&tx, &current.name, Some(&name))?;
            }
            tx.commit()?;
            Ok(DnsAccount {
                name,
                client_id,
                enabled: input.enabled,
                ..current
            })
        })
    }

    /// Delete an account (and its entries in filtering groups). Returns
    /// whether it existed.
    pub fn delete_dns_account(&self, id: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let name: Option<String> = tx
                .query_row("SELECT name FROM dns_accounts WHERE id = ?1", [id], |r| {
                    r.get(0)
                })
                .optional()?;
            let Some(name) = name else {
                return Ok(false);
            };
            tx.execute("DELETE FROM dns_accounts WHERE id = ?1", [id])?;
            rewrite_group_entries(&tx, &name, None)?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// Note that `name` was seen at `when` (RFC 3339; the caller limits
    /// this to about once a minute per account).
    pub fn touch_dns_account(&self, name: &str, when: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE dns_accounts SET last_seen_at = ?2 WHERE name = ?1",
                params![name, when],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daygle_dns_core::blocking::BlockingGroupInput;

    fn input(name: &str, client_id: &str) -> DnsAccountInput {
        DnsAccountInput {
            name: name.to_string(),
            client_id: client_id.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn accounts_are_created_validated_and_unique() {
        let store = ZoneStore::open(":memory:").unwrap();
        let generated = store.create_dns_account(&input("Laptop", "")).unwrap();
        assert_eq!(generated.client_id.len(), GENERATED_ID_LEN);
        validate_client_id(&generated.client_id).unwrap();
        let chosen = store
            .create_dns_account(&input("Phone", "Phone-1"))
            .unwrap();
        assert_eq!(chosen.client_id, "phone-1");

        assert!(
            store.create_dns_account(&input("laptop", "")).is_err(),
            "names ignore case"
        );
        assert!(store
            .create_dns_account(&input("Tablet", "phone-1"))
            .is_err());
        assert!(store.create_dns_account(&input("Bad:name", "")).is_err());
        assert!(store.create_dns_account(&input("Tablet", "-bad")).is_err());
        assert!(store
            .create_dns_account(&input("Tablet", "two.labels"))
            .is_err());
        assert_eq!(store.list_dns_accounts().unwrap().len(), 2);

        // Case is ignored beyond ASCII too (SQLite's NOCASE would not).
        store.create_dns_account(&input("Éva", "")).unwrap();
        assert!(store.create_dns_account(&input("éva", "")).is_err());
        // Renaming onto another account's name is refused; changing the
        // case of its own name is not.
        assert!(store
            .update_dns_account(&chosen.id, &input("ÉVA", ""))
            .is_err());
        store
            .update_dns_account(&chosen.id, &input("PHONE", ""))
            .unwrap();
    }

    #[test]
    fn renames_and_deletes_reach_filtering_groups() {
        let store = ZoneStore::open(":memory:").unwrap();
        let kid = store.create_dns_account(&input("Kid", "")).unwrap();
        let group = store
            .upsert_blocking_group(
                &serde_json::from_value::<BlockingGroupInput>(serde_json::json!({
                    "name": "Kids",
                    "clients": ["192.168.1.0/24", "account:kid"],
                }))
                .unwrap(),
            )
            .unwrap();

        store
            .update_dns_account(&kid.id, &input("Kid tablet", ""))
            .unwrap();
        let clients = store
            .get_blocking_group(&group.id)
            .unwrap()
            .unwrap()
            .clients;
        assert_eq!(clients, vec!["192.168.1.0/24", "account:Kid tablet"]);

        assert!(store.delete_dns_account(&kid.id).unwrap());
        let clients = store
            .get_blocking_group(&group.id)
            .unwrap()
            .unwrap()
            .clients;
        assert_eq!(clients, vec!["192.168.1.0/24"]);
        assert!(
            store
                .get_blocking_group(&group.id)
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(!store.delete_dns_account(&kid.id).unwrap());

        // A group that named only the deleted account is turned off rather
        // than left covering every client.
        let solo = store.create_dns_account(&input("Solo", "")).unwrap();
        let only = store
            .upsert_blocking_group(
                &serde_json::from_value::<BlockingGroupInput>(serde_json::json!({
                    "name": "Solo only",
                    "clients": ["account:Solo"],
                }))
                .unwrap(),
            )
            .unwrap();
        store.delete_dns_account(&solo.id).unwrap();
        let only = store.get_blocking_group(&only.id).unwrap().unwrap();
        assert!(only.clients.is_empty());
        assert!(!only.enabled);
    }
}
