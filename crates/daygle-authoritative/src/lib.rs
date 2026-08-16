//! # daygle-authoritative
//!
//! Authoritative DNS serving backed by SQLite.
//!
//! The crate is split into:
//!
//! - [`model`] — serializable `Zone`/`Record` data structures shared with the
//!   REST API and GUI.
//! - [`store`] — a SQLite-backed [`ZoneStore`] with full CRUD and schema
//!   management.
//! - [`parse`] — a BIND-style zone file parser for imports.
//! - [`catalog`] — converts stored zones into Hickory [`Record`]s/`RecordSet`s
//!   and assembles them into a [`Catalog`] ready for serving, including
//!   DNSSEC signing when keys are present.
//! - [`transfer`] — an AXFR/IXFR transfer client for secondary zones.
//! - [`secondary`] — periodic refresh of secondary zones from their masters.
//! - [`update`] — RFC 2136 dynamic updates with write-through to SQLite.

pub mod catalog;
pub mod model;
pub mod parse;
pub mod secondary;
pub mod split_horizon;
pub mod store;
pub mod transfer;
pub mod update;

pub use catalog::AuthorityCatalog;
pub use model::{Record, RecordInput, Zone, ZoneInput};
pub use split_horizon::{SplitHorizonIndex, SplitHorizonMatch};
pub use secondary::SecondaryRefresher;
pub use store::ZoneStore;
pub use transfer::XfrClient;
pub use update::handle_update;

use daygle_core::error::{DaygleError, Result};

/// Validate that a domain name is a plausible zone/record owner name.
pub fn validate_name(name: &str, allow_relative: bool) -> Result<()> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DaygleError::InvalidRecord("empty name".to_string()));
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DaygleError::InvalidRecord(format!(
                "name '{name}' has an empty label"
            )));
        }
        if label.len() > 63 {
            return Err(DaygleError::InvalidRecord(format!(
                "label '{label}' exceeds 63 bytes"
            )));
        }
        if label.starts_with('-')
            || label.ends_with('-')
            || label
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            return Err(DaygleError::InvalidRecord(format!(
                "invalid label '{label}' in '{name}'"
            )));
        }
    }
    if !allow_relative && !trimmed.contains('.') {
        return Err(DaygleError::InvalidRecord(format!(
            "name '{name}' is not fully qualified"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(validate_name("example.com", false).is_ok());
        assert!(validate_name("www", true).is_ok());
        assert!(validate_name("", true).is_err());
        assert!(validate_name("a..b", true).is_err());
        assert!(validate_name("-bad.example.com", true).is_err());
    }
}
