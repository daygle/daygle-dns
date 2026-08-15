//! The single error type shared by every Daygle crate.

use std::io;

/// Alias used throughout the code base for `Result<T, DaygleError>`.
pub type Result<T> = std::result::Result<T, DaygleError>;

/// Top-level error for Daygle DNS.
///
/// Every crate converts its local error conditions into this type so that
/// callers (the dispatcher, the API, tests) have a single place to match on.
#[derive(Debug, thiserror::Error)]
pub enum DaygleError {
    /// Invalid or missing configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O failure (sockets, files, certificates).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A zone/record stored in the database could not be understood.
    #[error("invalid record data: {0}")]
    InvalidRecord(String),

    /// A policy rule was malformed (bad CIDR, bad domain, ...).
    #[error("invalid policy rule: {0}")]
    InvalidPolicy(String),

    /// The request was refused by the policy engine or an ACL.
    #[error("request refused: {0}")]
    Refused(String),

    /// A DNS protocol-level failure.
    #[error("dns protocol error: {0}")]
    Proto(String),

    /// The recursive resolver failed to produce an answer.
    #[error("resolution failed: {0}")]
    Resolution(String),

    /// A zone/record was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A zone/record already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Database failure.
    #[error("database error: {0}")]
    Database(String),

    /// TLS / certificate failure.
    #[error("tls error: {0}")]
    Tls(String),

    /// Catch-all for internal invariant violations.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<rusqlite::Error> for DaygleError {
    fn from(e: rusqlite::Error) -> Self {
        DaygleError::Database(e.to_string())
    }
}

impl From<serde_json::Error> for DaygleError {
    fn from(e: serde_json::Error) -> Self {
        DaygleError::Config(format!("invalid json: {e}"))
    }
}
