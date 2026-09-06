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

    /// The recursive resolver failed to produce an answer. When the upstream
    /// returned an explicit DNS error (e.g. NXDOMAIN), `response_code` carries
    /// it so the dispatcher can pass it through instead of SERVFAIL.
    #[error("resolution failed: {message}")]
    Resolution {
        /// Human-readable error detail.
        message: String,
        /// The upstream's response code, when the failure is a negative
        /// answer rather than a transport/protocol failure.
        response_code: Option<u16>,
    },

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

/// Coarse classification of a [`DaygleError`]. Two errors with the same
/// `kind()` are guaranteed to represent the same failure mode regardless of
/// the human-readable message - useful for comparing validation outcomes
/// before/after a config edit without depending on `Display` strings (which
/// may include paths, line numbers, or other cosmetic context).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DaygleErrorKind {
    Config,
    Io,
    InvalidRecord,
    InvalidPolicy,
    Refused,
    Proto,
    Resolution,
    NotFound,
    AlreadyExists,
    Database,
    Tls,
    Internal,
}

impl DaygleError {
    /// Coarse classification; compare with [`DaygleErrorKind::eq`].
    pub fn kind(&self) -> DaygleErrorKind {
        match self {
            DaygleError::Config(_) => DaygleErrorKind::Config,
            DaygleError::Io(_) => DaygleErrorKind::Io,
            DaygleError::InvalidRecord(_) => DaygleErrorKind::InvalidRecord,
            DaygleError::InvalidPolicy(_) => DaygleErrorKind::InvalidPolicy,
            DaygleError::Refused(_) => DaygleErrorKind::Refused,
            DaygleError::Proto(_) => DaygleErrorKind::Proto,
            DaygleError::Resolution { .. } => DaygleErrorKind::Resolution,
            DaygleError::NotFound(_) => DaygleErrorKind::NotFound,
            DaygleError::AlreadyExists(_) => DaygleErrorKind::AlreadyExists,
            DaygleError::Database(_) => DaygleErrorKind::Database,
            DaygleError::Tls(_) => DaygleErrorKind::Tls,
            DaygleError::Internal(_) => DaygleErrorKind::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_reflects_variant() {
        assert_eq!(
            DaygleError::Config("foo".into()).kind(),
            DaygleErrorKind::Config
        );
        assert_eq!(
            DaygleError::NotFound("bar".into()).kind(),
            DaygleErrorKind::NotFound
        );
        assert_eq!(
            DaygleError::Resolution {
                message: "x".into(),
                response_code: Some(3)
            }
            .kind(),
            DaygleErrorKind::Resolution
        );
    }

    #[test]
    fn kind_is_stable_under_message_changes() {
        let a = DaygleError::Config("port 53 in use on line 12".into());
        let b = DaygleError::Config("port 53 in use on line 99".into());
        assert_eq!(a.kind(), b.kind());
    }
}
