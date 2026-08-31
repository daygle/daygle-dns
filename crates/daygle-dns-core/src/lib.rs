//! # daygle-dns-core
//!
//! Shared foundation for Daygle DNS: the global configuration model, the error
//! type used across all crates, runtime metrics and the in-memory log store.
//!
//! Nothing in this crate performs I/O on its own; it is a set of pure data
//! structures plus small runtime helpers that the server crates share.

pub mod auth;
pub mod config;
pub mod error;
pub mod logs;
pub mod metrics;
pub mod rate_limit;
pub mod stats;

pub use auth::{hash_password, verify_password};
pub use config::*;
pub use error::{DaygleError, Result};
pub use logs::{LogEntry, LogLevel, LogStore};
pub use metrics::Metrics;
pub use rate_limit::RateLimiter;
pub use stats::{Outcome, QueryStats, SeriesPoint, TopEntry};

/// Current version of the Daygle DNS server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration file name searched by the installer and binary.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/daygle-dns/daygle-dns.toml";
