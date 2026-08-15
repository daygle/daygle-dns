//! # daygle-core
//!
//! Shared foundation for Daygle DNS: the global configuration model, the error
//! type used across all crates, runtime metrics and the in-memory log store.
//!
//! Nothing in this crate performs I/O on its own; it is a set of pure data
//! structures plus small runtime helpers that the server crates share.

pub mod config;
pub mod error;
pub mod logs;
pub mod metrics;

pub use config::*;
pub use error::{DaygleError, Result};
pub use logs::{LogEntry, LogLevel, LogStore};
pub use metrics::Metrics;

/// Current version of the Daygle DNS server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration file name searched by the installer and binary.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/daygle/daygle.toml";
