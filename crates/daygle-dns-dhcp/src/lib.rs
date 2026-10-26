//! # daygle-dhcp
//!
//! A DHCPv4 and DHCPv6 server for small networks, with leases saved in the
//! zone database and registered as DNS names in a hosted zone.
//!
//! - [`v4`] and [`v6`] - the protocol logic, independent of sockets.
//! - [`leases`] - the lease table.
//! - [`ddns`] - DNS records for leases.
//! - [`net`] - sockets and interfaces (Linux).
//! - [`service`] - the running service.

pub mod ddns;
pub mod leases;
pub mod net;
pub mod service;
pub mod v4;
pub mod v6;

pub use service::{DhcpService, DhcpStatus};
