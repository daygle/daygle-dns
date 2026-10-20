//! The view of the local root zone (RFC 8806) the resolver needs. The zone
//! itself is kept by `daygle-dns-authoritative`; the resolver only asks where
//! it is served and which top-level domains exist.

use std::net::SocketAddr;

/// Read access to the local root zone.
pub trait LocalRootView: Send + Sync {
    /// The loopback address of the responder serving the verified root
    /// zone, or `None` while no unexpired copy is loaded.
    fn serving_addr(&self) -> Option<SocketAddr>;

    /// Whether `tld` (one label, any case) is delegated in the root zone, or
    /// `None` while no unexpired copy is loaded.
    fn tld_exists(&self, tld: &str) -> Option<bool>;
}
