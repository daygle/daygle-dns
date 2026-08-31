//! # daygle-dot
//!
//! Encrypted DNS listeners built on `rustls` and Hickory's [`Server`]:
//!
//! - **DNS over TLS (RFC 7858)** - the `dot` ALPN protocol on a plain TCP
//!   listener ([`register_dot`]).
//! - **DNS over HTTPS (RFC 8484)** - the `h2` ALPN protocol on a TLS listener
//!   serving POST requests at a configurable path, e.g. `/dns-query`
//!   ([`register_doh`]).
//!
//! This crate owns TLS certificate loading/generation and produces the
//! [`rustls::ServerConfig`] for either protocol; socket handling is delegated
//! to Hickory's [`Server`].

mod cert;

pub use cert::{
    ensure_certificate, ensure_certificate_paths, generate_self_signed, load_tls_config,
};

use std::sync::Arc;
use std::time::Duration;

use daygle_dns_core::config::{DohSettings, DotSettings};
use daygle_dns_core::error::{DaygleError, Result};
use hickory_server::server::{RequestHandler, Server};
use rustls::ServerConfig;
use tokio::net::TcpListener;

/// The ALPN protocol identifier for DNS over TLS.
pub const DOT_ALPN: &[u8] = b"dot";
/// The ALPN protocol identifier for DNS over HTTPS (HTTP/2).
pub const DOH_ALPN: &[u8] = b"h2";

/// Build the TLS configuration described by `settings`, generating a
/// self-signed certificate when requested and none is present.
pub fn build_tls_config(settings: &DotSettings) -> Result<Arc<ServerConfig>> {
    ensure_certificate(settings)?;
    load_tls_config(&settings.cert_path, &settings.key_path, DOT_ALPN).map(Arc::new)
}

/// Build the DoH TLS configuration (h2 ALPN) from `settings`, generating a
/// self-signed certificate when requested and none is present.
pub fn build_doh_tls_config(settings: &DohSettings) -> Result<Arc<ServerConfig>> {
    // DoH can reuse the DoT certificate when `doh.cert_path` matches the
    // default; generation only happens when the files are missing.
    ensure_certificate_paths(
        &settings.cert_path,
        &settings.key_path,
        settings.self_signed,
        &settings.server_name,
    )?;
    load_tls_config(&settings.cert_path, &settings.key_path, DOH_ALPN).map(Arc::new)
}

/// Register a DoT listener on a Hickory server.
pub fn register_dot<T: RequestHandler>(
    server: &mut Server<T>,
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
) -> Result<()> {
    server
        .register_tls_listener_with_tls_config(listener, handshake_timeout, tls_config)
        .map_err(|e| DaygleError::Tls(format!("cannot register DoT listener: {e}")))
}

/// Register a DoH listener on a Hickory server.
///
/// Serves POST requests carrying `application/dns-message` bodies at
/// `endpoint` (e.g. `/dns-query`). `dns_hostname` enables strict HTTP Host
/// header verification; pass `None` to accept any host (typical for
/// self-signed/LAN deployments).
pub fn register_doh<T: RequestHandler>(
    server: &mut Server<T>,
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
    dns_hostname: Option<String>,
    endpoint: &str,
) -> Result<()> {
    server
        .register_https_listener_with_tls_config(
            listener,
            handshake_timeout,
            tls_config,
            dns_hostname,
            endpoint.to_string(),
        )
        .map_err(|e| DaygleError::Tls(format!("cannot register DoH listener: {e}")))
}
