//! # daygle-dot
//!
//! DNS over TLS (RFC 7858) using `rustls`.
//!
//! This crate owns TLS certificate loading/generation and produces a
//! [`rustls::ServerConfig`] with the `dot` ALPN protocol negotiated. The
//! actual socket handling is delegated to Hickory's [`Server`], which manages
//! TCP, TLS framing and the DNS protocol; [`register_dot`] wires a bound
//! `TcpListener` plus TLS config into it.

mod cert;

pub use cert::{ensure_certificate, generate_self_signed, load_tls_config};

use std::sync::Arc;
use std::time::Duration;

use daygle_core::config::DotSettings;
use daygle_core::error::{DaygleError, Result};
use hickory_server::server::{RequestHandler, Server};
use rustls::ServerConfig;
use tokio::net::TcpListener;

/// The ALPN protocol identifier for DNS over TLS.
pub const DOT_ALPN: &[u8] = b"dot";

/// Build the TLS configuration described by `settings`, generating a
/// self-signed certificate when requested and none is present.
pub fn build_tls_config(settings: &DotSettings) -> Result<Arc<ServerConfig>> {
    ensure_certificate(settings)?;
    load_tls_config(&settings.cert_path, &settings.key_path).map(Arc::new)
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
