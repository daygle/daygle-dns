//! # daygle-dot
//!
//! Encrypted DNS listeners built on `rustls` and Hickory's [`Server`]:
//!
//! - **DNS over TLS (RFC 7858)** - the `dot` ALPN protocol ([`build_tls_config`];
//!   the listener itself lives in the `daygle-dns` crate).
//! - **DNS over HTTPS (RFC 8484)** - the `h2` ALPN protocol on a TLS listener
//!   serving POST requests at a configurable path, e.g. `/dns-query`
//!   ([`register_doh`]).
//!
//! This crate owns TLS certificate loading/generation and produces the
//! [`rustls::ServerConfig`] for each protocol; socket handling is delegated
//! to Hickory's [`Server`], including its native DoQ (RFC 9250) listener
//! (registered from the `daygle-dns` crate via
//! [`build_doq_tls_config`]).

mod cert;

pub use cert::{
    crypto_provider, describe_certificate, ensure_certificate, ensure_certificate_paths,
    generate_self_signed, generate_self_signed_pem, load_tls_config, load_tls_config_alpns,
    load_tls_config_versions, tls_config_from_pem, validate_pem_pair, CertificateInfo,
};

use std::sync::Arc;
use std::time::Duration;

use daygle_dns_core::config::{DohSettings, DoqSettings, DotSettings};
use daygle_dns_core::error::{DaygleError, Result};
use hickory_server::server::{RequestHandler, Server};
use rustls::ServerConfig;
use tokio::net::TcpListener;

/// The ALPN protocol identifier for DNS over TLS.
pub const DOT_ALPN: &[u8] = b"dot";
/// The ALPN protocol identifier for DNS over HTTPS (HTTP/2).
pub const DOH_ALPN: &[u8] = b"h2";
/// The ALPN protocol identifier for DNS over QUIC (RFC 9250 §4.3).
pub const DOQ_ALPN: &[u8] = b"doq";
/// The ALPN protocol identifier for HTTP/3 (DoH over QUIC).
pub const DOH3_ALPN: &[u8] = b"h3";
/// The ALPN protocol identifier for zone transfers over TLS (XoT, RFC 9103).
pub const XOT_ALPN: &[u8] = b"xot";

/// Build the TLS configuration described by `settings`, generating a
/// self-signed certificate when requested and none is present.
pub fn build_tls_config(settings: &DotSettings) -> Result<Arc<ServerConfig>> {
    ensure_certificate(settings)?;
    // RFC 9103: zone transfers over TLS use the "xot" ALPN on the same
    // listener as DoT, so both are offered here.
    load_tls_config_alpns(
        &settings.cert_path,
        &settings.key_path,
        &[DOT_ALPN, XOT_ALPN],
        rustls::DEFAULT_VERSIONS,
    )
    .map(Arc::new)
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

/// Build the TLS configuration for DoH over HTTP/3: the DoH certificate,
/// `h3` ALPN, TLS 1.3 only (QUIC requires it).
pub fn build_doh3_tls_config(settings: &DohSettings) -> Result<Arc<ServerConfig>> {
    ensure_certificate_paths(
        &settings.cert_path,
        &settings.key_path,
        settings.self_signed,
        &settings.server_name,
    )?;
    let config = load_tls_config_versions(
        &settings.cert_path,
        &settings.key_path,
        DOH3_ALPN,
        &[&rustls::version::TLS13],
    )?;
    Ok(Arc::new(config))
}

/// Register a DoH over HTTP/3 listener on a Hickory server, on a bound UDP
/// socket. `timeout` closes a connection that sends no request for that
/// long.
pub fn register_doh3<T: RequestHandler>(
    server: &mut Server<T>,
    socket: tokio::net::UdpSocket,
    tls_config: Arc<ServerConfig>,
    timeout: Duration,
) -> Result<()> {
    server
        .register_h3_listener_with_tls_config(socket, timeout, tls_config, None)
        .map_err(|e| DaygleError::Tls(format!("cannot register the DoH over HTTP/3 listener: {e}")))
}

/// Build the DoQ TLS configuration (RFC 9250): `doq` ALPN, TLS 1.3 only.
///
/// Certificates are loaded from `cert_path`/`key_path`, generating a
/// self-signed pair first when requested and missing. QUIC mandates TLS 1.3,
/// so the returned config advertises no older versions.
pub fn build_doq_tls_config(settings: &DoqSettings) -> Result<Arc<ServerConfig>> {
    ensure_certificate_paths(
        &settings.cert_path,
        &settings.key_path,
        settings.self_signed,
        &settings.server_name,
    )?;
    let config = load_tls_config_versions(
        &settings.cert_path,
        &settings.key_path,
        DOQ_ALPN,
        &[&rustls::version::TLS13],
    )?;
    Ok(Arc::new(config))
}
