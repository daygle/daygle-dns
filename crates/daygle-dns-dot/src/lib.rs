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
//! [`rustls::ServerConfig`] for each protocol; socket handling is delegated
//! to Hickory's [`Server`], including its native DoQ (RFC 9250) listener
//! (registered from the `daygle-dns` crate via
//! [`build_doq_tls_config`]).

mod cert;

pub use cert::{
    ensure_certificate, ensure_certificate_paths, generate_self_signed, load_tls_config,
    load_tls_config_versions,
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
    let config = load_tls_config_versions(&settings.cert_path, &settings.key_path, DOQ_ALPN)?;
    Ok(Arc::new(config))
}

/// The client-side rustls `ClientConfig` used by the DNS client tool and the
/// stub-zone refresher to contact DoT/DoH servers.
///
/// Certificate verification uses the bundled Mozilla root store
/// (webpki-roots), so publicly trusted servers validate normally; private or
/// self-signed servers can be queried by passing their certificate chain via
/// `extra_roots` (PEM files), e.g. a Daygle deployment's own cert.
pub fn client_tls_config() -> Result<rustls::ClientConfig> {
    client_tls_config_with_roots(&[])
}

/// Like [`client_tls_config`], additionally trusting the PEM certificate
/// files in `extra_roots` (used to talk to self-signed private servers).
pub fn client_tls_config_with_roots(extra_roots: &[&str]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_roots {
        for cert in rustls_pki_types::pem::PemObject::pem_file_iter(path)
            .map_err(|e| DaygleError::Tls(format!("cannot read '{path}': {e}")))?
        {
            let cert = cert
                .map_err(|e| DaygleError::Tls(format!("cannot parse '{path}': {e}")))?;
            roots
                .add(cert)
                .map_err(|e| DaygleError::Tls(format!("cannot add root from {path}: {e}")))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DaygleError::Tls(format!("tls versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// One upstream DNS endpoint the DNS client tool / stub refresher can query.
#[derive(Debug, Clone)]
pub struct DnsEndpoint {
    /// Server address, as `IP` or `IP:port` (bracketed IPv6 accepted).
    pub server: String,
    /// Port (protocol default when `None`).
    pub port: Option<u16>,
    /// TLS server name for DoT/DoH (required for those protocols).
    pub server_name: Option<String>,
}

impl DnsEndpoint {
    /// Parse `IP`, `IP:port`, or `[IPv6]:port` (also accepts host names for
    /// the server field; they are resolved by the caller where needed).
    pub fn parse(server: &str, port: Option<u16>) -> Result<Self> {
        Ok(Self {
            server: server.trim().to_string(),
            port,
            server_name: None,
        })
    }

    /// Effective port for the endpoint given the protocol default.
    pub fn port_or(&self, default: u16) -> u16 {
        self.port.unwrap_or(default)
    }
}

/// Query `endpoint` over DoT (RFC 7858) and return the response message.
pub async fn dot_query_message(
    endpoint: &DnsEndpoint,
    message: &hickory_proto::op::Message,
) -> Result<hickory_proto::op::Message> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let host = endpoint
        .server
        .trim()
        .trim_start_matches('[')
        .split_once(']')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| endpoint.server.clone());
    let server_name = endpoint
        .server_name
        .clone()
        .unwrap_or_else(|| host.clone());
    let addr = resolve_endpoint(&endpoint.server, endpoint.port_or(853)).await?;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| DaygleError::Proto(format!("cannot connect to {addr}: {e}")))?;
    let tls = Arc::new(client_tls_config()?);
    let connector = tokio_rustls::TlsConnector::from(tls);
    let sni = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|e| DaygleError::Tls(format!("bad server name '{server_name}': {e}")))?
        .to_owned();
    let mut stream = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| DaygleError::Tls(format!("TLS handshake with {addr} failed: {e}")))?;

    let bytes = message
        .to_vec()
        .map_err(|e| DaygleError::Proto(format!("encode query: {e}")))?;
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| DaygleError::Proto(format!("write query: {e}")))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| DaygleError::Proto(format!("read length: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| DaygleError::Proto(format!("read message: {e}")))?;
    hickory_proto::op::Message::from_vec(&body)
        .map_err(|e| DaygleError::Proto(format!("decode response: {e}")))
}

/// Query a DoH endpoint (RFC 8484, POST `application/dns-message`).
pub async fn doh_query_message(
    endpoint: &DnsEndpoint,
    path: &str,
    message: &hickory_proto::op::Message,
) -> Result<hickory_proto::op::Message> {
    use hickory_proto::op::DnsRequestOptions;
    use hickory_net::xfer::{DnsHandle, FirstAnswer};

    let host = endpoint
        .server
        .trim()
        .trim_start_matches('[')
        .split_once(']')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| endpoint.server.clone());
    let server_name: Arc<str> = Arc::from(
        endpoint
            .server_name
            .clone()
            .unwrap_or_else(|| host.clone())
            .as_str(),
    );
    let addr = resolve_endpoint(&endpoint.server, endpoint.port_or(443)).await?;

    let tls = Arc::new(client_tls_config()?);
    let exchange = hickory_net::h2::HttpsClientStream::builder(
        tls,
        hickory_net::runtime::TokioRuntimeProvider::default(),
    )
    .exchange(addr, server_name.clone(), Arc::from(path))
    .await
    .map_err(|e| DaygleError::Proto(format!("DoH connection failed: {e}")))?;

    let mut query = hickory_proto::op::Message::query();
    query.add_query(message.queries.first().cloned().ok_or_else(|| {
        DaygleError::Proto("query message has no question".to_string())
    })?);
    // RFC 8484 §4.1: the DNS message ID is always 0 over DoH.
    query.metadata.id = 0;
    let request = hickory_proto::op::DnsRequest::new(query, DnsRequestOptions::default());
    let mut exchange = exchange;
    let response = DnsHandle::send(&mut exchange, request)
        .first_answer()
        .await
        .map_err(|e| DaygleError::Proto(format!("DoH query failed: {e}")))?;
    Ok(hickory_proto::op::Message::from(response))
}

/// Resolve an endpoint host (`IP` or hostname) to a `SocketAddr`. Bare host
/// names are resolved with the system resolver.
async fn resolve_endpoint(server: &str, port: u16) -> Result<std::net::SocketAddr> {
    let server = server.trim();
    if let Some(stripped) = server.strip_prefix('[') {
        let host = stripped
            .split_once(']')
            .map(|(h, _)| h)
            .ok_or_else(|| DaygleError::Config(format!("unbalanced '[' in '{server}'")))?;
        return format!("{host}:{port}")
            .parse()
            .map_err(|e| DaygleError::Config(format!("bad address '{server}': {e}")));
    }
    if server.parse::<std::net::IpAddr>().is_ok() {
        return format!("{server}:{port}")
            .parse()
            .map_err(|e| DaygleError::Config(format!("bad address '{server}': {e}")));
    }
    let resolved = tokio::net::lookup_host((server, port))
        .await
        .map_err(|e| DaygleError::Proto(format!("cannot resolve '{server}': {e}")))?
        .next()
        .ok_or_else(|| DaygleError::Proto(format!("'{server}' resolved to no addresses")))?;
    Ok(resolved)
}
