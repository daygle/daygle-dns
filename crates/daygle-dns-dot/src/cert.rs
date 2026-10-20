//! TLS certificate loading and self-signed generation.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use daygle_dns_core::config::DotSettings;
use daygle_dns_core::error::{DaygleError, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use tracing::info;

/// Ensure the configured certificate/key exist, generating a self-signed pair
/// when `settings.self_signed` is enabled.
pub fn ensure_certificate(settings: &DotSettings) -> Result<()> {
    ensure_certificate_paths(
        &settings.cert_path,
        &settings.key_path,
        settings.self_signed,
        &settings.server_name,
    )
}

/// Ensure the given certificate/key exist, generating a self-signed pair when
/// `self_signed` is enabled. Shared by DoT and DoH (both may reuse the same
/// certificate files).
pub fn ensure_certificate_paths(
    cert_path: &str,
    key_path: &str,
    self_signed: bool,
    server_name: &str,
) -> Result<()> {
    let have_cert = Path::new(cert_path).exists();
    let have_key = Path::new(key_path).exists();

    if have_cert && have_key {
        return Ok(());
    }
    if !self_signed {
        return Err(DaygleError::Tls(format!(
            "certificate '{cert_path}' or key '{key_path}' is missing (set self_signed = true to generate one)"
        )));
    }
    generate_self_signed(cert_path, key_path, server_name)
}

/// Generate a self-signed ECDSA certificate for `server_name`, returning the
/// PEM certificate and private key (no files are touched).
pub fn generate_self_signed_pem(server_name: &str) -> Result<(String, String)> {
    let subject_alt_names = vec![server_name.to_string(), "localhost".to_string()];
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| DaygleError::Tls(format!("certificate generation failed: {e}")))?;

    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    Ok((cert_pem, key_pem))
}

/// Generate a self-signed ECDSA certificate and write PEM files to disk.
pub fn generate_self_signed(cert_path: &str, key_path: &str, server_name: &str) -> Result<()> {
    let (cert_pem, key_pem) = generate_self_signed_pem(server_name)?;

    write_if_parent_exists(cert_path, cert_pem.as_bytes())?;
    write_if_parent_exists(key_path, key_pem.as_bytes())?;
    info!("generated self-signed certificate for '{server_name}' at '{cert_path}'");
    Ok(())
}

/// What the console shows about a certificate: its first (leaf) entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Subject common name (or the whole subject when it has no CN).
    pub subject: String,
    /// Issuer common name (or the whole issuer).
    pub issuer: String,
    /// Issued by itself rather than by a certificate authority.
    pub self_signed: bool,
    /// Validity window, as UNIX seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// Subject alternative names (DNS names and IP addresses).
    pub names: Vec<String>,
}

/// Read the leaf certificate of a PEM chain for display.
pub fn describe_certificate(cert_pem: &str) -> Result<CertificateInfo> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::x509::X509Name;

    let der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| DaygleError::Tls("no certificate found in the PEM".to_string()))?
        .map_err(|e| DaygleError::Tls(format!("cannot parse certificate PEM: {e}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| DaygleError::Tls(format!("cannot read certificate: {e}")))?;

    let common_name = |name: &X509Name<'_>| {
        name.iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| name.to_string())
    };
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => names.push(dns.to_string()),
                GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => names.push(
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).unwrap_or_default())
                            .to_string(),
                    ),
                    16 => names.push(
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap_or_default())
                            .to_string(),
                    ),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let validity = cert.validity();
    Ok(CertificateInfo {
        subject: common_name(cert.subject()),
        issuer: common_name(cert.issuer()),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
        names,
    })
}

/// Build a TLS server config from an in-memory PEM pair (a certificate
/// managed on the Certificates page), offering the given ALPN protocols.
pub fn tls_config_from_pem(
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| DaygleError::Tls(format!("cannot parse certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(DaygleError::Tls("no certificate found in the PEM".into()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| DaygleError::Tls(format!("cannot parse key PEM: {e}")))?;
    let provider = crypto_provider().ok_or_else(|| {
        DaygleError::Tls("no rustls crypto provider available; enable `ring` or `aws_lc_rs`".into())
    })?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DaygleError::Tls(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| DaygleError::Tls(format!("invalid TLS material: {e}")))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// Validate that the PEM `cert_pem`/`key_pem` pair is well-formed and the key
/// matches the certificate (by building a rustls server config from them).
pub fn validate_pem_pair(cert_pem: &str, key_pem: &str) -> Result<()> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| DaygleError::Tls(format!("cannot parse certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(DaygleError::Tls(
            "no certificates found in the uploaded PEM".to_string(),
        ));
    }
    let key = PrivateKeyDer::pem_slice_iter(key_pem.as_bytes())
        .next()
        .ok_or_else(|| DaygleError::Tls("no private key found in the uploaded PEM".to_string()))?
        .map_err(|e| DaygleError::Tls(format!("cannot parse key PEM: {e}")))?;

    let provider = crypto_provider().ok_or_else(|| {
        DaygleError::Tls(
            "no rustls crypto provider available; enable the `ring` or `aws_lc_rs` feature".into(),
        )
    })?;
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DaygleError::Tls(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            DaygleError::Tls(format!(
                "invalid TLS material (key does not match the certificate?): {e}"
            ))
        })?;
    Ok(())
}

/// Return a crypto provider for rustls.
///
/// Tries the process-wide default first (set by `rustls::crypto::aws_lc_rs::default_provider`
/// or `ring::default_provider` depending on which feature the binary was built
/// with), then falls back to `ring` explicitly. Previously we hardcoded
/// `ring::default_provider()` which panics at runtime if the binary was built
/// with only `aws-lc-rs` enabled.
pub fn crypto_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    if let Some(p) = rustls::crypto::CryptoProvider::get_default() {
        return Some(p.clone());
    }
    // Fall back: install ring explicitly. On a race with another thread that
    // already installed a provider, `install_default` returns it in the Err.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => rustls::crypto::CryptoProvider::get_default().cloned(),
        Err(installed) => Some(installed),
    }
}

fn write_if_parent_exists(path: &str, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(DaygleError::Io)?;
        }
    }
    fs::write(path, bytes).map_err(DaygleError::Io)
}

/// Load a PEM certificate chain + private key into a rustls server config
/// advertising the given ALPN protocol (e.g. `dot` for DoT, `h2` for DoH).
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    alpn: &[u8],
) -> Result<rustls::ServerConfig> {
    load_tls_config_versions(cert_path, key_path, alpn)
}

/// Like [`load_tls_config`], but restricted to the given protocol versions
/// (needed for DoQ, where QUIC requires TLS 1.3 only).
pub fn load_tls_config_versions(
    cert_path: &str,
    key_path: &str,
    alpn: &[u8],
) -> Result<rustls::ServerConfig> {
    let certs = read_certs(cert_path)?;
    let key = read_key(key_path)?;

    // Use whatever crypto provider rustls has installed at runtime. We avoid
    // hardcoding `ring::default_provider()` so binaries built without the
    // `ring` feature (e.g. only `aws-lc-rs`) still start cleanly.
    let provider = crypto_provider().ok_or_else(|| {
        DaygleError::Tls("no rustls crypto provider available; enable `ring` or `aws_lc_rs`".into())
    })?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DaygleError::Tls(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| DaygleError::Tls(format!("invalid TLS material: {e}")))?;

    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

fn read_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| DaygleError::Tls(format!("cannot open cert file '{path}': {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| DaygleError::Tls(format!("cannot parse certificate '{path}': {e}")))?;
    if certs.is_empty() {
        return Err(DaygleError::Tls(format!(
            "no certificates found in '{path}'"
        )));
    }
    Ok(certs)
}

fn read_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::pem_file_iter(path)
        .map_err(|e| DaygleError::Tls(format!("cannot open key file '{path}': {e}")))?
        .next()
        .ok_or_else(|| DaygleError::Tls(format!("no private key found in '{path}'")))?
        .map_err(|e| DaygleError::Tls(format!("cannot parse key '{path}': {e}")))
}

#[cfg(test)]
mod tests {

    #[test]
    fn describes_a_generated_certificate() {
        let (cert_pem, _) = generate_self_signed_pem("dns.example.test").unwrap();
        let info = describe_certificate(&cert_pem).unwrap();
        assert!(info.self_signed);
        assert_eq!(info.subject, info.issuer);
        assert!(info.names.contains(&"dns.example.test".to_string()));
        assert!(info.names.contains(&"localhost".to_string()));
        assert!(info.not_before < info.not_after);
        assert!(describe_certificate("not a certificate").is_err());
    }
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_loads_self_signed() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        let cert = cert.to_str().unwrap().to_string();
        let key = key.to_str().unwrap().to_string();

        generate_self_signed(&cert, &key, "daygle.test").unwrap();
        assert!(Path::new(&cert).exists());
        assert!(Path::new(&key).exists());

        let config = load_tls_config(&cert, &key, crate::DOT_ALPN).unwrap();
        assert_eq!(config.alpn_protocols, vec![crate::DOT_ALPN.to_vec()]);
    }

    #[test]
    fn missing_cert_without_self_signed_fails() {
        let settings = DotSettings {
            cert_path: "/nonexistent/a.crt".to_string(),
            key_path: "/nonexistent/a.key".to_string(),
            self_signed: false,
            ..Default::default()
        };
        assert!(matches!(
            ensure_certificate(&settings),
            Err(DaygleError::Tls(_))
        ));
    }

    #[test]
    fn rejects_garbage_cert() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("bad.crt");
        fs::write(&cert, b"not a certificate").unwrap();
        let key = dir.path().join("bad.key");
        fs::write(&key, b"not a key").unwrap();
        assert!(load_tls_config(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            crate::DOT_ALPN
        )
        .is_err());
    }
}
