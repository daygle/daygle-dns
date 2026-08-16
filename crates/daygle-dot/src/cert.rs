//! TLS certificate loading and self-signed generation.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use daygle_core::config::DotSettings;
use daygle_core::error::{DaygleError, Result};
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

/// Generate a self-signed ECDSA certificate and write PEM files to disk.
pub fn generate_self_signed(
    cert_path: &str,
    key_path: &str,
    server_name: &str,
) -> Result<()> {
    let subject_alt_names = vec![server_name.to_string(), "localhost".to_string()];
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| DaygleError::Tls(format!("certificate generation failed: {e}")))?;

    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    write_if_parent_exists(cert_path, cert_pem.as_bytes())?;
    write_if_parent_exists(key_path, key_pem.as_bytes())?;
    info!("generated self-signed certificate for '{server_name}' at '{cert_path}'");
    Ok(())
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
pub fn load_tls_config(cert_path: &str, key_path: &str, alpn: &[u8]) -> Result<rustls::ServerConfig> {
    let certs = read_certs(cert_path)?;
    let key = read_key(key_path)?;

    // Pin the `ring` crypto provider explicitly: hickory's `tls-ring` feature
    // pulls in rustls/ring, which coexists with rustls' default aws-lc-rs
    // feature and would otherwise make `builder()` ambiguous.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
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
        assert!(load_tls_config(cert.to_str().unwrap(), key.to_str().unwrap(), crate::DOT_ALPN).is_err());
    }
}
