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
/// certificate files). A pair with only one half present is reported as an
/// error rather than completed: writing the generator's output over the file
/// that exists could destroy a certificate the operator installed.
pub fn ensure_certificate_paths(
    cert_path: &str,
    key_path: &str,
    self_signed: bool,
    server_name: &str,
) -> Result<()> {
    let have_cert = Path::new(cert_path).exists();
    let have_key = Path::new(key_path).exists();

    match (have_cert, have_key) {
        (true, true) => return Ok(()),
        // Only one half present: generating a pair here would overwrite the
        // file that exists, which may be a CA-issued certificate and its
        // only copy (a mistyped key_path must not destroy it). Name the
        // missing file and let the operator fix the path or remove the
        // other half deliberately.
        (true, false) => {
            return Err(DaygleError::Tls(format!(
                "certificate '{cert_path}' is present but its key '{key_path}' is missing; \
                 fix key_path, or remove the certificate so a self-signed pair is generated"
            )))
        }
        (false, true) => {
            return Err(DaygleError::Tls(format!(
                "key '{key_path}' is present but its certificate '{cert_path}' is missing; \
                 fix cert_path, or remove the key so a self-signed pair is generated"
            )))
        }
        (false, false) => {}
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

    write_pem_file(cert_path, cert_pem.as_bytes(), false)?;
    write_pem_file(key_path, key_pem.as_bytes(), true)?;
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

/// When a certificate valid from `not_before` to `not_after` (UNIX seconds)
/// is due for renewal: `renew_days` before it expires, but never earlier
/// than two thirds of the way through its life. A Let's Encrypt 90-day
/// certificate with the default 30 days is renewed at day 60 either way; a
/// short-lived one (a private CA's day-long certificates, a CA's
/// short-lived profile) is renewed partway through its life instead of at
/// every check, which a fixed window would demand from the day it is
/// issued.
pub fn renewal_due_at(not_before: i64, not_after: i64, renew_days: u32) -> i64 {
    let lifetime = (not_after - not_before).max(0);
    let window = (i64::from(renew_days) * 86_400).min(lifetime / 3);
    not_after - window
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

/// Write a PEM file, creating its directory first; a private key is created
/// owner-only (`0600`) and an existing file's mode is tightened before the
/// new bytes are written.
fn write_pem_file(path: &str, bytes: &[u8], private: bool) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(DaygleError::Io)?;
        }
    }
    #[cfg(unix)]
    if private {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path).map_err(DaygleError::Io)?;
        // Existing files retain their old mode when opened, so tighten it
        // before writing any new private-key bytes.
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(DaygleError::Io)?;
        file.write_all(bytes).map_err(DaygleError::Io)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    let _ = private;
    fs::write(path, bytes).map_err(DaygleError::Io)
}

/// TLS sessions an encrypted listener remembers for resumption. rustls keeps
/// 256 by default; a resolver with many (mobile) clients reconnecting after
/// every network change would evict them before they come back, and pay a
/// full handshake each time. An entry is a few hundred bytes.
pub const SESSION_CACHE_SIZE: usize = 8192;

/// Load a PEM certificate chain + private key into a rustls server config
/// advertising the given ALPN protocol (e.g. `dot` for DoT, `h2` for DoH),
/// with TLS 1.2 and 1.3.
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    alpn: &[u8],
) -> Result<rustls::ServerConfig> {
    load_tls_config_versions(cert_path, key_path, alpn, rustls::DEFAULT_VERSIONS)
}

/// Like [`load_tls_config`], restricted to `versions` (DoQ: QUIC requires
/// TLS 1.3 only).
pub fn load_tls_config_versions(
    cert_path: &str,
    key_path: &str,
    alpn: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ServerConfig> {
    load_tls_config_alpns(cert_path, key_path, &[alpn], versions)
}

/// Like [`load_tls_config_versions`], offering several ALPN protocols on one
/// listener (the DoT listener also serves zone transfers over TLS, RFC 9103).
pub fn load_tls_config_alpns(
    cert_path: &str,
    key_path: &str,
    alpns: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
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
        .with_protocol_versions(versions)
        .map_err(|e| DaygleError::Tls(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| DaygleError::Tls(format!("invalid TLS material: {e}")))?;

    config.alpn_protocols = alpns.iter().map(|p| p.to_vec()).collect();
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(SESSION_CACHE_SIZE);
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
    fn renewal_is_due_a_window_before_expiry_capped_at_a_third_of_the_life() {
        let day = 86_400;
        // 90 days, 30-day window: day 60.
        assert_eq!(renewal_due_at(0, 90 * day, 30), 60 * day);
        // 397 days: 30 days before expiry.
        assert_eq!(renewal_due_at(0, 397 * day, 30), 367 * day);
        // A day-long certificate: two thirds of the way, not at once.
        assert_eq!(renewal_due_at(0, day, 30), day - day / 3);
        // 6 days: day 4.
        assert_eq!(renewal_due_at(0, 6 * day, 30), 4 * day);
        // Nonsense validity (after before before): due at expiry.
        assert_eq!(renewal_due_at(day, 0, 30), 0);
    }

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
        assert!(config.session_storage.can_cache());

        // DoQ: TLS 1.3 only.
        let quic =
            load_tls_config_versions(&cert, &key, crate::DOQ_ALPN, &[&rustls::version::TLS13])
                .unwrap();
        assert_eq!(quic.alpn_protocols, vec![crate::DOQ_ALPN.to_vec()]);
    }

    #[cfg(unix)]
    #[test]
    fn generated_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        fs::write(&key, b"old key with permissive mode").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        generate_self_signed(cert.to_str().unwrap(), key.to_str().unwrap(), "daygle.test").unwrap();

        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// A half-present pair is never "completed" by generating a new
    /// certificate: that would overwrite the file that does exist.
    #[test]
    fn does_not_overwrite_the_half_of_a_pair_that_exists() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        fs::write(&cert, b"a CA-issued certificate the operator must not lose").unwrap();

        let error = ensure_certificate_paths(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            true,
            "daygle.test",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("key"), "{text}");
        assert!(!key.exists(), "a key was generated anyway");
        assert_eq!(
            fs::read(&cert).unwrap(),
            b"a CA-issued certificate the operator must not lose"
        );

        // The mirror case: a stray key does not overwrite itself either.
        let key_only = dir.path().join("only.key");
        fs::write(&key_only, b"stray key").unwrap();
        assert!(ensure_certificate_paths(
            dir.path().join("absent.crt").to_str().unwrap(),
            key_only.to_str().unwrap(),
            true,
            "daygle.test",
        )
        .is_err());
        assert_eq!(fs::read(&key_only).unwrap(), b"stray key");
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
