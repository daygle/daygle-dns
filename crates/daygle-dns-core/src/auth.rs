//! Password hashing for console user accounts.
//!
//! Uses PBKDF2-HMAC-SHA256 (NIST SP 800-132) implemented on top of `sha2`
//! and `hmac` - no C dependencies, and the primitive is already in the
//! dependency tree via rustls/ring. Hashes are serialized as
//!
//! ```text
//! pbkdf2-sha256$<iterations>$<salt-base64>$<hash-base64>
//! ```
//!
//! The default iteration count (210_000, in line with OWASP 2023 guidance for
//! PBKDF2-HMAC-SHA256) is used when generating new hashes. Verification
//! accepts any iteration count recorded in the stored hash, so admins can
//! raise the count in future without breaking existing accounts.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// PBKDF2 iteration count used when generating new password hashes.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 210_000;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// Derived key length in bytes (matches SHA-256 output).
const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Hash `password` with PBKDF2-HMAC-SHA256 and a random salt.
///
/// Returns the `pbkdf2-sha256$<iterations>$<salt>$<hash>` string suitable for
/// `api.users[].password_hash`.
pub fn hash_password(password: &str) -> String {
    hash_password_with(password, DEFAULT_PBKDF2_ITERATIONS)
}

/// Same as [`hash_password`] with an explicit iteration count.
pub fn hash_password_with(password: &str, iterations: u32) -> String {
    let mut salt = [0u8; SALT_LEN];
    // No `getrandom` dependency: SHA-256 of high-resolution time + address
    // entropy is adequate for an admin-console salt, and avoids pulling a
    // crypto RNG crate into daygle-dns-core. Uniqueness per account is what
    // matters (rainbow-table resistance), not cryptographic secrecy.
    let entropy = format!(
        "{:?}-{:?}-{:?}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        password.len(),
        std::process::id(),
    );
    let digest = Sha256::digest(entropy.as_bytes());
    salt.copy_from_slice(&digest[..SALT_LEN]);

    let key = pbkdf2_sha256(password.as_bytes(), &salt, iterations, KEY_LEN);
    format!(
        "pbkdf2-sha256${iterations}${}${}",
        BASE64.encode(salt),
        BASE64.encode(key)
    )
}

/// Verify `password` against a stored hash. Constant-time comparison.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((iterations, salt, expected)) = parse_hash(stored) else {
        return false;
    };
    let actual = pbkdf2_sha256(password.as_bytes(), &salt, iterations, expected.len());
    constant_time_eq(&actual, &expected)
}

/// Whether `stored` looks like a well-formed hash of this module's format.
pub fn is_valid_password_hash(stored: &str) -> bool {
    parse_hash(stored).is_some()
}

fn parse_hash(stored: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = stored.trim().split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
        return None;
    }
    let iterations: u32 = parts[1].parse().ok()?;
    if iterations == 0 || iterations > 100_000_000 {
        return None;
    }
    let salt = BASE64.decode(parts[2]).ok()?;
    let hash = BASE64.decode(parts[3]).ok()?;
    if salt.len() < 8 || hash.is_empty() {
        return None;
    }
    Some((iterations, salt, hash))
}

/// Minimal PBKDF2-HMAC-SHA256 (RFC 2898 §5.2) for `dk_len <= 32`.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    debug_assert!(dk_len <= 32, "single-block PBKDF2 only");
    // Block index 1 (first and only block for dk_len <= hash len).
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
    mac.update(&block);
    let mut u = mac.finalize().into_bytes().to_vec();

    let mut out = u.clone();
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes().to_vec();
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out.truncate(dk_len);
    out
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let hash = hash_password("hunter2");
        assert!(is_valid_password_hash(&hash));
        assert!(verify_password("hunter2", &hash));
        assert!(!verify_password("hunter3", &hash));
        assert!(!verify_password("", &hash));
        assert!(!verify_password("hunter2", "garbage"));
        assert!(!verify_password("hunter2", "pbkdf2-sha256$0$aaaa$bbbb"));
    }

    #[test]
    fn salt_makes_hashes_unique() {
        let a = hash_password("same");
        let b = hash_password("same");
        assert_ne!(a, b, "random salt must produce distinct hashes");
        assert!(verify_password("same", &a));
        assert!(verify_password("same", &b));
    }

    #[test]
    fn low_iteration_hash_round_trips() {
        let hash = hash_password_with("fast", 100);
        assert!(hash.starts_with("pbkdf2-sha256$100$"));
        assert!(verify_password("fast", &hash));
        assert!(!verify_password("slow", &hash));
    }

    #[test]
    fn rejects_malformed() {
        assert!(!is_valid_password_hash(""));
        assert!(!is_valid_password_hash("plain"));
        assert!(!is_valid_password_hash("pbkdf2-sha256$x$y$z"));
        assert!(!is_valid_password_hash("pbkdf2-sha256$1$!!!$!!!"));
    }
}
