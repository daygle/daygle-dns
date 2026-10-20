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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// PBKDF2 iteration count used when generating new password hashes.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 210_000;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// Derived key length in bytes (matches SHA-256 output).
const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Hash `password` with PBKDF2-HMAC-SHA256 and a CSPRNG-generated salt.
///
/// Returns the `pbkdf2-sha256$<iterations>$<salt>$<hash>` string suitable for
/// `api.users[].password_hash`.
pub fn hash_password(password: &str) -> String {
    hash_password_with(password, DEFAULT_PBKDF2_ITERATIONS)
}

/// Same as [`hash_password`] with an explicit iteration count.
pub fn hash_password_with(password: &str, iterations: u32) -> String {
    // Salt straight from the OS CSPRNG: 16 bytes = 128 bits, well above the
    // OWASP minimum.
    let mut salt = [0u8; SALT_LEN];
    if getrandom::fill(&mut salt).is_err() {
        // OS RNG unavailable: refuse to produce a hash rather than emit a
        // weak salt. The caller (CLI / setup handler) should treat this as a
        // fatal misconfiguration.
        panic!("no OS CSPRNG available to seed password salt");
    }

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
    // Key the PRF once and clone the keyed state for every iteration. Keying
    // per iteration re-hashed the whole password each time, which made a
    // single login attempt with a multi-megabyte password cost hundreds of
    // gigabytes of hashing.
    let prf = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");

    // Block index 1 (first and only block for dk_len <= hash len).
    let mut mac = prf.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();

    let mut out = u.to_vec();
    for _ in 1..iterations {
        let mut mac = prf.clone();
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out.truncate(dk_len);
    out
}

/// Constant-time byte comparison (the length itself is not secret).
/// How a login session or API token is stored: its SHA-256, hex. The
/// tokens are long random strings, so a fast hash is enough and a stolen
/// database cannot be used to sign in.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest as _;
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
mod tests;
