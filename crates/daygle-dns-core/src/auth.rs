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
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

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
    let mut salt = [0u8; SALT_LEN];
    // Cryptographic salt: pull entropy from the OS CSPRNG. We use a tiny
    // SHA-256 of the OS-provided random bytes (so that any caller missing
    // `getrandom` at link-time fails closed) and seed the password hash with
    // it. The salt is the only secret input to PBKDF2; its entropy must be
    // cryptographic. 16 bytes = 128 bits, well above the OWASP minimum.
    let mut seed = [0u8; 32];
    if getrandom_bytes(&mut seed).is_err() {
        // OS RNG unavailable: refuse to produce a hash rather than emit a
        // weak salt. The caller (CLI / setup handler) should treat this as a
        // fatal misconfiguration.
        panic!("no OS CSPRNG available to seed password salt");
    }
    let digest = Sha256::digest(&seed);
    salt.copy_from_slice(&digest[..SALT_LEN]);

    let key = pbkdf2_sha256(password.as_bytes(), &salt, iterations, KEY_LEN);
    format!(
        "pbkdf2-sha256${iterations}${}${}",
        BASE64.encode(salt),
        BASE64.encode(key)
    )
}

/// Fill `buf` with cryptographically-secure random bytes from the OS CSPRNG.
///
/// Uses `getrandom(2)` on Linux/BSDs that export it, `SecRandomCopyBytes` on
/// Apple platforms (macOS does not provide `getrandom(2)`, and declaring it
/// fails the final link), and BCrypt on Windows. Panics only when no source
/// is available - we never want to silently fall back to a weak RNG.
fn getrandom_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::ffi::c_void;
        #[link(name = "Security", kind = "framework")]
        extern "C" {
            fn SecRandomCopyBytes(rnd: *const c_void, count: usize, bytes: *mut u8) -> i32;
        }
        // NULL = kSecRandomDefault: the system CSPRNG. 0 = errSecSuccess.
        let status = unsafe { SecRandomCopyBytes(std::ptr::null(), buf.len(), buf.as_mut_ptr()) };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        // Try libc `getrandom(2)` directly to avoid pulling in a new crate.
        let mut filled = 0;
        while filled < buf.len() {
            let n = unsafe {
                libc_getrandom(&mut buf[filled..])
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            filled += n as usize;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut c_void,
                buffer: *mut u8,
                length: u32,
                flags: u32,
            ) -> i32;
        }
        let alg = std::ptr::null_mut();
        // BCRYPT_RNG_ALGORITHM = null handle; with the system-preferred RNG
        // flag set, the OS uses its own CSPRNG.
        let status = unsafe {
            BCryptGenRandom(
                alg,
                buf.as_mut_ptr(),
                buf.len() as u32,
                2, // BCRYPT_USE_SYSTEM_PREFERRED_RNG
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = buf;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no OS CSPRNG binding for this platform",
        ))
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
unsafe fn libc_getrandom(buf: &mut [u8]) -> isize {
    extern "C" {
        fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;
    }
    unsafe { getrandom(buf.as_mut_ptr(), buf.len(), 0) }
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
