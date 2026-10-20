//! Time-based one-time passwords (RFC 6238) for two-factor console login,
//! and the single-use recovery codes that go with them.
//!
//! Codes are 6 digits over 30-second steps with HMAC-SHA1, the settings
//! every authenticator app supports. A code is accepted one step either
//! side of now (clock drift), and never twice: the caller stores the step
//! of the last accepted code and passes it back.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::auth::constant_time_eq;

/// Seconds per code.
pub const STEP_SECS: u64 = 30;
/// Digits per code.
const DIGITS: u32 = 6;
/// Recovery codes handed out when two-factor login is turned on.
pub const RECOVERY_CODES: usize = 10;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    if getrandom::fill(&mut bytes).is_err() {
        // As for password salts: never fall back to a weak secret.
        panic!("no OS CSPRNG available for two-factor secrets");
    }
    bytes
}

/// A new secret (160 bits, base32 as authenticator apps expect it).
pub fn generate_secret() -> String {
    BASE32_NOPAD.encode(&random_bytes::<20>())
}

/// The `otpauth://` URI an authenticator app reads from a QR code.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let issuer = url::form_urlencoded::byte_serialize(issuer.as_bytes()).collect::<String>();
    let account = url::form_urlencoded::byte_serialize(account.as_bytes()).collect::<String>();
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}"
    )
}

/// The code for `step` (HOTP, RFC 4226).
fn code_at(key: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 10u32.pow(DIGITS)
}

/// The step `unix_secs` falls in.
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// Check `code` against `secret` at `unix_secs`. Returns the step it
/// matched, which must be later than `last_step` (a code is used once).
pub fn verify(secret: &str, code: &str, unix_secs: u64, last_step: u64) -> Option<u64> {
    let key = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(unix_secs);
    let mut matched = None;
    // Check every candidate step so the time taken does not depend on which
    // one matched.
    for step in [now.saturating_sub(1), now, now + 1] {
        let expected = format!("{:0width$}", code_at(&key, step), width = DIGITS as usize);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) && step > last_step {
            matched = Some(step);
        }
    }
    matched
}

/// The code an authenticator app shows for `secret` at `unix_secs`.
pub fn code_for(secret: &str, unix_secs: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    Some(format!(
        "{:0width$}",
        code_at(&key, step_at(unix_secs)),
        width = DIGITS as usize
    ))
}

/// New recovery codes (`xxxx-xxxx`, lowercase letters and digits), and
/// their hashes for storage.
pub fn generate_recovery_codes() -> (Vec<String>, Vec<String>) {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let codes: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| {
            let bytes = random_bytes::<8>();
            let chars: String = bytes
                .iter()
                .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
                .collect();
            format!("{}-{}", &chars[..4], &chars[4..])
        })
        .collect();
    let hashes = codes.iter().map(|c| hash_recovery_code(c)).collect();
    (codes, hashes)
}

/// How a recovery code is stored. They are random enough (about 39 bits
/// each, from a CSPRNG, and login attempts are throttled) that a plain
/// SHA-256 is enough; the dashes and case are ignored.
pub fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let digest = Sha256::digest(normalized.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `code` looks like a recovery code rather than a 6-digit one.
pub fn is_recovery_code(code: &str) -> bool {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).count() == 8
        && code.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B (SHA-1 key "12345678901234567890"), last 6 digits.
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        // The RFC's key: the ASCII digits 1-9, 0, twice.
        let key: Vec<u8> = b"1234567890".repeat(2);
        for (time, code) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(code_at(&key, step_at(time)), code, "t = {time}");
        }
    }

    #[test]
    fn verify_accepts_drift_and_refuses_replay() {
        let secret = generate_secret();
        let key = BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
        let now = 1_700_000_000;
        let code = |step| format!("{:06}", code_at(&key, step));
        let step = step_at(now);
        assert_eq!(verify(&secret, &code(step), now, 0), Some(step));
        assert_eq!(verify(&secret, &code(step - 1), now, 0), Some(step - 1));
        assert_eq!(verify(&secret, &code(step + 1), now, 0), Some(step + 1));
        assert_eq!(verify(&secret, &code(step - 2), now, 0), None);
        // Already used.
        assert_eq!(verify(&secret, &code(step), now, step), None);
        // Spaces are fine, other junk is not.
        let spaced = format!("{} {}", &code(step)[..3], &code(step)[3..]);
        assert_eq!(verify(&secret, &spaced, now, 0), Some(step));
        assert_eq!(verify(&secret, "12345", now, 0), None);
        assert_eq!(verify(&secret, "abcdef", now, 0), None);
        assert_eq!(verify("not base32!", &code(step), now, 0), None);
    }

    #[test]
    fn recovery_codes_hash_ignoring_case_and_dashes() {
        let (codes, hashes) = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == 9 && is_recovery_code(c)));
        assert_eq!(
            hash_recovery_code(&codes[0].to_uppercase().replace('-', "")),
            hashes[0]
        );
        assert!(!is_recovery_code("123456"));
        assert!(otpauth_uri("Daygle DNS", "glen", "ABC")
            .starts_with("otpauth://totp/Daygle+DNS:glen?secret=ABC&issuer=Daygle+DNS"));
    }
}
