//! Storage hashing for login-session and API tokens.
//!
//! Tokens are 256 bits straight from the OS CSPRNG, so there is no limited
//! input space to defend: one SHA-256 is the correct storage function and
//! keeps the cost at a few hundred nanoseconds. This runs twice per
//! authenticated request (the session lookup and the API-token lookup), and
//! the presented token is attacker-controlled, so a password KDF here would
//! hand any caller hundreds of milliseconds of CPU per request.
//!
//! The lowercase hex digest is the primary key of `console_sessions` and
//! `api_tokens`, so the encoding must not change without a migration.

use sha2::{Digest as _, Sha256};

/// How a login session or API token is stored: its SHA-256, lowercase hex.
pub fn hash_token(token: &str) -> String {
    // Encode into one pre-sized string: the obvious `format!("{b:02x}")` per
    // byte allocates a `String` 32 times per call.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_storage_format_is_stable() {
        // sha256("abc") is the FIPS 180 test vector. A different value here
        // would orphan every stored session and API token.
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn tokens_hash_to_lowercase_hex_and_stay_distinct() {
        let a = hash_token("token-a");
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(a, hash_token("token-a"));
        assert_ne!(a, hash_token("token-b"));
    }
}
