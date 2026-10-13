//! Unit tests for [`super`] (password hashing).

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
fn pbkdf2_matches_rfc7914_test_vector() {
    // RFC 7914 §11: P="passwd", S="salt", c=1, dkLen=32 (first block).
    let dk = pbkdf2_sha256(b"passwd", b"salt", 1, 32);
    let hex: String = dk.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    );
}

#[test]
fn long_passwords_are_cheap_to_verify() {
    // Keying the PRF once means a huge password costs one extra hash,
    // not one per iteration.
    let long = "x".repeat(4 * 1024 * 1024);
    let hash = hash_password_with("short", 1000);
    let started = std::time::Instant::now();
    assert!(!verify_password(&long, &hash));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn rejects_malformed() {
    assert!(!is_valid_password_hash(""));
    assert!(!is_valid_password_hash("plain"));
    assert!(!is_valid_password_hash("pbkdf2-sha256$x$y$z"));
    assert!(!is_valid_password_hash("pbkdf2-sha256$1$!!!$!!!"));
}
