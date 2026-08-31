//! TSIG transaction authentication (RFC 8945).
//!
//! TSIG authenticates DNS messages with a shared-secret HMAC carried in a
//! TSIG record at the end of the additional section. Daygle uses it for:
//!
//! - **Zone transfers** (AXFR/IXFR): a secondary must sign its request with
//!   a key the primary knows; every response message is signed in reply.
//! - **Dynamic updates** (RFC 2136): the updater signs the UPDATE; the
//!   response is signed back so the client can authenticate the server.
//!
//! The hickory primitives used here:
//!
//! - [`tsig::message_tbs`] builds the to-be-signed bytes of a message plus
//!   the TSIG variables (RFC 8945 §5.2).
//! - [`tsig::signed_bitmessage_to_buf`] recovers those bytes from a wire
//!   message that ends with a TSIG record (handling the request-MAC chaining
//!   through `previous_hash`).
//! - [`TsigAlgorithm::verify_mac`] / [`TsigAlgorithm::mac_data`] do the
//!   constant-time HMAC compare / signing.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;

use daygle_dns_core::config::TsigKeyConfig;
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::tsig::{
    make_tsig_record, message_tbs, signed_bitmessage_to_buf, TsigAlgorithm, TsigError, TSIG,
};
use hickory_proto::rr::{TSigner, TSigResponseContext};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;

/// Default time window (seconds) a TSIG timestamp may drift, per RFC 8945
/// §5.2.3 (fudge is usually 300).
pub const DEFAULT_FUDGE: u16 = 300;

/// A loaded TSIG key ready for signing and verification.
#[derive(Debug, Clone)]
pub struct TsigKey {
    /// Key name as sent on the wire (trailing dot).
    pub name: Name,
    /// HMAC algorithm.
    pub algorithm: TsigAlgorithm,
    /// Raw secret bytes (decoded from base64).
    pub secret: Vec<u8>,
    /// Accepted timestamp drift in seconds.
    pub fudge: u16,
}

impl TsigKey {
    /// Build a key from its configuration. Returns an error for unsupported
    /// algorithms or malformed base64 secrets.
    pub fn from_config(config: &TsigKeyConfig) -> Result<Self, String> {
        let algorithm = TsigAlgorithm::from_name(
            Name::from_ascii(config.algorithm.trim()).map_err(|e| {
                format!("tsig key '{}' has invalid algorithm name: {e}", config.name)
            })?,
        );
        if !algorithm.supported() {
            return Err(format!(
                "tsig key '{}' uses algorithm '{}' which hickory cannot sign (supported: hmac-sha256, hmac-sha384, hmac-sha512)",
                config.name, config.algorithm
            ));
        }
        let secret = base64::engine::general_purpose::STANDARD
            .decode(config.secret.trim())
            .map_err(|e| format!("tsig key '{}' secret is not valid base64: {e}", config.name))?;
        if secret.is_empty() {
            return Err(format!("tsig key '{}' has an empty secret", config.name));
        }
        let name = normalize_key_name(&config.name)?;
        Ok(Self {
            name,
            algorithm,
            secret,
            fudge: DEFAULT_FUDGE,
        })
    }

    /// Build the hickory [`TSigner`] for this key (signing + verification).
    pub fn tsigner(&self) -> TSigner {
        TSigner::new(
            self.secret.clone(),
            self.algorithm.clone(),
            self.name.clone(),
            self.fudge,
        )
        .expect("key algorithm and name validated at construction")
    }
}

/// Normalize a TSIG key name to a lowercase FQDN [`Name`].
pub fn normalize_key_name(name: &str) -> Result<Name, String> {
    let trimmed = name.trim();
    let with_dot = if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    };
    Name::from_ascii(&with_dot)
        .map(|n| n.to_lowercase())
        .map_err(|e| format!("invalid tsig key name '{name}': {e}"))
}

/// The set of keys this process knows, keyed by normalized lowercase name.
#[derive(Debug, Clone, Default)]
pub struct TsigKeyRing {
    keys: HashMap<String, TsigKey>,
}

impl TsigKeyRing {
    /// Load keys from configuration.
    pub fn from_configs(configs: &[TsigKeyConfig]) -> Result<Self, String> {
        let mut keys = HashMap::new();
        for config in configs {
            let key = TsigKey::from_config(config)?;
            keys.insert(key.name.to_string().to_lowercase(), key);
        }
        Ok(Self { keys })
    }

    /// Look up a key by its wire name.
    pub fn get(&self, name: &Name) -> Option<&TsigKey> {
        self.keys.get(&name.to_string().to_lowercase())
    }

    /// Look up a key by config-style name (with or without trailing dot).
    pub fn get_by_config_name(&self, name: &str) -> Option<&TsigKey> {
        normalize_key_name(name)
            .ok()
            .and_then(|n| self.get(&n))
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The outcome of verifying an inbound TSIG-signed request.
// `Valid` is deliberately the large variant: it is the success path returned
// once per verified transfer/update and consumed immediately, so boxing its
// fields would add an allocation on the hot path to shrink a short-lived value.
#[allow(clippy::large_enum_variant)]
pub enum TsigVerifyOutcome {
    /// The message carries a valid TSIG from a known key.
    Valid {
        /// The key that signed the request. Responses must be signed with
        /// the same key, and include the request MAC when chaining.
        key: TsigKey,
        /// The request MAC (from the verified TSIG record).
        request_mac: Vec<u8>,
        /// The TSIG record as received (time/fudge for the reply variables).
        request_tsig: Box<Record<TSIG>>,
        /// Ready-made response signer context (request MAC chained).
        response_context: TSigResponseContext,
    },
    /// The message carries a TSIG but verification failed. RFC 8945 §5.2.2:
    /// respond with the standard RCODE plus BADTIME/BADSIG/BADKEY in a
    /// signed reply when possible; Daygle refuses instead (safe for the
    /// transfer/update use case, which is ACL-shaped, not public).
    Invalid(TsigFailure),
    /// The message carries no TSIG at all.
    Unsigned,
}

/// Why verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigFailure {
    /// TSIG from an unknown key name.
    UnknownKey,
    /// MAC does not match.
    BadSignature,
    /// Timestamp outside the fudge window.
    BadTime,
    /// The wire message is malformed (no TSIG where one was claimed, etc.).
    Malformed,
}

impl TsigFailure {
    /// The TSIG error code to report (RFC 8945 §3.3).
    pub fn tsig_error(self) -> Option<TsigError> {
        match self {
            TsigFailure::UnknownKey => Some(TsigError::BadKey),
            TsigFailure::BadSignature => Some(TsigError::BadSig),
            TsigFailure::BadTime => Some(TsigError::BadTime),
            TsigFailure::Malformed => None,
        }
    }
}

/// Verify the TSIG on an inbound request given its raw wire bytes.
///
/// `raw` must be the exact bytes as received (before any re-encoding):
/// TSIG covers the wire form including the trailing TSIG record. On success
/// the caller gets the key, the request MAC (for response chaining), and a
/// [`TSigResponseContext`] ready to sign the reply (including RFC 8945
/// BADTIME/BADSIG error replies).
pub fn verify_request(
    key_ring: &TsigKeyRing,
    raw: &[u8],
    request_id: u16,
) -> TsigVerifyOutcome {
    // A message with no additional records cannot carry a TSIG.
    if raw.len() < 12 {
        return TsigVerifyOutcome::Invalid(TsigFailure::Malformed);
    }
    let additionals = u16::from_be_bytes([raw[10], raw[11]]);
    if additionals == 0 {
        return TsigVerifyOutcome::Unsigned;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Find the TSIG record's key name without full decode: hickory's
    // verify_message_byte handles key match, MAC, and time window at once,
    // but needs the signer up front. Peek the TSIG name from the wire.
    let Some(tsig_name) = peek_tsig_key_name(raw) else {
        return TsigVerifyOutcome::Invalid(TsigFailure::Malformed);
    };
    let Some(key) = key_ring.get(&tsig_name) else {
        return TsigVerifyOutcome::Invalid(TsigFailure::UnknownKey);
    };
    let signer = key.tsigner();

    let (_, time, window) = match signer.verify_message_byte(raw, None, true) {
        Ok(result) => result,
        Err(_) => {
            return TsigVerifyOutcome::Invalid(TsigFailure::BadSignature);
        }
    };
    if !window.contains(&now) {
        return TsigVerifyOutcome::Invalid(TsigFailure::BadTime);
    }
    let _ = time;

    // Rebuild the request MAC and response context from the wire record.
    let (_, tsig_rr) = match signed_bitmessage_to_buf(raw, None, true) {
        Ok(result) => result,
        Err(_) => return TsigVerifyOutcome::Invalid(TsigFailure::Malformed),
    };
    let request_mac = tsig_rr.data.mac.clone();
    
    TsigVerifyOutcome::Valid {
        key: key.clone(),
        request_mac: request_mac.clone(),
        request_tsig: tsig_rr,
        response_context: TSigResponseContext::new(
            request_id,
            now,
            signer,
            request_mac,
            None,
        ),
    }
}

/// Read the TSIG record's key name from a wire message without verifying:
/// the TSIG is the last record in the additional section.
fn peek_tsig_key_name(raw: &[u8]) -> Option<Name> {
    let message = Message::from_vec(raw).ok()?;
    message.signature().map(|tsig| tsig.name.clone())
}

/// Sign a response message with `key`, chaining the request MAC per
/// RFC 8945 §5.4.2 so the client can authenticate the server and detect
/// replay of an older request.
///
/// `response` is the finished response message (id, flags, sections set);
/// the returned bytes are the wire form with the TSIG record appended.
pub fn sign_response(
    response: &Message,
    key: &TsigKey,
    request_mac: &[u8],
) -> Result<Vec<u8>, String> {
    let signer = key.tsigner();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let context = TSigResponseContext::new(
        response.metadata.id,
        now,
        signer,
        request_mac.to_vec(),
        None,
    );

    // Encode the unsigned response body first, then sign it in context.
    let body = response
        .to_bytes()
        .map_err(|e| format!("tsig response encoding failed: {e}"))?;
    let tsig = context
        .sign(&body)
        .map_err(|e| format!("tsig response signing failed: {e}"))?;

    // Append the TSIG record to the response wire form. Re-encoding through
    // Message would drop the signature, so emit the body and the TSIG record
    // with the additional-count patched in the header.
    let mut out = body.clone();
    let tsig_bytes = tsig
        .to_bytes()
        .map_err(|e| format!("tsig record encoding failed: {e}"))?;
    out.extend_from_slice(&tsig_bytes);
    // Patch the additional record count (header bytes 10-11) by one.
    let additionals = u16::from_be_bytes([out[10], out[11]]) + 1;
    out[10..12].copy_from_slice(&additionals.to_be_bytes());
    Ok(out)
}

/// Sign a client request (used by the secondary-side transfer client).
/// Returns the wire bytes of `message` with its TSIG record appended.
pub fn sign_request(message: &Message, key: &TsigKey) -> Result<Vec<u8>, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pre_tsig = TSIG::new(
        key.algorithm.clone(),
        now,
        key.fudge,
        Vec::new(),
        message.metadata.id,
        None,
        Vec::new(),
    );
    let tbs = message_tbs(message, &pre_tsig, &key.name)
        .map_err(|e| format!("tsig request tbs failed: {e}"))?;
    let mac = key
        .algorithm
        .mac_data(&key.secret, &tbs)
        .map_err(|e| format!("tsig request mac failed: {e}"))?;
    let mut signed = message.clone();
    signed.set_signature(Box::new(make_tsig_record(
        key.name.clone(),
        pre_tsig.set_mac(mac),
    )));
    signed
        .to_bytes()
        .map_err(|e| format!("tsig request encoding failed: {e}"))
}

/// Verify a TSIG-signed response from a master, chaining the request MAC.
/// `request_mac` is the MAC of our signed request. Also enforces the
/// response timestamp window.
pub fn verify_response(raw: &[u8], key: &TsigKey, request_mac: &[u8]) -> Result<(), String> {
    let signer = key.tsigner();
    let (_, time, window) = signer
        .verify_message_byte(raw, Some(request_mac), true)
        .map_err(|e| format!("tsig response verification failed: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !window.contains(&now) {
        return Err(format!(
            "tsig response time {time} outside accepted window (now {now})"
        ));
    }
    Ok(())
}

/// Short label for test failure messages.
#[cfg(test)]
fn failure_label(outcome: &TsigVerifyOutcome) -> &'static str {
    match outcome {
        TsigVerifyOutcome::Valid { .. } => "valid",
        TsigVerifyOutcome::Invalid(_) => "invalid",
        TsigVerifyOutcome::Unsigned => "unsigned",
    }
}

/// Build a fresh response-signing context for `key` without a prior request
/// MAC (used when a valid request verification did not yield a context, e.g.
/// for tests or unsigned-refusal replies).
pub fn response_context_for(key: &TsigKey) -> hickory_proto::rr::TSigResponseContext {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    hickory_proto::rr::TSigResponseContext::new(0, now, key.tsigner(), Vec::new(), None)
}

/// True when `rtype` is a zone transfer type.
pub fn is_transfer_type(rtype: RecordType) -> bool {
    rtype == RecordType::AXFR || rtype == RecordType::IXFR
}

/// Whether this opcode is one Daygle authenticates with TSIG.
pub fn is_tsig_opcode(op: OpCode) -> bool {
    matches!(op, OpCode::Query | OpCode::Update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::RecordType;

    fn test_key() -> TsigKey {
        TsigKey::from_config(&TsigKeyConfig {
            name: "test-key.".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
        })
        .unwrap()
    }

    fn test_query() -> Message {
        let mut msg = Message::new(1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AXFR,
        ));
        msg
    }

    #[test]
    fn request_sign_verify_roundtrip() {
        let key = test_key();
        let query = test_query();
        let wire = sign_request(&query, &key).unwrap();

        let ring = TsigKeyRing::from_configs(&[TsigKeyConfig {
            name: "test-key.".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
        }])
        .unwrap();

        match verify_request(&ring, &wire, 1234) {
            TsigVerifyOutcome::Valid {
                key: verified_key,
                request_mac,
                ..
            } => {
                assert_eq!(verified_key.name, key.name);
                assert!(!request_mac.is_empty());
            }
            other => panic!("expected valid, got {}", failure_label(&other)),
        }
    }

    #[test]
    fn tampered_request_fails() {
        let key = test_key();
        let query = test_query();
        let mut wire = sign_request(&query, &key).unwrap();
        // Flip a byte in the middle (query name area, after 12-byte header).
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        wire[20] ^= 0x01;

        let ring = TsigKeyRing::from_configs(&[TsigKeyConfig {
            name: "test-key.".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
        }])
        .unwrap();
        assert!(matches!(
            verify_request(&ring, &wire, 1234),
            TsigVerifyOutcome::Invalid(_)
        ));
    }

    #[test]
    fn unknown_key_rejected() {
        let key = test_key();
        let wire = sign_request(&test_query(), &key).unwrap();
        let ring = TsigKeyRing::from_configs(&[TsigKeyConfig {
            name: "other-key.".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
        }])
        .unwrap();
        assert!(matches!(
            verify_request(&ring, &wire, 1234),
            TsigVerifyOutcome::Invalid(TsigFailure::UnknownKey)
        ));
    }

    #[test]
    fn unsigned_request_reports_unsigned() {
        let ring = TsigKeyRing::default();
        let plain = test_query().to_bytes().unwrap();
        assert!(matches!(
            verify_request(&ring, &plain, 1234),
            TsigVerifyOutcome::Unsigned
        ));
    }

    #[test]
    fn response_sign_verify_roundtrip() {
        let key = test_key();
        let query = test_query();
        let wire = sign_request(&query, &key).unwrap();

        // Extract the request MAC as a verifier would.
        let ring = TsigKeyRing::from_configs(&[TsigKeyConfig {
            name: "test-key.".to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
        }])
        .unwrap();
        let request_mac = match verify_request(&ring, &wire, 1234) {
            TsigVerifyOutcome::Valid { request_mac, .. } => request_mac,
            other => panic!("expected valid, got {}", failure_label(&other)),
        };

        // Build a response and sign it with the request MAC chained.
        let mut response = Message::new(1234, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AXFR,
        ));
        let response_bytes = sign_response(&response, &key, &request_mac).unwrap();

        // The client side verifies with the same request MAC.
        verify_response(&response_bytes, &key, &request_mac).unwrap();
    }

    #[test]
    fn response_with_wrong_request_mac_fails() {
        let key = test_key();
        let mut response = Message::new(1234, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AXFR,
        ));
        let response_bytes = sign_response(&response, &key, b"correct-mac").unwrap();
        assert!(verify_response(&response_bytes, &key, b"wrong-mac").is_err());
    }

    #[test]
    fn key_name_normalization() {
        let ring = TsigKeyRing::from_configs(&[TsigKeyConfig {
            name: "My-Key".to_string(),
            algorithm: "hmac-sha512".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"secret"),
        }])
        .unwrap();
        assert!(ring.get_by_config_name("my-key").is_some());
        assert!(ring.get_by_config_name("MY-KEY.").is_some());
        assert!(ring.get_by_config_name("other").is_none());
    }

    #[test]
    fn unsupported_algorithm_rejected() {
        assert!(TsigKey::from_config(&TsigKeyConfig {
            name: "k.".to_string(),
            algorithm: "hmac-md5".to_string(),
            secret: base64::engine::general_purpose::STANDARD.encode(b"secret"),
        })
        .is_err());
    }
}
