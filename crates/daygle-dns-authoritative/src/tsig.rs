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
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::rr::{TSigResponseContext, TSigner};
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
        let algorithm =
            TsigAlgorithm::from_name(Name::from_ascii(config.algorithm.trim()).map_err(|e| {
                format!("tsig key '{}' has invalid algorithm name: {e}", config.name)
            })?);
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
        normalize_key_name(name).ok().and_then(|n| self.get(&n))
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
pub fn verify_request(key_ring: &TsigKeyRing, raw: &[u8], request_id: u16) -> TsigVerifyOutcome {
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
        response_context: TSigResponseContext::new(request_id, now, signer, request_mac, None),
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
    let additionals = u16::from_be_bytes([out[10], out[11]])
        .checked_add(1)
        .ok_or_else(|| "tsig response has no room for another additional record".to_string())?;
    out[10..12].copy_from_slice(&additionals.to_be_bytes());
    Ok(out)
}

/// Sign a client request (used by the secondary-side transfer client).
/// Returns the wire bytes of `message` with its TSIG record appended.
pub fn sign_request(message: &Message, key: &TsigKey) -> Result<Vec<u8>, String> {
    sign_request_with_mac(message, key).map(|(wire, _)| wire)
}

/// [`sign_request`], also returning the request MAC, which the replies
/// chain from.
pub fn sign_request_with_mac(
    message: &Message,
    key: &TsigKey,
) -> Result<(Vec<u8>, Vec<u8>), String> {
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
        pre_tsig.set_mac(mac.clone()),
    )));
    let wire = signed
        .to_bytes()
        .map_err(|e| format!("tsig request encoding failed: {e}"))?;
    Ok((wire, mac))
}

/// The TSIG record for the second or a later message of a multi-message
/// response (a zone transfer), RFC 8945 §5.3.1: the MAC covers the previous
/// message's MAC, this message as sent without its TSIG (`body`), and only
/// the TSIG timers.
pub fn sign_subsequent(
    key: &TsigKey,
    previous_mac: &[u8],
    body: &[u8],
    original_id: u16,
) -> Result<Box<Record<TSIG>>, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tbs = subsequent_tbs(previous_mac, body, now, key.fudge);
    let mac = key
        .algorithm
        .mac_data(&key.secret, &tbs)
        .map_err(|e| format!("tsig response mac failed: {e}"))?;
    let tsig = TSIG::new(
        key.algorithm.clone(),
        now,
        key.fudge,
        mac,
        original_id,
        None,
        Vec::new(),
    );
    Ok(Box::new(make_tsig_record(key.name.clone(), tsig)))
}

/// The to-be-signed bytes of a later message: previous MAC (length
/// prefixed), the message data, then time signed (48 bits) and fudge.
fn subsequent_tbs(previous_mac: &[u8], data: &[u8], time: u64, fudge: u16) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(previous_mac.len() + data.len() + 10);
    tbs.extend_from_slice(&(previous_mac.len() as u16).to_be_bytes());
    tbs.extend_from_slice(previous_mac);
    tbs.extend_from_slice(data);
    tbs.extend_from_slice(&time.to_be_bytes()[2..]);
    tbs.extend_from_slice(&fudge.to_be_bytes());
    tbs
}

/// Checks each message of a signed multi-message response (a zone transfer)
/// in order, chaining every MAC from the one before (RFC 8945 §5.3.1). Later
/// messages may come unsigned, as long as no more than 99 in a row do and
/// the last one is signed; their bytes are covered by the next signature.
pub struct ResponseVerifier {
    key: TsigKey,
    previous_mac: Vec<u8>,
    first: bool,
    unsigned: Vec<u8>,
    unsigned_count: usize,
}

impl ResponseVerifier {
    /// Verify replies to a request signed with `key` whose MAC was
    /// `request_mac`.
    pub fn new(key: TsigKey, request_mac: Vec<u8>) -> Self {
        Self {
            key,
            previous_mac: request_mac,
            first: true,
            unsigned: Vec::new(),
            unsigned_count: 0,
        }
    }

    /// Check the next response message, as received.
    pub fn verify(&mut self, raw: &[u8]) -> Result<(), String> {
        let signed = Message::from_vec(raw)
            .map_err(|e| format!("cannot decode response: {e}"))?
            .signature()
            .is_some();
        if !signed {
            if self.first {
                return Err("the response is not TSIG-signed".to_string());
            }
            self.unsigned_count += 1;
            if self.unsigned_count >= 100 {
                return Err("more than 99 unsigned messages in a row".to_string());
            }
            self.unsigned.extend_from_slice(raw);
            return Ok(());
        }
        let (body, record) = signed_bitmessage_to_buf(raw, None, self.first)
            .map_err(|e| format!("malformed TSIG: {e}"))?;
        let tsig = &record.data;
        if record.name != self.key.name {
            return Err(format!(
                "response signed with another key ({})",
                record.name
            ));
        }
        if let Some(error) = &tsig.error {
            return Err(format!("the server reported TSIG error {error:?}"));
        }
        let mut tbs = Vec::with_capacity(self.previous_mac.len() + body.len() + 2);
        tbs.extend_from_slice(&(self.previous_mac.len() as u16).to_be_bytes());
        tbs.extend_from_slice(&self.previous_mac);
        tbs.extend_from_slice(&self.unsigned);
        tbs.extend_from_slice(&body);
        self.key
            .algorithm
            .verify_mac(&self.key.secret, &tbs, &tsig.mac)
            .map_err(|_| "TSIG signature does not verify".to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.abs_diff(tsig.time) > u64::from(tsig.fudge) {
            return Err(format!(
                "TSIG time {} is outside the accepted window (now {now})",
                tsig.time
            ));
        }
        self.previous_mac = tsig.mac.clone();
        self.first = false;
        self.unsigned.clear();
        self.unsigned_count = 0;
        Ok(())
    }

    /// Check that the response ended on a signed message.
    pub fn finish(&self) -> Result<(), String> {
        if self.first || self.unsigned_count > 0 {
            return Err("the response does not end with a TSIG-signed message".to_string());
        }
        Ok(())
    }
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

    /// A three-message signed response, as a primary sends a large
    /// transfer: hickory signs the first message, `sign_subsequent` the
    /// rest. Both hickory's verifier and `ResponseVerifier` accept it, and
    /// the verifier rejects a tampered message.
    #[test]
    fn multi_message_responses_chain_their_macs() {
        use hickory_proto::op::MessageType;
        let key = test_key();
        let (_, request_mac) = sign_request_with_mac(&test_query(), &key).unwrap();

        let message = |n: u8| {
            let mut m = Message::new(1234, MessageType::Response, OpCode::Query);
            m.add_answer(hickory_proto::rr::Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, n)),
            ));
            m.to_bytes().unwrap()
        };
        let append = |body: &[u8], tsig: &Record<TSIG>| {
            let mut out = body.to_vec();
            out.extend_from_slice(&tsig.to_bytes().unwrap());
            let count = u16::from_be_bytes([out[10], out[11]]) + 1;
            out[10..12].copy_from_slice(&count.to_be_bytes());
            out
        };

        let first_body = message(1);
        let first_tsig = TSigResponseContext::new(
            1234,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            key.tsigner(),
            request_mac.clone(),
            None,
        )
        .sign(&first_body)
        .unwrap();
        let first = append(&first_body, &first_tsig);
        let second_body = message(2);
        let second_tsig = sign_subsequent(&key, &first_tsig.data.mac, &second_body, 1234).unwrap();
        let second = append(&second_body, &second_tsig);
        let third = message(3);
        let fourth_body = message(4);
        // The fourth message's MAC also covers the unsigned third.
        let mut covered = third.clone();
        covered.extend_from_slice(&fourth_body);
        let fourth_tsig = {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let tbs = subsequent_tbs(&second_tsig.data.mac, &covered, now, key.fudge);
            let mac = key.algorithm.mac_data(&key.secret, &tbs).unwrap();
            make_tsig_record(
                key.name.clone(),
                TSIG::new(
                    key.algorithm.clone(),
                    now,
                    key.fudge,
                    mac,
                    1234,
                    None,
                    Vec::new(),
                ),
            )
        };
        let fourth = append(&fourth_body, &fourth_tsig);

        // Hickory agrees with the subsequent-message format.
        key.tsigner()
            .verify_message_byte(&second, Some(&first_tsig.data.mac), false)
            .expect("hickory verifies a later message");

        let mut verifier = ResponseVerifier::new(key.clone(), request_mac.clone());
        verifier.verify(&first).unwrap();
        verifier.verify(&second).unwrap();
        verifier.verify(&third).unwrap();
        assert!(verifier.finish().is_err(), "ends on an unsigned message");
        verifier.verify(&fourth).unwrap();
        verifier.finish().unwrap();

        // Flip a byte of the answer's address.
        let mut tampered = second.clone();
        tampered[second_body.len() - 1] ^= 1;
        let mut verifier = ResponseVerifier::new(key.clone(), request_mac.clone());
        verifier.verify(&first).unwrap();
        assert!(verifier.verify(&tampered).is_err());

        let mut verifier = ResponseVerifier::new(key, request_mac);
        assert!(
            verifier.verify(&first_body).is_err(),
            "an unsigned first message"
        );
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
