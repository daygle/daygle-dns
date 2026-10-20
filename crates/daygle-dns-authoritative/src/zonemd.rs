//! Zone verification for the local root zone: the ZONEMD message digest
//! (RFC 8976) and the DNSSEC signatures that make it trustworthy.
//!
//! A transferred zone is accepted only when
//!
//! 1. its DNSKEY RRset is signed by a key matching the trust anchor (the
//!    built-in root KSKs),
//! 2. its apex ZONEMD RRset is signed by one of those DNSKEYs, and
//! 3. a ZONEMD record with a supported scheme and hash algorithm carries the
//!    SOA serial and the digest of the zone as received.
//!
//! Together these prove every record came unmodified from the zone's
//! publisher, whichever server it was transferred from.

use std::collections::HashMap;

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::{PublicKey, TrustAnchors, Verifier};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder, NameEncoding};
use sha2::{Digest, Sha384, Sha512};

/// The ZONEMD record type (Hickory has no built-in support for it).
pub const ZONEMD: RecordType = RecordType::Unknown(63);

/// ZONEMD scheme 1: SIMPLE (one digest over the whole zone).
const SCHEME_SIMPLE: u8 = 1;
/// ZONEMD hash algorithm 1: SHA-384.
const HASH_SHA384: u8 = 1;
/// ZONEMD hash algorithm 2: SHA-512.
const HASH_SHA512: u8 = 2;

/// One parsed ZONEMD record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zonemd {
    pub serial: u32,
    pub scheme: u8,
    pub hash_algorithm: u8,
    pub digest: Vec<u8>,
}

impl Zonemd {
    /// Parse ZONEMD RDATA (`serial`, `scheme`, `hash algorithm`, `digest`).
    pub fn parse(record: &Record) -> Option<Self> {
        if record.record_type() != ZONEMD {
            return None;
        }
        let RData::Unknown { rdata, .. } = &record.data else {
            return None;
        };
        let bytes = &rdata.anything;
        // RFC 8976 section 2.2.4: digests shorter than 12 octets are invalid.
        if bytes.len() < 6 + 12 {
            return None;
        }
        Some(Self {
            serial: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            scheme: bytes[4],
            hash_algorithm: bytes[5],
            digest: bytes[6..].to_vec(),
        })
    }

    fn supported(&self) -> bool {
        self.scheme == SCHEME_SIMPLE && matches!(self.hash_algorithm, HASH_SHA384 | HASH_SHA512)
    }
}

/// The key a zone's DNSKEY RRset must be signed by.
#[derive(Debug, Clone)]
pub enum TrustAnchor {
    /// The root KSKs built into Hickory.
    BuiltinRoot,
    /// One explicit public key (DNSKEY public key bytes), for tests.
    Key(Vec<u8>),
}

impl TrustAnchor {
    fn trusts(&self, key: &DNSKEY) -> bool {
        match self {
            TrustAnchor::BuiltinRoot => TrustAnchors::default().contains(key.public_key()),
            TrustAnchor::Key(bytes) => key.public_key().public_bytes() == bytes.as_slice(),
        }
    }
}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The zone's SOA serial (equal to the verified ZONEMD serial).
    pub serial: u32,
    /// The hash algorithm of the ZONEMD record that matched.
    pub hash_algorithm: u8,
}

/// Verify a whole zone: DNSSEC chain from `anchor` to the ZONEMD RRset, then
/// the ZONEMD digest itself. `now` is the current UNIX time, used for the
/// signature validity windows.
pub fn verify_zone(
    origin: &Name,
    records: &[Record],
    anchor: &TrustAnchor,
    now: u64,
) -> Result<Verified, String> {
    let apex = |rtype: RecordType| -> Vec<&Record> {
        records
            .iter()
            .filter(|r| r.record_type() == rtype && &r.name == origin)
            .collect()
    };
    let soa_serial = match apex(RecordType::SOA).first().map(|r| &r.data) {
        Some(RData::SOA(soa)) => soa.serial,
        _ => return Err("the zone has no SOA record at its apex".to_string()),
    };

    // RRSIGs at the apex, by covered type.
    let mut signatures: HashMap<RecordType, Vec<&RRSIG>> = HashMap::new();
    for record in apex(RecordType::RRSIG) {
        if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &record.data {
            signatures
                .entry(sig.input().type_covered)
                .or_default()
                .push(sig);
        }
    }
    let dnskey_records = apex(RecordType::DNSKEY);
    let dnskeys: Vec<&DNSKEY> = dnskey_records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) if key.zone_key() && !key.revoke() => Some(key),
            _ => None,
        })
        .collect();
    let trusted: Vec<&DNSKEY> = dnskeys
        .iter()
        .copied()
        .filter(|k| anchor.trusts(k))
        .collect();
    if trusted.is_empty() {
        return Err("no DNSKEY in the zone matches the trust anchor".to_string());
    }
    verify_rrset(
        origin,
        &dnskey_records,
        signatures.get(&RecordType::DNSKEY),
        &trusted,
        now,
    )
    .map_err(|e| format!("DNSKEY RRset: {e}"))?;

    let zonemd_records = apex(ZONEMD);
    if zonemd_records.is_empty() {
        return Err("the zone has no ZONEMD record".to_string());
    }
    verify_rrset(
        origin,
        &zonemd_records,
        signatures.get(&ZONEMD),
        &dnskeys,
        now,
    )
    .map_err(|e| format!("ZONEMD RRset: {e}"))?;

    let candidates: Vec<Zonemd> = zonemd_records
        .iter()
        .filter_map(|r| Zonemd::parse(r))
        .filter(|z| z.serial == soa_serial && z.supported())
        .collect();
    if candidates.is_empty() {
        return Err(format!(
            "no ZONEMD record with a supported algorithm for serial {soa_serial}"
        ));
    }
    for zonemd in &candidates {
        if zone_digest(origin, records, zonemd.hash_algorithm)? == zonemd.digest {
            return Ok(Verified {
                serial: soa_serial,
                hash_algorithm: zonemd.hash_algorithm,
            });
        }
    }
    Err("the zone digest does not match its ZONEMD record".to_string())
}

/// Check that one of `signatures` over `rrset` is currently valid and made
/// by one of `keys`.
fn verify_rrset(
    origin: &Name,
    rrset: &[&Record],
    signatures: Option<&Vec<&RRSIG>>,
    keys: &[&DNSKEY],
    now: u64,
) -> Result<(), String> {
    let signatures = signatures.ok_or("not signed")?;
    // RRSIG times are 32-bit serial numbers (RFC 4034 section 3.1.5).
    let now = now as u32;
    let mut last_error = "no signature by a trusted key".to_string();
    for sig in signatures {
        let input = sig.input();
        let inception = input.sig_inception.get();
        let expiration = input.sig_expiration.get();
        if (now.wrapping_sub(inception) as i32) < 0 {
            last_error = "signature not yet valid".to_string();
            continue;
        }
        if (expiration.wrapping_sub(now) as i32) < 0 {
            last_error = "signature expired".to_string();
            continue;
        }
        for key in keys {
            if key.algorithm() != input.algorithm
                || key.calculate_key_tag().ok() != Some(input.key_tag)
            {
                continue;
            }
            match key.verify_rrsig(origin, DNSClass::IN, sig, rrset.iter().copied()) {
                Ok(()) => return Ok(()),
                Err(e) => last_error = format!("bad signature: {e}"),
            }
        }
    }
    Err(last_error)
}

/// The RFC 8976 SIMPLE-scheme digest of the zone at `origin`: every record
/// at or below the apex (occluded data included, out-of-zone data and
/// duplicates excluded) except the apex ZONEMD RRset and its signatures, in
/// DNSSEC canonical form and order.
pub fn zone_digest(
    origin: &Name,
    records: &[Record],
    hash_algorithm: u8,
) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(Name, u16, Vec<u8>, &Record)> = Vec::with_capacity(records.len());
    for record in records {
        if !origin.zone_of(&record.name) {
            continue;
        }
        let rtype = record.record_type();
        if &record.name == origin {
            if rtype == ZONEMD {
                continue;
            }
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &record.data {
                if sig.input().type_covered == ZONEMD {
                    continue;
                }
            }
        }
        entries.push((
            record.name.to_lowercase(),
            u16::from(rtype),
            canonical_rdata(record)?,
            record,
        ));
    }
    // Canonical RR order: owner name (Hickory's `Name` ordering is the
    // DNSSEC canonical one), then type, then RDATA as unsigned octets.
    entries.sort_by(|a, b| (&a.0, a.1, &a.2).cmp(&(&b.0, b.1, &b.2)));
    entries.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2);

    let mut hasher = match hash_algorithm {
        HASH_SHA384 => Hasher::Sha384(Sha384::new()),
        HASH_SHA512 => Hasher::Sha512(Sha512::new()),
        other => return Err(format!("unsupported ZONEMD hash algorithm {other}")),
    };
    let mut buf = Vec::new();
    for (name, rtype, rdata, record) in &entries {
        buf.clear();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_name_encoding(NameEncoding::UncompressedLowercase);
            name.emit(&mut encoder).map_err(|e| e.to_string())?;
        }
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&u16::from(record.dns_class).to_be_bytes());
        buf.extend_from_slice(&record.ttl.to_be_bytes());
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
        hasher.update(&buf);
    }
    Ok(hasher.finish())
}

/// A record's RDATA in DNSSEC canonical form (uncompressed, with the names
/// of the RFC 4034 section 6.2 types lowercased).
fn canonical_rdata(record: &Record) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    encoder.set_canonical_form(true);
    encoder.set_name_encoding(NameEncoding::Uncompressed);
    record.data.emit(&mut encoder).map_err(|e| {
        format!(
            "cannot encode {} {}: {e}",
            record.name,
            record.record_type()
        )
    })?;
    Ok(buf)
}

enum Hasher {
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Hasher::Sha384(h) => h.update(bytes),
            Hasher::Sha512(h) => h.update(bytes),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Build a signed test zone: the records are given a fresh ECDSA P-256 key,
/// a ZONEMD (SHA-384) record and RRSIGs over the DNSKEY and ZONEMD RRsets.
/// Returns the full record list and the key's public bytes (the trust
/// anchor for [`TrustAnchor::Key`]).
#[doc(hidden)]
pub fn sign_test_zone(origin: &Name, mut records: Vec<Record>, now: u64) -> (Vec<Record>, Vec<u8>) {
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::rdata::sig::SigInput;
    use hickory_proto::dnssec::{Algorithm, SigningKey, TBS};
    use hickory_proto::rr::rdata::NULL;

    let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("keygen");
    let key = EcdsaSigningKey::from_pkcs8(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.secret_pkcs8_der()),
        Algorithm::ECDSAP256SHA256,
    )
    .expect("key");
    let public = key.to_public_key().expect("public key");
    let anchor = public.public_bytes().to_vec();
    let dnskey = DNSKEY::new(true, true, false, public);
    let key_tag = dnskey.calculate_key_tag().expect("key tag");
    records.push(Record::from_rdata(
        origin.clone(),
        86400,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ));

    let sign = |records: &mut Vec<Record>, covered: RecordType| {
        let rrset: Vec<Record> = records
            .iter()
            .filter(|r| r.record_type() == covered && &r.name == origin)
            .cloned()
            .collect();
        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: origin.num_labels(),
            original_ttl: 86400,
            sig_expiration: ((now + 14 * 86400) as u32).into(),
            sig_inception: ((now - 3600) as u32).into(),
            key_tag,
            signer_name: origin.clone(),
        };
        let tbs = TBS::from_input(origin, DNSClass::IN, &input, rrset.iter()).expect("tbs");
        let sig = key.sign(&tbs).expect("sign");
        records.push(Record::from_rdata(
            origin.clone(),
            86400,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
        ));
    };
    // The DNSKEY signature is zone data the digest covers; the ZONEMD
    // signature is not.
    sign(&mut records, RecordType::DNSKEY);

    let serial = records
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) if &r.name == origin => Some(soa.serial),
            _ => None,
        })
        .expect("test zone needs an SOA");
    let digest = zone_digest(origin, &records, HASH_SHA384).expect("digest");
    let mut rdata = serial.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[SCHEME_SIMPLE, HASH_SHA384]);
    rdata.extend_from_slice(&digest);
    records.push(Record::from_rdata(
        origin.clone(),
        86400,
        RData::Unknown {
            code: ZONEMD,
            rdata: NULL::with(rdata),
        },
    ));
    sign(&mut records, ZONEMD);
    (records, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, NS, NULL, SOA, TXT};

    fn name(n: &str) -> Name {
        Name::from_ascii(n).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn zonemd(owner: &str, ttl: u32, serial: u32, digest: &[u8]) -> Record {
        let mut rdata = serial.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 1]);
        rdata.extend_from_slice(digest);
        Record::from_rdata(
            name(owner),
            ttl,
            RData::Unknown {
                code: ZONEMD,
                rdata: NULL::with(rdata),
            },
        )
    }

    fn txt(owner: &str, ttl: u32, text: &str) -> Record {
        Record::from_rdata(
            name(owner),
            ttl,
            RData::TXT(TXT::new(vec![text.to_string()])),
        )
    }

    /// RFC 8976 Appendix A.1 (the simple EXAMPLE zone).
    fn example_a1() -> Vec<Record> {
        vec![
            Record::from_rdata(
                name("example."),
                86400,
                RData::SOA(SOA::new(
                    name("ns1.example."),
                    name("admin.example."),
                    2018031900,
                    1800,
                    900,
                    604800,
                    86400,
                )),
            ),
            Record::from_rdata(name("example."), 86400, RData::NS(NS(name("ns1.example.")))),
            Record::from_rdata(name("example."), 86400, RData::NS(NS(name("ns2.example.")))),
            Record::from_rdata(
                name("ns1.example."),
                3600,
                RData::A(A::new(203, 0, 113, 63)),
            ),
            Record::from_rdata(
                name("ns2.example."),
                3600,
                RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x63)),
            ),
        ]
    }

    #[test]
    fn digest_matches_rfc8976_example_a1() {
        let expected = hex("c68090d90a7aed71 6bc459f9340e3d7c 1370d4d24b7e2fc3 \
             a1ddc0b9a87153b9 a9713b3c9ae5cc27 777f98b8e730044c");
        let mut records = example_a1();
        records.push(zonemd("example.", 86400, 2018031900, &expected));
        assert_eq!(
            zone_digest(&name("example."), &records, HASH_SHA384).unwrap(),
            expected
        );
    }

    /// RFC 8976 Appendix A.2: occluded data is digested, duplicates once,
    /// out-of-zone data never, and a non-apex ZONEMD is ordinary data.
    #[test]
    fn digest_matches_rfc8976_example_a2() {
        let expected = hex("31cefb03814f5062 ad12fa951ba0ef5f 8da6ae354a415767 \
             246f7dc932ceb1e7 42a2108f529db6a3 3a11c01493de358d");
        let mut records = example_a1();
        records.push(zonemd("example.", 86400, 2018031900, &expected));
        records.push(txt(
            "occluded.sub.example.",
            7200,
            "I'm occluded but must be digested",
        ));
        records.push(Record::from_rdata(
            name("sub.example."),
            7200,
            RData::NS(NS(name("ns1.example."))),
        ));
        records.push(txt(
            "duplicate.example.",
            300,
            "I must be digested just once",
        ));
        records.push(txt(
            "duplicate.example.",
            300,
            "I must be digested just once",
        ));
        records.push(txt("foo.test.", 555, "out-of-zone data must be excluded"));
        records.push(zonemd(
            "non-apex.example.",
            900,
            2018031900,
            &hex("616c6c6f77656420 6275742069676e6f 7265642e20616c6c \
                 6f77656420627574 2069676e6f726564 2e20616c6c6f7765"),
        ));
        assert_eq!(
            zone_digest(&name("example."), &records, HASH_SHA384).unwrap(),
            expected
        );
    }

    #[test]
    fn signed_zone_verifies_and_tampering_is_detected() {
        let origin = Name::root();
        let now = 1_800_000_000;
        let mut zone = example_a1();
        for r in &mut zone {
            // Re-home the example zone at the root.
            let labels = r.name.num_labels() as usize;
            r.name = if labels <= 1 {
                Name::root()
            } else {
                r.name.trim_to(labels - 1)
            };
        }
        let (records, anchor) = sign_test_zone(&origin, zone, now);
        let anchor = TrustAnchor::Key(anchor);
        let verified = verify_zone(&origin, &records, &anchor, now).unwrap();
        assert_eq!(verified.serial, 2018031900);

        // A changed record breaks the digest.
        let mut tampered = records.clone();
        for r in &mut tampered {
            if r.record_type() == RecordType::A {
                r.data = RData::A(A::new(192, 0, 2, 1));
            }
        }
        let err = verify_zone(&origin, &tampered, &anchor, now).unwrap_err();
        assert!(err.contains("digest"), "{err}");

        // An extra record breaks it too.
        let mut extra = records.clone();
        extra.push(txt("evil.", 300, "injected"));
        assert!(verify_zone(&origin, &extra, &anchor, now).is_err());

        // A different trust anchor rejects the zone.
        let err = verify_zone(&origin, &records, &TrustAnchor::BuiltinRoot, now).unwrap_err();
        assert!(err.contains("trust anchor"), "{err}");

        // Expired signatures are rejected.
        let err = verify_zone(&origin, &records, &anchor, now + 30 * 86400).unwrap_err();
        assert!(err.contains("expired"), "{err}");

        // A zone without ZONEMD is rejected.
        let unsigned: Vec<Record> = records
            .iter()
            .filter(|r| r.record_type() != ZONEMD)
            .cloned()
            .collect();
        assert!(verify_zone(&origin, &unsigned, &anchor, now).is_err());
    }
}
