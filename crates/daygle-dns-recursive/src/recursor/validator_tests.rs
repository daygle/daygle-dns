//! Tests of the vendored DNSSEC validator's zone cut search against a signed
//! fake root (see `vendor/README.md`).
//!
//! The validator proves an unsigned answer insecure by finding the zone cut
//! above it (an NS question at each name, asked of that name's own servers)
//! and asking the cut's parent for its DS. Here every name below the root
//! has servers whose replies cannot be read, as `ptsecurity.com`'s are to any
//! query carrying EDNS, so the parent's DS answer is all there is to go on.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::stream::{self, BoxStream, StreamExt};
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::sig::SigInput;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, NSEC, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, Proof, SigningKey, TrustAnchors, TBS};
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Message, OpCode, ResponseCode,
};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use hickory_resolver::net::dnssec::DnssecDnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::NetError;

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

/// The signed root zone: `unsigned.` is an unsigned delegation, `signed.`
/// a signed one, and `inside.` a name in the root zone itself that is no
/// delegation at all.
struct Root {
    records: Vec<Record>,
    anchor: TrustAnchors,
}

impl Root {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
        let public = key.to_public_key().unwrap();
        let mut anchor = TrustAnchors::empty();
        anchor.insert_with_name(&public, LowerName::from(Name::root()));
        let dnskey = DNSKEY::new(true, true, false, public);
        let key_tag = dnskey.calculate_key_tag().unwrap();

        let ttl = 86400;
        let nsec = |owner: &str, next: &str, types: &[RecordType]| {
            Record::from_rdata(
                name(owner),
                ttl,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(name(next), types.to_vec()))),
            )
        };
        let mut records = vec![
            Record::from_rdata(
                Name::root(),
                ttl,
                RData::SOA(SOA::new(
                    name("a.root.test."),
                    name("hostmaster.root.test."),
                    1,
                    1800,
                    900,
                    604800,
                    ttl,
                )),
            ),
            Record::from_rdata(
                Name::root(),
                ttl,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
            ),
            Record::from_rdata(
                name("signed."),
                ttl,
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    1234,
                    Algorithm::ECDSAP256SHA256,
                    DigestType::SHA256,
                    vec![0xab; 32],
                ))),
            ),
            Record::from_rdata(name("inside."), ttl, RData::A(A::new(192, 0, 2, 1))),
            // The chain: . -> inside. -> signed. -> unsigned. -> .
            nsec(
                ".",
                "inside.",
                &[
                    RecordType::SOA,
                    RecordType::DNSKEY,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
            nsec(
                "inside.",
                "signed.",
                &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            ),
            nsec(
                "signed.",
                "unsigned.",
                &[
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
            nsec(
                "unsigned.",
                ".",
                &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            ),
        ];

        let mut rrsets: Vec<(Name, RecordType)> = Vec::new();
        for r in &records {
            let set = (r.name.clone(), r.record_type());
            if !rrsets.contains(&set) {
                rrsets.push(set);
            }
        }
        for (owner, covered) in rrsets {
            let rrset: Vec<Record> = records
                .iter()
                .filter(|r| r.name == owner && r.record_type() == covered)
                .cloned()
                .collect();
            let input = SigInput {
                type_covered: covered,
                algorithm: Algorithm::ECDSAP256SHA256,
                num_labels: owner.num_labels(),
                original_ttl: ttl,
                sig_expiration: ((now + 14 * 86400) as u32).into(),
                sig_inception: ((now - 3600) as u32).into(),
                key_tag,
                signer_name: Name::root(),
            };
            let tbs = TBS::from_input(&owner, DNSClass::IN, &input, rrset.iter()).unwrap();
            let sig = key.sign(&tbs).unwrap();
            records.push(Record::from_rdata(
                owner,
                ttl,
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
            ));
        }
        Self { records, anchor }
    }

    /// The RRset `owner`/`rtype` with its signature.
    fn signed(&self, owner: &Name, rtype: RecordType) -> Vec<Record> {
        self.records
            .iter()
            .filter(|r| {
                &r.name == owner
                    && (r.record_type() == rtype
                        || matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(sig))
                            if sig.input().type_covered == rtype))
            })
            .cloned()
            .collect()
    }
}

/// Answers as the fake hierarchy does: the root zone from the root's
/// servers, an unsigned A record for every name below a delegation, and an
/// unreadable reply to every other question about a name below the root.
#[derive(Clone)]
struct Fake(Arc<Root>);

impl Fake {
    fn reply(&self, request: &DnsRequest) -> Result<DnsResponse, NetError> {
        let query = request.queries.first().expect("a question").clone();
        let qname = query.name().clone();
        let mut message = Message::response(request.metadata.id, OpCode::Query);
        message.queries.push(query.clone());
        message.metadata.authoritative = true;
        let root = &self.0;
        let in_root_zone = qname.num_labels() <= 1;
        if qname.is_root() || (in_root_zone && query.query_type() == RecordType::DS) {
            let answers = root.signed(&qname, query.query_type());
            if answers.is_empty() {
                // NODATA: the SOA and the NSEC at the name, both signed.
                message.add_authorities(root.signed(&Name::root(), RecordType::SOA));
                message.add_authorities(root.signed(&qname, RecordType::NSEC));
            } else {
                message.add_answers(answers);
            }
        } else if query.query_type() == RecordType::A && qname.num_labels() == 2 {
            // The unsigned answer the validator is asked to judge.
            message.add_answer(Record::from_rdata(
                qname.clone(),
                300,
                RData::A(A::new(198, 51, 100, 7)),
            ));
        } else {
            return Err(NetError::from(format!(
                "decoding error: the servers for {qname} sent a reply that cannot be read"
            )));
        }
        message.metadata.response_code = ResponseCode::NoError;
        Ok(DnsResponse::from_message(message).expect("a response"))
    }
}

impl DnsHandle for Fake {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        stream::once(std::future::ready(self.reply(&request))).boxed()
    }
}

/// The proof the validator gives the A record for `owner`.
async fn proof_of(owner: &str) -> Proof {
    let root = Arc::new(Root::new());
    let anchor = Arc::new(root.anchor.clone());
    let validator = DnssecDnsHandle::with_trust_anchor(Fake(root), anchor);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    options.edns_set_dnssec_ok = true;
    let response = validator
        .lookup(
            hickory_proto::op::Query::query(name(owner), RecordType::A),
            options,
        )
        .first_answer()
        .await;
    match response {
        Ok(response) => response
            .answers
            .iter()
            .find(|r| r.record_type() == RecordType::A)
            .map(|r| r.proof)
            .expect("the A record"),
        Err(e) => panic!("{owner}: {e}"),
    }
}

/// `rules.ptsecurity.com A`: the zone's servers cannot be read, so the zone
/// cut probe fails, but the parent's signed NSEC proves a delegation with no
/// DS, so the answer is insecure, not bogus.
#[tokio::test]
async fn an_answer_under_an_unsigned_delegation_with_unreadable_servers_is_insecure() {
    assert_eq!(proof_of("www.unsigned.").await, Proof::Insecure);
}

/// The parent publishes a DS: the zone is signed, so an unsigned answer from
/// it stays bogus whether or not its servers can be read.
#[tokio::test]
async fn an_answer_under_a_signed_delegation_with_unreadable_servers_stays_bogus() {
    assert_eq!(proof_of("www.signed.").await, Proof::Bogus);
}

/// `inside.` is a name in the signed root zone, not a delegation: its NSEC
/// has no NS bit. A "no DS" there proves nothing (every name that is not a
/// cut has none), so the answer stays bogus.
#[tokio::test]
async fn an_answer_under_a_name_that_is_no_delegation_stays_bogus() {
    assert_eq!(proof_of("www.inside.").await, Proof::Bogus);
}
