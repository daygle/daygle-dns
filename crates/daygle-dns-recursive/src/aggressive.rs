//! Aggressive use of the DNSSEC-validated cache (RFC 8198).
//!
//! A validating recursor normally answers only exact questions from its
//! cache. An NSEC record, though, proves a whole *range* of names absent: any
//! name ordered between its owner and its next owner does not exist, and a
//! name with an NSEC of its own exists only with the types its bitmap lists.
//! Keeping those validated records lets the resolver answer NXDOMAIN and
//! NODATA for names it was never asked about, without another round trip to
//! the authoritative servers.
//!
//! Only proofs the validator marked [`Proof::Secure`] are kept: an unsigned
//! or unproven denial says nothing about a signed zone, and using one would
//! let a forged answer suppress names for its TTL (RFC 8198 section 9). Each
//! record is also skipped when it is an ancestor-delegation NSEC, which
//! authenticates only the absence of `DS` at its owner (RFC 6840 section
//! 4.1), or when its zone differs from the SOA it came with.
//!
//! Zone-signed-with-NSEC3 aggressive caching (RFC 8198 section 5.2) and
//! positive synthesis from wildcards (section 5.3) are not done here: both
//! need more state than a validated denial carries, and queries they would
//! cover are simply resolved as usual.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::Proof;
use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Most zones whose proofs are kept; the least recently used is dropped.
const MAX_ZONES: usize = 1024;
/// Most NSEC records kept per zone.
const MAX_NSECS_PER_ZONE: usize = 512;

/// A negative answer synthesized from cached proofs.
pub struct Synthesized {
    /// `NXDomain` (the name does not exist) or `NoError` (NODATA).
    pub code: ResponseCode,
    /// The zone's SOA, for the authority section of the answer.
    pub soa: Record,
    /// The NSEC records that prove it (also for the authority section).
    pub proofs: Vec<Record>,
}

/// The cached NSEC proofs, by zone.
pub struct AggressiveNsec {
    state: Mutex<State>,
    /// `recursive.max_cache_ttl`: caps how long a proof is kept (0: no cap).
    max_ttl: u32,
}

#[derive(Default)]
struct State {
    zones: Vec<Zone>,
    /// Counts lookups and inserts, for least-recently-used eviction.
    tick: u64,
}

struct Zone {
    /// The zone apex: the owner of the SOA the proofs came with.
    apex: Name,
    soa: Record,
    soa_expires: Instant,
    nsecs: Vec<ProofRecord>,
    last_used: u64,
}

struct ProofRecord {
    /// The record as received, with its TTL reduced to the negative TTL.
    record: Record,
    /// Canonical-order key of the owner (RFC 4034 section 6.1).
    owner_key: Vec<Vec<u8>>,
    /// Canonical-order key of the next owner.
    next_key: Vec<Vec<u8>>,
    /// Types present at the owner, from the bitmap.
    types: Vec<RecordType>,
    expires: Instant,
}

impl AggressiveNsec {
    /// A proof cache; `max_ttl` is `recursive.max_cache_ttl` (0 = uncapped).
    pub fn new(max_ttl: u32) -> Self {
        Self {
            state: Mutex::new(State::default()),
            max_ttl,
        }
    }

    /// Keep the validated NSEC records of a negative answer.
    ///
    /// `soa` is the answer's SOA (for its zone and negative TTL) and
    /// `authorities` the authority section it came with. Records that are
    /// not secured NSECs of that zone are ignored, so the cache simply stays
    /// empty when nothing was proved.
    pub fn insert(&self, soa: &Record, authorities: &[Record]) {
        self.insert_at(soa, authorities, Instant::now());
    }

    fn insert_at(&self, soa: &Record, authorities: &[Record], now: Instant) {
        // A denial only speaks for the zone whose SOA accompanied it, and
        // only once the validator has secured both.
        if soa.proof != Proof::Secure {
            return;
        }
        let RData::SOA(soa_data) = &soa.data else {
            return;
        };
        let apex = soa.name.clone();
        let negative_ttl = soa.ttl.min(soa_data.minimum);
        let ttl = match self.max_ttl {
            0 => negative_ttl,
            max => negative_ttl.min(max),
        };
        if ttl == 0 {
            return;
        }
        let expires = now + Duration::from_secs(u64::from(ttl));

        let mut proofs = Vec::new();
        for record in authorities {
            let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data else {
                continue;
            };
            if record.proof != Proof::Secure || !apex.zone_of(&record.name) {
                continue;
            }
            // RFC 6840 section 4.1: a parent-side NSEC at a zone cut proves
            // only that no DS exists there, never that a name is absent.
            if nsec.is_ancestor_delegation() {
                continue;
            }
            // The proof lives no longer than the NSEC's own TTL, nor
            // past its signature's expiration (RFC 4035 section 5.3.3):
            // after either, the denial proves nothing any more.
            let mut proof_ttl = ttl.min(record.ttl);
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as u32)
                .unwrap_or(0);
            for other in authorities {
                let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &other.data else {
                    continue;
                };
                if other.name == record.name && rrsig.input().type_covered == RecordType::NSEC {
                    proof_ttl =
                        proof_ttl.min(rrsig.input().sig_expiration.get().saturating_sub(now_unix));
                }
            }
            if proof_ttl == 0 {
                continue;
            }
            let mut record = record.clone();
            record.ttl = proof_ttl;
            proofs.push(ProofRecord {
                owner_key: canonical_labels(&record.name),
                next_key: canonical_labels(nsec.next_domain_name()),
                types: nsec.type_bit_maps().collect(),
                record,
                expires: now + Duration::from_secs(u64::from(proof_ttl)),
            });
        }
        if proofs.is_empty() {
            return;
        }

        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.tick += 1;
        let tick = state.tick;
        if let Some(zone) = state.zones.iter_mut().find(|z| z.apex == apex) {
            zone.soa = soa.clone();
            zone.soa_expires = expires;
            zone.last_used = tick;
            // A later answer supersedes the same owner's older proof.
            for proof in proofs {
                match zone
                    .nsecs
                    .iter_mut()
                    .find(|kept| kept.record.name == proof.record.name)
                {
                    Some(kept) => *kept = proof,
                    None => zone.nsecs.push(proof),
                }
            }
            if zone.nsecs.len() > MAX_NSECS_PER_ZONE {
                let excess = zone.nsecs.len() - MAX_NSECS_PER_ZONE;
                zone.nsecs.drain(..excess);
            }
            return;
        }
        if state.zones.len() >= MAX_ZONES {
            // Drop the zone looked at (or filled) longest ago.
            if let Some((index, _)) = state
                .zones
                .iter()
                .enumerate()
                .min_by_key(|(_, zone)| zone.last_used)
            {
                state.zones.swap_remove(index);
            }
        }
        state.zones.push(Zone {
            apex,
            soa: soa.clone(),
            soa_expires: expires,
            nsecs: proofs,
            last_used: tick,
        });
    }

    /// A negative answer for `query` that cached proofs already establish,
    /// if there is one.
    pub fn synthesize(&self, query: &Query) -> Option<Synthesized> {
        let qname = query.name();
        let qtype = query.query_type();
        // Any/transfer queries and the parent-side types are never answered
        // from a child zone's proofs.
        if !qname.is_fqdn()
            || matches!(
                qtype,
                RecordType::ANY
                    | RecordType::AXFR
                    | RecordType::IXFR
                    | RecordType::OPT
                    | RecordType::TSIG
                    | RecordType::DS
                    | RecordType::DNSKEY
            )
        {
            return None;
        }
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        state.tick += 1;
        let tick = state.tick;
        // The most specific zone that contains the name and is still live.
        let index = state
            .zones
            .iter()
            .enumerate()
            .filter(|(_, zone)| zone.soa_expires > now && zone.apex.zone_of(qname))
            .max_by_key(|(_, zone)| zone.apex.num_labels())
            .map(|(index, _)| index)?;
        let zone = &mut state.zones[index];
        zone.last_used = tick;
        let qname_key = canonical_labels(qname);

        // NODATA: the name exists (an NSEC at it) without the asked type and
        // without a CNAME that would answer it instead (RFC 8198 section 5.1).
        if let Some(proof) = zone.nsecs.iter().find(|proof| proof.record.name == *qname) {
            if proof.expires > now
                && !proof.types.contains(&qtype)
                && !proof.types.contains(&RecordType::CNAME)
            {
                let remaining = proof
                    .expires
                    .duration_since(now)
                    .as_secs()
                    .min(u64::from(u32::MAX)) as u32;
                if remaining > 0 {
                    return Some(Synthesized {
                        code: ResponseCode::NoError,
                        soa: with_ttl(&zone.soa, remaining),
                        proofs: vec![with_ttl(&proof.record, remaining)],
                    });
                }
            }
        }

        // NXDOMAIN: an NSEC covers the name, and another covers the wildcard
        // at the closest encloser, so no wildcard can answer it either. The
        // closest encloser is the deepest ancestor an NSEC (or the apex SOA)
        // proves exists.
        let covering = zone.nsecs.iter().find(|proof| {
            proof.expires > now && proof.record.name != *qname && covers(proof, &qname_key)
        })?;
        let mut candidate = qname.base_name();
        let encloser = loop {
            // The candidate exists if the apex, an NSEC sits at it, or a
            // descendant's NSEC makes it an empty non-terminal (RFC 8198
            // section 5.1); an NSEC *above* it proves nothing about it.
            let exists = candidate == zone.apex
                || zone.nsecs.iter().any(|proof| {
                    proof.expires > now
                        && (proof.record.name == candidate || candidate.zone_of(&proof.record.name))
                        && !proof.types.is_empty()
                });
            if exists {
                break candidate;
            }
            if candidate.is_root() || !zone.apex.zone_of(&candidate) {
                return None;
            }
            candidate = candidate.base_name();
        };
        // The wildcard at the closest encloser, e.g. `*.example.`.
        let wildcard = Name::from_ascii(format!("*.{}", encloser.to_ascii())).ok()?;
        if wildcard.base_name() != encloser || !zone.apex.zone_of(&wildcard) {
            return None;
        }
        let wildcard_key = canonical_labels(&wildcard);
        // A cached NSEC at the wildcard itself means it exists: the name may
        // be answered positively by it, so NXDOMAIN is not proved.
        if zone.nsecs.iter().any(|proof| proof.record.name == wildcard) {
            return None;
        }
        let wildcard_proof = zone
            .nsecs
            .iter()
            .find(|proof| proof.expires > now && covers(proof, &wildcard_key))?;
        let mut proofs = vec![covering.record.clone()];
        if wildcard_proof.record.name != covering.record.name {
            proofs.push(wildcard_proof.record.clone());
        }
        let remaining = proofs
            .iter()
            .filter_map(|proof| {
                zone.nsecs
                    .iter()
                    .find(|nsec| nsec.record.name == proof.name)
                    .map(|nsec| nsec.expires)
            })
            .chain(std::iter::once(zone.soa_expires))
            .map(|expires| expires.duration_since(now).as_secs())
            .min()?
            .min(u64::from(u32::MAX)) as u32;
        if remaining == 0 {
            return None;
        }
        Some(Synthesized {
            code: ResponseCode::NXDomain,
            soa: with_ttl(&zone.soa, remaining),
            proofs: proofs
                .iter()
                .map(|proof| with_ttl(proof, remaining))
                .collect(),
        })
    }
}

/// Make a cached record safe to serve for no longer than `ttl` more seconds.
fn with_ttl(record: &Record, ttl: u32) -> Record {
    let mut record = record.clone();
    record.ttl = record.ttl.min(ttl);
    record
}

/// Whether `proof`'s owner-to-next range contains `name`, in canonical
/// ordering (RFC 4034 section 6.1).
fn covers(proof: &ProofRecord, name: &[Vec<u8>]) -> bool {
    if proof.next_key > proof.owner_key {
        proof.owner_key < name.to_vec() && name.to_vec() < proof.next_key
    } else {
        // The last NSEC of a zone wraps around to the apex.
        name.to_vec() > proof.owner_key || name.to_vec() < proof.next_key
    }
}

/// A name's labels in canonical order: least significant (root-most) first,
/// each lowercased, so plain slice comparison orders names as RFC 4034
/// section 6.1 does.
fn canonical_labels(name: &Name) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name
        .to_ascii()
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .map(|label| label.to_ascii_lowercase().into_bytes())
        .collect();
    labels.reverse();
    labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::NSEC;
    use hickory_proto::rr::rdata::SOA;

    fn name(n: &str) -> Name {
        Name::from_ascii(n).unwrap()
    }

    fn soa(zone: &str) -> Record {
        let mut record = Record::from_rdata(
            name(zone),
            3600,
            RData::SOA(SOA::new(
                name("ns.example."),
                name("hostmaster.example."),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );
        record.proof = Proof::Secure;
        record
    }

    /// An NSEC at `owner` for `next`, listing `types`.
    fn nsec(owner: &str, next: &str, types: &[RecordType], proof: Proof) -> Record {
        let mut record = Record::from_rdata(
            name(owner),
            3600,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
                name(next),
                types.to_vec(),
            ))),
        );
        record.proof = proof;
        record
    }

    fn query(n: &str, rtype: RecordType) -> Query {
        Query::query(name(n), rtype)
    }

    /// `example.` with `a.example.` (A) and `m.example.` (MX), the two NSECs
    /// and the apex; `example. -> a.example.` also covers `*.example.`.
    fn zone_cache() -> AggressiveNsec {
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &soa("example."),
            &[
                nsec(
                    "example.",
                    "a.example.",
                    &[RecordType::SOA, RecordType::NS, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "a.example.",
                    "m.example.",
                    &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "m.example.",
                    "example.",
                    &[RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
                    Proof::Secure,
                ),
            ],
        );
        cache
    }

    #[test]
    fn a_covered_name_is_nxdomain() {
        let cache = zone_cache();
        let answer = cache
            .synthesize(&query("zzz.example.", RecordType::A))
            .expect("the last NSEC wraps around and covers zzz.example.");
        assert_eq!(answer.code, ResponseCode::NXDomain);
        assert_eq!(answer.soa.name, name("example."));
        assert_eq!(answer.proofs.len(), 2, "the name and its wildcard");
    }

    #[test]
    fn an_existing_name_without_the_type_is_nodata() {
        let cache = zone_cache();
        let answer = cache
            .synthesize(&query("a.example.", RecordType::AAAA))
            .expect("a.example. exists without AAAA.");
        assert_eq!(answer.code, ResponseCode::NoError);
        assert_eq!(answer.proofs.len(), 1);
    }

    #[test]
    fn an_existing_type_is_not_answered_from_cache() {
        let cache = zone_cache();
        assert!(cache
            .synthesize(&query("a.example.", RecordType::A))
            .is_none());
        assert!(cache
            .synthesize(&query("m.example.", RecordType::MX))
            .is_none());
    }

    #[test]
    fn a_name_the_chain_does_not_cover_is_not_answered() {
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &soa("example."),
            &[nsec(
                "a.example.",
                "m.example.",
                &[RecordType::A, RecordType::NSEC],
                Proof::Secure,
            )],
        );
        // `b.example.` is between a and m, but no NSEC proves the closest
        // encloser or the wildcard, so the query must still go out.
        assert!(cache
            .synthesize(&query("b.example.", RecordType::AAAA))
            .is_none());
    }

    #[test]
    fn unvalidated_proofs_are_ignored() {
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &soa("example."),
            &[nsec(
                "example.",
                "a.example.",
                &[RecordType::SOA, RecordType::NSEC],
                Proof::Insecure,
            )],
        );
        assert!(cache
            .synthesize(&query("zzz.example.", RecordType::A))
            .is_none());

        let mut insecure_soa = soa("example.");
        insecure_soa.proof = Proof::Insecure;
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &insecure_soa,
            &[nsec(
                "example.",
                "a.example.",
                &[RecordType::SOA, RecordType::NSEC],
                Proof::Secure,
            )],
        );
        assert!(cache
            .synthesize(&query("zzz.example.", RecordType::A))
            .is_none());
    }

    #[test]
    fn ancestor_delegation_nsecs_prove_nothing_below_the_cut() {
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &soa("example."),
            &[
                // A parent-side delegation NSEC: NS without SOA.
                nsec(
                    "example.",
                    "sub.example.",
                    &[RecordType::NS, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "sub.example.",
                    "example.",
                    &[RecordType::NS, RecordType::NSEC],
                    Proof::Secure,
                ),
            ],
        );
        assert!(cache
            .synthesize(&query("nothing.sub.example.", RecordType::A))
            .is_none());
    }

    #[test]
    fn proofs_expire_with_the_negative_ttl() {
        let cache = AggressiveNsec::new(0);
        let now = Instant::now();
        cache.insert_at(
            &soa("example."),
            &[
                nsec(
                    "example.",
                    "a.example.",
                    &[RecordType::SOA, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "a.example.",
                    "example.",
                    &[RecordType::A, RecordType::NSEC],
                    Proof::Secure,
                ),
            ],
            now - Duration::from_secs(301),
        );
        assert!(cache
            .synthesize(&query("zzz.example.", RecordType::A))
            .is_none());
    }

    #[test]
    fn proofs_do_not_outlive_their_own_nsec_ttl() {
        // The SOA's negative TTL is 300s, but the NSECs themselves carry a
        // 10s TTL: the denial must stop being usable after 10s, not 300s.
        let cache = AggressiveNsec::new(0);
        let now = Instant::now();
        let short = |owner: &str, next: &str, types: &[RecordType]| {
            let mut record = nsec(owner, next, types, Proof::Secure);
            record.ttl = 10;
            record
        };
        cache.insert_at(
            &soa("example."),
            &[
                short(
                    "example.",
                    "a.example.",
                    &[RecordType::SOA, RecordType::NSEC],
                ),
                short("a.example.", "example.", &[RecordType::A, RecordType::NSEC]),
            ],
            now - Duration::from_secs(20),
        );
        assert!(cache
            .synthesize(&query("zzz.example.", RecordType::A))
            .is_none());
    }

    #[test]
    fn an_empty_non_terminal_is_a_closest_encloser() {
        // `y.example.` has no NSEC of its own, but `x.y.example.` does, so
        // `y.example.` exists (empty non-terminal) and is the closest
        // encloser of `q.y.example.`. Only the `w.example.` NSEC, which
        // covers both the name and `*.y.example.`, is needed as proof.
        let cache = AggressiveNsec::new(0);
        cache.insert(
            &soa("example."),
            &[
                nsec(
                    "example.",
                    "w.example.",
                    &[RecordType::SOA, RecordType::NS, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "w.example.",
                    "z.example.",
                    &[RecordType::A, RecordType::NSEC],
                    Proof::Secure,
                ),
                nsec(
                    "x.y.example.",
                    "z.example.",
                    &[RecordType::A, RecordType::NSEC],
                    Proof::Secure,
                ),
            ],
        );
        let answer = cache
            .synthesize(&query("q.y.example.", RecordType::A))
            .expect("the empty non-terminal y.example. is the closest encloser");
        assert_eq!(answer.code, ResponseCode::NXDomain);
        assert_eq!(answer.proofs.len(), 1);
        assert_eq!(answer.proofs[0].name, name("w.example."));
    }

    #[test]
    fn canonical_order_is_not_plain_string_order() {
        let labels = |n: &str| canonical_labels(&name(n));
        // `*.example.` sorts before any other label at that position, and a
        // deeper name sorts after its parent.
        assert!(labels("*.example.") < labels("a.example."));
        assert!(labels("example.") < labels("*.example."));
        assert!(labels("a.example.") < labels("m.example."));
        assert!(labels("zzz.example.") > labels("a.example."));
    }
}
