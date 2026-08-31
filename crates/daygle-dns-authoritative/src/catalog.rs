//! Assembles SQLite-backed zones into a Hickory [`Catalog`] for serving, with
//! optional DNSSEC signing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::dnskey::DNSKEY;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
use hickory_proto::rr::{LowerName, Name, RData, RrKey, Record, RecordSet, RecordType};
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType};
use tracing::{info, warn};

use crate::model::Record as DbRecord;
use crate::model::SigningKeyRecord;
use crate::split_horizon::SplitHorizonIndex;
use crate::store::ZoneStore;
use daygle_dns_core::config::AuthoritativeSettings;
use daygle_dns_core::error::{DaygleError, Result};

/// Signature validity derived from the configured day count.
pub(crate) fn sig_duration(settings: &AuthoritativeSettings) -> Duration {
    Duration::from_secs(u64::from(settings.dnssec_sig_validity_days) * 60 * 60 * 24)
}

/// An authoritative catalog backed by a [`ZoneStore`].
///
/// The catalog is rebuilt from the database whenever zones change
/// ([`AuthorityCatalog::reload`]). It is cheap to share: it wraps the Hickory
/// `Catalog` in an `Arc<RwLock<..>>`, and the DNS dispatcher takes a short
/// read lock per query.
pub struct AuthorityCatalog {
    store: ZoneStore,
    settings: AuthoritativeSettings,
    // `ArcSwap` lets readers clone out an owned `Arc<Catalog>` (which is `Send`)
    // instead of holding a lock guard across an `.await` in the dispatcher.
    catalog: arc_swap::ArcSwap<Catalog>,
    /// Pre-resolved split-horizon rules (client network → synthetic answer),
    /// rebuilt alongside the catalog so DNS and API changes stay in sync.
    split_horizon: arc_swap::ArcSwap<SplitHorizonIndex>,
}

impl AuthorityCatalog {
    /// Build a catalog from the store without any DNSSEC signing.
    pub fn new(store: ZoneStore, settings: AuthoritativeSettings) -> Result<Self> {
        let catalog = build_catalog(&store, &settings, false)?;
        let split_horizon = Arc::new(build_split_horizon(&store)?);
        Ok(Self {
            store,
            settings,
            catalog: arc_swap::ArcSwap::from_pointee(catalog),
            split_horizon: arc_swap::ArcSwap::from(split_horizon),
        })
    }

    pub fn store(&self) -> &ZoneStore {
        &self.store
    }

    pub fn settings(&self) -> &AuthoritativeSettings {
        &self.settings
    }

    /// The TSIG key ring built from the authoritative settings. Keys are
    /// validated at load time; an invalid key is a configuration error that
    /// surfaces at startup/reload rather than at first use.
    pub fn tsig_key_ring(&self) -> std::sync::Arc<crate::tsig::TsigKeyRing> {
        use std::sync::OnceLock;
        static CACHE_INVALID: OnceLock<()> = OnceLock::new();
        let _ = CACHE_INVALID;
        let ring = crate::tsig::TsigKeyRing::from_configs(&self.settings.tsig_keys)
            .unwrap_or_default();
        std::sync::Arc::new(ring)
    }

    /// The TSIG key (if any) required for transfers of `zone_name`.
    pub fn tsig_transfer_key(&self, zone_name: &str) -> Option<crate::tsig::TsigKey> {
        let ring = crate::tsig::TsigKeyRing::from_configs(&self.settings.tsig_keys)
            .unwrap_or_default();
        for binding in &self.settings.tsig_transfer_zones {
            if let Some((zone, key)) = binding.split_once('=') {
                if zone.trim_end_matches('.').eq_ignore_ascii_case(&zone_name.trim_end_matches('.')) {
                    return ring.get_by_config_name(key).cloned();
                }
            }
        }
        None
    }

    /// The TSIG key (if any) required for updates to `zone_name`.
    pub fn tsig_update_key(&self, zone_name: &str) -> Option<crate::tsig::TsigKey> {
        let ring = crate::tsig::TsigKeyRing::from_configs(&self.settings.tsig_keys)
            .unwrap_or_default();
        for binding in &self.settings.tsig_update_zones {
            if let Some((zone, key)) = binding.split_once('=') {
                if zone.trim_end_matches('.').eq_ignore_ascii_case(&zone_name.trim_end_matches('.')) {
                    return ring.get_by_config_name(key).cloned();
                }
            }
        }
        None
    }

    /// Clone out the current catalog for serving (cheap `Arc` bump).
    pub fn read(&self) -> Arc<Catalog> {
        self.catalog.load_full()
    }

    /// Whether `name` falls inside an authoritative zone (recursive search
    /// from the name up to the root).
    pub fn contains(&self, name: &LowerName) -> bool {
        self.catalog.load().find(name).is_some()
    }

    /// Rebuild the catalog and split-horizon index from the database,
    /// applying DNSSEC signing when keys are present and signing is enabled.
    pub fn reload(&self) -> Result<()> {
        let catalog = build_catalog(&self.store, &self.settings, self.settings.dnssec_enabled)?;
        self.catalog.store(Arc::new(catalog));
        let split_horizon = Arc::new(build_split_horizon(&self.store)?);
        self.split_horizon.store(split_horizon);
        info!("authoritative catalog reloaded");
        Ok(())
    }

    /// Clone out the current split-horizon index (cheap `Arc` bump).
    pub fn split_horizon(&self) -> Arc<SplitHorizonIndex> {
        self.split_horizon.load_full()
    }

    /// Generate (if necessary) a DNSSEC signing key for `zone_id`, sign the
    /// zone, and reload the catalog.
    pub fn sign_zone(&self, zone_id: &str) -> Result<()> {
        if self.store.list_signing_keys(zone_id)?.is_empty() {
            let (algorithm, der) = generate_signing_key()?;
            self.store.store_signing_key(zone_id, algorithm, &der)?;
            info!("generated DNSSEC signing key for zone {zone_id}");
        }
        self.reload()
    }

    /// Remove the signing key for a zone and reload.
    pub fn unsign_zone(&self, zone_id: &str) -> Result<()> {
        self.store.delete_signing_key(zone_id)?;
        self.reload()
    }

    /// Build the record list for a zone transfer (AXFR/IXFR response): the
    /// synthesized SOA, plus every other record in the zone. The caller is
    /// responsible for placing the SOA at both the start and end of the
    /// answer section, as RFC 5936 requires.
    ///
    /// Returns `None` when no zone with exactly `zone_name` exists.
    pub fn transfer_records(&self, zone_name: &str) -> Result<Option<(Record, Vec<Record>)>> {
        let Some(zone) = self.store.find_zone_by_name(zone_name)? else {
            return Ok(None);
        };
        let records = self.store.list_records(&zone.id)?;
        let map = zone_rrsets(&zone, &records)?;

        let mut soa = None;
        let mut others = Vec::with_capacity(map.len() * 2);
        for set in map.values() {
            for record in set.records_without_rrsigs() {
                if record.record_type() == RecordType::SOA {
                    soa = Some(record.clone());
                } else {
                    others.push(record.clone());
                }
            }
        }
        let Some(soa) = soa else {
            return Ok(None);
        };
        Ok(Some((soa, others)))
    }
}

/// Generate an ECDSA P-256 signing key, returning `(algorithm, pkcs8_der)`.
pub fn generate_signing_key() -> Result<(u8, Vec<u8>)> {
    let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
        .map_err(|e| DaygleError::Internal(format!("key generation failed: {e}")))?;
    Ok((u8::from(Algorithm::ECDSAP256SHA256), der.secret_pkcs8_der().to_vec()))
}

/// Build the split-horizon index from the store's networks and entries.
fn build_split_horizon(store: &ZoneStore) -> Result<SplitHorizonIndex> {
    let networks = store.list_split_horizon_networks()?;
    let entries = store.list_split_horizon_entries()?;
    Ok(SplitHorizonIndex::build(&networks, &entries))
}

/// Build a fresh Hickory `Catalog` from the store.
fn build_catalog(
    store: &ZoneStore,
    settings: &AuthoritativeSettings,
    sign_zones: bool,
) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    let data = store.load_catalog_data()?;
    let secondary_ids: std::collections::HashSet<String> = store
        .list_secondary()?
        .into_iter()
        .map(|s| s.zone_id)
        .collect();

    let sig_validity = sig_duration(settings);

    for (zone, records, keys) in data {
        let origin = fqdn_name(&zone.name)?;
        let zone_type = if secondary_ids.contains(&zone.id) {
            ZoneType::Secondary
        } else {
            ZoneType::Primary
        };
        let active: Vec<&SigningKeyRecord> = keys.iter().filter(|k| k.is_active()).collect();
        let retired: Vec<&SigningKeyRecord> = keys.iter().filter(|k| k.is_retired()).collect();
        let mut map = zone_rrsets(&zone, &records)?;

        // Retired keys no longer sign, but their DNSKEY stays published for
        // the retirement grace period so validators holding cached RRSIGs
        // made by the old key can still build a chain of trust (RFC 6781).
        if sign_zones {
            for key in &retired {
                match build_dnskey_record(&origin, key.algorithm, &key.key_der, zone.minimum.max(300))
                {
                    Ok(record) => {
                        insert_record_set(&mut map, record)?;
                    }
                    Err(e) => warn!(
                        zone = %zone.name,
                        error = %e,
                        "cannot publish retired DNSKEY"
                    ),
                }
            }
        }

        let nx_proof_kind = if sign_zones && !active.is_empty() {
            Some(NxProofKind::Nsec)
        } else {
            None
        };

        let mut handler: InMemoryZoneHandler = InMemoryZoneHandler::new(
            origin.clone(),
            map,
            zone_type,
            AxfrPolicy::Deny,
            nx_proof_kind,
        )
        .map_err(DaygleError::InvalidRecord)?;

        // Apply DNSSEC signing: every active key signs every RRset (and the
        // DNSKEY RRset), which is what makes pre-publish/double-sign rollover
        // work - validators can pick either key while both are published.
        if sign_zones {
            let mut added = 0usize;
            for key in &active {
                match build_signer(origin.clone(), key.algorithm, &key.key_der, sig_validity) {
                    Ok(signer) => match handler.add_zone_signing_key_mut(signer) {
                        Ok(()) => added += 1,
                        Err(e) => warn!("failed to add signing key for {}: {e}", zone.name),
                    },
                    Err(e) => warn!("cannot reconstruct signing key for {}: {e}", zone.name),
                }
            }
            if added > 0 {
                match handler.secure_zone_mut() {
                    Ok(()) => info!(
                        zone = %zone.name,
                        keys = added,
                        retired = retired.len(),
                        "zone signed with DNSSEC"
                    ),
                    Err(e) => warn!("failed to sign zone {}: {e}", zone.name),
                }
            }
        }

        let lower = LowerName::from(origin);
        catalog.upsert(lower, vec![Arc::new(handler) as Arc<dyn ZoneHandler>]);
    }

    Ok(catalog)
}

/// Build the full set of `RrKey -> RecordSet` for one zone, including the
/// synthesized SOA record. Shared by the catalog builder and zone transfers.
fn zone_rrsets(
    zone: &crate::model::Zone,
    records: &[DbRecord],
) -> Result<BTreeMap<RrKey, RecordSet>> {
    let origin = fqdn_name(&zone.name)?;
    let mut map: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

    // Synthesize the SOA record from zone metadata.
    let soa_rdata = RData::try_from_str(
        RecordType::SOA,
        &format!(
            "{} {} {} {} {} {} {}",
            zone.primary_ns,
            zone.admin_mailbox,
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum,
        ),
    )
    .map_err(|e| DaygleError::InvalidRecord(format!("SOA for {}: {e}", zone.name)))?;
    insert_record(&mut map, &origin, zone.minimum.max(300), soa_rdata)?;

    // Insert every enabled record.
    for record in records {
        if record.disabled {
            continue;
        }
        match record_to_hickory(record) {
            Ok(rec) => insert_record_set(&mut map, rec)?,
            Err(e) => warn!("skipping record {} ({}): {e}", record.name, record.rtype),
        }
    }
    Ok(map)
}

/// Parse a domain string as an absolute Hickory [`Name`].
fn fqdn_name(name: &str) -> Result<Name> {
    Name::from_utf8(&format!("{}.", name.trim().trim_end_matches('.')))
        .map_err(|e| DaygleError::InvalidRecord(format!("name '{name}': {e}")))
}

/// Convert a database record into a Hickory record.
fn record_to_hickory(record: &DbRecord) -> Result<Record> {
    let name = fqdn_name(&record.name)?;
    let rtype = record
        .rtype
        .parse::<RecordType>()
        .map_err(|e| DaygleError::InvalidRecord(format!("type {}: {e}", record.rtype)))?;
    let rdata = RData::try_from_str(rtype, &record.content)
        .map_err(|e| DaygleError::InvalidRecord(format!("rdata '{}': {e}", record.content)))?;
    Ok(Record::from_rdata(name, record.ttl, rdata))
}

/// Insert a single record, creating or appending to the owning `RecordSet`.
fn insert_record(
    map: &mut BTreeMap<RrKey, RecordSet>,
    name: &Name,
    ttl: u32,
    rdata: RData,
) -> Result<()> {
    let rec = Record::from_rdata(name.clone(), ttl, rdata);
    insert_record_set(map, rec)
}

fn insert_record_set(map: &mut BTreeMap<RrKey, RecordSet>, record: Record) -> Result<()> {
    let key = RrKey::new(LowerName::from(record.name.clone()), record.record_type());
    let ttl = record.ttl;
    match map.get_mut(&key) {
        Some(set) => {
            set.insert(record, 0);
        }
        None => {
            let mut set = RecordSet::with_ttl(record.name.clone(), record.record_type(), ttl);
            set.insert(record, 0);
            map.insert(key, set);
        }
    }
    Ok(())
}

/// Reconstruct a [`DnssecSigner`] from stored PKCS#8 key material.
pub(crate) fn build_signer(
    origin: Name,
    algorithm: u8,
    der: &[u8],
    sig_duration: Duration,
) -> Result<DnssecSigner> {
    let algorithm = Algorithm::from_u8(algorithm);
    let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(der);
    let key = EcdsaSigningKey::from_pkcs8(&key_der, algorithm)
        .map_err(|e| DaygleError::Internal(format!("invalid signing key: {e}")))?;
    let public = key
        .to_public_key()
        .map_err(|e| DaygleError::Internal(format!("cannot derive public key: {e}")))?;
    let dnskey = DNSKEY::new(true, true, false, public);
    Ok(DnssecSigner::new(
        dnskey,
        Box::new(key),
        origin,
        sig_duration,
    ))
}

/// Build the DNSKEY record for a stored key without a signer (used to keep
/// retired keys published during the rollover grace period).
pub(crate) fn build_dnskey_record(
    origin: &Name,
    algorithm: u8,
    der: &[u8],
    ttl: u32,
) -> Result<Record> {
    let algorithm = Algorithm::from_u8(algorithm);
    let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(der);
    let key = EcdsaSigningKey::from_pkcs8(&key_der, algorithm)
        .map_err(|e| DaygleError::Internal(format!("invalid signing key: {e}")))?;
    let public = key
        .to_public_key()
        .map_err(|e| DaygleError::Internal(format!("cannot derive public key: {e}")))?;
    let dnskey = DNSKEY::new(true, true, false, public);
    Ok(Record::from_rdata(
        origin.clone(),
        ttl,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RecordInput, ZoneInput};

    fn catalog() -> AuthorityCatalog {
        let store = ZoneStore::open(":memory:").unwrap();
        let settings = AuthoritativeSettings {
            dnssec_enabled: false,
            ..Default::default()
        };
        let zone = store
            .create_zone(&ZoneInput {
                name: "example.com".to_string(),
                ..Default::default()
            })
            .unwrap();
        store
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "www".to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.10".to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
        AuthorityCatalog::new(store, settings).unwrap()
    }

    #[test]
    fn builds_catalog_with_zones() {
        let catalog = catalog();
        let lower: LowerName = "example.com.".parse().unwrap();
        assert!(catalog.contains(&lower));
        assert!(!catalog.contains(&"other.com.".parse().unwrap()));
    }

    #[test]
    fn reload_keeps_catalog_valid() {
        let catalog = catalog();
        catalog.reload().unwrap();
        let lower: LowerName = "example.com.".parse().unwrap();
        assert!(catalog.contains(&lower));
    }
}
