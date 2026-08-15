//! Assembles SQLite-backed zones into a Hickory [`Catalog`] for serving, with
//! optional DNSSEC signing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::dnskey::DNSKEY;
use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
use hickory_proto::rr::{LowerName, Name, RData, RrKey, Record, RecordSet, RecordType};
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType};
use tracing::{info, warn};

use crate::model::Record as DbRecord;
use crate::store::ZoneStore;
use daygle_core::config::AuthoritativeSettings;
use daygle_core::error::{DaygleError, Result};

/// Signature validity window for DNSSEC signing (14 days).
const SIG_DURATION: Duration = Duration::from_secs(60 * 60 * 24 * 14);

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
}

impl AuthorityCatalog {
    /// Build a catalog from the store without any DNSSEC signing.
    pub fn new(store: ZoneStore, settings: AuthoritativeSettings) -> Result<Self> {
        let catalog = build_catalog(&store, &settings, false)?;
        Ok(Self {
            store,
            settings,
            catalog: arc_swap::ArcSwap::from_pointee(catalog),
        })
    }

    pub fn store(&self) -> &ZoneStore {
        &self.store
    }

    pub fn settings(&self) -> &AuthoritativeSettings {
        &self.settings
    }

    /// Clone out the current catalog for serving (cheap `Arc` bump).
    pub fn read(&self) -> Arc<Catalog> {
        self.catalog.load_full()
    }

    /// Whether a zone apex is present in the catalog.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.catalog.load().contains(name)
    }

    /// Rebuild the catalog from the database, applying DNSSEC signing when
    /// keys are present and signing is enabled.
    pub fn reload(&self) -> Result<()> {
        let catalog = build_catalog(&self.store, &self.settings, self.settings.dnssec_enabled)?;
        self.catalog.store(Arc::new(catalog));
        info!("authoritative catalog reloaded");
        Ok(())
    }

    /// Generate (if necessary) a DNSSEC signing key for `zone_id`, sign the
    /// zone, and reload the catalog.
    pub fn sign_zone(&self, zone_id: &str) -> Result<()> {
        if self.store.get_signing_key(zone_id)?.is_none() {
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
}

/// Generate an ECDSA P-256 signing key, returning `(algorithm, pkcs8_der)`.
fn generate_signing_key() -> Result<(u8, Vec<u8>)> {
    let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
        .map_err(|e| DaygleError::Internal(format!("key generation failed: {e}")))?;
    Ok((u8::from(Algorithm::ECDSAP256SHA256), der.secret_pkcs8_der().to_vec()))
}

/// Build a fresh Hickory `Catalog` from the store.
fn build_catalog(
    store: &ZoneStore,
    settings: &AuthoritativeSettings,
    sign_zones: bool,
) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    let data = store.load_catalog_data()?;

    for (zone, records, key) in data {
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
        for record in &records {
            if record.disabled {
                continue;
            }
            match record_to_hickory(record) {
                Ok(rec) => insert_record_set(&mut map, rec)?,
                Err(e) => warn!("skipping record {} ({}): {e}", record.name, record.rtype),
            }
        }

        let nx_proof_kind = if sign_zones && key.is_some() {
            Some(NxProofKind::Nsec)
        } else {
            None
        };

        let mut handler: InMemoryZoneHandler = InMemoryZoneHandler::new(
            origin.clone(),
            map,
            ZoneType::Primary,
            AxfrPolicy::Deny,
            nx_proof_kind,
        )
        .map_err(DaygleError::InvalidRecord)?;

        // Apply DNSSEC signing when a key is present.
        if sign_zones {
            if let Some((algorithm, der)) = key {
                match build_signer(origin.clone(), algorithm, &der) {
                    Ok(signer) => {
                        if let Err(e) = handler.add_zone_signing_key_mut(signer) {
                            warn!("failed to add signing key for {}: {e}", zone.name);
                        } else if let Err(e) = handler.secure_zone_mut() {
                            warn!("failed to sign zone {}: {e}", zone.name);
                        } else {
                            info!("zone {} signed with DNSSEC", zone.name);
                        }
                    }
                    Err(e) => warn!("cannot reconstruct signing key for {}: {e}", zone.name),
                }
            }
        }

        let lower = LowerName::from(origin);
        catalog.upsert(lower, vec![Arc::new(handler) as Arc<dyn ZoneHandler>]);
    }

    // Silence the unused-variable warning when settings is only used above.
    let _ = settings;
    Ok(catalog)
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
fn build_signer(origin: Name, algorithm: u8, der: &[u8]) -> Result<DnssecSigner> {
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
        SIG_DURATION,
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
