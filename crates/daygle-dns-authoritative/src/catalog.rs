//! Assembles SQLite-backed zones into a Hickory [`Catalog`] for serving, with
//! optional DNSSEC signing.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::dnskey::DNSKEY;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::dnssec::NxProofKind;
use hickory_server::net::runtime::{RuntimeProvider, Time, TokioRuntimeProvider, TokioTime};
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
    // `ArcSwap` so the console can hot-swap the per-request gate settings
    // (AXFR and dynamic-update policy) without rebuilding the zones.
    settings: arc_swap::ArcSwap<AuthoritativeSettings>,
    // `ArcSwap` lets readers clone out an owned `Arc<Catalog>` (which is `Send`)
    // instead of holding a lock guard across an `.await` in the dispatcher.
    catalog: arc_swap::ArcSwap<Catalog>,
    /// Pre-resolved split-horizon rules (client network → synthetic answer),
    /// rebuilt alongside the catalog so DNS and API changes stay in sync.
    split_horizon: arc_swap::ArcSwap<SplitHorizonIndex>,
    /// The named networks split-horizon entries refer to (built-in and
    /// configured; see [`Self::set_networks`]).
    networks: arc_swap::ArcSwap<Vec<daygle_dns_core::config::NamedNetwork>>,
    /// ALIAS records by owner name (lowercase, no trailing dot), rebuilt
    /// with the catalog.
    aliases: arc_swap::ArcSwap<std::collections::HashMap<String, Alias>>,
    /// Woken when the published catalog zone's member list changes, so
    /// its secondaries can be sent a NOTIFY.
    catalog_zone_changed: Arc<tokio::sync::Notify>,
    /// Ids of health-checked records currently failing their check.
    unhealthy: arc_swap::ArcSwap<std::collections::HashSet<String>>,
    /// Held while a catalog is built and published, so a slow rebuild that
    /// read the database first cannot replace a newer one.
    reload_lock: Mutex<()>,
    /// The served data of zones whose transfers must carry it verbatim
    /// (signed zones, and secondaries kept as their master sent them), by
    /// lowercase zone name.
    transfer_sets: arc_swap::ArcSwap<HashMap<String, Arc<ServedRecords>>>,
    /// The SOA serial each primary zone was last served with.
    serials: Mutex<HashMap<String, u32>>,
    /// Primary zones whose serial changed since [`Self::take_changed_zones`]
    /// was last called.
    changed_zones: Mutex<BTreeSet<String>>,
    /// Woken when `changed_zones` gains a zone, so its secondaries can be
    /// sent a NOTIFY.
    zones_changed: Arc<tokio::sync::Notify>,
    /// Dynamic updates run one at a time (RFC 2136 §3.7): prerequisites are
    /// checked against the zone as it will be when the update applies.
    pub(crate) update_lock: tokio::sync::Mutex<()>,
}

/// A zone's served records, with their signatures.
pub type ServedRecords = BTreeMap<RrKey, Arc<RecordSet>>;

/// How far signature inceptions are backdated. Hickory stamps each RRSIG
/// with the signing time; a validator whose clock runs behind ours would
/// reject a signature made moments ago as not yet valid, after every
/// re-sign, until its clock caught up. An hour (as BIND uses) absorbs
/// ordinary clock skew.
const INCEPTION_BACKDATE_SECS: u64 = 3600;

/// Hickory's Tokio runtime, with a clock that reads [`INCEPTION_BACKDATE_SECS`]
/// early. Zone handlers use the clock only to stamp signature inceptions.
#[derive(Clone, Default)]
pub struct SigningRuntime(TokioRuntimeProvider);

/// The backdated signing clock of [`SigningRuntime`].
pub struct SigningClock;

#[async_trait::async_trait]
impl Time for SigningClock {
    async fn delay_for(duration: Duration) {
        TokioTime::delay_for(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> std::io::Result<F::Output> {
        TokioTime::timeout(duration, future).await
    }

    fn current_time() -> u64 {
        TokioTime::current_time().saturating_sub(INCEPTION_BACKDATE_SECS)
    }
}

impl RuntimeProvider for SigningRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = SigningClock;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        self.0.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        self.0.bind_udp(local_addr, server_addr)
    }
}

/// The zone handler every hosted zone is served by.
type ZoneData = InMemoryZoneHandler<SigningRuntime>;

/// A freshly built catalog and what changed in it.
struct Built {
    catalog: Catalog,
    catalog_zone_changed: bool,
    /// Served SOA serial of each primary zone, by lowercase name.
    serials: HashMap<String, u32>,
    transfer_sets: HashMap<String, Arc<ServedRecords>>,
}

/// The key zones are filed under: lowercase, no trailing dot.
fn zone_key(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// An ALIAS record: A and AAAA queries for its name are answered with its
/// target's addresses, looked up when asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    /// The target (lowercase, trailing dot).
    pub target: String,
    pub ttl: u32,
}

/// Every enabled ALIAS record in the store, by owner name.
fn build_aliases(store: &ZoneStore) -> Result<std::collections::HashMap<String, Alias>> {
    let mut aliases = std::collections::HashMap::new();
    for (zone, records, _) in store.load_catalog_data()? {
        if !zone.enabled {
            continue;
        }
        for record in records {
            if record.rtype == "ALIAS" && !record.disabled {
                aliases.insert(
                    record.name.trim_end_matches('.').to_ascii_lowercase(),
                    Alias {
                        target: record.content.clone(),
                        ttl: record.ttl,
                    },
                );
            }
        }
    }
    Ok(aliases)
}

impl AuthorityCatalog {
    /// Build a catalog from the store without any DNSSEC signing.
    pub fn new(store: ZoneStore, settings: AuthoritativeSettings) -> Result<Self> {
        let built = build_catalog(&store, &settings, false, &Default::default())?;
        let networks = daygle_dns_core::config::builtin_networks();
        let split_horizon = Arc::new(build_split_horizon(&store, &networks)?);
        let aliases = build_aliases(&store)?;
        Ok(Self {
            store,
            settings: arc_swap::ArcSwap::from_pointee(settings),
            catalog: arc_swap::ArcSwap::from_pointee(built.catalog),
            split_horizon: arc_swap::ArcSwap::from(split_horizon),
            networks: arc_swap::ArcSwap::from_pointee(networks),
            aliases: arc_swap::ArcSwap::from_pointee(aliases),
            catalog_zone_changed: Arc::new(tokio::sync::Notify::new()),
            unhealthy: Default::default(),
            reload_lock: Mutex::new(()),
            transfer_sets: arc_swap::ArcSwap::from_pointee(built.transfer_sets),
            serials: Mutex::new(built.serials),
            changed_zones: Mutex::new(BTreeSet::new()),
            zones_changed: Arc::new(tokio::sync::Notify::new()),
            update_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Woken when a primary zone is served with a new serial (any change:
    /// console edit, import, dynamic update, re-sign), so its secondaries
    /// can be sent a NOTIFY. Collect the zones with
    /// [`Self::take_changed_zones`].
    pub fn zones_changed(&self) -> Arc<tokio::sync::Notify> {
        self.zones_changed.clone()
    }

    /// The primary zones whose serial changed since the last call.
    pub fn take_changed_zones(&self) -> Vec<String> {
        std::mem::take(&mut *self.changed_zones.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .collect()
    }

    /// The health-checked records now failing their check.
    pub fn unhealthy(&self) -> Arc<std::collections::HashSet<String>> {
        self.unhealthy.load_full()
    }

    /// Record which health-checked records are failing, and reload when
    /// that changed (so answers fail over to the healthy ones).
    pub fn set_unhealthy(&self, unhealthy: std::collections::HashSet<String>) -> Result<()> {
        if *self.unhealthy.load_full() == unhealthy {
            return Ok(());
        }
        self.unhealthy.store(Arc::new(unhealthy));
        self.reload()
    }

    /// Woken whenever the published catalog zone's member list changes.
    pub fn catalog_zone_changed(&self) -> Arc<tokio::sync::Notify> {
        self.catalog_zone_changed.clone()
    }

    /// Publish the catalog zone under `name` (empty: stop publishing it)
    /// and reload.
    pub fn set_catalog_zone(&self, name: &str) -> Result<()> {
        let name = daygle_dns_core::config::normalize_zone_name(name);
        self.settings.rcu(|s| {
            let mut s = AuthoritativeSettings::clone(s);
            s.catalog_zone = name.clone();
            s
        });
        self.reload()
    }

    pub fn store(&self) -> &ZoneStore {
        &self.store
    }

    /// Clone the store handle for best-effort background writes.
    pub fn store_handle(&self) -> ZoneStore {
        self.store.clone()
    }

    /// A snapshot of the authoritative settings. Returned owned (not a
    /// reference) so callers may hold it across `.await` points.
    pub fn settings(&self) -> std::sync::Arc<AuthoritativeSettings> {
        self.settings.load_full()
    }

    /// Hot-swap the per-request gate settings: the AXFR/IXFR policy and the
    /// RFC 2136 dynamic-update policy. The dispatcher and update handler read
    /// these per request, so changes apply immediately.
    ///
    /// DNSSEC signing parameters are deliberately untouched: they are baked
    /// into the signed zone data at build time and still require a restart.
    pub fn update_gate_settings(
        &self,
        axfr_enabled: bool,
        axfr_networks: Vec<String>,
        allow_dynamic_updates: bool,
        update_networks: Vec<String>,
    ) {
        self.settings.rcu(|s| {
            let mut s = AuthoritativeSettings::clone(s);
            s.axfr_enabled = axfr_enabled;
            s.axfr_networks = axfr_networks.clone();
            s.allow_dynamic_updates = allow_dynamic_updates;
            s.update_networks = update_networks.clone();
            s
        });
    }

    /// The TSIG key ring built from the authoritative settings. Keys are
    /// validated at load time; an invalid key is a configuration error that
    /// surfaces at startup/reload rather than at first use.
    pub fn tsig_key_ring(&self) -> std::sync::Arc<crate::tsig::TsigKeyRing> {
        let settings = self.settings.load_full();
        let ring = crate::tsig::TsigKeyRing::from_configs(&settings.tsig_keys).unwrap_or_default();
        std::sync::Arc::new(ring)
    }

    /// The TSIG key (if any) required for transfers of `zone_name`.
    pub fn tsig_transfer_key(&self, zone_name: &str) -> Option<crate::tsig::TsigKey> {
        let settings = self.settings.load_full();
        let ring = crate::tsig::TsigKeyRing::from_configs(&settings.tsig_keys).unwrap_or_default();
        for binding in &settings.tsig_transfer_zones {
            if let Some((zone, key)) = binding.split_once('=') {
                if zone
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(zone_name.trim_end_matches('.'))
                {
                    return ring.get_by_config_name(key).cloned();
                }
            }
        }
        None
    }

    /// The TSIG key (if any) required for updates to `zone_name`.
    pub fn tsig_update_key(&self, zone_name: &str) -> Option<crate::tsig::TsigKey> {
        let settings = self.settings.load_full();
        let ring = crate::tsig::TsigKeyRing::from_configs(&settings.tsig_keys).unwrap_or_default();
        for binding in &settings.tsig_update_zones {
            if let Some((zone, key)) = binding.split_once('=') {
                if zone
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(zone_name.trim_end_matches('.'))
                {
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
        let _reload = self.reload_lock.lock().unwrap_or_else(|e| e.into_inner());
        let settings = self.settings.load_full();
        let built = build_catalog(
            &self.store,
            &settings,
            settings.dnssec_enabled,
            &self.unhealthy.load(),
        )?;
        self.catalog.store(Arc::new(built.catalog));
        self.transfer_sets.store(Arc::new(built.transfer_sets));
        if built.catalog_zone_changed {
            self.catalog_zone_changed.notify_waiters();
        }
        let split_horizon = Arc::new(build_split_horizon(&self.store, &self.networks.load())?);
        self.split_horizon.store(split_horizon);
        self.aliases.store(Arc::new(build_aliases(&self.store)?));

        let mut serials = self.serials.lock().unwrap_or_else(|e| e.into_inner());
        let changed: Vec<String> = built
            .serials
            .iter()
            .filter(|(name, serial)| serials.get(*name) != Some(*serial))
            .map(|(name, _)| name.clone())
            .collect();
        *serials = built.serials;
        drop(serials);
        if !changed.is_empty() {
            self.changed_zones
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(changed);
            self.zones_changed.notify_one();
        }
        info!("authoritative catalog reloaded");
        Ok(())
    }

    /// The DS records (SHA-256 digest) a parent zone should publish for the
    /// signed zone `zone_id`, one per active key, in presentation form.
    /// Empty when the zone is not served signed.
    pub fn ds_records(&self, zone_id: &str) -> Result<Vec<String>> {
        if !self.settings.load().dnssec_enabled {
            return Ok(Vec::new());
        }
        let Some(zone) = self.store.get_zone(zone_id)? else {
            return Ok(Vec::new());
        };
        let origin = fqdn_name(&zone.name)?;
        let mut out = Vec::new();
        for key in self.store.list_signing_keys(zone_id)? {
            if !key.is_active() {
                continue;
            }
            let record = build_dnskey_record(&origin, key.algorithm, &key.key_der, 0)?;
            let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &record.data else {
                continue;
            };
            let tag = dnskey
                .calculate_key_tag()
                .map_err(|e| DaygleError::Internal(format!("DNSKEY key tag: {e}")))?;
            let digest = dnskey
                .to_digest(&origin, hickory_proto::dnssec::DigestType::SHA256)
                .map_err(|e| DaygleError::Internal(format!("DNSKEY digest: {e}")))?;
            let hex: String = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
            out.push(format!("{origin} IN DS {tag} {} 2 {hex}", key.algorithm));
        }
        Ok(out)
    }

    /// The ALIAS record at `name` (lowercase, with or without the trailing
    /// dot), if any.
    pub fn alias(&self, name: &str) -> Option<Alias> {
        let aliases = self.aliases.load();
        if aliases.is_empty() {
            return None;
        }
        aliases.get(name.trim_end_matches('.')).cloned()
    }

    /// The enabled `rtype` records stored at `name` (lowercase, no trailing
    /// dot), for answering an ALIAS whose target is hosted here.
    pub fn local_records(&self, name: &str, rtype: RecordType) -> Result<Vec<Record>> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        // The most specific hosted zone holding the name.
        let Some(zone) = self
            .store
            .list_zones()?
            .into_iter()
            .filter(|z| z.enabled && (name == z.name || name.ends_with(&format!(".{}", z.name))))
            .max_by_key(|z| z.name.len())
        else {
            return Ok(Vec::new());
        };
        let wanted = rtype.to_string();
        Ok(self
            .store
            .list_records(&zone.id)?
            .iter()
            .filter(|r| !r.disabled && r.rtype == wanted && r.name.eq_ignore_ascii_case(&name))
            .filter_map(|r| record_to_hickory(r).ok())
            .collect())
    }

    /// Clone out the current split-horizon index (cheap `Arc` bump).
    /// Replace the named networks (built-in and configured) and rebuild the
    /// split-horizon index that refers to them.
    pub fn set_networks(&self, networks: Vec<daygle_dns_core::config::NamedNetwork>) -> Result<()> {
        if **self.networks.load() == networks {
            return Ok(());
        }
        let index = build_split_horizon(&self.store, &networks)?;
        self.networks.store(Arc::new(networks));
        self.split_horizon.store(Arc::new(index));
        Ok(())
    }

    pub fn split_horizon(&self) -> Arc<SplitHorizonIndex> {
        self.split_horizon.load_full()
    }

    /// Generate (if necessary) a DNSSEC signing key for `zone_id`, sign the
    /// zone, and reload the catalog.
    pub fn sign_zone(&self, zone_id: &str) -> Result<()> {
        self.sign_zone_with(zone_id, None)
    }

    /// [`sign_zone`](Self::sign_zone), also choosing NSEC3 (`Some(true)`)
    /// or NSEC (`Some(false)`) for denial of existence; `None` keeps the
    /// zone's current choice (NSEC for a zone never signed before). Signing
    /// an already-signed zone again just switches the proof.
    pub fn sign_zone_with(&self, zone_id: &str, nsec3: Option<bool>) -> Result<()> {
        if self
            .store
            .list_records(zone_id)?
            .iter()
            .any(|r| r.rtype == "ALIAS")
        {
            return Err(DaygleError::InvalidRecord(
                "the zone has ALIAS records, whose answers are made when asked and cannot be signed: replace them with A/AAAA or CNAME records first".to_string(),
            ));
        }
        // With signing turned off the key would be stored but never used:
        // the zone would read as signed while it is served unsigned, and a
        // DS published for it would make it bogus.
        if !self.settings.load().dnssec_enabled {
            return Err(DaygleError::Config(
                "DNSSEC signing is turned off (authoritative.dnssec_enabled = false)".to_string(),
            ));
        }
        if let Some(nsec3) = nsec3 {
            self.store.set_zone_nsec3(zone_id, nsec3)?;
        }
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
        // Signed zones (and secondaries kept as their master sent them) are
        // transferred exactly as served, signatures, NSEC chain and DNSKEYs
        // included: a secondary given the bare records would serve the zone
        // unsigned, which validators reject once the parent has a DS.
        if let Some(served) = self.transfer_sets.load().get(&zone_key(zone_name)) {
            let mut soa = None;
            let mut others = Vec::with_capacity(served.len() * 2);
            for set in served.values() {
                if set.record_type() == RecordType::SOA {
                    soa = set.records_without_rrsigs().next().cloned();
                    others.extend(set.rrsigs().iter().cloned());
                } else {
                    others.extend(set.records_with_rrsigs().cloned());
                }
            }
            return Ok(soa.map(|soa| (soa, others)));
        }
        let map = match self.store.find_zone_by_name(zone_name)? {
            Some(zone) if zone.enabled => {
                let records = self.store.list_records(&zone.id)?;
                zone_rrsets(&zone, &records)?
            }
            Some(_) => return Ok(None),
            None => {
                let catalog = self.settings.load().catalog_zone.clone();
                if catalog.is_empty()
                    || daygle_dns_core::config::normalize_zone_name(zone_name) != catalog
                {
                    return Ok(None);
                }
                catalog_zone_rrsets(&self.store, &catalog)?.0
            }
        };

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
    Ok((
        u8::from(Algorithm::ECDSAP256SHA256),
        der.secret_pkcs8_der().to_vec(),
    ))
}

/// Build the split-horizon index from the named networks and the store's
/// entries.
fn build_split_horizon(
    store: &ZoneStore,
    networks: &[daygle_dns_core::config::NamedNetwork],
) -> Result<SplitHorizonIndex> {
    let entries = store.list_split_horizon_entries()?;
    Ok(SplitHorizonIndex::build(networks, &entries))
}

/// Build a fresh Hickory `Catalog` from the store.
fn build_catalog(
    store: &ZoneStore,
    settings: &AuthoritativeSettings,
    sign_zones: bool,
    unhealthy: &std::collections::HashSet<String>,
) -> Result<Built> {
    let mut catalog = Catalog::new();
    let checked: std::collections::HashSet<String> = store
        .list_health_checks()?
        .into_iter()
        .map(|(check, _)| check.record_id)
        .collect();
    let data = store.load_catalog_data()?;
    let secondary_ids: std::collections::HashSet<String> = store
        .list_secondary()?
        .into_iter()
        .map(|s| s.zone_id)
        .collect();

    let sig_validity = sig_duration(settings);
    let mut serials = HashMap::new();
    let mut transfer_sets = HashMap::new();

    for (zone, records, keys) in data {
        if !zone.enabled {
            continue;
        }
        let origin = fqdn_name(&zone.name)?;
        let lower = LowerName::from(origin.clone());

        if secondary_ids.contains(&zone.id) {
            let handler = match store.transfer_data(&zone.id)? {
                // As the master sent it: its signatures stay valid only if
                // every record is served byte for byte as signed.
                Some(wire) => match secondary_zone(&origin, &wire) {
                    Ok(handler) => Some(handler),
                    Err(e) => {
                        warn!(zone = %zone.name, error = %e, "stored transfer is unreadable; serving the record table");
                        None
                    }
                },
                None => None,
            };
            let mut handler = match handler {
                Some(handler) => handler,
                None => ZoneData::new(
                    origin.clone(),
                    zone_rrsets(&zone, &records)?,
                    ZoneType::Secondary,
                    AxfrPolicy::Deny,
                    None,
                )
                .map_err(DaygleError::InvalidRecord)?,
            };
            transfer_sets.insert(
                zone_key(&zone.name),
                Arc::new(handler.records_get_mut().clone()),
            );
            catalog.upsert(lower, vec![Arc::new(handler) as Arc<dyn ZoneHandler>]);
            continue;
        }

        let records = failover(records, &checked, unhealthy);

        // Every active key signs every RRset (and the DNSKEY RRset), which
        // is what makes pre-publish/double-sign rollover work: validators
        // can pick either key while both are published.
        let signers: Vec<DnssecSigner> = if sign_zones {
            keys.iter()
                .filter(|k| k.is_active())
                .filter_map(|key| {
                    build_signer(origin.clone(), key.algorithm, &key.key_der, sig_validity)
                        .map_err(|e| warn!("cannot reconstruct signing key for {}: {e}", zone.name))
                        .ok()
                })
                .collect()
        } else {
            Vec::new()
        };

        let handler = if signers.is_empty() {
            None
        } else {
            let retired: Vec<&SigningKeyRecord> = keys.iter().filter(|k| k.is_retired()).collect();
            match signed_zone(store, &zone, &records, &origin, signers, &retired) {
                Ok(mut handler) => {
                    transfer_sets.insert(
                        zone_key(&zone.name),
                        Arc::new(handler.records_get_mut().clone()),
                    );
                    Some(handler)
                }
                Err(e) => {
                    warn!(zone = %zone.name, error = %e, "failed to sign zone; serving it unsigned");
                    None
                }
            }
        };
        let handler = match handler {
            Some(handler) => handler,
            None => ZoneData::new(
                origin.clone(),
                zone_rrsets(&zone, &records)?,
                ZoneType::Primary,
                AxfrPolicy::Deny,
                None,
            )
            .map_err(DaygleError::InvalidRecord)?,
        };
        serials.insert(zone_key(&zone.name), zone.serial);
        catalog.upsert(lower, vec![Arc::new(handler) as Arc<dyn ZoneHandler>]);
    }

    let mut catalog_changed = false;
    let catalog_zone = &settings.catalog_zone;
    if !catalog_zone.is_empty() {
        if store
            .find_zone_by_name(catalog_zone)?
            .is_some_and(|zone| zone.enabled)
        {
            warn!(
                zone = %catalog_zone,
                "a hosted zone has the catalog zone's name; not publishing the catalog"
            );
        } else {
            let (map, changed) = catalog_zone_rrsets(store, catalog_zone)?;
            catalog_changed = changed;
            let origin = fqdn_name(catalog_zone)?;
            let handler = ZoneData::new(
                origin.clone(),
                map,
                ZoneType::Primary,
                AxfrPolicy::Deny,
                None,
            )
            .map_err(DaygleError::InvalidRecord)?;
            catalog.upsert(
                LowerName::from(origin),
                vec![Arc::new(handler) as Arc<dyn ZoneHandler>],
            );
        }
    }

    Ok(Built {
        catalog,
        catalog_zone_changed: catalog_changed,
        serials,
        transfer_sets,
    })
}

/// Build and sign a primary zone with `signers`.
fn signed_zone(
    store: &ZoneStore,
    zone: &crate::model::Zone,
    records: &[DbRecord],
    origin: &Name,
    signers: Vec<DnssecSigner>,
    retired: &[&SigningKeyRecord],
) -> Result<ZoneData> {
    // Hickory bumps the SOA serial when it signs. Start one below the
    // stored serial so the zone is served (and transferred) with the serial
    // the console shows, and unsigning it later does not move it backwards.
    let mut unbumped = zone.clone();
    unbumped.serial = zone.serial.wrapping_sub(1);
    let mut map = zone_rrsets(&unbumped, records)?;

    // Retired keys no longer sign, but their DNSKEY stays published for the
    // retirement grace period so validators holding cached RRSIGs made by
    // the old key can still build a chain of trust (RFC 6781).
    for key in retired {
        match build_dnskey_record(origin, key.algorithm, &key.key_der, zone.minimum.max(300)) {
            Ok(record) => insert_record_set(&mut map, record)?,
            Err(e) => warn!(zone = %zone.name, error = %e, "cannot publish retired DNSKEY"),
        }
    }

    let nx_proof_kind = if store.zone_nsec3(&zone.id).unwrap_or(false) {
        // RFC 9276: SHA-1, no extra iterations, no salt, no opt-out.
        NxProofKind::Nsec3 {
            algorithm: Default::default(),
            salt: Arc::new([]),
            iterations: 0,
            opt_out: false,
        }
    } else {
        NxProofKind::Nsec
    };
    let mut handler = ZoneData::new(
        origin.clone(),
        map,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(nx_proof_kind),
    )
    .map_err(DaygleError::InvalidRecord)?;
    let keys = signers.len();
    for signer in signers {
        handler
            .add_zone_signing_key_mut(signer)
            .map_err(|e| DaygleError::Internal(format!("add signing key: {e}")))?;
    }
    handler
        .secure_zone_mut()
        .map_err(|e| DaygleError::Internal(format!("sign zone: {e}")))?;
    info!(zone = %zone.name, keys, retired = retired.len(), "zone signed with DNSSEC");
    Ok(handler)
}

/// Serve a secondary zone from the records its master transferred
/// (`wire`, see [`encode_transfer`]), signatures and denial proofs
/// included, without re-signing anything.
fn secondary_zone(origin: &Name, wire: &[u8]) -> Result<ZoneData> {
    let mut map: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
    let mut rrsigs = Vec::new();
    let mut nsec = false;
    let mut nsec3: Option<NxProofKind> = None;
    let mut opt_out = false;
    for record in decode_transfer(wire)? {
        match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(_)) => {
                rrsigs.push(record);
                continue;
            }
            RData::DNSSEC(DNSSECRData::NSEC(_)) => nsec = true,
            RData::DNSSEC(DNSSECRData::NSEC3(n)) => opt_out |= n.opt_out(),
            RData::DNSSEC(DNSSECRData::NSEC3PARAM(p)) if record.name == *origin => {
                nsec3 = Some(NxProofKind::Nsec3 {
                    algorithm: p.hash_algorithm(),
                    salt: Arc::from(p.salt()),
                    iterations: p.iterations(),
                    opt_out: false,
                });
            }
            _ => {}
        }
        insert_record_set(&mut map, record)?;
    }
    let nx_proof_kind = match nsec3 {
        Some(NxProofKind::Nsec3 {
            algorithm,
            salt,
            iterations,
            ..
        }) => Some(NxProofKind::Nsec3 {
            algorithm,
            salt,
            iterations,
            opt_out,
        }),
        _ if nsec => Some(NxProofKind::Nsec),
        other => other,
    };
    let mut handler = ZoneData::new(
        origin.clone(),
        map,
        ZoneType::Secondary,
        AxfrPolicy::Deny,
        nx_proof_kind,
    )
    .map_err(DaygleError::InvalidRecord)?;
    // The handler takes records only; signatures are attached to their
    // RRsets afterwards.
    let served = handler.records_get_mut();
    for rrsig in rrsigs {
        let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &rrsig.data else {
            continue;
        };
        let key = RrKey::new(
            LowerName::from(rrsig.name.clone()),
            sig.input().type_covered,
        );
        if let Some(set) = served.get_mut(&key) {
            Arc::make_mut(set).insert_rrsig(rrsig);
        }
    }
    Ok(handler)
}

/// Encode a transfer's records for storage: each in wire format, after
/// its length (4 bytes). The closing SOA of the transfer must already be
/// removed.
pub(crate) fn encode_transfer(records: &[Record]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for record in records {
        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        record
            .emit(&mut encoder)
            .map_err(|e| DaygleError::Internal(format!("encode transferred record: {e}")))?;
        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&buf);
    }
    Ok(out)
}

/// Decode records stored by [`encode_transfer`].
fn decode_transfer(mut wire: &[u8]) -> Result<Vec<Record>> {
    let corrupt = || DaygleError::Internal("stored transfer is truncated".to_string());
    let mut records = Vec::new();
    while !wire.is_empty() {
        let (len, rest) = wire.split_first_chunk::<4>().ok_or_else(corrupt)?;
        let len = u32::from_be_bytes(*len) as usize;
        let (record, rest) = rest.split_at_checked(len).ok_or_else(corrupt)?;
        let mut decoder = BinDecoder::new(record);
        records.push(
            Record::read(&mut decoder)
                .map_err(|e| DaygleError::Internal(format!("decode stored transfer: {e}")))?,
        );
        wire = rest;
    }
    Ok(records)
}

/// Health-checked failover: in each A or AAAA RRset holding a
/// health-checked record, serve only the healthy records with the lowest
/// priority (lower numbers are primaries, higher ones backups). Records
/// without a check count as healthy. When none is healthy, the whole RRset
/// is served: answering with every address beats answering with none.
fn failover(
    records: Vec<DbRecord>,
    checked: &std::collections::HashSet<String>,
    unhealthy: &std::collections::HashSet<String>,
) -> Vec<DbRecord> {
    if checked.is_empty() {
        return records;
    }
    let key = |r: &DbRecord| (r.name.to_ascii_lowercase(), r.rtype.clone());
    let mut keep: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut groups: BTreeMap<(String, String), Vec<&DbRecord>> = BTreeMap::new();
    for record in &records {
        if matches!(record.rtype.as_str(), "A" | "AAAA") && !record.disabled {
            groups.entry(key(record)).or_default().push(record);
        }
    }
    let mut filtered: std::collections::HashSet<(String, String)> = Default::default();
    for (group_key, group) in &groups {
        if !group.iter().any(|r| checked.contains(&r.id)) {
            continue;
        }
        let healthy: Vec<&&DbRecord> = group
            .iter()
            .filter(|r| !unhealthy.contains(&r.id))
            .collect();
        let Some(best) = healthy.iter().map(|r| r.priority).min() else {
            continue;
        };
        filtered.insert(group_key.clone());
        keep.extend(
            healthy
                .iter()
                .filter(|r| r.priority == best)
                .map(|r| r.id.clone()),
        );
    }
    records
        .into_iter()
        .filter(|r| !filtered.contains(&key(r)) || r.disabled || keep.contains(&r.id))
        .collect()
}

/// The catalog zone (RFC 9432, schema version 2) this server publishes as
/// `name`: one PTR per primary zone, under `zones.<name>`, with a unique
/// label that stays the same for the life of the zone. Also returns whether
/// the member list changed since the serial was last bumped.
fn catalog_zone_rrsets(
    store: &ZoneStore,
    name: &str,
) -> Result<(BTreeMap<RrKey, RecordSet>, bool)> {
    use hickory_proto::rr::rdata::{NS, PTR, SOA, TXT};

    let origin = fqdn_name(name)?;
    let secondary: std::collections::HashSet<String> = store
        .list_secondary()?
        .into_iter()
        .map(|s| s.zone_id)
        .collect();
    let mut members: Vec<(String, Name)> = Vec::new();
    for zone in store.list_zones()? {
        if !zone.enabled || secondary.contains(&zone.id) || zone.name.eq_ignore_ascii_case(name) {
            continue;
        }
        let label: String = zone
            .id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(63)
            .collect::<String>()
            .to_ascii_lowercase();
        members.push((label, fqdn_name(&zone.name)?));
    }
    members.sort();
    let digest = members
        .iter()
        .map(|(label, zone)| format!("{label}={zone}"))
        .collect::<Vec<_>>()
        .join(",");
    let (serial, changed) = store.catalog_serial(name, &digest)?;

    let invalid = Name::from_ascii("invalid.").expect("valid name");
    let at = |prefix: &str| -> Result<Name> {
        Name::from_ascii(prefix)
            .and_then(|p| p.append_domain(&origin))
            .map_err(|e| DaygleError::InvalidRecord(format!("catalog name {prefix}: {e}")))
    };
    let mut map = BTreeMap::new();
    let records = [
        Record::from_rdata(
            origin.clone(),
            0,
            RData::SOA(SOA::new(
                invalid.clone(),
                invalid.clone(),
                serial,
                600,
                300,
                2_419_200,
                0,
            )),
        ),
        Record::from_rdata(origin.clone(), 0, RData::NS(NS(invalid))),
        Record::from_rdata(
            at("version")?,
            0,
            RData::TXT(TXT::new(vec!["2".to_string()])),
        ),
    ];
    for record in records {
        insert_record_set(&mut map, record)?;
    }
    for (label, zone) in members {
        insert_record_set(
            &mut map,
            Record::from_rdata(at(&format!("{label}.zones"))?, 0, RData::PTR(PTR(zone))),
        )?;
    }
    Ok((map, changed))
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
        // ALIAS is answered by the dispatcher, not served as a record.
        if record.disabled || record.rtype == "ALIAS" {
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
    Name::from_utf8(format!("{}.", name.trim().trim_end_matches('.')))
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
    use chrono::Utc;

    #[test]
    fn failover_serves_the_healthy_records_of_the_best_priority() {
        let rec = |id: &str, name: &str, rtype: &str, priority: u16| DbRecord {
            id: id.to_string(),
            zone_id: "z".to_string(),
            name: name.to_string(),
            rtype: rtype.to_string(),
            content: String::new(),
            ttl: 60,
            priority,
            disabled: false,
            last_modified_at: String::new(),
            last_used_at: None,
        };
        let records = vec![
            rec("p1", "www.example.com", "A", 0),
            rec("p2", "www.example.com", "A", 0),
            rec("b1", "www.example.com", "A", 10),
            rec("v6", "www.example.com", "AAAA", 0),
            rec("other", "api.example.com", "A", 5),
            rec("mx", "www.example.com", "TXT", 0),
        ];
        let set = |ids: &[&str]| ids.iter().map(|s| s.to_string()).collect();
        let served = |unhealthy: &[&str]| {
            let mut ids: Vec<String> =
                failover(records.clone(), &set(&["p1", "p2", "b1"]), &set(unhealthy))
                    .into_iter()
                    .map(|r| r.id)
                    .collect();
            ids.sort();
            ids
        };
        // All up: the primaries (priority 0); the backup waits.
        assert_eq!(served(&[]), ["mx", "other", "p1", "p2", "v6"]);
        // One primary down: the other primary.
        assert_eq!(served(&["p1"]), ["mx", "other", "p2", "v6"]);
        // Both primaries down: the backup.
        assert_eq!(served(&["p1", "p2"]), ["b1", "mx", "other", "v6"]);
        // Everything down: all of them, rather than nothing.
        assert_eq!(
            served(&["p1", "p2", "b1"]),
            ["b1", "mx", "other", "p1", "p2", "v6"]
        );
        // No checks: untouched.
        assert_eq!(failover(records.clone(), &set(&[]), &set(&["p1"])).len(), 6);
    }

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

    /// Every change to a primary zone's serial, however it was made, is
    /// reported once, so the zone's secondaries are sent a NOTIFY.
    #[test]
    fn serial_changes_are_reported_for_notify() {
        let catalog = catalog();
        catalog.reload().unwrap();
        assert!(
            catalog.take_changed_zones().is_empty(),
            "nothing changed yet"
        );

        let zone = catalog
            .store()
            .find_zone_by_name("example.com")
            .unwrap()
            .unwrap();
        catalog
            .store()
            .upsert_record(
                &zone.id,
                &RecordInput {
                    name: "mail".to_string(),
                    rtype: "A".to_string(),
                    content: "192.0.2.25".to_string(),
                    ttl: 300,
                    priority: 0,
                    disabled: false,
                },
            )
            .unwrap();
        catalog.reload().unwrap();
        assert_eq!(
            catalog.take_changed_zones(),
            vec!["example.com".to_string()]
        );
        catalog.reload().unwrap();
        assert!(catalog.take_changed_zones().is_empty());
    }

    /// Signing keeps the stored serial (hickory's own bump is undone), and
    /// signatures start an hour back so validators with a slow clock accept
    /// them at once.
    #[tokio::test]
    async fn signed_zones_keep_their_serial_and_backdate_inception() {
        let store = ZoneStore::open(":memory:").unwrap();
        let zone = store
            .create_zone(&ZoneInput {
                name: "signed.example".to_string(),
                ..Default::default()
            })
            .unwrap();
        let catalog = AuthorityCatalog::new(
            store,
            AuthoritativeSettings {
                dnssec_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        catalog.sign_zone(&zone.id).unwrap();
        assert!(
            catalog.take_changed_zones().is_empty(),
            "signing changes no serial"
        );

        let (soa, records) = catalog.transfer_records("signed.example").unwrap().unwrap();
        let RData::SOA(soa) = &soa.data else {
            panic!("not an SOA")
        };
        assert_eq!(soa.serial, zone.serial);
        let now = Utc::now().timestamp() as u32;
        let inceptions: Vec<u32> = records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.input().sig_inception.get()),
                _ => None,
            })
            .collect();
        assert!(!inceptions.is_empty());
        for inception in inceptions {
            let behind = now - inception;
            assert!((3590..=3700).contains(&behind), "inception {behind}s back");
        }
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

    #[test]
    fn disabled_zone_is_removed_from_serving_catalog_and_transfers() {
        let catalog = catalog();
        let zone = catalog
            .store()
            .find_zone_by_name("example.com")
            .unwrap()
            .unwrap();
        let lower: LowerName = "example.com.".parse().unwrap();
        assert!(catalog.contains(&lower));
        assert!(catalog.transfer_records("example.com").unwrap().is_some());

        assert!(catalog.store().set_zone_enabled(&zone.id, false).unwrap());
        catalog.reload().unwrap();

        assert!(!catalog.contains(&lower));
        assert!(catalog.alias("example.com").is_none());
        assert!(catalog.transfer_records("example.com").unwrap().is_none());
        assert!(catalog
            .local_records("www.example.com", RecordType::A)
            .unwrap()
            .is_empty());

        assert!(catalog.store().set_zone_enabled(&zone.id, true).unwrap());
        catalog.reload().unwrap();
        assert!(catalog.contains(&lower));
        assert!(catalog.transfer_records("example.com").unwrap().is_some());
    }
}
