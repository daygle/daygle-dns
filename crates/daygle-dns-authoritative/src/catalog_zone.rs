//! Consuming catalog zones (RFC 9432): each configured catalog is
//! transferred from its masters, and every member zone it lists is served
//! here as a secondary zone from the same masters. Zones the catalog drops
//! are removed again; so are those of a catalog taken out of the settings.
//! (Publishing this server's own catalog lives in [`crate::catalog`].)
//!
//! A catalog is checked on its `refresh_secs` (or at once when its master
//! sends a NOTIFY); it is transferred again only when its serial changed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use daygle_dns_core::config::{
    normalize_zone_name, parse_master_addr, CatalogConsumerConfig, DaygleConfig,
    SecondaryZoneConfig,
};
use daygle_dns_core::error::{DaygleError, Result};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::catalog::AuthorityCatalog;
use crate::model::ZoneInput;
use crate::secondary::SecondaryRefresher;
use crate::store::ZoneStore;
use crate::transfer::XfrClient;

/// How often the loop looks for catalogs that are due (or newly added), at
/// most.
const TICK: Duration = Duration::from_secs(5);

/// The member zones a catalog lists (lowercase, no trailing dot), from its
/// transferred records. Fails unless the catalog declares schema version 2.
pub fn catalog_members(catalog: &Name, records: &[Record]) -> Result<Vec<String>> {
    let version = Name::from_ascii("version")
        .and_then(|v| v.append_domain(catalog))
        .map_err(|e| DaygleError::Proto(e.to_string()))?;
    let zones = Name::from_ascii("zones")
        .and_then(|v| v.append_domain(catalog))
        .map_err(|e| DaygleError::Proto(e.to_string()))?;
    let versions: Vec<String> = records
        .iter()
        .filter(|r| r.record_type() == RecordType::TXT && r.name.eq_case(&version))
        .filter_map(|r| match &r.data {
            RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect();
    if versions.len() != 1 || versions[0].trim_matches('"') != "2" {
        return Err(DaygleError::Proto(format!(
            "catalog zone {catalog} does not declare schema version 2 (found {versions:?})"
        )));
    }
    let mut seen_labels = HashSet::new();
    let mut members = Vec::new();
    for record in records {
        let RData::PTR(ptr) = &record.data else {
            continue;
        };
        // Members are exactly one label below `zones.<catalog>`; deeper
        // names are member properties.
        if record.name.num_labels() != zones.num_labels() + 1 || !zones.zone_of(&record.name) {
            continue;
        }
        // A unique label lists one zone (RFC 9432 §4.1: more is an error
        // for that member; the first is kept).
        if !seen_labels.insert(record.name.to_lowercase()) {
            continue;
        }
        let member = normalize_zone_name(&ptr.0.to_string());
        if !member.is_empty() && !members.contains(&member) {
            members.push(member);
        }
    }
    Ok(members)
}

/// Follows the configured catalog zones.
pub struct CatalogConsumer {
    store: ZoneStore,
    catalog: Arc<AuthorityCatalog>,
    refresher: Arc<SecondaryRefresher>,
    client: XfrClient,
    config: Arc<ArcSwap<DaygleConfig>>,
    /// Per catalog: the serial last applied, and when it was last checked.
    state: Mutex<HashMap<String, (Option<u32>, Instant)>>,
    wake: tokio::sync::Notify,
}

impl CatalogConsumer {
    pub fn new(
        store: ZoneStore,
        catalog: Arc<AuthorityCatalog>,
        refresher: Arc<SecondaryRefresher>,
        client: XfrClient,
        config: Arc<ArcSwap<DaygleConfig>>,
    ) -> Self {
        Self {
            store,
            catalog,
            refresher,
            client,
            config,
            state: Mutex::new(HashMap::new()),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// The configured catalog called `name`, if any.
    pub fn consumer(&self, name: &str) -> Option<CatalogConsumerConfig> {
        let name = normalize_zone_name(name);
        self.config
            .load()
            .authoritative
            .catalog_consumers
            .iter()
            .find(|c| normalize_zone_name(&c.name) == name)
            .cloned()
    }

    /// Check the catalog `name` now (after a NOTIFY), even if unchanged.
    pub fn wake(&self, name: &str) {
        self.state
            .lock()
            .expect("catalog state lock poisoned")
            .remove(&normalize_zone_name(name));
        self.wake.notify_one();
    }

    /// Run until `shutdown` is cancelled.
    pub async fn run_forever(&self, shutdown: CancellationToken) {
        loop {
            self.tick().await;
            let shortest = self
                .config
                .load()
                .authoritative
                .catalog_consumers
                .iter()
                .filter(|c| c.enabled)
                .map(|c| Duration::from_secs(c.refresh_secs.max(1)))
                .min()
                .unwrap_or(TICK);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(TICK.min(shortest)) => {}
            }
        }
    }

    /// Check every catalog that is due, and drop the zones of catalogs no
    /// longer configured.
    pub async fn tick(&self) {
        let consumers = self.config.load().authoritative.catalog_consumers.clone();
        let configured: HashSet<String> = consumers
            .iter()
            .map(|c| normalize_zone_name(&c.name))
            .collect();
        if let Err(e) = self.remove_orphans(&configured) {
            warn!(error = %e, "cannot remove the zones of a catalog no longer followed");
        }
        for consumer in consumers.iter().filter(|c| c.enabled) {
            let name = normalize_zone_name(&consumer.name);
            let due = {
                let state = self.state.lock().expect("catalog state lock poisoned");
                state.get(&name).is_none_or(|(_, checked)| {
                    checked.elapsed() >= Duration::from_secs(consumer.refresh_secs)
                })
            };
            if !due {
                continue;
            }
            if let Err(e) = self.refresh(consumer).await {
                warn!(catalog = %name, error = %e, "catalog zone refresh failed");
                // Try again on the catalog's next refresh, not every tick.
                let mut state = self.state.lock().expect("catalog state lock poisoned");
                let serial = state.get(&name).and_then(|(s, _)| *s);
                state.insert(name, (serial, Instant::now()));
            }
        }
    }

    /// Check one catalog: transfer it when its serial changed, then bring
    /// the member zones in line. Returns whether any zone was added or
    /// removed.
    pub async fn refresh(&self, consumer: &CatalogConsumerConfig) -> Result<bool> {
        let name = normalize_zone_name(&consumer.name);
        let apex = Name::from_utf8(format!("{name}."))
            .map_err(|e| DaygleError::Config(format!("catalog zone '{name}': {e}")))?;
        let last = self
            .state
            .lock()
            .expect("catalog state lock poisoned")
            .get(&name)
            .and_then(|(s, _)| *s);
        let mut last_error = None;
        for master in &consumer.masters {
            let addr = parse_master_addr(master)
                .map_err(|e| DaygleError::Config(format!("bad master '{master}': {e}")))?;
            let serial = match self.client.query_soa(addr, &apex).await {
                Ok(Some(soa)) => match &soa.data {
                    RData::SOA(soa) => soa.serial,
                    _ => continue,
                },
                Ok(None) => {
                    last_error = Some(DaygleError::Proto(format!(
                        "{master} has no SOA for catalog zone {name}"
                    )));
                    continue;
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            let changed = if last == Some(serial) {
                // Unchanged: still make sure every member is being served
                // (e.g. after a restart, or a member deleted by hand).
                self.reconcile(consumer, None)?
            } else {
                let records = match self.client.axfr(addr, &apex).await {
                    Ok(records) => records,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };
                let members = catalog_members(&apex, &records)?;
                info!(catalog = %name, serial, members = members.len(), "catalog zone transferred from {master}");
                self.reconcile(consumer, Some(&members))?
            };
            self.state
                .lock()
                .expect("catalog state lock poisoned")
                .insert(name, (Some(serial), Instant::now()));
            return Ok(changed);
        }
        Err(last_error.unwrap_or_else(|| {
            DaygleError::Proto(format!("no reachable master for catalog zone '{name}'"))
        }))
    }

    /// Serve every zone in `members` as a secondary from the catalog's
    /// masters, and remove the zones this catalog added that it no longer
    /// lists. With `members` `None` the list is unchanged: only make sure
    /// the zones already added are being refreshed.
    fn reconcile(
        &self,
        consumer: &CatalogConsumerConfig,
        members: Option<&[String]>,
    ) -> Result<bool> {
        let name = normalize_zone_name(&consumer.name);
        let owners = self.store.catalog_members()?;
        let zones = self.store.list_zones()?;
        let owned: HashMap<String, String> = zones
            .iter()
            .filter(|z| owners.get(&z.id) == Some(&name))
            .map(|z| (z.name.to_ascii_lowercase(), z.id.clone()))
            .collect();
        let secondary = |zone: &str| SecondaryZoneConfig {
            name: zone.to_string(),
            masters: consumer.masters.clone(),
            refresh_secs: consumer.refresh_secs,
            enabled: true,
            tsig_key: String::new(),
        };
        let mut changed = false;
        let wanted: Vec<String> = match members {
            Some(members) => members.to_vec(),
            None => owned.keys().cloned().collect(),
        };
        for member in &wanted {
            let config = secondary(member);
            match zones.iter().find(|z| z.name.eq_ignore_ascii_case(member)) {
                Some(zone) if owners.get(&zone.id) == Some(&name) => {
                    if self.refresher.zone_config(member).as_ref() != Some(&config) {
                        self.store
                            .set_secondary(&zone.id, &config.masters, config.refresh_secs)?;
                        self.refresher.set_zone(config);
                    }
                }
                Some(_) => {
                    warn!(
                        catalog = %name,
                        zone = %member,
                        "catalog lists a zone this server already has; leaving it alone"
                    );
                }
                None => {
                    let zone = self.store.create_zone(&ZoneInput {
                        name: member.clone(),
                        ..Default::default()
                    })?;
                    self.store
                        .set_secondary(&zone.id, &config.masters, config.refresh_secs)?;
                    self.store.add_catalog_member(&zone.id, &name)?;
                    self.refresher.set_zone(config);
                    info!(catalog = %name, zone = %member, "zone added from catalog");
                    changed = true;
                }
            }
        }
        if members.is_some() {
            for (zone, id) in &owned {
                if !wanted.contains(zone) {
                    self.remove_member(&name, zone, id)?;
                    changed = true;
                }
            }
        }
        if changed {
            self.catalog.reload()?;
        }
        Ok(changed)
    }

    fn remove_member(&self, catalog: &str, zone: &str, id: &str) -> Result<()> {
        self.store.delete_zone(id)?;
        self.refresher.remove_zone(zone);
        info!(catalog = %catalog, zone = %zone, "zone removed: no longer in its catalog");
        Ok(())
    }

    /// Remove the zones added by catalogs that are no longer configured.
    fn remove_orphans(&self, configured: &HashSet<String>) -> Result<()> {
        let owners = self.store.catalog_members()?;
        if owners.values().all(|c| configured.contains(c)) {
            return Ok(());
        }
        for zone in self.store.list_zones()? {
            if let Some(catalog) = owners.get(&zone.id) {
                if !configured.contains(catalog) {
                    self.remove_member(catalog, &zone.name, &zone.id)?;
                }
            }
        }
        self.catalog.reload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, rdata: RData) -> Record {
        Record::from_rdata(Name::from_ascii(name).unwrap(), 0, rdata)
    }

    #[test]
    fn members_are_read_from_a_version_2_catalog() {
        use hickory_proto::rr::rdata::{PTR, TXT};
        let apex = Name::from_ascii("catalog.example.").unwrap();
        let ptr = |n: &str| RData::PTR(PTR(Name::from_ascii(n).unwrap()));
        let mut records = vec![
            record(
                "version.catalog.example.",
                RData::TXT(TXT::new(vec!["2".into()])),
            ),
            record("a1.zones.catalog.example.", ptr("One.Example.")),
            record("b2.zones.catalog.example.", ptr("two.example.")),
            // A second PTR for the same label is ignored.
            record("b2.zones.catalog.example.", ptr("other.example.")),
            // Properties sit deeper and are not members.
            record("group.a1.zones.catalog.example.", ptr("x.example.")),
            // The same zone twice is listed once.
            record("c3.zones.catalog.example.", ptr("one.example.")),
        ];
        assert_eq!(
            catalog_members(&apex, &records).unwrap(),
            ["one.example", "two.example"]
        );
        records[0] = record(
            "version.catalog.example.",
            RData::TXT(TXT::new(vec!["1".into()])),
        );
        assert!(catalog_members(&apex, &records).is_err());
        records.remove(0);
        assert!(catalog_members(&apex, &records).is_err());
    }
}
