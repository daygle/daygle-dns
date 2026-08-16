//! Secondary-zone refresh: periodically synchronize configured zones from
//! their masters into the local store and catalog.
//!
//! Each configured secondary zone is checked on its `refresh_secs` interval.
//! A refresh compares the master's SOA serial against the local serial and
//! performs a transfer when the master is newer (or the local zone is empty).
//! Transferred records replace the stored zone data and the catalog is
//! reloaded so new answers are served immediately.

use std::sync::Arc;
use std::time::Duration;

use daygle_core::config::SecondaryZoneConfig;
use daygle_core::error::{DaygleError, Result};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::catalog::AuthorityCatalog;
use crate::model::{RecordInput, ZoneInput};
use crate::store::ZoneStore;
use crate::transfer::XfrClient;

/// Drives refresh for a set of secondary zones.
pub struct SecondaryRefresher {
    store: ZoneStore,
    catalog: Arc<AuthorityCatalog>,
    zones: Vec<SecondaryZoneConfig>,
    client: XfrClient,
}

impl SecondaryRefresher {
    pub fn new(
        store: ZoneStore,
        catalog: Arc<AuthorityCatalog>,
        zones: Vec<SecondaryZoneConfig>,
        client: XfrClient,
    ) -> Self {
        Self {
            store,
            catalog,
            zones,
            client,
        }
    }

    /// Synchronize every enabled zone once, in order.
    ///
    /// Errors are logged per zone; a failure on one zone does not stop the
    /// others. Returns the number of zones that changed.
    pub async fn refresh_all(&self) -> usize {
        let mut changed = 0;
        for zone in &self.zones {
            if !zone.enabled {
                continue;
            }
            match self.refresh_zone(zone).await {
                Ok(true) => changed += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(zone = %zone.name, error = %e, "secondary zone refresh failed");
                }
            }
        }
        changed
    }

    /// Run the refresh loop until `shutdown` is cancelled.
    pub async fn run_forever(&self, shutdown: CancellationToken) {
        loop {
            let changed = self.refresh_all().await;
            if changed > 0 {
                info!("secondary zones refreshed ({changed} changed)");
            }
            // Sleep the smallest configured interval, but check for shutdown.
            let delay = self
                .zones
                .iter()
                .filter(|z| z.enabled)
                .map(|z| z.refresh_secs)
                .min()
                .unwrap_or(3600);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
            }
        }
    }

    /// Synchronize a single secondary zone. Returns `true` when data changed.
    pub async fn refresh_zone(&self, config: &SecondaryZoneConfig) -> Result<bool> {
        let zone = self.ensure_zone(config)?;
        let zone_name: Name = fqdn(&config.name)?;

        let mut last_error: Option<DaygleError> = None;
        for master in &config.masters {
            let addr = daygle_core::config::parse_master_addr(master)
                .map_err(|e| DaygleError::Config(format!("bad master '{master}': {e}")))?;
            match self.client.query_soa(addr, &zone_name).await {
                Ok(Some(soa)) => {
                    let master_serial = match &soa.data {
                        RData::SOA(soa) => soa.serial,
                        _ => 0,
                    };
                    let current_serial = zone.serial;
                    // A zone that has never completed a transfer (freshly
                    // created, or after a restart before the first sync) is
                    // always pulled, even when the default serial matches.
                    let never_transferred = !self.store_has_transferred(&zone.id)?;
                    let needs = never_transferred
                        || serial_newer(master_serial, current_serial)
                        || zone_has_no_data(&self.store, &zone.id)?;
                    if !needs {
                        return Ok(false);
                    }
                    return self.transfer_from(addr, &zone_name, master_serial, current_serial, &zone.id).await;
                }
                Ok(None) => {
                    warn!(zone = %zone.name, %master, "master returned no SOA");
                }
                Err(e) => {
                    warn!(zone = %zone.name, %master, error = %e, "SOA query failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DaygleError::Proto(format!("no reachable master for secondary zone '{}'", config.name))
        }))
    }

    async fn transfer_from(
        &self,
        master: std::net::SocketAddr,
        zone_name: &Name,
        master_serial: u32,
        current_serial: u32,
        zone_id: &str,
    ) -> Result<bool> {
        let records = self
            .client
            .ixfr_or_axfr(master, zone_name, Some(current_serial))
            .await?;

        // Apply the transfer: extract SOA metadata, store the rest.
        let (soa, inputs) = records_to_inputs(zone_name, &records);
        if let Some((mname, rname, serial, refresh, retry, expire, minimum)) = soa {
            self.store.set_zone_soa(
                zone_id,
                &mname,
                &rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            )?;
        } else {
            // Some masters do not include the SOA in the record list; apply
            // the serial we learned from the SOA query.
            let zone = self
                .store
                .get_zone(zone_id)?
                .ok_or_else(|| DaygleError::NotFound(format!("zone {zone_id}")))?;
            self.store.set_zone_soa(
                zone_id,
                &zone.primary_ns,
                &zone.admin_mailbox,
                master_serial,
                zone.refresh,
                zone.retry,
                zone.expire,
                zone.minimum,
            )?;
        }

        self.store.replace_records(zone_id, &inputs)?;
        self.store.touch_secondary(zone_id)?;
        self.catalog.reload()?;
        info!(zone = %zone_name, records = inputs.len(), "secondary zone transferred from {master}");
        Ok(true)
    }

    /// Ensure the zone row exists in the store and is marked secondary.
    fn ensure_zone(&self, config: &SecondaryZoneConfig) -> Result<crate::model::Zone> {
        let zone = match self.store.find_zone_by_name(&config.name)? {
            Some(zone) => zone,
            None => self
                .store
                .create_zone(&ZoneInput {
                    name: config.name.clone(),
                    ..Default::default()
                })?,
        };
        self.store
            .set_secondary(&zone.id, &config.masters, config.refresh_secs)?;
        Ok(zone)
    }
}

/// True when `master` is a newer serial than `local` under RFC 1982 serial
/// arithmetic (wraps at 2^31).
fn serial_newer(master: u32, local: u32) -> bool {
    master != local && (master.wrapping_sub(local) as i32) > 0
}

fn zone_has_no_data(store: &ZoneStore, zone_id: &str) -> Result<bool> {
    Ok(store.list_records(zone_id)?.is_empty())
}

impl SecondaryRefresher {
    /// True when the zone row has a recorded successful transfer.
    fn store_has_transferred(&self, zone_id: &str) -> Result<bool> {
        Ok(self
            .store
            .list_secondary()?
            .iter()
            .any(|s| s.zone_id == zone_id && s.last_transfer.is_some()))
    }
}

/// Convert transfer records into store inputs, extracting the SOA separately.
/// DNSSEC records (RRSIG, NSEC, DNSKEY, …) and OPT are dropped — the local
/// catalog re-signs zones that have signing keys.
fn records_to_inputs(
    zone: &Name,
    records: &[Record],
) -> (Option<(String, String, u32, u32, u32, u32, u32)>, Vec<RecordInput>) {
    let mut soa = None;
    let mut inputs = Vec::with_capacity(records.len());
    for record in records {
        if record.record_type() == RecordType::SOA {
            if let RData::SOA(soa_data) = &record.data {
                soa = Some((
                    soa_data.mname.to_string(),
                    soa_data.rname.to_string(),
                    soa_data.serial,
                    soa_data.refresh.max(0) as u32,
                    soa_data.retry.max(0) as u32,
                    soa_data.expire.max(0) as u32,
                    soa_data.minimum,
                ));
            }
            continue;
        }
        // Skip DNSSEC and meta record types we do not store.
        if record.record_type().is_dnssec() || record.record_type() == RecordType::OPT {
            continue;
        }
        let rtype = record.record_type().to_string();
        if !crate::model::KNOWN_RECORD_TYPES.contains(&rtype.as_str()) {
            continue;
        }
        let name = strip_dot(&record.name.to_string());
        inputs.push(RecordInput {
            name,
            rtype,
            content: record.data.to_string(),
            ttl: record.ttl,
            priority: 0,
            disabled: false,
        });
    }
    // The store synthesizes the SOA from zone metadata, so never store an SOA
    // record in the records table.
    let _ = zone;
    (soa, inputs)
}

fn strip_dot(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

fn fqdn(name: &str) -> Result<Name> {
    Name::from_utf8(&format!("{}.", name.trim().trim_end_matches('.')))
        .map_err(|e| DaygleError::InvalidRecord(format!("name '{name}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_arithmetic() {
        assert!(serial_newer(2, 1));
        assert!(!serial_newer(1, 1));
        assert!(!serial_newer(1, 2));
        // Wrap-around within the 2^31 window: 2 is newer than 0xFFFF_FFFF.
        assert!(serial_newer(2, 0xFFFF_FFFF));
        assert!(!serial_newer(0xFFFF_FFFF, 2));
        // Exactly half the space apart is ambiguous and not "newer".
        assert!(!serial_newer(0x8000_0000, 0));
    }

    #[test]
    fn strips_trailing_dot() {
        assert_eq!(strip_dot("www.example.com."), "www.example.com");
        assert_eq!(strip_dot("www.example.com"), "www.example.com");
    }
}
