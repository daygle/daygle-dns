//! DNSSEC maintenance: background RRSIG renewal and automatic key rollover.
//!
//! Signatures are regenerated every time the catalog is rebuilt, with an
//! inception of "now" and an expiry of `dnssec_sig_validity_days`. Left
//! alone, a signed zone goes bogus once that window passes without a reload.
//! The [`DnssecMaintenance`] task prevents that in two ways:
//!
//! 1. **RRSIG renewal** - when the current signatures are older than half
//!    their validity window, the catalog is reloaded, which re-signs every
//!    zone with fresh inceptions. Signatures therefore always have at least
//!    half their validity remaining.
//!
//! 2. **Key rollover** - when the active key reaches `dnssec_rollover_days`
//!    of age, a new key is generated. Both keys then sign the zone
//!    (double-signing) and both DNSKEYs are published for
//!    `dnssec_rollover_overlap_days`, after which the old key is retired: it
//!    stops signing but its DNSKEY stays published for a further
//!    `dnssec_rollover_retire_days` so validators with cached RRSIGs can
//!    still verify (RFC 6781 pre-publish rollover), and finally the key is
//!    deleted and its DNSKEY disappears.
//!
//! Note for public zones: automated rollover cannot update the parent's DS
//! record. When the parent DS points at the old key, submit the new DS (or
//! CDS/CDNSKEY) to the parent during the overlap window; Daygle keeps the
//! old key published long enough for that exchange.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::catalog::{generate_signing_key, AuthorityCatalog};
use crate::model::SigningKeyRecord;
use crate::store::ZoneStore;
use daygle_dns_core::config::AuthoritativeSettings;
use daygle_dns_core::error::Result;

/// Maintenance thresholds derived from configuration.
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// How often the task wakes up.
    pub interval: Duration,
    /// Re-sign when signatures are older than this (half the validity).
    pub resign_after: Duration,
    /// Key age that starts a rollover (0 disables rollover).
    pub rollover_after: Duration,
    /// Double-sign overlap before an old key is retired.
    pub overlap: Duration,
    /// Extra publication time for a retired key before deletion.
    pub retire: Duration,
}

impl MaintenanceConfig {
    pub fn from_settings(settings: &AuthoritativeSettings) -> Self {
        let days = |d: u32| Duration::from_secs(u64::from(d) * 60 * 60 * 24);
        let validity = days(settings.dnssec_sig_validity_days);
        Self {
            interval: Duration::from_secs(settings.dnssec_maintenance_secs),
            resign_after: validity / 2,
            rollover_after: days(settings.dnssec_rollover_days),
            overlap: days(settings.dnssec_rollover_overlap_days),
            retire: days(settings.dnssec_rollover_retire_days),
        }
    }
}

/// Background DNSSEC caretaker: renews signatures and rolls keys.
pub struct DnssecMaintenance {
    store: ZoneStore,
    catalog: Arc<AuthorityCatalog>,
    config: MaintenanceConfig,
    /// Only primary zones roll keys; replicas get their signed data (and
    /// their key states) from the master.
    secondary_ids: std::collections::HashSet<String>,
}

impl DnssecMaintenance {
    pub fn new(
        store: ZoneStore,
        catalog: Arc<AuthorityCatalog>,
        settings: &AuthoritativeSettings,
    ) -> Self {
        let secondary_ids = store
            .list_secondary()
            .map(|list| list.into_iter().map(|s| s.zone_id).collect())
            .unwrap_or_default();
        Self {
            store,
            catalog,
            config: MaintenanceConfig::from_settings(settings),
            secondary_ids,
        }
    }

    /// Run until `shutdown` is cancelled, checking on `config.interval`.
    pub async fn run_forever(self, shutdown: CancellationToken) {
        let mut last_resign = Instant::now();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(self.config.interval) => {}
            }

            // 1. RRSIG renewal: reload re-signs everything with fresh
            //    inceptions, keeping signatures well within their validity.
            if last_resign.elapsed() >= self.config.resign_after {
                match self.catalog.reload() {
                    Ok(()) => {
                        last_resign = Instant::now();
                        info!("re-signed DNSSEC zones (RRSIG renewal)");
                    }
                    Err(e) => warn!(error = %e, "RRSIG renewal reload failed"),
                }
            }

            // 2. Key rollover.
            match self.process_rollover() {
                Ok(0) => {}
                Ok(events) => info!(events, "DNSSEC key rollover progressed"),
                Err(e) => warn!(error = %e, "DNSSEC key rollover failed"),
            }
        }
    }

    /// Advance every zone's rollover state machine by one step. Returns the
    /// number of key events (new keys generated, keys retired, keys deleted).
    /// When anything changed the catalog is reloaded so the new state is
    /// served immediately.
    pub fn process_rollover(&self) -> Result<usize> {
        let mut events = 0usize;
        let mut changed = false;

        for zone in self.store.list_zones()? {
            if self.secondary_ids.contains(&zone.id) {
                continue;
            }
            let keys = self.store.list_signing_keys(&zone.id)?;
            if keys.is_empty() {
                continue; // unsigned zone
            }
            let active: Vec<&SigningKeyRecord> = keys.iter().filter(|k| k.is_active()).collect();
            let retired: Vec<&SigningKeyRecord> = keys.iter().filter(|k| k.is_retired()).collect();
            if active.is_empty() {
                debug!(zone = %zone.name, "skipping rollover: no active keys");
                continue;
            }

            // -- Start a rollover ----------------------------------------
            // Only when the zone has exactly one active key and nothing is
            // in flight; otherwise a rollover is already running and the
            // guard keeps it from stacking a third key.
            if !self.config.rollover_after.is_zero()
                && active.len() == 1
                && retired.is_empty()
                && key_age(active[0]) >= self.config.rollover_after
            {
                let (algorithm, der) = generate_signing_key()?;
                self.store
                    .store_signing_key(&zone.id, algorithm, &der)?;
                changed = true;
                events += 1;
                info!(
                    zone = %zone.name,
                    "DNSSEC rollover: generated new signing key; the zone is now \
                     double-signed - update the parent DS during the overlap window"
                );
            }

            // -- Retire the superseded key -------------------------------
            // An active key older than rollover + overlap retires once a
            // newer active key exists, so the zone is never left unsigned.
            let retire_after = self.config.rollover_after + self.config.overlap;
            let newest_active = active
                .iter()
                .map(|k| key_created_at(k))
                .max()
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
            for key in &active {
                if key_age(key) >= retire_after && key_created_at(key) < newest_active
                    && self.store.set_key_state(&key.id, "retired")? {
                        changed = true;
                        events += 1;
                        info!(
                            zone = %zone.name,
                            "DNSSEC rollover: retired old key; it stays published for \
                             the retirement grace period"
                        );
                    }
            }

            // -- Delete fully aged-out keys ------------------------------
            let delete_after = retire_after + self.config.retire;
            for key in &retired {
                if key_age(key) >= delete_after
                    && self.store.delete_key(&key.id)? {
                        changed = true;
                        events += 1;
                        info!(zone = %zone.name, "DNSSEC rollover: removed old key");
                    }
            }
        }

        if changed {
            self.catalog.reload()?;
        }
        Ok(events)
    }
}

/// Parse a key's RFC 3339 creation timestamp; unparseable values are treated
/// as "created now" (age 0) so corrupt rows never trigger destructive steps.
fn key_created_at(key: &SigningKeyRecord) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&key.created_at)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// Age of a key since its creation timestamp.
fn key_age(key: &SigningKeyRecord) -> Duration {
    let created = key_created_at(key);
    let now = Utc::now();
    if now <= created {
        Duration::ZERO
    } else {
        Duration::from_secs((now - created).num_seconds().max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RecordInput, ZoneInput};

    /// Maintenance with 1-day thresholds (rollover, overlap, retire all 24 h).
    fn maintenance(rollover_days: u32) -> DnssecMaintenance {
        let store = ZoneStore::open(":memory:").unwrap();
        let settings = AuthoritativeSettings {
            dnssec_enabled: true,
            dnssec_rollover_days: rollover_days,
            dnssec_rollover_overlap_days: 1,
            dnssec_rollover_retire_days: 1,
            ..Default::default()
        };
        let catalog = Arc::new(AuthorityCatalog::new(store.clone(), settings.clone()).unwrap());
        DnssecMaintenance::new(store, catalog, &settings)
    }

    fn zone_with_key(
        m: &DnssecMaintenance,
        name: &str,
        age: chrono::Duration,
    ) -> crate::model::Zone {
        let zone = m
            .store
            .create_zone(&ZoneInput {
                name: name.to_string(),
                ..Default::default()
            })
            .unwrap();
        m.store
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
        let (algorithm, der) = generate_signing_key().unwrap();
        m.store
            .store_signing_key_created(&zone.id, algorithm, &der, Utc::now() - age)
            .unwrap();
        m.catalog.reload().unwrap();
        zone
    }

    fn key_states(m: &DnssecMaintenance, zone_id: &str) -> Vec<String> {
        let mut states: Vec<String> = m
            .store
            .list_signing_keys(zone_id)
            .unwrap()
            .into_iter()
            .map(|k| k.state)
            .collect();
        states.sort();
        states
    }

    #[test]
    fn rollover_advances_through_all_stages() {
        let m = maintenance(1);
        // The key is 48 h old: past the 24 h rollover threshold, and exactly
        // at the 48 h retire threshold.
        let zone = zone_with_key(&m, "roll.test", chrono::Duration::hours(48));

        // Pass 1: the old key is past rollover age -> a new key is
        // generated. Both are active (double-signing).
        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active", "active"]);

        // Pass 2: the old key (48 h >= 48 h rollover+overlap) retires; it is
        // not yet old enough to be deleted (needs 72 h).
        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active", "retired"]);

        // Age the retired key past the delete threshold and remove it.
        let old_key = m
            .store
            .list_signing_keys(&zone.id)
            .unwrap()
            .into_iter()
            .find(|k| k.is_retired())
            .unwrap();
        m.store
            .set_key_created_at(&old_key.id, Utc::now() - chrono::Duration::hours(96))
            .unwrap();
        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active"]);

        // Steady state: one active, young key - nothing happens.
        assert_eq!(m.process_rollover().unwrap(), 0);
    }

    #[test]
    fn rollover_does_not_stack_a_third_key() {
        let m = maintenance(1);
        // Two active keys: a rollover is already in progress. The older key
        // (36 h) is past rollover age but not yet at the 48 h retire
        // threshold, so no key is generated and none is retired.
        let zone = zone_with_key(&m, "stack.test", chrono::Duration::hours(36));
        let (algorithm, der) = generate_signing_key().unwrap();
        m.store
            .store_signing_key_created(
                &zone.id,
                algorithm,
                &der,
                Utc::now() - chrono::Duration::hours(12),
            )
            .unwrap();

        assert_eq!(m.process_rollover().unwrap(), 0);
        assert_eq!(key_states(&m, &zone.id), vec!["active", "active"]);
    }

    #[test]
    fn ancient_key_is_replaced_and_removed() {
        let m = maintenance(1);
        // A single key left far past every threshold (e.g. after an
        // abandoned rollover or a very long gap): rollover starts, and on
        // the next pass the old key retires and is deleted in one go.
        let zone = zone_with_key(&m, "ancient.test", chrono::Duration::hours(100));

        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active", "active"]);
        // Pass 2 retires the old key; pass 3 deletes it (state changes are
        // observed one pass apart, never cascaded within a single pass).
        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active", "retired"]);
        assert_eq!(m.process_rollover().unwrap(), 1);
        assert_eq!(key_states(&m, &zone.id), vec!["active"]);
    }

    #[test]
    fn rollover_disabled_never_generates_keys() {
        let m = maintenance(0);
        let zone = zone_with_key(&m, "frozen.test", chrono::Duration::hours(2400));

        assert_eq!(m.process_rollover().unwrap(), 0);
        assert_eq!(key_states(&m, &zone.id), vec!["active"]);
        assert_eq!(m.store.list_signing_keys(&zone.id).unwrap().len(), 1);
    }

    #[test]
    fn unsigned_and_secondary_zones_are_untouched() {
        let m = maintenance(1);
        let zone = zone_with_key(&m, "plain.test", chrono::Duration::hours(240));

        // Mark the zone secondary: rollover must skip it.
        m.store
            .set_secondary(&zone.id, &["192.0.2.1".to_string()], 3600)
            .unwrap();
        let m = DnssecMaintenance::new(
            m.store.clone(),
            m.catalog.clone(),
            &AuthoritativeSettings {
                dnssec_rollover_days: 1,
                dnssec_rollover_overlap_days: 1,
                dnssec_rollover_retire_days: 1,
                ..Default::default()
            },
        );

        assert_eq!(m.process_rollover().unwrap(), 0);
        assert_eq!(m.store.list_signing_keys(&zone.id).unwrap().len(), 1);
    }

    #[test]
    fn unparseable_timestamp_never_triggers_destructive_steps() {
        let key = SigningKeyRecord {
            id: "k".to_string(),
            zone_id: "z".to_string(),
            algorithm: 13,
            key_der: vec![],
            state: "active".to_string(),
            created_at: "not-a-date".to_string(),
        };
        // Treated as "created now": age ~0, so no threshold can fire.
        assert!(key_age(&key) < Duration::from_secs(60));
    }
}
