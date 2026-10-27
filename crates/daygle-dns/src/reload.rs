//! Live configuration reload.
//!
//! Daygle watches its TOML configuration file and applies changes without a
//! restart:
//!
//! - **policy** - the [`PolicyEngine`] is rebuilt and swapped atomically.
//! - **upstreams / recursion** - the [`RecursiveResolver`] is rebuilt when the
//!   `recursive` section changes.
//! - **listeners** - UDP/TCP/DoT listeners are gracefully rebound when the
//!   `server` or `dot` sections change.
//!
//! Everything is published through [`arc_swap`] containers so the dispatcher
//! and the REST API observe a consistent snapshot per query without locks.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_core::config::DaygleConfig;
use daygle_dns_core::error::Result;
use daygle_dns_core::{LogStore, Metrics, RateLimiter};
use daygle_dns_policy::{AdvancedBlocking, BlocklistSourceManager, PolicyEngine};
use daygle_dns_recursive::RecursiveResolver;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Mutable runtime state shared by the dispatcher, the REST API and the
/// reload machinery.
pub struct Shared {
    pub catalog: Arc<AuthorityCatalog>,
    pub policy: Arc<ArcSwap<PolicyEngine>>,
    /// Advanced Blocking groups (built from the store, swapped on CRUD).
    pub advanced_blocking: Arc<ArcSwap<AdvancedBlocking>>,
    /// Persistent query logger; `None` unless `logging.query_log_enabled`.
    pub query_logger: Option<Arc<daygle_dns_core::QueryLogger>>,
    /// SQLite query-log sink feeding the console's Query Logs view; it skips
    /// entries while `logging.query_db_enabled` is off.
    pub query_db_logger: Option<Arc<crate::query_db_log::QueryDbLogger>>,
    pub resolver: Arc<ArcSwapOption<RecursiveResolver>>,
    pub recursive_admission: Arc<crate::dispatcher::RecursiveAdmission>,
    pub config: Arc<ArcSwap<DaygleConfig>>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Recent block-page answers (the page reads them).
    pub block_log: Arc<daygle_dns_core::block_log::BlockLog>,
    /// The block page's web server; `None` in tests.
    pub block_page: Option<Arc<crate::block_page::BlockPageServer>>,
    /// The DHCP server; `None` in tests.
    pub dhcp: Option<Arc<daygle_dns_dhcp::DhcpService>>,
    /// Response policy zones; `None` in tests.
    pub rpz: Option<Arc<daygle_dns_authoritative::rpz::RpzManager>>,
    /// Response rate limiting (`[rrl]`), shared by every listener.
    pub rrl: Arc<daygle_dns_core::rrl::ResponseRateLimiter>,
    pub metrics: Arc<Metrics>,
    pub logs: Arc<LogStore>,
    /// Coalescing session-failure logger for DoT/DoH/DoQ: certificate
    /// lifecycle reports and handshake/connection failures (tagged `tls`,
    /// `https`, `quic` like the query log).
    pub session: Arc<crate::tls_diag::SessionLog>,
    /// Dashboard time-series + top-N tables.
    pub stats: Arc<daygle_dns_core::stats::QueryStats>,
    /// NOTIFY hooks (RFC 1996): outbound sender + inbound handler, built once
    /// at startup and reused verbatim by every listener rebuild so secondary
    /// replication and NOTIFY-triggered refreshes survive live reloads.
    pub notify_hooks: daygle_dns_authoritative::notify::NotifyHooks,
    /// TSIG key ring (RFC 8945) for transfer/update authentication, built
    /// once at startup and reused verbatim by every listener rebuild.
    pub tsig_keys: Arc<daygle_dns_authoritative::tsig::TsigKeyRing>,
    /// The local root zone (RFC 8806), handed to every resolver rebuild.
    pub local_root: Arc<daygle_dns_authoritative::LocalRoot>,
    /// Remote logging (syslog); `None` in tests.
    pub syslog: Option<Arc<crate::syslog::SyslogSender>>,
    /// Query export to an HTTP endpoint; `None` in tests.
    pub log_export: Option<Arc<daygle_dns_api::log_export::LogExporter>>,
    /// Held while the configuration is read, changed and published (console
    /// saves and config-file reloads), so two changes landing together
    /// cannot overwrite each other.
    pub config_write: Arc<tokio::sync::Mutex<()>>,
}

/// The currently bound DNS listener addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListenerAddrs {
    pub udp: Option<std::net::SocketAddr>,
    pub tcp: Option<std::net::SocketAddr>,
    pub dot: Option<std::net::SocketAddr>,
    pub doh: Option<std::net::SocketAddr>,
    pub doq: Option<std::net::SocketAddr>,
    /// DoH over HTTP/3 (UDP).
    pub doh3: Option<std::net::SocketAddr>,
}

/// Commands sent to the DNS listener supervisor.
pub enum ReloadCommand {
    /// Rebind listeners from the configuration currently stored in `Shared`.
    Rebuild {
        /// Acknowledges completion (used by the synchronous `reload()` API).
        ack: Option<oneshot::Sender<Result<()>>>,
    },
}

/// Apply a freshly parsed configuration to the shared state.
///
/// Returns `true` when the `server`/`dot` listener settings changed and the
/// caller must ask the supervisor to rebind the sockets.
pub fn apply_config(shared: &Shared, new: Arc<DaygleConfig>) -> bool {
    let old = shared.config.load_full();
    // Compare and build from the network names resolved to addresses, so a
    // change to a named network reaches every setting that names it.
    let old_r = old.with_networks_resolved();
    let new_r = new.with_networks_resolved();

    let listeners_changed = old_r.server != new_r.server
        || old_r.dot != new_r.dot
        || old_r.doh != new_r.doh
        || old_r.doq != new_r.doq;

    // Publish the new configuration first so the API token, `/api/config` and
    // the listener supervisor all observe the requested state immediately.
    shared.config.store(Arc::clone(&new));
    daygle_dns_core::schedule::set_time_zone(&new.display.time_zone);
    shared
        .recursive_admission
        .set_limit(new.recursive.max_concurrent_lookups);

    // Policy engine.
    if old_r.policy != new_r.policy {
        match daygle_dns_policy::build_engine(&new_r.policy) {
            Ok(engine) => {
                // Rebuilding the engine must not discard domain sets the
                // source refresher owns (remote sources, and the DoT-scoped
                // listener set): the live engine's are kept.
                daygle_dns_policy::publish_rebuilt(&shared.policy, engine);
                info!("policy engine reloaded");
            }
            Err(e) => warn!("policy reload failed, keeping previous engine: {e}"),
        }
    }

    // Named networks (split horizon resolves them in its index).
    if old.networks != new.networks {
        match shared.catalog.set_networks(new.all_networks()) {
            Ok(()) => info!("networks reloaded"),
            Err(e) => warn!("cannot apply the networks: {e}"),
        }
    }

    // The published catalog zone (consumed catalogs are read live).
    if old.authoritative.catalog_zone != new.authoritative.catalog_zone {
        match shared
            .catalog
            .set_catalog_zone(&new.authoritative.catalog_zone)
        {
            Ok(()) => info!("catalog zone setting reloaded"),
            Err(e) => warn!("cannot publish the catalog zone: {e}"),
        }
    }

    // Recursive resolver / upstreams / stub zones. The resolver owns the stub
    // zones (see StubZoneConfig), so a change to them rebuilds it together
    // with the recursive settings.
    shared
        .local_root
        .set_settings(new.recursive.local_root_in_effect());
    if old_r.recursive != new_r.recursive
        || old_r.authoritative.stub_zones != new_r.authoritative.stub_zones
    {
        if new_r.recursive.enabled {
            match RecursiveResolver::build(
                &new_r.recursive,
                shared.metrics.clone(),
                &new_r.authoritative.stub_zones,
                Some(shared.local_root.clone()),
            ) {
                Ok(resolver) => {
                    shared.resolver.store(Some(Arc::new(resolver)));
                    info!("recursive resolver reloaded");
                }
                Err(e) => warn!("recursive resolver reload failed, keeping previous: {e}"),
            }
        } else {
            shared.resolver.store(None);
            info!("recursion disabled by reload");
        }
    }

    // Zone-transfer and dynamic-update gates: read per request, so a changed
    // list (or a changed network it names) applies at once.
    let (old_gates, new_gates) = (&old_r.authoritative, &new_r.authoritative);
    if old_gates.axfr_enabled != new_gates.axfr_enabled
        || old_gates.axfr_networks != new_gates.axfr_networks
        || old_gates.allow_dynamic_updates != new_gates.allow_dynamic_updates
        || old_gates.update_networks != new_gates.update_networks
    {
        shared.catalog.update_gate_settings(
            new_gates.axfr_enabled,
            new_gates.axfr_networks.clone(),
            new_gates.allow_dynamic_updates,
            new_gates.update_networks.clone(),
        );
        info!("zone transfer and dynamic update settings reloaded");
    }

    // Rate limiting. The shared limiter holds its own settings snapshot and
    // keeps its buckets, so a reload applies new limits (or disables the
    // limiter) without dropping in-flight window state.
    if old.block_page != new.block_page {
        if let Some(page) = &shared.block_page {
            page.apply(&new.block_page);
        }
    }
    if old.dhcp != new.dhcp {
        if let Some(dhcp) = &shared.dhcp {
            dhcp.apply(&new.dhcp);
            info!("DHCP settings reloaded");
        }
    }
    if old.rpz != new.rpz {
        if let Some(rpz) = &shared.rpz {
            rpz.set_zones(&new.rpz);
            info!("response policy zones reloaded");
        }
    }
    if old.rrl != new.rrl || old.networks != new.networks {
        apply_rrl(shared, &new);
    }
    if old.rate_limit != new.rate_limit {
        shared.rate_limiter.set_settings(&new.rate_limit);
        if new.rate_limit.enabled {
            info!("rate limiting reloaded");
        } else {
            info!("rate limiting disabled by reload");
        }
    }

    listeners_changed
}

/// Spawn the background configuration-file watcher.
///
/// Polls `path` for mtime changes every `interval` and additionally wakes
/// immediately when `notify` fires (the `POST /api/config/reload` endpoint).
pub fn spawn_watcher(
    path: Arc<std::path::PathBuf>,
    shared: Arc<Shared>,
    reload_tx: mpsc::Sender<ReloadCommand>,
    notify: Option<Arc<tokio::sync::Notify>>,
    interval: Duration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_mtime = last_modified(&path);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
                _ = notified(notify.as_deref()) => {}
            }

            let mtime = last_modified(&path);
            if mtime == last_mtime {
                continue;
            }
            last_mtime = mtime;

            // Serialized with console saves: the overlay read below and the
            // publish must not interleave with one.
            let _config_write = shared.config_write.lock().await;
            let new = match DaygleConfig::load(path.as_ref()) {
                Ok(mut cfg) => {
                    // The database overlay owns the console-managed runtime
                    // settings: re-apply it so an external file edit cannot
                    // silently revert GUI-made changes.
                    if let Ok(Some(overlay)) = shared
                        .catalog
                        .store()
                        .get_runtime_settings::<daygle_dns_core::config::RuntimeSettings>(
                    ) {
                        overlay.apply_to(&mut cfg);
                        if let Err(e) = cfg.validate() {
                            warn!(
                                "config reload produced an invalid configuration, keeping previous: {e}"
                            );
                            continue;
                        }
                    }
                    cfg
                }
                Err(e) => {
                    warn!("config reload failed, keeping previous configuration: {e}");
                    continue;
                }
            };

            let changed = apply_config(&shared, Arc::new(new));
            if changed
                && reload_tx
                    .send(ReloadCommand::Rebuild { ack: None })
                    .await
                    .is_err()
            {
                warn!("DNS supervisor is gone; cannot apply listener changes");
            }
        }
    })
}

/// A future that completes when `notify` fires, or never when it is `None`.
async fn notified(notify: Option<&tokio::sync::Notify>) {
    match notify {
        Some(n) => {
            n.notified().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn last_modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Spawn the remote blocklist source refresher.
///
/// Polls the sources on the smallest configured refresh interval and, when
/// anything is due, swaps the merged remote blocklist into the shared policy
/// engine without touching the static (config + files) blocklist.
///
/// Returns the [`BlocklistSourceManager`] so the API can expose source status
/// and trigger manual refreshes.
pub fn spawn_blocklist_refresh(
    shared: Arc<Shared>,
    sources: Vec<daygle_dns_core::config::BlocklistSourceConfig>,
    group_lists: Arc<daygle_dns_policy::GroupBlocklists>,
    shutdown: CancellationToken,
) -> Option<Arc<BlocklistSourceManager>> {
    let manager = match BlocklistSourceManager::new(sources, group_lists) {
        Ok(m) => m,
        Err(e) => {
            warn!("blocklist sources disabled: {e}");
            return None;
        }
    };

    // The loop runs even with an empty source list (sleeping 24 h, doing
    // nothing), so sources added later at runtime - a fresh install that
    // gains its first source through the console - are still auto-refreshed
    // on their own schedule without a restart.
    let manager = Arc::new(manager);
    let refresh_manager = Arc::clone(&manager);
    tokio::spawn(async move {
        loop {
            // First cycle runs immediately (fetch on startup). Afterwards the
            // loop sleeps the smallest configured refresh interval, but wakes
            // immediately when the console replaces the source list, so a
            // changed schedule takes effect without waiting out the old one.
            // The notify future is armed before the snapshot so a change
            // landing anywhere in the cycle is either seen by the snapshot
            // or completes this future.
            let changed = refresh_manager.changed_notify().notified();
            let expected = refresh_manager.sources();
            match refresh_manager.refresh_due().await {
                Ok(list) => {
                    // Publish both source-owned sets together, and only when
                    // they differ from the live ones. A DoT-scoped set that
                    // is gone (its last source removed or disabled) clears
                    // the engine's: before, it kept blocking until restart.
                    let domains = list.len();
                    let dot = refresh_manager.dot_blocklist();
                    let dot_domains = dot.as_ref().map_or(0, |d| d.len());
                    if daygle_dns_policy::publish_source_lists(
                        &shared.policy,
                        Some(Arc::new(list)),
                        dot,
                    ) {
                        info!(domains, dot_domains, "remote blocklists refreshed");
                    }
                }
                Err(e) => warn!("blocklist refresh failed: {e}"),
            }
            // The source list changed while the cycle was running (e.g. a
            // console save): loop again right away instead of resting.
            // `take_change` is the sticky flag set by `set_sources`, which
            // catches changes whose `Notify` wake was consumed before the
            // select below re-armed it (rapid back-to-back edits).
            if refresh_manager.sources() != expected || refresh_manager.take_change() {
                continue;
            }
            let period = refresh_manager.min_refresh();
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = changed => {}
                _ = tokio::time::sleep(period) => {}
            }
        }
    });
    Some(manager)
}

/// Apply `config.rrl` to the shared response rate limiter.
pub fn apply_rrl(shared: &Shared, config: &DaygleConfig) {
    // Exemptions name networks; an unknown name was rejected when saved.
    let exempt = config
        .resolve_networks(&config.rrl.exempt)
        .unwrap_or_default();
    shared.rrl.set_settings(&config.rrl, exempt);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> DaygleConfig {
        let mut cfg = DaygleConfig::default();
        cfg.recursive.enabled = false;
        cfg.authoritative.database = ":memory:".to_string();
        cfg
    }

    fn shared(cfg: DaygleConfig) -> Shared {
        let store = daygle_dns_authoritative::ZoneStore::open(":memory:").unwrap();
        let catalog = Arc::new(AuthorityCatalog::new(store, cfg.authoritative.clone()).unwrap());
        Shared {
            catalog,
            policy: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
            advanced_blocking: Arc::new(ArcSwap::from_pointee(AdvancedBlocking::default())),
            query_logger: None,
            query_db_logger: None,
            resolver: Arc::new(ArcSwapOption::empty()),
            recursive_admission: Arc::new(crate::dispatcher::RecursiveAdmission::new(
                cfg.recursive.max_concurrent_lookups,
            )),
            config: Arc::new(ArcSwap::from(Arc::new(cfg))),
            rate_limiter: Arc::new(RateLimiter::default()),
            rrl: Arc::default(),
            rpz: None,
            block_log: Arc::default(),
            block_page: None,
            dhcp: None,
            metrics: Arc::new(Metrics::default()),
            logs: Arc::new(LogStore::new(16)),
            session: Arc::new(crate::tls_diag::SessionLog::new(Arc::new(LogStore::new(
                16,
            )))),
            stats: Arc::new(daygle_dns_core::stats::QueryStats::new()),
            notify_hooks: Default::default(),
            tsig_keys: Arc::new(Default::default()),
            local_root: Arc::new(daygle_dns_authoritative::LocalRoot::new(
                Default::default(),
                None,
            )),
            syslog: None,
            log_export: None,
            config_write: Arc::default(),
        }
    }

    #[test]
    fn detects_listener_changes() {
        let s = shared(base());
        let mut next = base();
        next.server.port = 5353;
        assert!(apply_config(&s, Arc::new(next)));
        assert_eq!(s.config.load_full().server.port, 5353);
    }

    #[test]
    fn policy_only_change_does_not_rebind() {
        let s = shared(base());
        let mut next = base();
        next.policy.blocklist = vec!["ads.example".to_string()];
        assert!(!apply_config(&s, Arc::new(next)));
        assert_eq!(
            s.config.load_full().policy.blocklist,
            vec!["ads.example".to_string()]
        );
    }

    #[test]
    fn identical_config_is_a_noop() {
        let s = shared(base());
        assert!(!apply_config(&s, Arc::new(base())));
    }
}
