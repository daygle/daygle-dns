//! # daygle_dns
//!
//! Library surface of the Daygle DNS server binary: the combined
//! [`DnsDispatcher`] and a [`bind`] helper that wires every subsystem into a
//! runnable server. The `daygle-dns` binary is a thin CLI wrapper around this.

mod connection_admission;
pub mod cookies;
pub mod dispatcher;
mod doq;
mod dot;
mod net;
pub mod proxy_protocol;
pub mod query_db_log;
pub mod reload;
pub mod syslog;
pub mod tls_diag;
pub mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_dns_api::{router, AppState};
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_core::config::DaygleConfig;
use daygle_dns_core::error::{DaygleError, Result};
use daygle_dns_core::{LogLevel, LogStore, Metrics, RateLimiter};
use daygle_dns_policy::BlocklistSourceManager;
use daygle_dns_recursive::RecursiveResolver;
use dispatcher::DnsDispatcher;
use hickory_server::server::Server;
use reload::{
    apply_config, spawn_blocklist_refresh, spawn_watcher, ListenerAddrs, ReloadCommand, Shared,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub use dispatcher::DnsDispatcher as CombinedHandler;

/// A fully-bound Daygle server, ready to run.
pub struct BoundServer {
    /// The initially bound plaintext UDP address, if UDP is enabled.
    pub udp_addr: Option<std::net::SocketAddr>,
    /// The initially bound plaintext TCP address, if TCP is enabled.
    pub tcp_addr: Option<std::net::SocketAddr>,
    /// The initially bound DNS-over-TLS address, if DoT is enabled.
    pub dot_addr: Option<std::net::SocketAddr>,
    /// The initially bound DNS-over-HTTPS address, if DoH is enabled.
    pub doh_addr: Option<std::net::SocketAddr>,
    /// The initially bound DNS-over-QUIC address, if DoQ is enabled.
    pub doq_addr: Option<std::net::SocketAddr>,
    /// The REST API + GUI address as bound at startup: the HTTP listener,
    /// or HTTPS when HTTP is off (see [`BoundServer::web_addrs`]).
    pub api_addr: std::net::SocketAddr,
    /// Shared runtime metrics.
    pub metrics: Arc<Metrics>,
    /// In-memory log ring buffer.
    pub logs: Arc<LogStore>,
    /// The authoritative zone catalog.
    pub catalog: Arc<AuthorityCatalog>,
    /// The recursive resolver as built at startup (superseded on reload; see
    /// [`BoundServer::reload`]).
    pub resolver: Option<Arc<RecursiveResolver>>,
    /// Remote blocklist source manager (fetches and status; `None` when no
    /// sources are configured).
    pub blocklist_sources: Option<Arc<BlocklistSourceManager>>,

    shared: Arc<Shared>,
    addrs: Arc<ArcSwap<ListenerAddrs>>,
    shutdown: CancellationToken,
    dns_task: Option<tokio::task::JoinHandle<Result<()>>>,
    web: Arc<web::WebServer>,
    reload_task: Option<tokio::task::JoinHandle<()>>,
    reload_tx: mpsc::Sender<ReloadCommand>,
    config_path: Option<PathBuf>,
}

impl BoundServer {
    /// Clone the cancellation token used to shut every subsystem down.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Where the web console is listening now (reflecting Settings changes).
    pub async fn web_addrs(&self) -> web::WebAddrs {
        self.web.addrs().await
    }

    /// The currently bound DNS listener addresses (reflecting any reloads).
    pub fn addrs(&self) -> ListenerAddrs {
        *self.addrs.load_full()
    }

    /// Re-read the configuration file and apply policy/upstream/listener
    /// changes immediately, without waiting for the poll interval.
    ///
    /// Awaits completion of any listener rebinding before returning.
    pub async fn reload(&self) -> Result<()> {
        let Some(path) = self.config_path.clone() else {
            return Err(DaygleError::Config(
                "live reload is unavailable: no config file path".to_string(),
            ));
        };
        // Serialized with console saves, which also read-modify-write it.
        let config_write = self.shared.config_write.clone();
        let _config_write = config_write.lock().await;
        let mut new = DaygleConfig::load(&path)?;
        // The DB overlay owns the console-managed runtime settings: re-apply
        // it so a file edit cannot silently revert GUI-made changes.
        if let Ok(Some(overlay)) =
            self.shared
                .catalog
                .store()
                .get_runtime_settings::<daygle_dns_core::config::RuntimeSettings>()
        {
            overlay.apply_to(&mut new);
            new.validate()?;
        }
        let changed = apply_config(&self.shared, Arc::new(new));

        if changed {
            let (ack_tx, ack_rx) = oneshot::channel();
            self.reload_tx
                .send(ReloadCommand::Rebuild { ack: Some(ack_tx) })
                .await
                .map_err(|_| DaygleError::Internal("DNS supervisor is gone".to_string()))?;
            ack_rx.await.map_err(|_| {
                DaygleError::Internal("DNS supervisor did not ack reload".to_string())
            })??;
        }
        Ok(())
    }

    /// Stop every subsystem and wait for the DNS listeners to finish, so the
    /// database is released before this returns (a restart can then replace
    /// it).
    pub async fn stop(mut self) -> Result<()> {
        self.shutdown.cancel();
        if let Some(task) = self.reload_task.take() {
            task.abort();
        }
        match self.dns_task.take() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(e) => Err(DaygleError::Internal(format!(
                    "DNS supervisor panicked: {e}"
                ))),
            },
            None => Ok(()),
        }
    }

    /// Run until the server is shut down (or a listener fails fatally).
    pub async fn run(mut self) -> Result<()> {
        let dns = match self.dns_task.take() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(e) => Err(DaygleError::Internal(format!(
                    "DNS supervisor panicked: {e}"
                ))),
            },
            None => Ok(()),
        };

        // Shut down the remaining background tasks now that DNS has stopped.
        self.shutdown.cancel();
        if let Some(task) = self.reload_task.take() {
            task.abort();
        }

        dns
    }
}

/// Build every subsystem and bind the DNS + API listeners.
///
/// A port of `0` in the configuration selects an ephemeral port; the actual
/// bound address is reported back through [`BoundServer`].
pub async fn bind(config: Arc<DaygleConfig>) -> Result<BoundServer> {
    bind_with(config, None).await
}

/// Like [`bind`], but also watches `config_path` for changes and applies them
/// live when `server.reload_enabled` is set.
pub async fn bind_with(
    config: Arc<DaygleConfig>,
    config_path: Option<PathBuf>,
) -> Result<BoundServer> {
    let metrics = Arc::new(Metrics::default());
    let logs = Arc::new(LogStore::new(config.logging.ring_buffer));
    let stats = Arc::new(daygle_dns_core::stats::QueryStats::new());
    let started_at = std::time::Instant::now();
    let shutdown = CancellationToken::new();

    // A restore staged from the console or `daygle-dns restore` replaces
    // the database before it is opened.
    let restored = match daygle_dns_authoritative::backup::apply_pending_restore(
        &config.authoritative.database,
    ) {
        Ok(aside) => aside,
        Err(e) => {
            warn!("{e}");
            logs.push(daygle_dns_core::LogLevel::Error, "backup", e.to_string());
            None
        }
    };

    // Authoritative.
    let store = daygle_dns_authoritative::ZoneStore::open(&config.authoritative.database)?;
    // Runtime components take the network names resolved to addresses; the
    // stored config keeps the names.
    let resolved = config.with_networks_resolved();
    let catalog = Arc::new(AuthorityCatalog::new(
        store.clone(),
        resolved.authoritative.clone(),
    )?);
    catalog.reload()?;
    import_zone_files(&catalog, &config, &logs)?;

    // DB-backed runtime settings: the TOML file supplies bootstrap values
    // (listeners, addresses, ports, paths); everything the console edits
    // lives in the database and wins over the file on every boot. On first
    // boot (nothing stored yet) the file's values are seeded into the DB so
    // file-based installs transition seamlessly.
    let mut config = Arc::unwrap_or_clone(config);
    let overlay = store.get_runtime_settings::<daygle_dns_core::config::RuntimeSettings>()?;
    // Stored settings from before networks were shared hold none yet.
    let adopt_split_horizon_networks = overlay.as_ref().is_none_or(|o| o.networks.is_none());
    match overlay {
        Some(overlay) => {
            // No `validate()` here: `bind` accepts pre-validated configs and
            // test setups legitimately keep ephemeral port 0. The overlay was
            // validated when it was captured (console saves run validate).
            overlay.apply_to(&mut config);
        }
        None => {
            store.put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(
                &config,
            ))?;
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "api",
                "runtime settings seeded into the database from the config file".to_string(),
            );
        }
    }
    if adopt_split_horizon_networks && config.networks.is_empty() {
        adopt_legacy_networks(&store, &mut config, &logs)?;
    }
    catalog.set_networks(config.all_networks())?;
    // Note: no `validate()` here - `bind` accepts pre-validated configs, and
    // test setups legitimately use ephemeral port 0.
    let config = Arc::new(config);
    // Shared, atomically-swappable runtime config.
    let config_swap = Arc::new(ArcSwap::from(config.clone()));

    // Console accounts live in the database (the GUI manages them at
    // runtime). `[[api.users]]` entries in the config file are a seed source:
    // they are imported on startup unless the same username already exists in
    // the database, so config-managed accounts keep working while DB-created
    // accounts survive config rewrites.
    {
        let mut seeded = 0usize;
        for user in &config.api.users {
            if store.get_console_user(&user.username)?.is_none() {
                store.create_console_user(
                    &user.username,
                    &daygle_dns_authoritative::ConsoleUserInput {
                        password_hash: user.password_hash.clone(),
                        role: user.role,
                        enabled: true,
                        first_name: String::new(),
                        last_name: String::new(),
                        email: String::new(),
                    },
                )?;
                seeded += 1;
            }
        }
        if seeded > 0 {
            logs.push(
                daygle_dns_core::LogLevel::Info,
                "api",
                format!("imported {seeded} console account(s) from the config file"),
            );
        }
    }

    // DNSSEC maintenance: renews RRSIGs before they expire and rolls keys
    // on schedule, so signed zones never go bogus.
    if config.authoritative.dnssec_enabled {
        let maintenance = daygle_dns_authoritative::DnssecMaintenance::new(
            store.clone(),
            catalog.clone(),
            &config.authoritative,
        );
        tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                maintenance.run_forever(shutdown).await;
            }
        });
    }

    // Secondary zone refreshers (AXFR/IXFR from configured masters). The
    // refresher is shared with the NOTIFY listener so inbound NOTIFYs can
    // trigger immediate refreshes (RFC 1996).
    let refresher = {
        let refresher = Arc::new(daygle_dns_authoritative::SecondaryRefresher::new(
            store.clone(),
            catalog.clone(),
            config.authoritative.secondary_zones.clone(),
            daygle_dns_authoritative::XfrClient::default(),
        ));
        tokio::spawn({
            let refresher = refresher.clone();
            let shutdown = shutdown.clone();
            async move {
                refresher.run_forever(shutdown).await;
            }
        });
        Some(refresher)
    };

    // Health checks on failover records.
    let health = Arc::new(daygle_dns_authoritative::HealthMonitor::new(
        catalog.clone(),
    ));
    tokio::spawn(health.clone().run_forever(shutdown.clone()));

    // Consumed catalog zones (RFC 9432): their member zones become
    // secondary zones, refreshed by the refresher above.
    let catalog_consumer = refresher.clone().map(|refresher| {
        let consumer = Arc::new(daygle_dns_authoritative::CatalogConsumer::new(
            store.clone(),
            catalog.clone(),
            refresher,
            daygle_dns_authoritative::XfrClient::default(),
            config_swap.clone(),
        ));
        tokio::spawn({
            let consumer = consumer.clone();
            let shutdown = shutdown.clone();
            async move { consumer.run_forever(shutdown).await }
        });
        consumer
    });

    // Outbound NOTIFY: sent to secondaries when a primary zone changes.
    let notify_sender = if config.authoritative.notify_enabled {
        match daygle_dns_authoritative::NotifySender::new(&config.authoritative.notify_targets) {
            Ok(sender) => Some(Arc::new(sender)),
            Err(e) => {
                warn!(error = %e, "disabling outbound NOTIFY");
                None
            }
        }
    } else {
        None
    };

    // Inbound NOTIFY: masters trigger an immediate secondary-zone refresh.
    // Handled on the regular DNS listeners (OpCode::Notify interception), so
    // no extra socket is bound.
    let notify_inbound = match (
        config.authoritative.notify_listen_enabled,
        refresher.clone(),
    ) {
        (true, Some(refresher)) => {
            let inbound = daygle_dns_authoritative::notify::NotifyInbound::new(
                config.authoritative.secondary_zones.clone(),
                refresher,
            );
            Some(Arc::new(match &catalog_consumer {
                Some(consumer) => inbound.with_catalogs(consumer.clone()),
                None => inbound,
            }))
        }
        (true, None) => {
            warn!(
                "notify_listen_enabled is set but no secondary zones are configured; \
                 inbound NOTIFY disabled"
            );
            None
        }
        _ => None,
    };
    // The published catalog zone: NOTIFY its secondaries when its member
    // list changes (the catalog's name is read live, as it can change).
    if let Some(sender) = notify_sender.clone() {
        let changed = catalog.catalog_zone_changed();
        let catalog = catalog.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = changed.notified() => {}
                }
                let name = catalog.settings().catalog_zone.clone();
                if !name.is_empty() {
                    sender.notify_zone(&name).await;
                }
            }
        });
    }
    // Primary zones: NOTIFY their secondaries whenever a zone is served
    // with a new serial, whatever changed it (console, import, dynamic
    // update, DNSSEC re-sign).
    if let Some(sender) = notify_sender.clone() {
        let changed = catalog.zones_changed();
        let catalog = catalog.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = changed.notified() => {}
                }
                for zone in catalog.take_changed_zones() {
                    sender.notify_zone(&zone).await;
                }
            }
        });
    }
    let notify_hooks = daygle_dns_authoritative::notify::NotifyHooks {
        sender: notify_sender,
        inbound: notify_inbound,
    };

    // Local root zone (RFC 8806): transferred, ZONEMD-verified and served
    // to the resolver on loopback while `recursive.local_root.enabled`. The
    // verified copy is cached next to the database across restarts.
    let local_root = Arc::new(daygle_dns_authoritative::LocalRoot::new(
        config.recursive.local_root_in_effect(),
        local_root_cache_path(&config.authoritative.database),
    ));
    tokio::spawn(local_root.clone().run_forever(shutdown.clone()));

    // Recursive.
    let resolver = if config.recursive.enabled {
        Some(Arc::new(RecursiveResolver::build(
            &resolved.recursive,
            metrics.clone(),
            &resolved.authoritative.stub_zones,
            Some(local_root.clone()),
        )?))
    } else {
        warn!("recursion is disabled");
        None
    };

    // Policy.
    let mut policy = daygle_dns_policy::build_engine(&resolved.policy)?;

    // Finish a restore: the backup's AI overrides go into the AI database
    // (whose path may come from the restored settings).
    if let Some(aside) = &restored {
        let ai_database = daygle_dns_ml::database_path(&config.ai, &config.authoritative.database);
        if let Err(e) = store.finish_restore(&ai_database) {
            warn!("restore: {e}");
            logs.push(
                daygle_dns_core::LogLevel::Error,
                "backup",
                format!("restore: {e}"),
            );
        }
        let message = format!(
            "restored from a backup; the previous database was kept as {}",
            aside.display()
        );
        info!("{message}");
        logs.push(daygle_dns_core::LogLevel::Info, "backup", message);
    }

    // AI subsystem (daygle-dns-ml): a CPU-only background classifier over
    // domains observed in the query log. Opt-in via `[ai] enabled = true`.
    // The scanner runs on its own cadence - never on the DNS hot path - and
    // the policy plugin defers in train mode, blocks in enforce mode. The
    // user allowlist and operator blocklists still run before plugins, so
    // operator decisions always supersede AI verdicts.
    let ai_engine = daygle_dns_ml::build_ai_engine(
        &config.ai,
        &config.authoritative.database,
        Arc::new(store.clone()),
        logs.clone(),
    );
    if let Some(ai) = &ai_engine {
        policy.add_plugin(ai.block_plugin());
        tokio::spawn({
            let ai = ai.clone();
            let shutdown = shutdown.clone();
            async move {
                ai.run_forever(shutdown).await;
            }
        });
        info!(
            mode = ?config.ai.mode,
            "AI scanner enabled"
        );
    }

    // Advanced Blocking groups (per-client allow/block policies) built from
    // the store; swapped atomically when the groups change via the API. The
    // blocklist sources scoped to groups are filled in by the refresher.
    let group_blocklists = Arc::new(daygle_dns_policy::GroupBlocklists::default());
    let advanced_blocking = Arc::new(ArcSwap::from_pointee(
        daygle_dns_policy::AdvancedBlocking::build(
            &resolved.resolve_blocking_groups(catalog.store().list_blocking_groups()?),
            group_blocklists.clone(),
        ),
    ));

    // Persistent query logging (daily JSON-lines files), when enabled.
    let query_logger = if config.logging.query_log_enabled {
        Some(Arc::new(daygle_dns_core::QueryLogger::new(
            std::path::Path::new(&config.logging.query_log_dir),
            config.logging.query_log_retention_days,
        )))
    } else {
        None
    };

    // SQLite-backed query log for the console's Query Logs view (search,
    // filter, paginate, export). The sink batches writes off the query path.
    let query_db_logger = if config.logging.query_db_enabled {
        Some(Arc::new(crate::query_db_log::QueryDbLogger::spawn(
            store.clone(),
            config.logging.query_db_max_rows,
            shutdown.clone(),
        )))
    } else {
        None
    };

    // Rate limiting (per client + per domain).
    let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limit));

    // TSIG keys (RFC 8945) for transfer/update authentication. Key
    // construction errors are configuration errors: fail fast at startup.
    // Stored in `Shared` so every listener rebuild reuses the same ring.
    let tsig_keys = Arc::new(
        daygle_dns_authoritative::tsig::TsigKeyRing::from_configs(&config.authoritative.tsig_keys)
            .map_err(DaygleError::Config)?,
    );

    // Remote logging: the server log goes to syslog when `[syslog]` is on
    // (settings are read per line, so console changes apply at once).
    let syslog = syslog::SyslogSender::start(config_swap.clone(), shutdown.clone());
    logs.set_forwarder({
        let syslog = syslog.clone();
        Arc::new(move |entry| syslog.log_entry(entry))
    });
    // Encrypted-DNS session diagnostics: certificate lifecycle reports and
    // coalesced handshake/connection failure warnings for DoT/DoH/DoQ.
    // Registered before any listener binds, so the hickory bridge in the
    // server binary's tracing setup forwards into this Server Log.
    let session = Arc::new(tls_diag::SessionLog::new(logs.clone()));
    tls_diag::set_current(session.clone());
    let shared = Arc::new(Shared {
        catalog: catalog.clone(),
        policy: Arc::new(ArcSwap::from_pointee(policy)),
        advanced_blocking: advanced_blocking.clone(),
        query_logger: query_logger.clone(),
        query_db_logger: query_db_logger.clone(),
        resolver: Arc::new(arc_swap::ArcSwapOption::from(resolver.clone())),
        recursive_admission: Arc::new(dispatcher::RecursiveAdmission::new(
            config.recursive.max_concurrent_lookups,
        )),
        config: config_swap,
        rate_limiter: rate_limiter.clone(),
        metrics: metrics.clone(),
        logs: logs.clone(),
        session: session.clone(),
        stats: stats.clone(),
        notify_hooks: notify_hooks.clone(),
        tsig_keys: tsig_keys.clone(),
        local_root: local_root.clone(),
        syslog: Some(syslog),
        config_write: Arc::default(),
    });

    // DNS listeners (bound immediately so the server serves right away).
    let dispatcher = build_dispatcher(&shared, &config);
    let mut server = Server::new(dispatcher.clone());
    let mut initial_addrs = ListenerAddrs::default();
    let initial_native = bind_listeners(
        &config,
        &session,
        &store,
        &dispatcher,
        &mut server,
        &mut initial_addrs,
    )
    .await?;
    let addrs = Arc::new(ArcSwap::from_pointee(initial_addrs));

    // DNS supervisor: owns the listeners and rebinds them on command.
    let (reload_tx, reload_rx) = mpsc::channel(16);
    let dns_task = tokio::spawn(run_dns_supervisor(
        shared.clone(),
        addrs.clone(),
        shutdown.clone(),
        reload_rx,
        server,
        initial_native,
        config.clone(),
    ));

    // Config-file watcher.
    let reload_notify = if config.server.reload_enabled && config_path.is_some() {
        Some(Arc::new(tokio::sync::Notify::new()))
    } else {
        None
    };
    let reload_task = match (config_path.clone(), reload_notify.clone()) {
        (Some(path), Some(notify)) if config.server.reload_enabled => Some(spawn_watcher(
            Arc::new(path),
            shared.clone(),
            reload_tx.clone(),
            Some(notify),
            Duration::from_millis(config.server.reload_interval_ms),
            shutdown.clone(),
        )),
        _ => None,
    };

    // Remote blocklist sources: fetch on schedule, expose status via the API.
    let blocklist_sources = spawn_blocklist_refresh(
        shared.clone(),
        config.policy.blocklist_sources.clone(),
        group_blocklists,
        shutdown.clone(),
    );

    // REST API and web console, over HTTP and/or HTTPS (Settings ->
    // General); the listeners are bound once the router exists below.
    // The API can request a DNS listener rebuild after settings changes.
    let rebuild_tx = reload_tx.clone();
    let request_dns_rebuild: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let _ = rebuild_tx.try_send(ReloadCommand::Rebuild { ack: None });
    });
    // The web server needs the router, and the router's settings handler
    // needs the web server: the handle is filled in right after.
    // Weak: the router's state holds this closure, so a strong reference here
    // would keep the web server (and with it the database) alive forever.
    let web_cell: Arc<std::sync::OnceLock<std::sync::Weak<web::WebServer>>> =
        Arc::new(std::sync::OnceLock::new());
    let web_apply: daygle_dns_api::WebApplyFn = {
        let cell = web_cell.clone();
        Arc::new(move |settings| {
            let cell = cell.clone();
            Box::pin(async move {
                match cell.get().and_then(|web| web.upgrade()) {
                    Some(web) => web.apply(settings).await.map(|_| ()),
                    None => Err("the web console is still starting".to_string()),
                }
            })
        })
    };
    let app_state = AppState {
        catalog: catalog.clone(),
        resolver: shared.resolver.clone(),
        metrics: metrics.clone(),
        logs: logs.clone(),
        config: shared.config.clone(),
        policy: shared.policy.clone(),
        advanced_blocking: shared.advanced_blocking.clone(),
        secondary_refresher: refresher.clone(),
        health: Some(health.clone()),
        local_root: local_root.clone(),
        blocklist_sources: blocklist_sources.clone(),
        started_at,
        config_path: config_path.clone().map(Arc::new),
        reload_notify,
        sessions: Arc::new(daygle_dns_api::SessionStore::with_store(store.clone())),
        login_throttle: Arc::new(daygle_dns_api::LoginThrottle::default()),
        request_dns_rebuild: Some(request_dns_rebuild),
        config_write: shared.config_write.clone(),
        apply_runtime: Some({
            let shared = shared.clone();
            Arc::new(move |config: &DaygleConfig| {
                shared
                    .recursive_admission
                    .set_limit(config.recursive.max_concurrent_lookups);
            })
        }),
        web_apply: Some(web_apply),
        stats: stats.clone(),
        ai: ai_engine.clone(),
        acme: Arc::new(daygle_dns_api::acme::Acme::default()),
    };
    // Issue and renew ACME (Let's Encrypt) certificates in the background.
    tokio::spawn(daygle_dns_api::acme::run_renewals(
        app_state.clone(),
        shutdown.clone(),
    ));
    // Check for a newer release in the background at the [updates] interval
    // (Settings -> General: "Update Checks"), so /api/status - polled by the
    // dashboard every 10 s - can report availability off a warm cache
    // without ever waiting on GitHub. No-op on hosts that cannot
    // self-update, and skipped while checks are disabled.
    tokio::spawn(daygle_dns_api::refresh_release_forever(
        shared.config.clone(),
        shutdown.clone(),
    ));
    let app = router(app_state);
    let web = Arc::new(web::WebServer::new(
        app,
        catalog.clone(),
        config.api.listen.clone(),
        config.server.ipv6_only,
        config.api.port,
        shutdown.clone(),
    ));
    let _ = web_cell.set(Arc::downgrade(&web));
    let web_addrs = match web.apply(config.web.clone()).await {
        Ok(addrs) => addrs,
        // The saved web settings cannot start (a port taken, a certificate
        // gone): fall back to plain HTTP on the config file's port so the
        // console stays reachable to fix them.
        Err(e) if config.web != daygle_dns_core::config::WebSettings::default() => {
            warn!("web console settings cannot be applied ({e}); serving plain HTTP on api.port");
            logs.push(
                daygle_dns_core::LogLevel::Error,
                "api",
                format!("web console settings cannot be applied ({e}); serving plain HTTP on port {} instead", config.api.port),
            );
            let mut fallback = shared.config.load_full().as_ref().clone();
            fallback.web = daygle_dns_core::config::WebSettings::default();
            shared.config.store(Arc::new(fallback));
            web.apply(daygle_dns_core::config::WebSettings::default())
                .await
                .map_err(DaygleError::Config)?
        }
        Err(e) => return Err(DaygleError::Config(e)),
    };
    let api_addr = web_addrs
        .http
        .or(web_addrs.https)
        .ok_or_else(|| DaygleError::Config("the web console has no listener".into()))?;

    Ok(BoundServer {
        udp_addr: initial_addrs.udp,
        tcp_addr: initial_addrs.tcp,
        dot_addr: initial_addrs.dot,
        doh_addr: initial_addrs.doh,
        doq_addr: initial_addrs.doq,
        api_addr,
        metrics,
        logs,
        catalog,
        resolver,
        blocklist_sources,
        shared,
        addrs,
        shutdown,
        dns_task: Some(dns_task),
        web,
        reload_task,
        reload_tx,
        config_path,
    })
}

/// A single generation of bound DNS listeners.
struct ListenerGen {
    /// Cancels the serving tasks when this generation is stopped.
    token: CancellationToken,
    /// The serving task (`Server::block_until_done`).
    task: tokio::task::JoinHandle<std::result::Result<(), hickory_server::net::NetError>>,
    /// The DoT and DoQ serving task; `None` when both are disabled. It is
    /// separate because those listeners (see `dot` and `doq`) live outside
    /// Hickory's `Server`.
    native: Option<tokio::task::JoinHandle<()>>,
}

/// Spawn a listener generation and return its handle.
fn spawn_listeners(
    server: Server<DnsDispatcher>,
    native: Option<tokio::task::JoinHandle<()>>,
) -> ListenerGen {
    let token = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        let mut server = server;
        server.block_until_done().await
    });
    ListenerGen {
        token,
        task,
        native,
    }
}

/// Gracefully stop a listener generation, awaiting completion.
async fn stop_listeners(listeners: &mut Option<ListenerGen>) {
    let Some(gen) = listeners.take() else {
        return;
    };
    gen.token.cancel();
    if let Some(native) = gen.native {
        let _ = native.await;
    }
    match gen.task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("listener task ended with error: {e}"),
        Err(e) => warn!("listener task panicked: {e}"),
    }
}

/// Bind the listeners described by `shared`'s current config, publishing the
/// new addresses to `addrs`.
async fn start_listeners(
    shared: &Shared,
    addrs: &Arc<ArcSwap<ListenerAddrs>>,
) -> Result<ListenerGen> {
    let config = shared.config.load_full();
    start_listeners_with(shared, addrs, &config).await
}

/// Supervisor loop: keep the listeners running, rebinding them on command.
///
/// `last_good` remembers the last configuration that bound successfully so a
/// failing reload can restore the previous listeners.
async fn run_dns_supervisor(
    shared: Arc<Shared>,
    addrs: Arc<ArcSwap<ListenerAddrs>>,
    shutdown: CancellationToken,
    mut cmd_rx: mpsc::Receiver<ReloadCommand>,
    initial: Server<DnsDispatcher>,
    initial_native: Option<tokio::task::JoinHandle<()>>,
    initial_config: Arc<DaygleConfig>,
) -> Result<()> {
    let mut listeners = Some(spawn_listeners(initial, initial_native));
    let mut last_good = initial_config;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                stop_listeners(&mut listeners).await;
                return Ok(());
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ReloadCommand::Rebuild { ack }) => {
                        let requested = shared.config.load_full();
                        let encrypted = requested.dot.enabled
                            || requested.doh.enabled
                            || requested.doq.enabled;
                        stop_listeners(&mut listeners).await;

                        let outcome = match start_listeners(&shared, &addrs).await {
                            Ok(gen) => {
                                listeners = Some(gen);
                                last_good = requested;
                                info!("DNS listeners rebound");
                                // State change worth seeing in the console's
                                // Server Log, not just tracing: encrypted
                                // listeners now serve the new TLS material.
                                if encrypted {
                                    shared.logs.info(
                                        "tls",
                                        "TLS configuration reloaded (listeners rebound)",
                                    );
                                }
                                Ok(())
                            }
                            Err(e) => {
                                warn!("listener reload failed ({e}); restoring previous listeners");
                                // Self-heal: restore the last good listeners.
                                match start_listeners_with(&shared, &addrs, &last_good).await {
                                    Ok(gen) => {
                                        listeners = Some(gen);
                                        Err(DaygleError::Config(format!(
                                            "listener reload failed ({e}); previous listeners restored"
                                        )))
                                    }
                                    Err(restore) => Err(DaygleError::Config(format!(
                                        "listener reload failed ({e}) and restore failed ({restore})"
                                    ))),
                                }
                            }
                        };

                        if let Some(ack) = ack {
                            let _ = ack.send(outcome);
                        }
                    }
                    None => {
                        stop_listeners(&mut listeners).await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Build the request handler shared by every listener of one generation.
///
/// The NOTIFY hooks and TSIG keys built at startup are reused: rebuilding them
/// here (or worse, substituting defaults) would silently drop secondary
/// replication and transfer/update authentication after any live reload.
fn build_dispatcher(shared: &Shared, config: &DaygleConfig) -> DnsDispatcher {
    DnsDispatcher::with_stats(
        shared.catalog.clone(),
        shared.resolver.clone(),
        shared.policy.clone(),
        shared.rate_limiter.clone(),
        shared.metrics.clone(),
        shared.logs.clone(),
        shared.notify_hooks.clone(),
        shared.tsig_keys.clone(),
        shared.stats.clone(),
    )
    .with_client_timeout(Duration::from_millis(config.server.client_timeout_ms))
    .with_recursive_admission(shared.recursive_admission.clone())
    .with_cookies(config.server.dns_cookies)
    .with_config(shared.config.clone())
    .with_syslog(shared.syslog.clone())
    .with_advanced_blocking(shared.advanced_blocking.clone())
    .with_query_logger(shared.query_logger.clone())
    .with_query_db_logger(shared.query_db_logger.clone())
}

/// Bind listeners for a specific configuration snapshot (the current one, or
/// the last good one when restoring after a failed reload).
async fn start_listeners_with(
    shared: &Shared,
    addrs: &Arc<ArcSwap<ListenerAddrs>>,
    config: &DaygleConfig,
) -> Result<ListenerGen> {
    let dispatcher = build_dispatcher(shared, config);
    let mut server = Server::new(dispatcher.clone());
    let mut snapshot = ListenerAddrs::default();
    let native = bind_listeners(
        config,
        &shared.session,
        shared.catalog.store(),
        &dispatcher,
        &mut server,
        &mut snapshot,
    )
    .await?;
    addrs.store(Arc::new(snapshot));
    Ok(spawn_listeners(server, native))
}

/// Materialize the console-managed certificates (stored PEM in the database)
/// that the DoT/DoH/DoQ listeners reference by name. Each is written next to
/// the zone database under `<db-dir>/tls/<name>.crt|key`, and the listener's
/// `cert_path`/`key_path` are pointed at those files (self-signed generation
/// is disabled for such listeners). Idempotent: files are only rewritten when
/// their content changed.
fn materialize_stored_certs(
    config: &mut DaygleConfig,
    store: &daygle_dns_authoritative::ZoneStore,
) -> Result<()> {
    let db = std::path::Path::new(&config.authoritative.database);
    let dir = match db.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
    .join("tls");

    materialize_one(
        store,
        &dir,
        &config.dot.certificate,
        "DoT",
        &mut config.dot.cert_path,
        &mut config.dot.key_path,
        &mut config.dot.self_signed,
    )?;
    materialize_one(
        store,
        &dir,
        &config.doh.certificate,
        "DoH",
        &mut config.doh.cert_path,
        &mut config.doh.key_path,
        &mut config.doh.self_signed,
    )?;
    materialize_one(
        store,
        &dir,
        &config.doq.certificate,
        "DoQ",
        &mut config.doq.cert_path,
        &mut config.doq.key_path,
        &mut config.doq.self_signed,
    )?;
    Ok(())
}

/// Materialize a single listener's referenced certificate (no-op when
/// `certificate` is empty, i.e. the listener uses file paths or self-signed).
fn materialize_one(
    store: &daygle_dns_authoritative::ZoneStore,
    dir: &std::path::Path,
    certificate: &str,
    label: &str,
    cert_path: &mut String,
    key_path: &mut String,
    self_signed: &mut bool,
) -> Result<()> {
    if certificate.is_empty() {
        return Ok(());
    }
    let cert = store.get_tls_certificate(certificate)?.ok_or_else(|| {
        DaygleError::Config(format!(
            "{label} references an unknown managed certificate '{certificate}'"
        ))
    })?;
    let crt = dir.join(format!("{certificate}.crt"));
    let key = dir.join(format!("{certificate}.key"));
    write_if_changed(&crt, cert.cert_pem.as_bytes())?;
    write_if_changed(&key, cert.key_pem.as_bytes())?;
    *cert_path = crt.to_string_lossy().into_owned();
    *key_path = key.to_string_lossy().into_owned();
    *self_signed = false;
    Ok(())
}

/// Write `bytes` to `path` unless the file already holds the same content.
///
/// On Unix the file is created with mode `0600` so a managed private key is
/// never world-readable. Writes go through a sibling `.tmp` file and are
/// atomically renamed into place so a crash between cert and key writes
/// cannot leave the listener with a mismatched pair.
fn write_if_changed(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(path).map(|b| b == bytes).unwrap_or(false) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(DaygleError::Io)?;
        // Refuse to follow a symlinked directory for TLS material - an
        // attacker who controls a symlink there could redirect our write.
        let meta = std::fs::symlink_metadata(parent).map_err(DaygleError::Io)?;
        if meta.file_type().is_symlink() {
            return Err(DaygleError::Config(format!(
                "refusing to write TLS material under symlinked {}",
                parent.display()
            )));
        }
    }
    let tmp = path.with_extension("tmp");
    // A leftover temp file (e.g. from a crash) may carry looser permissions
    // or be a planted symlink; `mode` only applies on creation, so remove it
    // and create a fresh file exclusively.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(DaygleError::Io(e)),
    }
    {
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(DaygleError::Io)?;
        file.write_all(bytes).map_err(DaygleError::Io)?;
        file.sync_all().map_err(DaygleError::Io)?;
    }
    // `rename` is atomic on POSIX for files on the same filesystem and best-
    // effort on Windows (replaces if the destination exists).
    std::fs::rename(&tmp, path).map_err(DaygleError::Io)
}

/// The certificate's display name in diagnostics: the console-managed name
/// when set, otherwise the file path.
fn cert_name<'a>(certificate: &'a str, cert_path: &'a str) -> &'a str {
    if certificate.is_empty() {
        cert_path
    } else {
        certificate
    }
}

/// `[section].listen` and a port as socket addresses (one or several, IPv4
/// or IPv6), each with whether it is bound IPv6-only (see
/// [`net::v6_only`]).
fn listen_addrs(
    section: &str,
    listen: &str,
    port: u16,
    ipv6_only: bool,
) -> Result<Vec<(std::net::SocketAddr, bool)>> {
    let addrs = daygle_dns_core::config::listen_socket_addrs(listen, port)
        .map_err(|e| DaygleError::Config(format!("{section}.listen: {e}")))?;
    let v6_only = net::v6_only(&addrs, ipv6_only);
    Ok(addrs.into_iter().map(|a| (a, v6_only)).collect())
}

/// Bind every listener `config` enables onto `server`, plus the DoT/DoQ
/// listeners that run beside it (their task is returned). On error nothing
/// keeps running: the native listeners already started are stopped through
/// the generation's token, so they free their ports for the restore that
/// follows a failed reload.
async fn bind_listeners(
    config: &DaygleConfig,
    session: &Arc<tls_diag::SessionLog>,
    store: &daygle_dns_authoritative::ZoneStore,
    dispatcher: &DnsDispatcher,
    server: &mut Server<DnsDispatcher>,
    addrs: &mut ListenerAddrs,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    let token = server.shutdown_token().clone();
    let mut native_tasks = Vec::new();
    let bound = bind_listeners_inner(
        config,
        session,
        store,
        dispatcher,
        server,
        addrs,
        &mut native_tasks,
    )
    .await;
    if let Err(e) = bound {
        token.cancel();
        // Wait for them to close their sockets before anything rebinds.
        for task in native_tasks {
            let _ = task.await;
        }
        return Err(e);
    }
    Ok((!native_tasks.is_empty()).then(|| {
        tokio::spawn(async move {
            for task in native_tasks {
                let _ = task.await;
            }
        })
    }))
}

async fn bind_listeners_inner(
    config: &DaygleConfig,
    session: &Arc<tls_diag::SessionLog>,
    store: &daygle_dns_authoritative::ZoneStore,
    dispatcher: &DnsDispatcher,
    server: &mut Server<DnsDispatcher>,
    addrs: &mut ListenerAddrs,
    native_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    // Console-managed certificates referenced by name are materialized next
    // to the zone database so the file-based TLS loaders can read them.
    let mut config = config.clone();
    materialize_stored_certs(&mut config, store)?;
    // The renewal window in force (ACME settings; 30 days by default), for
    // the certificate lifecycle reports on each encrypted listener below.
    let renew_days = daygle_dns_api::acme::renewal_window_days(store);
    let ipv6_only = config.server.ipv6_only;
    let listen = listen_addrs(
        "server",
        &config.server.listen,
        config.server.port,
        ipv6_only,
    )?;

    // PROXY protocol: TCP-based listeners are fronted (see
    // `proxy_protocol`), and Hickory serves a hidden loopback listener.
    let proxy_protocol = config.with_networks_resolved().server.proxy_protocol;
    let proxy_trusted: Option<Arc<Vec<ipnet::IpNet>>> = (!proxy_protocol.is_empty()).then(|| {
        Arc::new(
            proxy_protocol
                .iter()
                .filter_map(|n| daygle_dns_core::config::parse_network(n))
                .collect(),
        )
    });
    let token = server.shutdown_token().clone();
    let serve = |public: tokio::net::TcpListener,
                 connection_limit: Option<usize>|
     -> Result<tokio::net::TcpListener> {
        let Some(trusted) = &proxy_trusted else {
            return Ok(public);
        };
        let hidden = net::bind_tcp(([127, 0, 0, 1], 0).into(), false)?;
        let max_connections =
            connection_limit.unwrap_or(config.server.proxy_protocol_max_connections);
        let _front = proxy_protocol::spawn_front(
            public,
            hidden.local_addr()?,
            trusted.clone(),
            max_connections,
            token.clone(),
        );
        Ok(hidden)
    };

    // `addrs` records the first address of each listener.
    if config.server.udp_enabled {
        let buffer_bytes = |kb: u32| {
            (kb as usize)
                .checked_mul(1024)
                .ok_or_else(|| DaygleError::Config("udp buffer size is too large".to_string()))
        };
        for &(addr, v6_only) in &listen {
            // Bind through a std socket so the kernel send/receive buffers
            // can be sized before the socket is wrapped for Tokio (the
            // buffer sizes must be set before Windows picks them up on the
            // first connect). These knobs use `socket2` because
            // std::net::UdpSocket no longer exposes SO_SNDBUF/SO_RCVBUF
            // setters.
            let std_socket = net::bind_udp_std(addr, v6_only)?;
            socket2::SockRef::from(&std_socket)
                .set_send_buffer_size(buffer_bytes(config.server.udp_send_buffer_kb)?)?;
            socket2::SockRef::from(&std_socket)
                .set_recv_buffer_size(buffer_bytes(config.server.udp_recv_buffer_kb)?)?;
            std_socket.set_nonblocking(true)?;
            let socket = tokio::net::UdpSocket::from_std(std_socket)?;
            let bound = socket.local_addr()?;
            addrs.udp.get_or_insert(bound);
            server.register_socket(socket);
            info!(
                addr = %bound,
                send_buffer_kb = config.server.udp_send_buffer_kb,
                recv_buffer_kb = config.server.udp_recv_buffer_kb,
                "plaintext UDP DNS listening"
            );
        }
    }
    if config.server.tcp_enabled {
        for &(addr, v6_only) in &listen {
            let listener = net::bind_tcp(addr, v6_only)?;
            let bound = listener.local_addr()?;
            addrs.tcp.get_or_insert(bound);
            server.register_listener(
                serve(listener, None)?,
                Duration::from_millis(config.server.tcp_timeout_ms),
                config.server.response_buffer_size,
            );
            info!(addr = %bound, "plaintext TCP DNS listening");
        }
    }

    if config.dot.enabled {
        let tls_config = daygle_dns_dot::build_tls_config(&config.dot)?;
        tls_diag::report_certificate(
            tls_diag::TLS,
            "DoT",
            cert_name(&config.dot.certificate, &config.dot.cert_path),
            &config.dot.cert_path,
            renew_days,
            session,
        );
        let options = crate::dot::DotOptions {
            max_connections: config.dot.max_connections,
            timeout: Duration::from_secs(config.dot.handshake_timeout_secs),
            proxy_trusted: proxy_trusted.clone(),
        };
        for (addr, v6_only) in listen_addrs("dot", &config.dot.listen, config.dot.port, ipv6_only)?
        {
            let listener = net::bind_tcp(addr, v6_only)?;
            let bound = listener.local_addr()?;
            addrs.dot.get_or_insert(bound);
            native_tasks.push(tokio::spawn(crate::dot::serve_dot(
                listener,
                tls_config.clone(),
                dispatcher.clone(),
                session.clone(),
                server.shutdown_token().clone(),
                options.clone(),
            )));
            info!(addr = %bound, max_connections = config.dot.max_connections, "DNS over TLS listening");
        }
        tls_diag::report_dot_readiness(&config, session);
    }

    if config.doh.enabled {
        let tls_config = daygle_dns_dot::build_doh_tls_config(&config.doh)?;
        tls_diag::report_certificate(
            tls_diag::HTTPS,
            "DoH",
            cert_name(&config.doh.certificate, &config.doh.cert_path),
            &config.doh.cert_path,
            renew_days,
            session,
        );
        for (addr, v6_only) in listen_addrs("doh", &config.doh.listen, config.doh.port, ipv6_only)?
        {
            let public = net::bind_tcp(addr, v6_only)?;
            let admission = crate::connection_admission::ConnectionAdmission::new(
                public,
                config.doh.max_connections,
                server.shutdown_token().clone(),
                proxy_trusted.clone(),
            )?;
            let bound = admission.public_addr;
            let _admission_task = admission.task;
            addrs.doh.get_or_insert(bound);
            daygle_dns_dot::register_doh(
                server,
                admission.backend,
                tls_config.clone(),
                Duration::from_secs(config.doh.handshake_timeout_secs),
                None,
                &config.doh.endpoint,
            )?;
            info!(addr = %bound, endpoint = %config.doh.endpoint, "DNS over HTTPS listening");
        }
    }

    if config.doq.enabled {
        let tls_config = daygle_dns_dot::build_doq_tls_config(&config.doq)?;
        tls_diag::report_certificate(
            tls_diag::QUIC,
            "DoQ",
            cert_name(&config.doq.certificate, &config.doq.cert_path),
            &config.doq.cert_path,
            renew_days,
            session,
        );
        for (addr, v6_only) in listen_addrs("doq", &config.doq.listen, config.doq.port, ipv6_only)?
        {
            let socket = net::bind_udp(addr, v6_only)?;
            let endpoint = crate::doq::build_doq_endpoint(
                socket,
                tls_config.clone(),
                Duration::from_secs(config.doq.idle_timeout_secs),
                config.doq.max_concurrent_streams,
                config.doq.max_connections,
            )
            .map_err(|e| DaygleError::Config(format!("cannot build DoQ listener: {e}")))?;
            let bound = endpoint.local_addr().map_err(DaygleError::Io)?;
            addrs.doq.get_or_insert(bound);
            let token = server.shutdown_token().clone();
            native_tasks.push(tokio::spawn(crate::doq::serve_doq(
                endpoint,
                dispatcher.clone(),
                session.clone(),
                token,
                config.doq.max_connections,
                config.doq.max_concurrent_streams,
            )));
            info!(
                addr = %bound,
                idle_timeout_s = config.doq.idle_timeout_secs,
                "DNS over QUIC (RFC 9250) listening"
            );
        }
    }

    Ok(())
}

/// Import BIND zone files from `authoritative.zones_dir` (if configured).
/// Split horizon kept its own named networks before networks were shared
/// (Settings -> Networks): adopt them as the server's networks, once. A name
/// taken by a built-in network is renamed, along with what refers to it.
fn adopt_legacy_networks(
    store: &daygle_dns_authoritative::ZoneStore,
    config: &mut DaygleConfig,
    logs: &LogStore,
) -> Result<()> {
    let legacy = store.list_split_horizon_networks()?;
    if legacy.is_empty() {
        return Ok(());
    }
    for network in legacy {
        let mut name = network.name.trim().to_string();
        if daygle_dns_core::config::builtin_networks()
            .iter()
            .any(|b| b.name.eq_ignore_ascii_case(&name))
        {
            let renamed = format!("{name} (Split Horizon)");
            store.rename_network_refs(&name, &renamed)?;
            name = renamed;
        }
        config.networks.push(daygle_dns_core::config::NamedNetwork {
            name,
            cidrs: network.cidrs,
            description: String::new(),
        });
    }
    store.put_runtime_settings(&daygle_dns_core::config::RuntimeSettings::capture(config))?;
    logs.push(
        daygle_dns_core::LogLevel::Info,
        "api",
        format!(
            "split horizon networks are now shared networks (Settings -> Networks): {}",
            config
                .networks
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    Ok(())
}

fn import_zone_files(
    catalog: &AuthorityCatalog,
    config: &DaygleConfig,
    logs: &LogStore,
) -> Result<()> {
    let Some(dir) = &config.authoritative.zones_dir else {
        return Ok(());
    };
    let entries = std::fs::read_dir(dir)
        .map_err(|e| DaygleError::Config(format!("cannot read zones_dir '{dir}': {e}")))?;

    for entry in entries.flatten() {
        let path = entry.path();
        let is_zone = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "zone" | "db" | "txt"));
        if !is_zone {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("imported");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| DaygleError::Config(format!("cannot read zone file: {e}")))?;
        let records = daygle_dns_authoritative::parse::parse_zone_file(&text)?;

        let zone = match catalog.store().find_zone_by_name(name) {
            Ok(Some(z)) => z,
            Ok(None) => {
                catalog
                    .store()
                    .create_zone(&daygle_dns_authoritative::model::ZoneInput {
                        name: name.to_string(),
                        ..Default::default()
                    })?
            }
            Err(e) => return Err(e),
        };
        catalog.store().replace_records(&zone.id, &records)?;
        logs.push(
            LogLevel::Info,
            "authoritative",
            format!("imported zone '{}' ({} records)", zone.name, records.len()),
        );
    }
    catalog.reload()
}

/// Where the verified local root zone is cached: next to the database (none
/// for an in-memory database).
fn local_root_cache_path(database: &str) -> Option<std::path::PathBuf> {
    if database.is_empty() || database == ":memory:" {
        return None;
    }
    Some(std::path::Path::new(database).with_file_name("local-root.zone"))
}
