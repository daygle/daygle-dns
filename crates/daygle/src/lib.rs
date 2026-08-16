//! # daygle
//!
//! Library surface of the Daygle DNS server binary: the combined
//! [`DnsDispatcher`] and a [`bind`] helper that wires every subsystem into a
//! runnable server. The `daygle` binary is a thin CLI wrapper around this.

pub mod dispatcher;
pub mod reload;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use daygle_api::{router, AppState};
use daygle_authoritative::AuthorityCatalog;
use daygle_core::config::DaygleConfig;
use daygle_core::error::{DaygleError, Result};
use daygle_core::{LogLevel, LogStore, Metrics, RateLimiter};
use daygle_policy::BlocklistSourceManager;
use daygle_recursive::RecursiveResolver;
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
    /// The REST API + GUI address.
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
    api_task: Option<tokio::task::JoinHandle<()>>,
    reload_task: Option<tokio::task::JoinHandle<()>>,
    reload_tx: mpsc::Sender<ReloadCommand>,
    config_path: Option<PathBuf>,
}

impl BoundServer {
    /// Clone the cancellation token used to shut every subsystem down.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
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
        let new = DaygleConfig::load(&path)?;
        let changed = apply_config(&self.shared, Arc::new(new));

        if changed {
            let (ack_tx, ack_rx) = oneshot::channel();
            self.reload_tx
                .send(ReloadCommand::Rebuild { ack: Some(ack_tx) })
                .await
                .map_err(|_| DaygleError::Internal("DNS supervisor is gone".to_string()))?;
            ack_rx
                .await
                .map_err(|_| DaygleError::Internal("DNS supervisor did not ack reload".to_string()))??;
        }
        Ok(())
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
        if let Some(task) = self.api_task.take() {
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
    let started_at = std::time::Instant::now();

    // Authoritative.
    let store = daygle_authoritative::ZoneStore::open(&config.authoritative.database)?;
    let catalog = Arc::new(AuthorityCatalog::new(
        store.clone(),
        config.authoritative.clone(),
    )?);
    catalog.reload()?;
    import_zone_files(&catalog, &config, &logs)?;

    // Secondary zone refreshers (AXFR/IXFR from configured masters).
    let shutdown = CancellationToken::new();
    if !config.authoritative.secondary_zones.is_empty() {
        let refresher = daygle_authoritative::SecondaryRefresher::new(
            store,
            catalog.clone(),
            config.authoritative.secondary_zones.clone(),
            daygle_authoritative::XfrClient::default(),
        );
        tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                refresher.run_forever(shutdown).await;
            }
        });
    }

    // Recursive.
    let resolver = if config.recursive.enabled {
        Some(Arc::new(RecursiveResolver::build(
            &config.recursive,
            metrics.clone(),
        )?))
    } else {
        warn!("recursion is disabled");
        None
    };

    // Policy.
    let policy = daygle_policy::build_engine(&config.policy)?;

    // Rate limiting (per client + per domain).
    let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limit));

    // Shared, atomically-swappable runtime state.
    let shared = Arc::new(Shared {
        catalog: catalog.clone(),
        policy: Arc::new(ArcSwap::from_pointee(policy)),
        resolver: Arc::new(arc_swap::ArcSwapOption::from(resolver.clone())),
        config: Arc::new(ArcSwap::from(config.clone())),
        rate_limiter: rate_limiter.clone(),
        metrics: metrics.clone(),
        logs: logs.clone(),
    });

    // DNS listeners (bound immediately so the server serves right away).
    let dispatcher = DnsDispatcher::new(
        catalog.clone(),
        shared.resolver.clone(),
        shared.policy.clone(),
        rate_limiter.clone(),
        metrics.clone(),
        logs.clone(),
    );
    let mut server = Server::new(dispatcher);
    let mut initial_addrs = ListenerAddrs::default();
    bind_listeners(&config, &mut server, &mut initial_addrs).await?;
    let addrs = Arc::new(ArcSwap::from_pointee(initial_addrs));

    // DNS supervisor: owns the listeners and rebinds them on command.
    let (reload_tx, reload_rx) = mpsc::channel(16);
    let dns_task = tokio::spawn(run_dns_supervisor(
        shared.clone(),
        addrs.clone(),
        shutdown.clone(),
        reload_rx,
        server,
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
        shutdown.clone(),
    );

    // REST API.
    let api_addr: std::net::SocketAddr = format!("{}:{}", config.api.listen, config.api.port)
        .parse()
        .map_err(|e| DaygleError::Config(format!("bad API listen address: {e}")))?;
    let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
    let api_addr = api_listener.local_addr()?;
    let app = router(AppState {
        catalog: catalog.clone(),
        resolver: shared.resolver.clone(),
        metrics: metrics.clone(),
        logs: logs.clone(),
        config: shared.config.clone(),
        policy: shared.policy.clone(),
        blocklist_sources: blocklist_sources.clone(),
        started_at,
        config_path: config_path.clone().map(Arc::new),
        reload_notify,
    });
    info!(addr = %api_addr, "REST API and GUI listening");
    let api_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, app).await {
            warn!("api server error: {e}");
        }
    });

    Ok(BoundServer {
        udp_addr: initial_addrs.udp,
        tcp_addr: initial_addrs.tcp,
        dot_addr: initial_addrs.dot,
        doh_addr: initial_addrs.doh,
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
        api_task: Some(api_task),
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
}

/// Spawn a listener generation and return its handle.
fn spawn_listeners(server: Server<DnsDispatcher>) -> ListenerGen {
    let token = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        let mut server = server;
        server.block_until_done().await
    });
    ListenerGen { token, task }
}

/// Gracefully stop a listener generation, awaiting completion.
async fn stop_listeners(listeners: &mut Option<ListenerGen>) {
    let Some(gen) = listeners.take() else {
        return;
    };
    gen.token.cancel();
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
    let dispatcher = DnsDispatcher::new(
        shared.catalog.clone(),
        shared.resolver.clone(),
        shared.policy.clone(),
        shared.rate_limiter.clone(),
        shared.metrics.clone(),
        shared.logs.clone(),
    );
    let mut server = Server::new(dispatcher);
    let mut snapshot = ListenerAddrs::default();
    bind_listeners(&config, &mut server, &mut snapshot).await?;
    addrs.store(Arc::new(snapshot));
    Ok(spawn_listeners(server))
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
    initial_config: Arc<DaygleConfig>,
) -> Result<()> {
    let mut listeners = Some(spawn_listeners(initial));
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
                        stop_listeners(&mut listeners).await;

                        let outcome = match start_listeners(&shared, &addrs).await {
                            Ok(gen) => {
                                listeners = Some(gen);
                                last_good = requested;
                                info!("DNS listeners rebound");
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

/// Bind listeners for a specific configuration snapshot (used to restore the
/// previous configuration after a failed reload).
async fn start_listeners_with(
    shared: &Shared,
    addrs: &Arc<ArcSwap<ListenerAddrs>>,
    config: &DaygleConfig,
) -> Result<ListenerGen> {
    let dispatcher = DnsDispatcher::new(
        shared.catalog.clone(),
        shared.resolver.clone(),
        shared.policy.clone(),
        shared.rate_limiter.clone(),
        shared.metrics.clone(),
        shared.logs.clone(),
    );
    let mut server = Server::new(dispatcher);
    let mut snapshot = ListenerAddrs::default();
    bind_listeners(config, &mut server, &mut snapshot).await?;
    addrs.store(Arc::new(snapshot));
    Ok(spawn_listeners(server))
}

/// Bind every enabled listener from `config` into `server`, recording the
/// bound addresses in `addrs`.
async fn bind_listeners(
    config: &DaygleConfig,
    server: &mut Server<DnsDispatcher>,
    addrs: &mut ListenerAddrs,
) -> Result<()> {
    let listen: std::net::SocketAddr = format!("{}:{}", config.server.listen, config.server.port)
        .parse()
        .map_err(|e| DaygleError::Config(format!("bad server listen address: {e}")))?;

    if config.server.udp_enabled {
        let socket = tokio::net::UdpSocket::bind(listen).await?;
        addrs.udp = Some(socket.local_addr()?);
        server.register_socket(socket);
        info!(addr = %addrs.udp.unwrap(), "plaintext UDP DNS listening");
    }
    if config.server.tcp_enabled {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        addrs.tcp = Some(listener.local_addr()?);
        server.register_listener(
            listener,
            Duration::from_millis(config.server.tcp_timeout_ms),
            config.server.response_buffer_size,
        );
        info!(addr = %addrs.tcp.unwrap(), "plaintext TCP DNS listening");
    }

    if config.dot.enabled {
        let addr: std::net::SocketAddr = format!("{}:{}", config.dot.listen, config.dot.port)
            .parse()
            .map_err(|e| DaygleError::Config(format!("bad DoT listen address: {e}")))?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        addrs.dot = Some(listener.local_addr()?);
        let tls_config = daygle_dot::build_tls_config(&config.dot)?;
        daygle_dot::register_dot(
            server,
            listener,
            tls_config,
            Duration::from_secs(10),
        )?;
        info!(addr = %addrs.dot.unwrap(), "DNS over TLS listening");
    }

    if config.doh.enabled {
        let addr: std::net::SocketAddr = format!("{}:{}", config.doh.listen, config.doh.port)
            .parse()
            .map_err(|e| DaygleError::Config(format!("bad DoH listen address: {e}")))?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        addrs.doh = Some(listener.local_addr()?);
        let tls_config = daygle_dot::build_doh_tls_config(&config.doh)?;
        daygle_dot::register_doh(
            server,
            listener,
            tls_config,
            Duration::from_secs(10),
            None,
            &config.doh.endpoint,
        )?;
        info!(addr = %addrs.doh.unwrap(), endpoint = %config.doh.endpoint, "DNS over HTTPS listening");
    }

    Ok(())
}

/// Import BIND zone files from `authoritative.zones_dir` (if configured).
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
        let records = daygle_authoritative::parse::parse_zone_file(&text)?;

        let zone = match catalog.store().find_zone_by_name(name) {
            Ok(Some(z)) => z,
            Ok(None) => catalog
                .store()
                .create_zone(&daygle_authoritative::model::ZoneInput {
                    name: name.to_string(),
                    ..Default::default()
                })?,
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
