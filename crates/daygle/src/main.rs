//! Daygle DNS — the server binary.
//!
//! Wires together the authoritative catalog, recursive resolver, policy
//! engine, DoT listener and REST API into a single process.

mod dispatcher;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use daygle_api::{router, AppState};
use daygle_authoritative::{AuthorityCatalog, ZoneStore};
use daygle_core::config::DaygleConfig;
use daygle_core::error::{DaygleError, Result};
use daygle_core::{LogLevel, LogStore, Metrics, DEFAULT_CONFIG_PATH};
use daygle_dot::build_tls_config;
use daygle_recursive::RecursiveResolver;
use dispatcher::DnsDispatcher;
use hickory_server::server::Server;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Daygle DNS — a modern, combined DNS server.
#[derive(Parser, Debug)]
#[command(name = "daygle", version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: String,

    /// Log filter, overriding the configuration file.
    #[arg(long)]
    log_level: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Load configuration before logging so we know the requested level.
    let config = match DaygleConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("daygle: failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let filter = args
        .log_level
        .clone()
        .unwrap_or_else(|| config.logging.level.clone());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter)),
        )
        .init();

    if let Err(e) = run(config) {
        eprintln!("daygle: fatal error: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run(config: DaygleConfig) -> Result<()> {
    let metrics = Arc::new(Metrics::default());
    let logs = Arc::new(LogStore::new(config.logging.ring_buffer));
    let config = Arc::new(config);
    let started_at = std::time::Instant::now();

    // ---- Authoritative ---------------------------------------------------
    let store = ZoneStore::open(&config.authoritative.database)?;
    let catalog = Arc::new(AuthorityCatalog::new(
        store,
        config.authoritative.clone(),
    )?);
    catalog.reload()?;
    logs.info("authoritative", format!("loaded catalog from database"));
    import_zone_files(&catalog, &config, &logs)?;

    // ---- Recursive -------------------------------------------------------
    let resolver = if config.recursive.enabled {
        Some(Arc::new(RecursiveResolver::build(
            &config.recursive,
            metrics.clone(),
        )?))
    } else {
        warn!("recursion is disabled");
        None
    };

    // ---- Policy ----------------------------------------------------------
    let policy = Arc::new(daygle_policy::build_engine(&config.policy)?);

    // ---- DNS listeners ---------------------------------------------------
    let dispatcher = DnsDispatcher::new(
        catalog.clone(),
        resolver.clone(),
        policy,
        metrics.clone(),
        logs.clone(),
    );
    let mut server = Server::new(dispatcher);

    let listen: std::net::SocketAddr = format!("{}:{}", config.server.listen, config.server.port)
        .parse()
        .map_err(|e| DaygleError::Config(format!("bad server listen address: {e}")))?;

    if config.server.udp_enabled {
        let socket = tokio::net::UdpSocket::bind(listen).await?;
        server.register_socket(socket);
        info!(%listen, "plaintext UDP DNS listening");
    }
    if config.server.tcp_enabled {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        server.register_listener(
            listener,
            Duration::from_millis(config.server.tcp_timeout_ms),
            config.server.response_buffer_size,
        );
        info!(%listen, "plaintext TCP DNS listening");
    }

    if config.dot.enabled {
        let dot_addr: std::net::SocketAddr =
            format!("{}:{}", config.dot.listen, config.dot.port)
                .parse()
                .map_err(|e| DaygleError::Config(format!("bad DoT listen address: {e}")))?;
        let listener = tokio::net::TcpListener::bind(dot_addr).await?;
        let tls_config = build_tls_config(&config.dot)?;
        daygle_dot::register_dot(
            &mut server,
            listener,
            tls_config,
            Duration::from_secs(10),
        )?;
        info!(%dot_addr, "DNS over TLS listening");
    }

    // ---- REST API --------------------------------------------------------
    let api_state = AppState {
        catalog: catalog.clone(),
        resolver: resolver.clone(),
        metrics: metrics.clone(),
        logs: logs.clone(),
        config: config.clone(),
        started_at,
    };
    let app = router(api_state);
    let api_addr: std::net::SocketAddr =
        format!("{}:{}", config.api.listen, config.api.port)
            .parse()
            .map_err(|e| DaygleError::Config(format!("bad API listen address: {e}")))?;
    let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
    info!(%api_addr, "REST API and GUI listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, app).await {
            warn!("api server error: {e}");
        }
    });

    // ---- Signal handling -------------------------------------------------
    let shutdown_token = server.shutdown_token().clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
            shutdown_token.cancel();
        }
    });

    // Block until all DNS listener tasks finish.
    server.block_until_done().await.map_err(|e| {
        DaygleError::Internal(format!("DNS server stopped unexpectedly: {e}"))
    })?;
    info!("daygle shut down cleanly");
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
        let is_zone = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
            matches!(e.to_ascii_lowercase().as_str(), "zone" | "db" | "txt")
        });
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
