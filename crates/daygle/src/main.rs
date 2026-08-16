//! Daygle DNS - the server binary.
//!
//! A thin CLI wrapper around [`daygle::bind`] / [`daygle::BoundServer`].

use std::sync::Arc;

use clap::Parser;
use daygle::bind_with;
use daygle_core::config::DaygleConfig;
use daygle_core::DEFAULT_CONFIG_PATH;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Daygle DNS - a modern, combined DNS server.
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

    let config_path = args.config.clone();
    if let Err(e) = run(config, config_path) {
        eprintln!("daygle: fatal error: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run(config: DaygleConfig, config_path: String) -> daygle_core::error::Result<()> {
    let config = Arc::new(config);
    let bound = bind_with(config, Some(config_path.into())).await?;

    let shutdown = bound.shutdown_token();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    bound.run().await
}
