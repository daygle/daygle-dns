//! Daygle DNS - the server binary.
//!
//! A thin CLI wrapper around [`daygle_dns::bind`] / [`daygle_dns::BoundServer`].
//!
//! Subcommands:
//!
//! - *(default)* run the server with the given config file
//! - `hash-password` - print a PBKDF2 hash for `[[api.users]]` entries
//! - `seed-ai-settings` - copy the config file's `[ai]` into the database
//! - `reset-web-access` - put the web console back to plain HTTP on `api.port`
//! - `backup` - write a backup of the database to a file
//! - `restore` - stage a backup to replace the database on the next start

use std::io::Write as _;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use daygle_dns::bind_with;
use daygle_dns_authoritative::ZoneStore;
use daygle_dns_core::config::{AiSettings, AiUpdate, DaygleConfig, RuntimeSettings};
use daygle_dns_core::DEFAULT_CONFIG_PATH;
use tracing::{info, Level};
use tracing_subscriber::layer::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{filter::Targets, EnvFilter};

/// Daygle DNS - a modern, combined DNS server.
#[derive(Parser, Debug)]
#[command(name = "daygle-dns", version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: String,

    /// Log filter, overriding the configuration file.
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print a PBKDF2-HMAC-SHA256 hash for an `[[api.users]]` entry.
    ///
    /// The hash goes into `password_hash` in the config file; the plaintext
    /// password is never stored anywhere.
    HashPassword {
        /// The password to hash. Omitted to read it from stdin (e.g. a pipe).
        password: Option<String>,
    },
    /// Copy the config file's `[ai]` settings into the database overlay.
    ///
    /// Runtime settings live in the database and win over the config file on
    /// every boot, so `install.sh` runs this on upgrades: the appended
    /// `[ai]` section (bundled starter model, train mode) would otherwise be
    /// ignored because an older boot already stored an overlay. The stored
    /// AI settings are only replaced when they are still exactly the
    /// defaults - anything the console actively edited is left alone.
    SeedAiSettings,
    /// Put web console access back to plain HTTP on `api.port`.
    ///
    /// For when a Settings change (HTTPS only, a port, a certificate) left
    /// the console unreachable: clears the web settings stored in the
    /// database so the config file's `[api]` applies again. Restart the
    /// service afterwards.
    ResetWebAccess,
    /// Write a backup of the database (zones, settings, users,
    /// certificates, AI overrides) to a file. Safe while the server runs.
    ///
    /// The file holds private keys and password hashes: keep it safe.
    Backup {
        /// Where to write the backup (must not exist).
        file: std::path::PathBuf,
        /// Include the query logs (left out by default: they can be large).
        #[arg(long)]
        query_logs: bool,
    },
    /// Check a backup and stage it to replace the database on the next
    /// start. The current database is kept as
    /// `<database>.before-restore-<time>`. Restart the service afterwards.
    Restore {
        /// The backup file.
        file: std::path::PathBuf,
    },
}

/// Load the config file, or exit with the reason.
fn load_config_or_exit(path: &str) -> DaygleConfig {
    match DaygleConfig::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("daygle-dns: failed to load configuration: {e}");
            std::process::exit(1);
        }
    }
}

/// A one-line summary of a backup (counts only; the console shows the
/// rest).
fn print_backup_info(info: &daygle_dns_authoritative::backup::BackupInfo) {
    println!(
        "  {} zones, {} records, {} users, {} AI overrides, {} query log entries",
        info.zones, info.records, info.users, info.ai_overrides, info.query_logs
    );
}

fn main() {
    let args = Args::parse();

    if let Some(Command::HashPassword { password }) = &args.command {
        let password = match password {
            Some(p) => p.clone(),
            None => {
                eprint!("password (input is echoed): ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_err() {
                    eprintln!("daygle-dns: failed to read password from stdin");
                    std::process::exit(1);
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    eprintln!("daygle-dns: empty password");
                    std::process::exit(1);
                }
                trimmed.to_string()
            }
        };
        println!("{}", daygle_dns_core::hash_password(&password));
        return;
    }

    if let Some(Command::SeedAiSettings) = &args.command {
        let config = match DaygleConfig::load(&args.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("daygle-dns: failed to load configuration: {e}");
                std::process::exit(1);
            }
        };
        let untouched = AiUpdate::capture_ai(&AiSettings::default());
        let store = match ZoneStore::open(&config.authoritative.database) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "daygle-dns: cannot open zone database '{}': {e}",
                    config.authoritative.database
                );
                std::process::exit(1);
            }
        };
        match store.get_runtime_settings::<RuntimeSettings>() {
            Ok(None) => {
                // Nothing stored: the next server boot seeds from the file.
                let _ = store.put_runtime_settings(&RuntimeSettings::capture(&config));
                println!("ai settings seeded from {} (first boot)", args.config);
            }
            Ok(Some(mut overlay)) => {
                if overlay.ai.as_ref() == Some(&untouched) {
                    overlay.ai = Some(AiUpdate::capture_ai(&config.ai));
                    match store.put_runtime_settings(&overlay) {
                        Ok(()) => println!("ai settings synchronized from {}", args.config),
                        Err(e) => {
                            eprintln!("daygle-dns: cannot write runtime settings: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!("stored ai settings were edited by the console - left untouched");
                }
            }
            Err(e) => {
                eprintln!("daygle-dns: cannot read runtime settings: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(Command::Backup { file, query_logs }) = &args.command {
        let mut config = load_config_or_exit(&args.config);
        let store = match ZoneStore::open(&config.authoritative.database) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "daygle-dns: cannot open zone database '{}': {e}",
                    config.authoritative.database
                );
                std::process::exit(1);
            }
        };
        // The AI database path may be a console setting.
        if let Ok(Some(overlay)) = store.get_runtime_settings::<RuntimeSettings>() {
            overlay.apply_to(&mut config);
        }
        if file.exists() {
            eprintln!("daygle-dns: {} already exists", file.display());
            std::process::exit(1);
        }
        let ai_database = daygle_dns_ml::database_path(&config.ai, &config.authoritative.database);
        match store.backup_to(file, *query_logs, Some(&ai_database)) {
            Ok(info) => {
                println!("backup written to {}", file.display());
                print_backup_info(&info);
            }
            Err(e) => {
                eprintln!("daygle-dns: backup failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(Command::Restore { file }) = &args.command {
        let config = load_config_or_exit(&args.config);
        match daygle_dns_authoritative::backup::stage_restore(&config.authoritative.database, file)
        {
            Ok(info) => {
                println!(
                    "restore staged: restart the service to replace the database with {}",
                    file.display()
                );
                print_backup_info(&info);
            }
            Err(e) => {
                eprintln!("daygle-dns: cannot restore {}: {e}", file.display());
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(Command::ResetWebAccess) = &args.command {
        let config = match DaygleConfig::load(&args.config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("daygle-dns: failed to load configuration: {e}");
                std::process::exit(1);
            }
        };
        let store = match ZoneStore::open(&config.authoritative.database) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "daygle-dns: cannot open zone database '{}': {e}",
                    config.authoritative.database
                );
                std::process::exit(1);
            }
        };
        match store.get_runtime_settings::<RuntimeSettings>() {
            Ok(Some(mut overlay)) if overlay.web.is_some() => {
                overlay.web = None;
                if let Err(e) = store.put_runtime_settings(&overlay) {
                    eprintln!("daygle-dns: cannot write runtime settings: {e}");
                    std::process::exit(1);
                }
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("daygle-dns: cannot read runtime settings: {e}");
                std::process::exit(1);
            }
        }
        let addr =
            daygle_dns_core::config::listen_socket_addrs(&config.api.listen, config.api.port)
                .ok()
                .and_then(|addrs| addrs.first().map(|a| a.to_string()))
                .unwrap_or_else(|| format!("{}:{}", config.api.listen, config.api.port));
        println!(
            "web console access reset: after a restart it is served over plain HTTP at http://{addr}/"
        );
        return;
    }

    // Load configuration before logging so we know the requested level.
    let config = match DaygleConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("daygle-dns: failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let filter = args
        .log_level
        .clone()
        .unwrap_or_else(|| config.logging.level.clone());
    // fmt keeps the configured level; the hickory bridge additionally sees
    // Hickory's own `debug` DoH failure events so it can re-emit them
    // into the console's Server Log - tagged with the query-log protocol
    // values and coalesced per client (see `daygle_dns::tls_diag`).
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(daygle_dns::tracing_filter(&filter)));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
        .with(
            daygle_dns::tls_diag::hickory_bridge()
                .with_filter(Targets::new().with_target("hickory_server", Level::DEBUG)),
        )
        .init();

    let config_path = args.config.clone();
    if let Err(e) = run(config, config_path) {
        eprintln!("daygle-dns: fatal error: {e}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run(config: DaygleConfig, config_path: String) -> daygle_dns_core::error::Result<()> {
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
