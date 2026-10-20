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

use std::io::Write as _;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use daygle_dns::bind_with;
use daygle_dns_authoritative::ZoneStore;
use daygle_dns_core::config::{AiSettings, AiUpdate, DaygleConfig, RuntimeSettings};
use daygle_dns_core::DEFAULT_CONFIG_PATH;
use tracing::info;
use tracing_subscriber::EnvFilter;

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
        println!(
            "web console access reset: after a restart it is served over plain HTTP at http://{}:{}/",
            config.api.listen, config.api.port
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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter)),
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
