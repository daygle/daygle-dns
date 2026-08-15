//! Live configuration reload.
//!
//! Daygle watches its TOML configuration file and applies changes without a
//! restart:
//!
//! - **policy** — the [`PolicyEngine`] is rebuilt and swapped atomically.
//! - **upstreams / recursion** — the [`RecursiveResolver`] is rebuilt when the
//!   `recursive` section changes.
//! - **listeners** — UDP/TCP/DoT listeners are gracefully rebound when the
//!   `server` or `dot` sections change.
//!
//! Everything is published through [`arc_swap`] containers so the dispatcher
//! and the REST API observe a consistent snapshot per query without locks.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use daygle_authoritative::AuthorityCatalog;
use daygle_core::config::DaygleConfig;
use daygle_core::error::Result;
use daygle_core::{LogStore, Metrics};
use daygle_policy::PolicyEngine;
use daygle_recursive::RecursiveResolver;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Mutable runtime state shared by the dispatcher, the REST API and the
/// reload machinery.
pub struct Shared {
    pub catalog: Arc<AuthorityCatalog>,
    pub policy: Arc<ArcSwap<PolicyEngine>>,
    pub resolver: Arc<ArcSwapOption<RecursiveResolver>>,
    pub config: Arc<ArcSwap<DaygleConfig>>,
    pub metrics: Arc<Metrics>,
    pub logs: Arc<LogStore>,
}

/// The currently bound DNS listener addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListenerAddrs {
    pub udp: Option<std::net::SocketAddr>,
    pub tcp: Option<std::net::SocketAddr>,
    pub dot: Option<std::net::SocketAddr>,
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

    let listeners_changed = old.server != new.server || old.dot != new.dot;

    // Publish the new configuration first so the API token, `/api/config` and
    // the listener supervisor all observe the requested state immediately.
    shared.config.store(Arc::clone(&new));

    // Policy engine.
    if old.policy != new.policy {
        match daygle_policy::build_engine(&new.policy) {
            Ok(engine) => {
                shared.policy.store(Arc::new(engine));
                info!("policy engine reloaded");
            }
            Err(e) => warn!("policy reload failed, keeping previous engine: {e}"),
        }
    }

    // Recursive resolver / upstreams.
    if old.recursive != new.recursive {
        if new.recursive.enabled {
            match RecursiveResolver::build(&new.recursive, shared.metrics.clone()) {
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

            let new = match DaygleConfig::load(path.as_ref()) {
                Ok(cfg) => cfg,
                Err(e) => {
                    warn!("config reload failed, keeping previous configuration: {e}");
                    continue;
                }
            };

            let changed = apply_config(&shared, Arc::new(new));
            if changed {
                if reload_tx
                    .send(ReloadCommand::Rebuild { ack: None })
                    .await
                    .is_err()
                {
                    warn!("DNS supervisor is gone; cannot apply listener changes");
                }
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
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
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
        let store = daygle_authoritative::ZoneStore::open(":memory:").unwrap();
        let catalog = Arc::new(
            AuthorityCatalog::new(store, cfg.authoritative.clone()).unwrap(),
        );
        Shared {
            catalog,
            policy: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
            resolver: Arc::new(ArcSwapOption::empty()),
            config: Arc::new(ArcSwap::from(Arc::new(cfg))),
            metrics: Arc::new(Metrics::default()),
            logs: Arc::new(LogStore::new(16)),
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
