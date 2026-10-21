//! Health checks for failover records: each checked A/AAAA record's address
//! is probed on its interval (a TCP connection, or an HTTP(S) GET), and the
//! records that fail are handed to the catalog, which answers with their
//! healthy siblings instead (see `failover` in [`crate::catalog`]).
//!
//! A record goes down after [`DOWN_AFTER`] failures in a row and comes back
//! after [`UP_AFTER`] successes, so one lost packet does not flip answers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::catalog::AuthorityCatalog;
use crate::model::{HealthCheck, Record};

/// Consecutive failures before a record is taken out of answers.
pub const DOWN_AFTER: u32 = 2;
/// Consecutive successes before it is put back.
pub const UP_AFTER: u32 = 2;
/// The longest a single probe may take.
const MAX_PROBE: Duration = Duration::from_secs(10);
/// How often the loop looks for checks that are due.
const TICK: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
struct State {
    healthy: bool,
    fails: u32,
    passes: u32,
    last_checked: Option<i64>,
    last_error: Option<String>,
    next_due: Instant,
}

impl State {
    fn new() -> Self {
        Self {
            // Unknown counts as healthy until checks say otherwise.
            healthy: true,
            fails: 0,
            passes: 0,
            last_checked: None,
            last_error: None,
            next_due: Instant::now(),
        }
    }
}

/// A health check with its record and current state, for the API.
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    #[serde(flatten)]
    pub check: HealthCheck,
    pub zone_id: String,
    pub name: String,
    pub rtype: String,
    pub address: String,
    pub priority: u16,
    pub healthy: bool,
    /// UNIX seconds of the last probe, if any yet.
    pub last_checked: Option<i64>,
    /// Why the last probe failed (`None` when it passed).
    pub last_error: Option<String>,
}

pub struct HealthMonitor {
    catalog: Arc<AuthorityCatalog>,
    state: Mutex<HashMap<String, State>>,
    wake: tokio::sync::Notify,
}

impl HealthMonitor {
    pub fn new(catalog: Arc<AuthorityCatalog>) -> Self {
        Self {
            catalog,
            state: Mutex::new(HashMap::new()),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// Check `record_id` at once (its check was just added or changed).
    pub fn recheck(&self, record_id: &str) {
        if let Some(state) = self
            .state
            .lock()
            .expect("health state lock poisoned")
            .get_mut(record_id)
        {
            state.next_due = Instant::now();
        }
        self.wake.notify_one();
    }

    /// Every health check with its record and state.
    pub fn status(&self) -> Vec<HealthStatus> {
        let checks = self
            .catalog
            .store()
            .list_health_checks()
            .unwrap_or_default();
        let state = self.state.lock().expect("health state lock poisoned");
        checks
            .into_iter()
            .map(|(check, record)| {
                let s = state
                    .get(&check.record_id)
                    .cloned()
                    .unwrap_or_else(State::new);
                HealthStatus {
                    zone_id: record.zone_id,
                    name: record.name,
                    rtype: record.rtype,
                    address: record.content,
                    priority: record.priority,
                    healthy: s.healthy,
                    last_checked: s.last_checked,
                    last_error: s.last_error,
                    check,
                }
            })
            .collect()
    }

    /// Run until `shutdown` is cancelled.
    pub async fn run_forever(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            self.tick().await;
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    }

    /// Probe every check that is due, and publish the failing records.
    pub async fn tick(&self) {
        let checks = match self.catalog.store().list_health_checks() {
            Ok(checks) => checks,
            Err(e) => {
                warn!(error = %e, "cannot read the health checks");
                return;
            }
        };
        let due: Vec<(HealthCheck, Record)> = {
            let mut state = self.state.lock().expect("health state lock poisoned");
            let ids: HashSet<&str> = checks.iter().map(|(c, _)| c.record_id.as_str()).collect();
            state.retain(|id, _| ids.contains(id.as_str()));
            let now = Instant::now();
            checks
                .into_iter()
                .filter(|(check, _)| {
                    state
                        .entry(check.record_id.clone())
                        .or_insert_with(State::new)
                        .next_due
                        <= now
                })
                .collect()
        };
        let mut probes = tokio::task::JoinSet::new();
        for (check, record) in due {
            probes.spawn(async move {
                let result = probe(&check, &record).await;
                (check, record, result)
            });
        }
        let results = probes.join_all().await;
        let unhealthy = {
            let mut state = self.state.lock().expect("health state lock poisoned");
            for (check, record, result) in results {
                let Some(s) = state.get_mut(&check.record_id) else {
                    continue;
                };
                s.next_due = Instant::now() + Duration::from_secs(u64::from(check.interval_secs));
                s.last_checked = Some(chrono::Utc::now().timestamp());
                match result {
                    Ok(()) => {
                        s.fails = 0;
                        s.passes += 1;
                        s.last_error = None;
                        if !s.healthy && s.passes >= UP_AFTER {
                            s.healthy = true;
                            info!(name = %record.name, address = %record.content, "health check passing again: back in answers");
                        }
                    }
                    Err(e) => {
                        s.passes = 0;
                        s.fails += 1;
                        if s.healthy && s.fails >= DOWN_AFTER {
                            s.healthy = false;
                            warn!(name = %record.name, address = %record.content, error = %e, "health check failing: out of answers");
                        }
                        s.last_error = Some(e);
                    }
                }
            }
            state
                .iter()
                .filter(|(_, s)| !s.healthy)
                .map(|(id, _)| id.clone())
                .collect::<HashSet<String>>()
        };
        if let Err(e) = self.catalog.set_unhealthy(unhealthy) {
            warn!(error = %e, "cannot apply health check results");
        }
    }
}

/// One probe of `record`'s address.
async fn probe(check: &HealthCheck, record: &Record) -> Result<(), String> {
    let ip: IpAddr = record
        .content
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not an address", record.content))?;
    let addr = SocketAddr::new(ip, check.port);
    let timeout = MAX_PROBE.min(Duration::from_secs(u64::from(check.interval_secs)));
    if check.kind == "tcp" {
        return match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("connection failed: {e}")),
            Err(_) => Err("connection timed out".to_string()),
        };
    }
    let host = if check.host.is_empty() {
        record.name.trim_end_matches('.').to_string()
    } else {
        check.host.clone()
    };
    // Connect to the record's address, but name the host (Host header and
    // SNI). Certificates are not verified: this checks that the service
    // answers, and an address-only check could not verify them anyway.
    let client = reqwest::Client::builder()
        .resolve(&host, addr)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .tls_danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
    let url = format!("{}://{host}:{}{}", check.kind, check.port, check.path);
    let response = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, "daygle-dns health check")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = response.status();
    if status.as_u16() < 400 {
        Ok(())
    } else {
        Err(format!("HTTP {status}"))
    }
}
