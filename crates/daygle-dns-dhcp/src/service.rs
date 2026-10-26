//! The DHCP service: listeners for DHCPv4 and DHCPv6, the lease table and
//! a background worker that saves leases and keeps their DNS names in step.

use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use daygle_dns_authoritative::catalog::AuthorityCatalog;
use daygle_dns_core::dhcp::{DhcpLease, DhcpSettings};
use daygle_dns_core::logs::LogStore;
#[cfg(target_os = "linux")]
use dhcproto::{Decodable, Encodable};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::leases::{self, Leases};
#[cfg(target_os = "linux")]
use crate::v4;
use crate::{ddns, net, v6};

/// The named setting holding this server's DHCPv6 DUID (hex).
const DUID_SETTING: &str = "dhcp_server_duid";
const LOG: &str = "dhcp";

/// How the listeners are doing, for the console.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct DhcpStatus {
    /// Whether this platform can serve DHCP.
    pub supported: bool,
    /// "Off", "Listening on UDP port 67", or why it is not listening.
    pub v4: String,
    pub v6: String,
    /// This server's DHCPv6 DUID, hex.
    pub server_duid: String,
}

struct State {
    settings: DhcpSettings,
    leases: Leases,
    /// Answers DHCPv6, which is only served on Linux.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    duid: Vec<u8>,
}

/// What the listeners were started with.
#[derive(Clone, PartialEq, Eq)]
struct Listening {
    v4: Option<u16>,
    v6: Option<u16>,
}

struct Running {
    listening: Listening,
    token: CancellationToken,
}

pub struct DhcpService {
    catalog: Arc<AuthorityCatalog>,
    logs: Arc<LogStore>,
    state: Mutex<State>,
    running: Mutex<Option<Running>>,
    status: Mutex<DhcpStatus>,
    /// Wakes the worker when leases changed.
    dirty: Notify,
}

impl DhcpService {
    /// The service, with the leases saved in the store. Nothing listens
    /// until [`DhcpService::apply`].
    pub fn new(catalog: Arc<AuthorityCatalog>, logs: Arc<LogStore>) -> Arc<Self> {
        let store = catalog.store();
        let saved = store.list_dhcp_leases().unwrap_or_else(|e| {
            logs.warn(LOG, format!("the saved leases could not be read: {e}"));
            Vec::new()
        });
        let duid = store
            .get_named_setting::<String>(DUID_SETTING)
            .ok()
            .flatten()
            .and_then(|hex| decode_hex(&hex))
            .unwrap_or_else(|| {
                let duid = v6::new_server_duid();
                let _ = store.put_named_setting(DUID_SETTING, &leases::hex(&duid));
                duid
            });
        Arc::new(Self {
            status: Mutex::new(DhcpStatus {
                supported: net::SUPPORTED,
                v4: "Off".to_string(),
                v6: "Off".to_string(),
                server_duid: leases::hex(&duid),
            }),
            catalog,
            logs,
            state: Mutex::new(State {
                settings: DhcpSettings::default(),
                leases: Leases::new(saved),
                duid,
            }),
            running: Mutex::new(None),
            dirty: Notify::new(),
        })
    }

    /// Start the background worker; it stops with `shutdown`, as do the
    /// listeners.
    pub fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = service.dirty.notified() => {
                        // Let a burst of changes settle.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        service.sweep(true);
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => service.sweep(false),
                }
            }
            if let Some(running) = service.running.lock().take() {
                running.token.cancel();
            }
        });
    }

    /// Use `settings`: scopes take effect at once, listeners are
    /// (re)started or stopped as needed.
    pub fn apply(self: &Arc<Self>, settings: &DhcpSettings) {
        {
            let mut state = self.state.lock();
            if state.settings.dns_zone.trim() != settings.dns_zone.trim() {
                state.leases.touch_all();
                self.dirty.notify_one();
            }
            state.settings = settings.clone();
        }
        let port = |p: u16, standard: u16| if p == 0 { standard } else { p };
        let wanted = Listening {
            v4: (settings.enabled && settings.scopes.iter().any(|s| s.enabled))
                .then(|| port(settings.port_v4, 67)),
            v6: (settings.enabled && settings.scopes_v6.iter().any(|s| s.enabled))
                .then(|| port(settings.port_v6, 547)),
        };
        let mut running = self.running.lock();
        if running.as_ref().map(|r| &r.listening) == Some(&wanted) {
            return;
        }
        if let Some(old) = running.take() {
            old.token.cancel();
        }
        let token = CancellationToken::new();
        let mut status = self.status.lock();
        status.v4 = self.listen_v4(wanted.v4, &token);
        status.v6 = self.listen_v6(wanted.v6, &token);
        *running = Some(Running {
            listening: wanted,
            token,
        });
    }

    pub fn status(&self) -> DhcpStatus {
        self.status.lock().clone()
    }

    /// The leases, offers and declines, by address.
    pub fn leases(&self) -> Vec<DhcpLease> {
        self.state.lock().leases.all().cloned().collect()
    }

    /// Forget the lease on `address` and remove its DNS names. The device
    /// asks again when it next renews.
    pub fn delete_lease(&self, address: &IpAddr) -> Result<bool, String> {
        let removed = self.state.lock().leases.remove(address);
        let Some(mut lease) = removed else {
            return Ok(false);
        };
        let store = self.catalog.store();
        if ddns::unregister(store, &mut lease) {
            self.reload_zones();
        }
        store
            .delete_dhcp_lease(address)
            .map_err(|e| e.to_string())?;
        // The removal is written out; nothing is left for the worker.
        self.state.lock().leases.forget_change(address);
        Ok(true)
    }

    fn reload_zones(&self) {
        if let Err(e) = self.catalog.reload() {
            self.logs
                .warn(LOG, format!("zones could not be reloaded: {e}"));
        }
    }

    /// Expire leases, save changes and bring DNS names in line. `loud`
    /// logs registration problems (they are retried quietly later).
    fn sweep(&self, loud: bool) {
        let store = self.catalog.store();
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.lock();
        state.leases.expire(now);
        for address in state.leases.take_granted() {
            if let Some(lease) = state.leases.get(&address) {
                let who = match (lease.hw_address.as_str(), lease.hostname.as_str()) {
                    ("", "") => String::new(),
                    (hw, "") => format!(" to {hw}"),
                    ("", name) => format!(" to {name}"),
                    (hw, name) => format!(" to {name} ({hw})"),
                };
                self.logs.info(
                    LOG,
                    format!("{address} leased{who} in scope {}", lease.scope),
                );
            }
        }
        let changes: HashSet<IpAddr> = state.leases.take_changes().into_iter().collect();
        let zone = state.settings.dns_zone.trim().to_string();
        let mut ours: HashSet<String> = state
            .leases
            .all()
            .flat_map(|l| l.dns_records.iter().cloned())
            .collect();
        // Changed leases, and bound ones still waiting for their name.
        let mut look_at: Vec<IpAddr> = changes.iter().copied().collect();
        look_at.extend(
            state
                .leases
                .all()
                .filter(|l| !changes.contains(&l.address))
                .filter(|l| ddns::wanted_name(l, &zone).is_some_and(|n| n != l.dns_name))
                .map(|l| l.address),
        );
        let mut zones_changed = false;
        for address in look_at {
            let Some(mut lease) = state.leases.get(&address).cloned() else {
                if let Err(e) = store.delete_dhcp_lease(&address) {
                    self.logs
                        .warn(LOG, format!("lease {address} could not be removed: {e}"));
                }
                continue;
            };
            let wanted = ddns::wanted_name(&lease, &zone);
            let in_place = wanted.as_deref() == Some(lease.dns_name.as_str())
                && ddns::registered(store, &lease);
            let mut modified = false;
            if !in_place {
                for id in &lease.dns_records {
                    ours.remove(id);
                }
                modified |= ddns::unregister(store, &mut lease);
                if let Some(name) = wanted {
                    match ddns::register(store, &zone, &name, &mut lease, &ours) {
                        Ok(()) => {
                            modified = true;
                            ours.extend(lease.dns_records.iter().cloned());
                        }
                        Err(e) if loud || changes.contains(&address) => self
                            .logs
                            .info(LOG, format!("{} gets no DNS name: {e}", lease.address)),
                        Err(_) => {}
                    }
                }
                zones_changed |= modified;
            }
            if modified || changes.contains(&address) {
                if let Err(e) = store.put_dhcp_lease(&lease) {
                    self.logs
                        .warn(LOG, format!("lease {address} could not be saved: {e}"));
                }
                state.leases.restore(lease);
            }
        }
        drop(state);
        if zones_changed {
            self.reload_zones();
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    (text.len().is_multiple_of(2) && !text.is_empty())
        .then(|| {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
                .collect()
        })
        .flatten()
}

#[cfg(target_os = "linux")]
impl DhcpService {
    /// Note a handled request: wake the worker when leases changed.
    fn handled(&self, state: &State) {
        if state.leases.has_changes() {
            self.dirty.notify_one();
        }
    }

    fn listen_v4(self: &Arc<Self>, port: Option<u16>, token: &CancellationToken) -> String {
        let Some(port) = port else {
            return "Off".to_string();
        };
        let socket = match net::PktSocket::v4(port) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("Cannot listen on UDP port {port}: {e}");
                self.logs.error(LOG, format!("DHCPv4: {msg}"));
                return msg;
            }
        };
        let service = self.clone();
        let token = token.clone();
        let client_port = if port == 67 { 68 } else { port + 1 };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = token.cancelled() => return,
                    r = socket.recv_v4(&mut buf) => r,
                };
                let Ok(r) = received else { continue };
                let Ok(request) = dhcproto::v4::Message::from_bytes(&buf[..r.len]) else {
                    continue;
                };
                let Some((reply, ifindex, source)) = service.answer_v4(&request, &r) else {
                    continue;
                };
                let Ok(bytes) = reply.to_vec() else { continue };
                let (to, ifindex) = match v4::destination(&request, &reply) {
                    v4::Destination::Relay(relay) => (SocketAddrV4::new(relay, r.from.port()), 0),
                    v4::Destination::Unicast(ip) => (SocketAddrV4::new(ip, client_port), 0),
                    v4::Destination::Broadcast => {
                        (SocketAddrV4::new(Ipv4Addr::BROADCAST, client_port), ifindex)
                    }
                };
                if let Err(e) = socket.send_v4(&bytes, to, ifindex, source).await {
                    tracing::debug!(error = %e, %to, "DHCPv4 reply not sent");
                }
            }
        });
        format!("Listening on UDP port {port}")
    }

    /// The reply to a DHCPv4 request, the interface and the source address
    /// to send it from.
    fn answer_v4(
        &self,
        request: &dhcproto::v4::Message,
        r: &net::Received<SocketAddrV4>,
    ) -> Option<(dhcproto::v4::Message, u32, Ipv4Addr)> {
        let IpAddr::V4(local) = r.local else {
            return None;
        };
        let interfaces = net::interfaces();
        let iface = interfaces.iter().find(|i| i.index == r.ifindex);
        let mut state = self.state.lock();
        let giaddr = request.giaddr();
        let (scope, server_ip) = state
            .settings
            .scopes
            .iter()
            .filter(|s| s.enabled)
            .find_map(|s| {
                let net = s.net()?;
                if !giaddr.is_unspecified() {
                    return net.contains(&giaddr).then_some((s.clone(), local));
                }
                let iface = iface?;
                let on_iface = if s.interface.trim().is_empty() {
                    iface.v4_in(&net).is_some()
                } else {
                    s.interface.trim() == iface.name
                };
                on_iface.then(|| (s.clone(), iface.v4_in(&net).unwrap_or(local)))
            })?;
        let ctx = v4::Context {
            net: scope.net()?,
            scope: &scope,
            server_ip,
            now: chrono::Utc::now().timestamp(),
        };
        let reply = v4::handle(&ctx, request, &mut state.leases);
        self.handled(&state);
        reply.map(|m| (m, r.ifindex, server_ip))
    }

    fn listen_v6(self: &Arc<Self>, port: Option<u16>, token: &CancellationToken) -> String {
        let Some(port) = port else {
            return "Off".to_string();
        };
        let socket = match net::PktSocket::v6(port) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("Cannot listen on UDP port {port}: {e}");
                self.logs.error(LOG, format!("DHCPv6: {msg}"));
                return msg;
            }
        };
        let service = self.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = token.cancelled() => return,
                    r = socket.recv_v6(&mut buf) => r,
                };
                let Ok(r) = received else { continue };
                // Relayed messages (Relay-forw, 12) are not served.
                if r.len == 0 || buf[0] == 12 {
                    continue;
                }
                let Ok(request) = dhcproto::v6::Message::from_bytes(&buf[..r.len]) else {
                    continue;
                };
                let Some(reply) = service.answer_v6(&request, r.ifindex) else {
                    continue;
                };
                let Ok(bytes) = reply.to_vec() else { continue };
                if let Err(e) = socket.send_v6(&bytes, r.from).await {
                    tracing::debug!(error = %e, to = %r.from, "DHCPv6 reply not sent");
                }
            }
        });
        format!("Listening on UDP port {port}")
    }

    fn answer_v6(
        &self,
        request: &dhcproto::v6::Message,
        ifindex: u32,
    ) -> Option<dhcproto::v6::Message> {
        let interfaces = net::interfaces();
        let iface = interfaces.iter().find(|i| i.index == ifindex)?;
        let mut state = self.state.lock();
        let scope = state
            .settings
            .scopes_v6
            .iter()
            .filter(|s| s.enabled)
            .find(|s| {
                let Some(net) = s.net() else { return false };
                if s.interface.trim().is_empty() {
                    iface.v6_in(&net).is_some()
                } else {
                    s.interface.trim() == iface.name
                }
            })?
            .clone();
        let net = scope.net()?;
        let duid = state.duid.clone();
        let ctx = v6::Context {
            scope: &scope,
            net,
            server_duid: &duid,
            dns_default: iface.v6_in(&net),
            now: chrono::Utc::now().timestamp(),
        };
        let reply = v6::handle(&ctx, request, &mut state.leases);
        self.handled(&state);
        reply
    }
}

#[cfg(not(target_os = "linux"))]
impl DhcpService {
    fn listen_v4(self: &Arc<Self>, port: Option<u16>, _token: &CancellationToken) -> String {
        port.map_or("Off", |_| "Not supported on this platform")
            .to_string()
    }

    fn listen_v6(self: &Arc<Self>, port: Option<u16>, _token: &CancellationToken) -> String {
        port.map_or("Off", |_| "Not supported on this platform")
            .to_string()
    }
}
