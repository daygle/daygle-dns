//! Encrypted-DNS session diagnostics: DoT, DoH and DoQ.
//!
//! Three things the operator needs before a client notices a problem:
//!
//! - **Certificate lifecycle** ([`report_certificate`]): every listener start
//!   or reload logs the certificate's name, subject and expiry, and warns
//!   when it is already expired or inside the ACME renewal window - the
//!   failure that takes an encrypted listener down before anyone reports it.
//! - **Session failures** ([`SessionLog`]): failed handshakes and dropped
//!   connections at `warn`, with the client address, a protocol tag and the
//!   reason. Repeats from the same client are coalesced - the first failure
//!   per (protocol, client) per interval is logged, later ones are counted
//!   and summarised - so a loop of failing handshakes cannot flood the log.
//!   Entries carry the same protocol values the query log records (`tls`,
//!   `https`, `quic`) as their console Server Log component, so the two logs
//!   correlate, and they feed syslog when it is enabled.
//!   A client address behind a listener's admission bridge is translated to
//!   the real peer with [`crate::proxy_protocol::real_client`], like the
//!   query log does. One event is deliberately not a failure: hickory ends an
//!   established DoT session whose client stays idle past the configured
//!   handshake timeout (the same duration doubles as the session's read
//!   timeout), which is normal keep-alive expiry and is logged at `debug`
//!   only.
//! - **Hickory bridge** ([`hickory_bridge`]): Hickory logs DoT handshake
//!   failures at `debug` and DoH request rejections at `warn`, but never
//!   into the console's Server Log. This layer re-emits the actionable
//!   events through the [`SessionLog`] - tagged, coalesced and visible in
//!   the console.
//!
//! Documented limitation: Hickory's handshake-timeout warnings carry no
//! client address (its TLS acceptor logs the timeout without the peer), so
//! those entries are logged with an unknown client; everything else is
//! attributed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use daygle_dns_core::{LogLevel, LogStore};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// The protocol tags used for encrypted-DNS diagnostics - exactly the values
/// the query log records, so failures and served queries correlate.
pub const TLS: &str = "tls";
pub const HTTPS: &str = "https";
pub const QUIC: &str = "quic";

/// How long one client stays quiet after its failures were reported.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
/// Upper bound on tracked clients. A spoofed-source flood evicts old
/// windows (and clears the map as a last resort) instead of growing it
/// without limit; coalescing still holds at most one line per clear.
const MAX_TRACKED: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: &'static str,
    client: Option<IpAddr>,
}

/// One (protocol, client) failure window.
#[derive(Debug)]
struct Window {
    since: Instant,
    count: u64,
}

/// Coalescing warn-logger for encrypted-DNS session failures.
///
/// The first failure per (protocol, client) within the interval is logged at
/// `warn` with the client address, the protocol tag and the reason; repeats
/// are counted silently and, when the window rolls over, reported as one
/// summary line. A client looping failed handshakes therefore produces at
/// most one line per protocol per interval.
///
/// A read-inactivity timeout on an established session (`nothing ready in
/// …`, which hickory reports when its DoT read timeout expires) is normal
/// keep-alive expiry, not a failure: it goes to `debug` and is never
/// counted as one.
///
/// Every emission goes to `tracing` and to the console's Server Log
/// ([`LogStore`], which also feeds syslog), tagged with the protocol values
/// the query log uses.
#[derive(Debug)]
pub struct SessionLog {
    logs: Arc<LogStore>,
    interval: Duration,
    inner: Mutex<HashMap<Key, Window>>,
}

impl SessionLog {
    pub fn new(logs: Arc<LogStore>) -> Self {
        Self::with_interval(logs, DEFAULT_INTERVAL)
    }

    /// A logger with a custom window (tests).
    fn with_interval(logs: Arc<LogStore>, interval: Duration) -> Self {
        Self {
            logs,
            interval,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// The Server Log this logger writes to.
    pub fn logs(&self) -> &Arc<LogStore> {
        &self.logs
    }

    /// Record one session failure. `client` is `None` when the transport
    /// could not attribute one (Hickory's handshake timeouts log no peer).
    /// An idle read-timeout is logged at `debug` only - it is not a failure.
    pub fn record(&self, protocol: &'static str, client: Option<IpAddr>, reason: &str) {
        if idle_expiry(reason) {
            tracing::debug!(protocol, client = ?client, reason, "idle {protocol} session closed");
            return;
        }
        let now = Instant::now();
        let (message, failures) = {
            let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Bound the map: stale windows go first, a full map is cleared
            // outright (a flood then yields at most one line per clear).
            if map.len() >= MAX_TRACKED {
                map.retain(|_, w| now.duration_since(w.since) < self.interval.saturating_mul(2));
                if map.len() >= MAX_TRACKED {
                    map.clear();
                }
            }
            let key = Key { protocol, client };
            match map.get_mut(&key) {
                None => {
                    map.insert(
                        key,
                        Window {
                            since: now,
                            count: 1,
                        },
                    );
                    (first_message(protocol, client, reason), 1)
                }
                Some(window) if now.duration_since(window.since) >= self.interval => {
                    let earlier = window.count;
                    window.since = now;
                    window.count = 1;
                    if earlier > 1 {
                        (
                            summary_message(protocol, client, reason, earlier, self.interval),
                            earlier,
                        )
                    } else {
                        (first_message(protocol, client, reason), 1)
                    }
                }
                // Inside the window: count it and stay quiet.
                Some(window) => {
                    window.count += 1;
                    return;
                }
            }
        };
        tracing::warn!(protocol, client = ?client, reason, failures, "{message}");
        self.logs.warn(protocol, message);
    }

    /// Record one session event for the accepted peer `peer` of a TCP-based
    /// listener, resolving the admission bridge's loopback address back to
    /// the client that actually connected.
    pub fn record_peer(&self, protocol: &'static str, peer: Option<SocketAddr>, reason: &str) {
        let client = peer.map(|addr| crate::proxy_protocol::real_client(addr).ip());
        self.record(protocol, client, reason);
    }
}

/// Hickory's read-inactivity timeout on an established TLS session reports
/// `"nothing ready in <duration>"`: the client simply had nothing to send
/// before the session read timeout expired, so nothing failed.
fn idle_expiry(reason: &str) -> bool {
    reason.starts_with("nothing ready in ")
}

fn who(client: Option<IpAddr>) -> String {
    client.map_or_else(|| "unknown client".to_string(), |c| c.to_string())
}

fn first_message(protocol: &str, client: Option<IpAddr>, reason: &str) -> String {
    format!("{} {protocol} session failure: {reason}", who(client))
}

fn summary_message(
    protocol: &str,
    client: Option<IpAddr>,
    reason: &str,
    earlier: u64,
    interval: Duration,
) -> String {
    format!(
        "{} {protocol} session failure: {reason} ({earlier} earlier failures in the last {interval:?})",
        who(client)
    )
}

/// The session log the hickory bridge forwards into; set by `bind` before
/// any listener starts. The last server bound wins (one server per process
/// in production; tests bind one at a time).
static CURRENT: RwLock<Option<Arc<SessionLog>>> = RwLock::new(None);

/// Point [`hickory_bridge`] at this server's session log.
pub fn set_current(session: Arc<SessionLog>) {
    *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(session);
}

fn current() -> Option<Arc<SessionLog>> {
    CURRENT.read().unwrap_or_else(|e| e.into_inner()).clone()
}

// ---- Certificate lifecycle -------------------------------------------------

/// How a certificate's validity relates to the renewal window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertHealth {
    /// Already past `not_after`.
    Expired { days_ago: u64 },
    /// Still valid but inside the renewal window.
    RenewSoon { days_left: u64 },
    /// Valid for longer than the renewal window.
    Valid,
}

/// Classify a certificate against the renewal window (whole days, floored).
pub fn cert_health(not_after: i64, now: i64, renew_days: u32) -> CertHealth {
    let remaining = not_after - now;
    if remaining < 0 {
        CertHealth::Expired {
            days_ago: remaining.unsigned_abs() / 86_400,
        }
    } else if remaining < i64::from(renew_days) * 86_400 {
        CertHealth::RenewSoon {
            days_left: (remaining / 86_400) as u64,
        }
    } else {
        CertHealth::Valid
    }
}

fn humanize_days(days: u64) -> String {
    match days {
        0 => "under a day".to_string(),
        1 => "1 day".to_string(),
        n => format!("{n} days"),
    }
}

/// Report one encrypted listener's certificate on every listener start or
/// reload: subject and validity at `info`, a `warn` when it is already
/// expired or inside the renewal window (see
/// [`daygle_dns_api::acme::renewal_window_days`]) - the failure that takes
/// a listener down before any client reports it.
///
/// Never fails: a certificate the TLS config cannot use is already reported
/// by the config build, which runs first.
pub fn report_certificate(
    protocol: &'static str,
    label: &str,
    name: &str,
    cert_path: &str,
    renew_days: u32,
    session: &SessionLog,
) {
    let emit = |level: LogLevel, message: String| {
        match level {
            LogLevel::Info => tracing::info!("{message}"),
            LogLevel::Warn => tracing::warn!("{message}"),
            LogLevel::Error => tracing::error!("{message}"),
            LogLevel::Debug => tracing::debug!("{message}"),
        }
        session.logs().push(level, protocol, message);
    };

    let pem = match std::fs::read_to_string(cert_path) {
        Ok(pem) => pem,
        Err(e) => {
            emit(
                LogLevel::Warn,
                format!("{label} certificate '{name}' cannot be read from '{cert_path}': {e}"),
            );
            return;
        }
    };
    let info = match daygle_dns_dot::describe_certificate(&pem) {
        Ok(info) => info,
        Err(e) => {
            emit(
                LogLevel::Warn,
                format!("{label} certificate '{name}' in '{cert_path}' cannot be parsed: {e}"),
            );
            return;
        }
    };

    let now = chrono::Utc::now().timestamp();
    let until = chrono::DateTime::from_timestamp(info.not_after, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("unix timestamp {}", info.not_after));
    let subject = if info.names.is_empty() {
        format!("subject '{}'", info.subject)
    } else {
        format!("subject '{}' ({})", info.subject, info.names.join(", "))
    };
    let health = cert_health(info.not_after, now, renew_days);
    let (level, message) = match health {
        CertHealth::Valid => (
            LogLevel::Info,
            format!("{label} certificate '{name}': {subject}, valid until {until}"),
        ),
        CertHealth::RenewSoon { days_left } => (
            LogLevel::Warn,
            format!(
                "{label} certificate '{name}': {subject}, expires {until} ({} left), \
                 inside the {renew_days}-day renewal window",
                humanize_days(days_left)
            ),
        ),
        CertHealth::Expired { days_ago } => (
            LogLevel::Warn,
            format!(
                "{label} certificate '{name}': {subject}, expired {until} ({} ago); \
                 encrypted clients cannot connect",
                humanize_days(days_ago)
            ),
        ),
    };
    emit(level, message);
}

// ---- Hickory bridge --------------------------------------------------------

/// Which hickory event a line is, and how to pull the client out of it.
#[derive(Debug)]
enum Shape {
    /// Structured `src_addr` + `error` fields on the event.
    Fields,
    /// `"<prefix><addr>: <reason>"` inside the rendered message.
    Prefixed(&'static str),
    /// `"https handshake src: <addr> error: <reason>"`.
    Handshake,
    /// No address (Hickory's handshake timeouts log none).
    NoAddress(&'static str),
}

/// How much of a message the classification pass renders. Tracing exposes
/// no event format template (the callsite name is `"event <file>:<line>"`),
/// so the message must be rendered to recognise it - bounded so routine
/// events like `"Received request: {:#?}"` never pay for their full dump.
const PEEK_LIMIT: usize = 128;

fn render_limited(value: &dyn std::fmt::Debug, limit: usize) -> String {
    struct Truncated {
        buf: String,
        limit: usize,
    }
    impl std::fmt::Write for Truncated {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            if self.buf.len() >= self.limit {
                return Ok(()); // keep formatting, drop the output
            }
            let mut end = (self.limit - self.buf.len()).min(s.len());
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.buf.push_str(&s[..end]);
            Ok(())
        }
    }
    use std::fmt::Write as _;
    let mut out = Truncated {
        buf: String::new(),
        limit,
    };
    let _ = write!(out, "{value:?}");
    out.buf
}

/// First pass: the (bounded) rendered message, enough to classify.
#[derive(Debug, Default)]
struct Peek {
    message: Option<String>,
}

impl Peek {
    fn store(&mut self, name: &str, text: String) {
        if name == "message" && self.message.is_none() {
            self.message = Some(text);
        }
    }
}

impl tracing::field::Visit for Peek {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && self.message.is_none() {
            self.message = Some(render_limited(value, PEEK_LIMIT));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.store(field.name(), value.to_string());
    }
}

/// Map a Hickory event's rendered message to the protocol tag and the shape
/// of its payload. Only actionable events are classified: handshake
/// failures, connection drops and rejected requests - not routine
/// per-request logs.
fn classify(rendered: &str) -> Option<(&'static str, Shape)> {
    Some(match rendered {
        "tls handshake error" | "error in TLS request stream" => (TLS, Shape::Fields),
        "tls timeout expired during handshake" => (
            TLS,
            Shape::NoAddress("handshake timeout (client address unavailable)"),
        ),
        "https timeout expired during handshake" => (
            HTTPS,
            Shape::NoAddress("handshake timeout (client address unavailable)"),
        ),
        m if m.starts_with("https handshake src: ") => (HTTPS, Shape::Handshake),
        m if m.starts_with("handshake error from ") => {
            (HTTPS, Shape::Prefixed("handshake error from "))
        }
        m if m.starts_with("error while handling request from ") => {
            (HTTPS, Shape::Prefixed("error while handling request from "))
        }
        m if m.starts_with("error accepting request ") => {
            (HTTPS, Shape::Prefixed("error accepting request "))
        }
        _ => return None,
    })
}

/// An event's rendered message and named fields.
#[derive(Debug, Default)]
struct Rendered {
    message: Option<String>,
    fields: HashMap<String, String>,
}

impl Rendered {
    fn store(&mut self, name: &str, text: String) {
        if name == "message" && self.message.is_none() {
            self.message = Some(text);
        } else {
            self.fields.insert(name.to_string(), text);
        }
    }
}

impl tracing::field::Visit for Rendered {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // `fmt::Arguments` renders through `Debug` exactly as through
        // `Display`, so format-argument messages arrive fully rendered here.
        self.store(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.store(field.name(), value.to_string());
    }
}

/// Parse `"127.0.0.1:54321"` / `"[::1]:54321"` (possibly debug-quoted) to a
/// socket address; a bare IP is kept with port 0 (it cannot be translated
/// through the admission bridge, but still names the client).
fn parse_peer(text: &str) -> Option<SocketAddr> {
    let text = text.trim().trim_matches('"');
    text.parse::<SocketAddr>()
        .ok()
        .or_else(|| text.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0)))
}

fn extract(shape: &Shape, rendered: &Rendered) -> (Option<SocketAddr>, String) {
    let message = rendered.message.clone().unwrap_or_default();
    match shape {
        Shape::Fields => {
            let client = rendered.fields.get("src_addr").and_then(|s| parse_peer(s));
            let reason = rendered
                .fields
                .get("error")
                .cloned()
                .unwrap_or_else(|| message.clone());
            (client, reason)
        }
        Shape::Prefixed(prefix) => {
            let rest = message.strip_prefix(prefix).unwrap_or(&message);
            match rest.split_once(": ") {
                Some((addr, reason)) => match parse_peer(addr) {
                    Some(peer) => (Some(peer), reason.to_string()),
                    None => (None, message.clone()),
                },
                None => (None, message.clone()),
            }
        }
        Shape::Handshake => {
            let rest = message
                .strip_prefix("https handshake src: ")
                .unwrap_or(&message);
            match rest.split_once(" error: ") {
                Some((addr, reason)) => (parse_peer(addr), reason.to_string()),
                None => (None, message.clone()),
            }
        }
        Shape::NoAddress(reason) => (None, reason.to_string()),
    }
}

/// The [`tracing`] layer that surfaces Hickory's DoT/DoH failures in the
/// console's Server Log. Install it with its own target filter so Hickory's
/// `debug` events reach it while the console-facing fmt layer keeps the
/// configured level:
///
/// ```ignore
/// registry()
///     .with(fmt::layer().with_filter(env_filter))
///     .with(tls_diag::hickory_bridge().with_filter(
///         Targets::new().with_target("hickory_server", Level::DEBUG),
///     ))
///     .init();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HickoryBridge;

/// Build the bridge layer (see [`HickoryBridge`]).
pub fn hickory_bridge() -> HickoryBridge {
    HickoryBridge
}

impl<S> Layer<S> for HickoryBridge
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if !meta.target().starts_with("hickory_server") {
            return;
        }
        let mut peek = Peek::default();
        event.record(&mut peek);
        let Some(rendered) = peek.message.as_deref() else {
            return;
        };
        let Some((protocol, shape)) = classify(rendered) else {
            return;
        };
        let Some(session) = current() else {
            return;
        };
        // Matched (rare: real failures): render in full to extract the
        // client address and the actionable reason.
        let mut full = Rendered::default();
        event.record(&mut full);
        let (peer, reason) = extract(&shape, &full);
        session.record_peer(protocol, peer, &reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn store() -> Arc<LogStore> {
        Arc::new(LogStore::new(64))
    }

    fn warns(logs: &LogStore, component: &str) -> Vec<String> {
        logs.entries()
            .into_iter()
            .filter(|e| e.level == LogLevel::Warn && e.component == component)
            .map(|e| e.message)
            .collect()
    }

    #[test]
    fn coalesces_repeats_and_summarizes_after_the_interval() {
        let logs = store();
        let session = SessionLog::with_interval(logs.clone(), Duration::from_millis(20));
        let client = Some(IpAddr::from(Ipv4Addr::new(192, 0, 2, 10)));

        session.record(QUIC, client, "handshake failed: boom");
        session.record(QUIC, client, "handshake failed: boom");
        session.record(QUIC, client, "handshake failed: boom");
        let first = warns(&logs, QUIC);
        assert_eq!(first.len(), 1, "{first:?}");
        assert!(first[0].contains("192.0.2.10"), "{:?}", first[0]);
        assert!(first[0].contains("boom"), "{:?}", first[0]);

        std::thread::sleep(Duration::from_millis(60));
        session.record(QUIC, client, "handshake failed: again");
        let after = warns(&logs, QUIC);
        assert_eq!(after.len(), 2, "{after:?}");
        assert!(after[1].contains("3 earlier failures"), "{:?}", after[1]);
        assert!(after[1].contains("in the last 20ms"), "{:?}", after[1]);

        // Protocols keep independent windows.
        session.record(TLS, client, "tls reason");
        assert_eq!(warns(&logs, QUIC).len(), 2);
        assert_eq!(warns(&logs, TLS).len(), 1);
        assert!(warns(&logs, TLS)[0].contains("tls reason"));
    }

    #[test]
    fn reports_failures_without_a_client_address() {
        let logs = store();
        let session = SessionLog::with_interval(logs.clone(), Duration::from_secs(60));
        session.record(TLS, None, "handshake timeout (client address unavailable)");
        let entries = warns(&logs, TLS);
        assert_eq!(entries.len(), 1);
        // The Server Log sentence-cases every message on push.
        assert!(entries[0].contains("Unknown client"), "{:?}", entries[0]);
    }

    #[test]
    fn idle_session_expiry_is_not_a_failure() {
        let logs = store();
        let session = SessionLog::with_interval(logs.clone(), Duration::from_secs(60));
        // Hickory reports its established-session read timeout this way after
        // the TLS handshake succeeded; the client was merely idle.
        session.record(
            TLS,
            Some(IpAddr::from(Ipv4Addr::LOCALHOST)),
            "nothing ready in 10s",
        );
        assert!(warns(&logs, TLS).is_empty(), "{:?}", warns(&logs, TLS));
        assert!(session.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn attributes_failures_to_the_client_behind_the_admission_bridge() {
        let logs = store();
        let session = SessionLog::with_interval(logs.clone(), Duration::from_secs(60));
        // The admitted connection reaches hickory from a loopback backend;
        // the bridge maps that local address back to the real peer.
        let backend: SocketAddr = "127.0.0.1:41234".parse().unwrap();
        let client: SocketAddr = "198.51.100.20:5555".parse().unwrap();
        crate::proxy_protocol::register_client(backend, client);
        session.record_peer(TLS, Some(backend), "connection reset");
        crate::proxy_protocol::unregister_client(backend);
        let entries = warns(&logs, TLS);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert!(entries[0].contains("198.51.100.20"), "{entries:?}");
        assert!(!entries[0].contains("127.0.0.1"), "{entries:?}");
    }

    #[test]
    fn bounds_the_number_of_tracked_clients() {
        let logs = store();
        let session = SessionLog::with_interval(logs.clone(), Duration::from_secs(60));
        for i in 0..(MAX_TRACKED + 5) {
            let ip = IpAddr::from(Ipv4Addr::from(0x0b00_0000u32 + u32::try_from(i).unwrap()));
            session.record(TLS, Some(ip), "reason");
        }
        let tracked = session.inner.lock().unwrap().len();
        assert!(tracked <= 6, "tracked {tracked} clients");
    }

    #[test]
    fn classifies_certificate_expiry() {
        let now = 1_700_000_000;
        assert_eq!(cert_health(now + 90 * 86_400, now, 30), CertHealth::Valid);
        assert_eq!(
            cert_health(now + 10 * 86_400, now, 30),
            CertHealth::RenewSoon { days_left: 10 }
        );
        assert_eq!(
            cert_health(now - 3 * 86_400 - 1, now, 30),
            CertHealth::Expired { days_ago: 3 }
        );
        assert_eq!(
            cert_health(now - 3 * 86_400 - 90_000, now, 30),
            CertHealth::Expired { days_ago: 4 }
        );
    }

    #[test]
    fn classifies_hickory_event_messages() {
        assert!(classify("tls handshake error").is_some());
        assert!(classify("error in TLS request stream").is_some());
        assert!(classify("tls timeout expired during handshake").is_some());
        assert!(classify("https timeout expired during handshake").is_some());
        assert!(classify("https handshake src: 127.0.0.1:443 error: bad").is_some());
        assert!(classify("handshake error from 127.0.0.1:443: bad").is_some());
        assert!(classify("error while handling request from 127.0.0.1:1: bad path: /x").is_some());
        assert!(classify("error accepting request 127.0.0.1:1: broken").is_some());
        // Routine events stay out of the log.
        assert!(classify("Received request: Request {").is_none());
        assert!(classify("starting TLS request").is_none());
        assert!(classify("accepted TCP request").is_none());
    }

    #[test]
    fn peeks_at_messages_within_the_render_limit() {
        let heavy = format!("Received request: {:#?}", vec!["large"; 50]);
        let peeked = render_limited(&heavy, PEEK_LIMIT);
        assert!(peeked.len() <= PEEK_LIMIT, "{} bytes", peeked.len());
        assert!(classify(&peeked).is_none());
    }

    #[test]
    fn pulls_client_and_reason_out_of_hickory_events() {
        // DoH request rejection: address and actionable reason in the text.
        let mut rendered = Rendered::default();
        rendered.store(
            "message",
            "error while handling request from 127.0.0.1:51000: bad path: /x, expected: /dns-query"
                .to_string(),
        );
        let (protocol, shape) = classify(
            "error while handling request from 127.0.0.1:51000: bad path: /x, expected: /dns-query",
        )
        .unwrap();
        let (client, reason) = extract(&shape, &rendered);
        assert_eq!(protocol, HTTPS);
        assert_eq!(client, Some("127.0.0.1:51000".parse().unwrap()));
        assert!(reason.starts_with("bad path: /x"), "{reason}");

        // DoT handshake failure: structured fields, IPv6 address.
        let mut rendered = Rendered::default();
        rendered.store("message", "tls handshake error".to_string());
        rendered.store("src_addr", "[2001:db8::7]:853".to_string());
        rendered.store("error", "connection reset".to_string());
        let (protocol, shape) = classify("tls handshake error").unwrap();
        let (client, reason) = extract(&shape, &rendered);
        assert_eq!(protocol, TLS);
        assert_eq!(client, Some("[2001:db8::7]:853".parse().unwrap()));
        assert_eq!(reason, "connection reset");

        // DoH handshake failure: address embedded before " error: ".
        let mut rendered = Rendered::default();
        rendered.store(
            "message",
            "https handshake src: 127.0.0.1:443 error: invalid certificate".to_string(),
        );
        let (protocol, shape) =
            classify("https handshake src: 127.0.0.1:443 error: invalid certificate").unwrap();
        let (client, reason) = extract(&shape, &rendered);
        assert_eq!(protocol, HTTPS);
        assert_eq!(client, Some("127.0.0.1:443".parse().unwrap()));
        assert_eq!(reason, "invalid certificate");

        // Handshake timeout: no address, but the reason still says why.
        let (protocol, shape) = classify("tls timeout expired during handshake").unwrap();
        let (client, reason) = extract(&shape, &Rendered::default());
        assert_eq!(protocol, TLS);
        assert!(client.is_none());
        assert!(reason.contains("timeout"), "{reason}");
    }
}
