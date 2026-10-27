//! Remote logging: the server log, and optionally every query, sent to a
//! syslog server as RFC 5424 lines over UDP, or over TCP with octet-counting
//! framing (RFC 6587). The `[syslog]` settings are read for every line, so
//! a change in Settings applies at once.
//!
//! Lines go through a bounded queue to one background task, so logging never
//! blocks a query or a request; when the queue is full (or the server is
//! down) lines are dropped and counted, and the count is reported once the
//! server can be reached again.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, SecondsFormat, Utc};
use daygle_dns_core::config::{DaygleConfig, SyslogTarget};
use daygle_dns_core::{LogEntry, LogLevel};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Queued lines before new ones are dropped.
const QUEUE: usize = 4096;
/// Longest message text sent (UDP datagrams beyond this risk truncation).
const MAX_TEXT: usize = 1800;
/// Wait this long after failing to reach the server before trying again.
const RETRY_AFTER: Duration = Duration::from_secs(10);

struct Line {
    ts: DateTime<Utc>,
    /// RFC 5424 severity.
    severity: u8,
    /// `server` or `query`.
    msgid: &'static str,
    text: String,
}

pub struct SyslogSender {
    tx: mpsc::Sender<Line>,
    config: Arc<ArcSwap<DaygleConfig>>,
    dropped: AtomicU64,
}

/// One query, for the query line.
pub struct QueryLine<'a> {
    pub client: IpAddr,
    pub qname: &'a str,
    pub qtype: &'a str,
    pub protocol: &'a str,
    pub outcome: &'a str,
    pub rcode: Option<&'a str>,
    pub elapsed_ms: u64,
    /// Why it was blocked, for blocked queries.
    pub block: Option<&'a daygle_dns_core::block_log::BlockReason>,
}

impl SyslogSender {
    /// Start the sender. It does nothing until `[syslog]` is enabled.
    pub fn start(config: Arc<ArcSwap<DaygleConfig>>, shutdown: CancellationToken) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE);
        let sender = Arc::new(Self {
            tx,
            config,
            dropped: AtomicU64::new(0),
        });
        tokio::spawn(run(sender.clone(), rx, shutdown));
        sender
    }

    fn queue(&self, line: Line) {
        if self.tx.try_send(line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A server-log entry (from the log store's forwarder).
    pub fn log_entry(&self, entry: &LogEntry) {
        let config = self.config.load();
        let settings = &config.syslog;
        if !settings.enabled {
            return;
        }
        let (rank, severity) = match entry.level {
            LogLevel::Error => (3, 3),
            LogLevel::Warn => (2, 4),
            LogLevel::Info => (1, 6),
            LogLevel::Debug => (0, 7),
        };
        if rank < settings.level_rank().unwrap_or(1) {
            return;
        }
        self.queue(Line {
            ts: entry.timestamp,
            severity,
            msgid: "server",
            text: format!("[{}] {}", entry.component, entry.message),
        });
    }

    /// One answered query, when `[syslog] queries` is on.
    pub fn query(&self, q: QueryLine<'_>) {
        let config = self.config.load();
        if !(config.syslog.enabled && config.syslog.queries) {
            return;
        }
        let mut text = format!(
            "client={} qname={} qtype={} protocol={} outcome={} rcode={} ms={}",
            q.client,
            if q.qname.is_empty() { "." } else { q.qname },
            q.qtype,
            q.protocol,
            q.outcome,
            q.rcode.unwrap_or("-"),
            q.elapsed_ms
        );
        if let Some(block) = q.block {
            text.push_str(&format!(" source={}", block.source));
            if let Some(group) = &block.group {
                text.push_str(&format!(" group={}", quoted(group)));
            }
            if let Some(matched) = &block.matched {
                text.push_str(&format!(" matched={}", quoted(matched)));
            }
            text.push_str(&format!(" reason={}", quoted(&block.reason)));
        }
        self.queue(Line {
            ts: Utc::now(),
            severity: 6,
            msgid: "query",
            text,
        });
    }
}

/// `value` in double quotes, with `"` and `\` escaped, for a `key=value`
/// field that may hold spaces.
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The RFC 5424 line for `line` (no trailing newline).
fn format_line(line: &Line, facility: u8, hostname: &str) -> String {
    let mut text = line.text.replace(['\n', '\r'], " ");
    if text.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    format!(
        "<{}>1 {} {} daygle-dns {} {} - {}",
        u16::from(facility) * 8 + u16::from(line.severity),
        line.ts.to_rfc3339_opts(SecondsFormat::Millis, true),
        hostname,
        std::process::id(),
        line.msgid,
        text
    )
}

enum Connection {
    Udp(tokio::net::UdpSocket, SocketAddr),
    Tcp(tokio::net::TcpStream),
}

async fn connect(target: &SyslogTarget) -> std::io::Result<Connection> {
    let addr = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("{} has no address", target.host)))?;
    if target.tcp {
        let stream =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| std::io::Error::other("connection timed out"))??;
        Ok(Connection::Tcp(stream))
    } else {
        let local: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid")
        } else {
            "[::]:0".parse().expect("valid")
        };
        Ok(Connection::Udp(
            tokio::net::UdpSocket::bind(local).await?,
            addr,
        ))
    }
}

async fn send(connection: &mut Connection, message: &str) -> std::io::Result<()> {
    match connection {
        Connection::Udp(socket, addr) => {
            socket.send_to(message.as_bytes(), *addr).await.map(|_| ())
        }
        Connection::Tcp(stream) => {
            // Octet counting (RFC 6587 §3.4.1).
            let framed = format!("{} {message}", message.len());
            stream.write_all(framed.as_bytes()).await
        }
    }
}

async fn run(sender: Arc<SyslogSender>, mut rx: mpsc::Receiver<Line>, shutdown: CancellationToken) {
    let hostname = daygle_dns_core::config::detect_server_name()
        .map(|n| n.trim_end_matches('.').to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut connection: Option<(SyslogTarget, Connection)> = None;
    let mut retry_at: Option<Instant> = None;
    loop {
        let line = tokio::select! {
            _ = shutdown.cancelled() => return,
            line = rx.recv() => match line {
                Some(line) => line,
                None => return,
            },
        };
        let config = sender.config.load();
        let settings = &config.syslog;
        if !settings.enabled {
            connection = None;
            continue;
        }
        let Ok(target) = settings.target() else {
            continue;
        };
        let facility = settings.facility_code().unwrap_or(3);
        if connection.as_ref().is_some_and(|(t, _)| *t != target) {
            connection = None;
            retry_at = None;
        }
        if connection.is_none() {
            if retry_at.is_some_and(|at| Instant::now() < at) {
                sender.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match connect(&target).await {
                Ok(c) => {
                    connection = Some((target.clone(), c));
                    retry_at = None;
                }
                Err(e) => {
                    warn!("cannot reach the syslog server {}: {e}", settings.server);
                    retry_at = Some(Instant::now() + RETRY_AFTER);
                    sender.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }
        let (_, conn) = connection.as_mut().expect("connected above");
        let dropped = sender.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let note = Line {
                ts: Utc::now(),
                severity: 4,
                msgid: "server",
                text: format!("[syslog] {dropped} log lines were dropped while the syslog server was unreachable or the queue was full"),
            };
            let _ = send(conn, &format_line(&note, facility, &hostname)).await;
        }
        if let Err(e) = send(conn, &format_line(&line, facility, &hostname)).await {
            warn!("syslog send to {} failed: {e}", settings.server);
            sender.dropped.fetch_add(1, Ordering::Relaxed);
            connection = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_follow_rfc_5424() {
        let line = Line {
            ts: DateTime::parse_from_rfc3339("2026-10-20T23:10:26.5Z")
                .unwrap()
                .with_timezone(&Utc),
            severity: 4,
            msgid: "server",
            text: "[api] two\nlines".into(),
        };
        let text = format_line(&line, 3, "dns1");
        let pid = std::process::id();
        assert_eq!(
            text,
            format!(
                "<28>1 2026-10-20T23:10:26.500Z dns1 daygle-dns {pid} server - [api] two lines"
            )
        );
        let long = Line {
            text: "é".repeat(2000),
            ..line
        };
        assert!(format_line(&long, 16, "-").len() < MAX_TEXT + 100);
    }
}
