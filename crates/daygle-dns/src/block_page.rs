//! The block page: a small web server that answers every request with a
//! page saying the site was blocked by this network's DNS filter, and why
//! (from [`BlockLog`], when the visitor's lookup was recent).
//!
//! Blocked names point here when `[block_page]` is on (see the dispatcher).
//! Only plain HTTP is served: an HTTPS site cannot be impersonated, so the
//! browser shows its own connection or certificate error for those.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use daygle_dns_core::block_log::BlockLog;
use daygle_dns_core::config::BlockPageSettings;
use daygle_dns_core::LogStore;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Clone)]
struct PageState {
    log: Arc<BlockLog>,
    settings: Arc<Mutex<BlockPageSettings>>,
}

/// Runs the block page's listeners, rebinding when the settings change.
pub struct BlockPageServer {
    state: PageState,
    logs: Arc<LogStore>,
    shutdown: CancellationToken,
    /// The settings the listeners were bound with, and their stop token.
    running: Mutex<Option<(BlockPageSettings, CancellationToken)>>,
}

impl BlockPageServer {
    pub fn new(log: Arc<BlockLog>, logs: Arc<LogStore>, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            state: PageState {
                log,
                settings: Arc::new(Mutex::new(BlockPageSettings::default())),
            },
            logs,
            shutdown,
            running: Mutex::new(None),
        })
    }

    /// Apply `settings`: (re)bind when the page is turned on or its address
    /// changes, stop when it is turned off. A port that cannot be bound is
    /// reported in the server log.
    pub fn apply(&self, settings: &BlockPageSettings) {
        *self
            .state
            .settings
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = settings.clone();
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let same_listeners = running.as_ref().is_some_and(|(old, _)| {
            old.enabled == settings.enabled
                && old.listen == settings.listen
                && old.port == settings.port
        });
        if same_listeners || (running.is_none() && !settings.enabled) {
            return;
        }
        if let Some((_, stop)) = running.take() {
            stop.cancel();
        }
        if !settings.enabled {
            info!("block page stopped");
            return;
        }
        let addrs =
            match daygle_dns_core::config::listen_socket_addrs(&settings.listen, settings.port) {
                Ok(addrs) => addrs,
                Err(e) => {
                    self.logs.error("block-page", format!("block page: {e}"));
                    return;
                }
            };
        let v6_only = crate::net::v6_only(&addrs, false);
        let stop = self.shutdown.child_token();
        let app = Router::new().fallback(page).with_state(self.state.clone());
        for addr in addrs {
            let socket = match crate::net::bind_tcp(addr, v6_only) {
                Ok(socket) => socket,
                Err(e) => {
                    self.logs.error(
                        "block-page",
                        format!("the block page cannot listen on {addr}: {e}"),
                    );
                    continue;
                }
            };
            let app = app.clone();
            let done = stop.clone();
            tokio::spawn(async move {
                let served = axum::serve(
                    socket,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(done.cancelled_owned())
                .await;
                if let Err(e) = served {
                    warn!("block page listener error: {e}");
                }
            });
            info!(%addr, "block page listening");
        }
        *running = Some((settings.clone(), stop));
    }
}

/// Every request: the page.
async fn page(
    State(state): State<PageState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(strip_port)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reason = (!host.is_empty())
        .then(|| state.log.reason(peer.ip(), &host))
        .flatten();
    let message = state
        .settings
        .lock()
        .map(|s| s.message.clone())
        .unwrap_or_default();
    let html = render(&host, reason.as_deref(), &message);
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response()
}

/// `example.com:8080` -> `example.com`; `[2001:db8::1]:80` -> `2001:db8::1`.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The page itself: self-contained, light and dark.
fn render(host: &str, reason: Option<&str>, message: &str) -> String {
    let site = if host.is_empty() {
        "This site".to_string()
    } else {
        format!("<strong>{}</strong>", escape(host))
    };
    let reason = reason
        .map(|r| format!("<p class=\"reason\">Reason: {}</p>", escape(r)))
        .unwrap_or_default();
    let message = if message.trim().is_empty() {
        "If you think this is a mistake, ask whoever looks after this network.".to_string()
    } else {
        escape(message.trim()).replace('\n', "<br>")
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Blocked</title>
<style>
  :root {{ color-scheme: light dark; --bg: #f5f6f8; --card: #fff; --text: #1d2330; --muted: #5c6577; --accent: #d64545; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg: #0f131c; --card: #171d29; --text: #e6e9ef; --muted: #9aa3b5; --accent: #ff6b6b; }} }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ background: var(--card); max-width: 520px; margin: 16px; padding: 32px; border-radius: 14px; box-shadow: 0 8px 30px rgb(0 0 0 / 0.12); }}
  .icon {{ width: 48px; height: 48px; border-radius: 50%; background: var(--accent); color: #fff; display: grid; place-items: center; font-size: 26px; font-weight: 700; }}
  h1 {{ font-size: 1.4rem; margin: 18px 0 8px; }}
  p {{ line-height: 1.5; margin: 8px 0; }}
  .reason, .note {{ color: var(--muted); font-size: 0.92rem; }}
  .note {{ margin-top: 20px; }}
</style>
</head>
<body>
<main>
  <div class="icon" aria-hidden="true">!</div>
  <h1>Site Blocked</h1>
  <p>{site} was blocked by this network's DNS filter.</p>
  {reason}
  <p class="note">{message}</p>
</main>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_lose_their_port_and_text_is_escaped() {
        assert_eq!(strip_port("ads.example:8080"), "ads.example");
        assert_eq!(strip_port("ads.example"), "ads.example");
        assert_eq!(strip_port("[2001:db8::1]:80"), "2001:db8::1");
        let html = render("<x>", Some("on 'list' & more"), "Call <b>me</b>");
        assert!(html.contains("&lt;x&gt;"));
        assert!(html.contains("on &#39;list&#39; &amp; more"));
        assert!(html.contains("Call &lt;b&gt;me&lt;/b&gt;"));
        assert!(!html.contains("<b>me"));
    }
}
