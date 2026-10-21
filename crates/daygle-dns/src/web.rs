//! The web console / REST API listeners: plain HTTP and/or HTTPS, moved at
//! runtime from Settings -> General without a restart.
//!
//! A change binds any new port and loads the certificate before touching
//! the running listeners, so a failed change leaves the console reachable
//! where it was. Certificate changes take effect in place (the HTTPS
//! listener reads the current TLS config on every handshake), and the
//! HTTP -> HTTPS redirect is decided per request, so only enabling,
//! disabling or moving a listener rebinds a socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::extract::{Request, State};
use axum::http::header::HOST;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::serve::ListenerExt;
use axum::Router;
use daygle_dns_authoritative::AuthorityCatalog;
use daygle_dns_core::config::WebSettings;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How long a client may take to finish the TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The addresses the web listeners are bound to (the first, when
/// `api.listen` names several).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebAddrs {
    pub http: Option<SocketAddr>,
    pub https: Option<SocketAddr>,
}

/// One running listener (a socket per `api.listen` address): the port it
/// was asked for (0 = ephemeral, in tests), where it is bound first, and
/// how to stop it.
struct Running {
    port: u16,
    addr: SocketAddr,
    stop: CancellationToken,
}

#[derive(Default)]
struct Listeners {
    http: Option<Running>,
    https: Option<Running>,
}

/// Owns the console's HTTP and HTTPS listeners.
pub struct WebServer {
    app: Router,
    catalog: Arc<AuthorityCatalog>,
    listen: String,
    /// `server.ipv6_only`: a `::` listen address takes IPv6 clients only.
    ipv6_only: bool,
    api_port: u16,
    /// The settings in force (the redirect reads them per request).
    settings: Arc<ArcSwap<WebSettings>>,
    /// The HTTPS listener's TLS config, swapped in place on a change.
    tls: Arc<ArcSwapOption<rustls::ServerConfig>>,
    listeners: Mutex<Listeners>,
    shutdown: CancellationToken,
}

impl WebServer {
    pub fn new(
        app: Router,
        catalog: Arc<AuthorityCatalog>,
        listen: String,
        ipv6_only: bool,
        api_port: u16,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            app,
            catalog,
            listen,
            ipv6_only,
            api_port,
            settings: Arc::new(ArcSwap::from_pointee(WebSettings::default())),
            tls: Arc::new(ArcSwapOption::empty()),
            listeners: Mutex::new(Listeners::default()),
            shutdown,
        }
    }

    /// Where the listeners are bound now.
    pub async fn addrs(&self) -> WebAddrs {
        let l = self.listeners.lock().await;
        WebAddrs {
            http: l.http.as_ref().map(|r| r.addr),
            https: l.https.as_ref().map(|r| r.addr),
        }
    }

    /// Move the listeners to `new`. On error nothing has changed.
    pub async fn apply(&self, new: WebSettings) -> Result<WebAddrs, String> {
        new.check(self.api_port)?;
        let mut listeners = self.listeners.lock().await;

        // Everything that can fail happens before the running listeners are
        // touched: the certificate, then any new sockets.
        let tls = if new.https_enabled {
            Some(Arc::new(self.load_tls(&new.https_certificate)?))
        } else {
            None
        };
        let want_http = new
            .http_enabled
            .then(|| new.effective_http_port(self.api_port));
        let want_https = new.https_enabled.then_some(new.https_port);
        let keep = |running: &Option<Running>, want: Option<u16>| matches!((running, want), (Some(r), Some(p)) if r.port == p);
        let keep_http = keep(&listeners.http, want_http);
        let keep_https = keep(&listeners.https, want_https);
        let http_socket = match want_http {
            Some(port) if !keep_http => Some((port, self.bind(port, "HTTP").await?)),
            _ => None,
        };
        let https_socket = match want_https {
            Some(port) if !keep_https => Some((port, self.bind(port, "HTTPS").await?)),
            _ => None,
        };

        // Commit.
        self.settings.store(Arc::new(new));
        self.tls.store(tls);
        if !keep_http {
            if let Some(old) = listeners.http.take() {
                old.stop.cancel();
            }
            if let Some((port, socket)) = http_socket {
                listeners.http = Some(self.spawn_http(port, socket));
            }
        }
        if !keep_https {
            if let Some(old) = listeners.https.take() {
                old.stop.cancel();
            }
            if let Some((port, socket)) = https_socket {
                listeners.https = Some(self.spawn_https(port, socket));
            }
        }
        Ok(WebAddrs {
            http: listeners.http.as_ref().map(|r| r.addr),
            https: listeners.https.as_ref().map(|r| r.addr),
        })
    }

    fn load_tls(&self, name: &str) -> Result<rustls::ServerConfig, String> {
        if name.is_empty() {
            return Err("choose a certificate for HTTPS".into());
        }
        let cert = self
            .catalog
            .store()
            .get_tls_certificate(name)
            .map_err(|e| format!("cannot read certificate '{name}': {e}"))?
            .ok_or_else(|| format!("certificate '{name}' does not exist"))?;
        daygle_dns_dot::tls_config_from_pem(&cert.cert_pem, &cert.key_pem, &[b"http/1.1"])
            .map_err(|e| format!("certificate '{name}' cannot be used: {e}"))
    }

    async fn bind(&self, port: u16, label: &str) -> Result<Vec<TcpListener>, String> {
        let addrs = daygle_dns_core::config::listen_socket_addrs(&self.listen, port)
            .map_err(|e| format!("api.listen: {e}"))?;
        let v6_only = crate::net::v6_only(&addrs, self.ipv6_only);
        addrs
            .into_iter()
            .map(|addr| {
                crate::net::bind_tcp(addr, v6_only)
                    .map_err(|e| format!("cannot listen for {label} on {addr}: {e}"))
            })
            .collect()
    }

    fn spawn_http(&self, port: u16, sockets: Vec<TcpListener>) -> Running {
        let stop = self.shutdown.child_token();
        let app = self.app.clone().layer(middleware::from_fn_with_state(
            self.settings.clone(),
            redirect_to_https,
        ));
        let mut first = None;
        for socket in sockets {
            let addr = socket.local_addr().expect("bound socket has an address");
            first.get_or_insert(addr);
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
                    warn!("web console HTTP listener error: {e}");
                }
            });
            info!(%addr, "web console listening (HTTP)");
        }
        let addr = first.expect("api.listen names at least one address");
        Running { port, addr, stop }
    }

    fn spawn_https(&self, port: u16, sockets: Vec<TcpListener>) -> Running {
        let stop = self.shutdown.child_token();
        let mut first = None;
        for socket in sockets {
            let addr = socket.local_addr().expect("bound socket has an address");
            first.get_or_insert(addr);
            self.serve_https(socket, addr, &stop);
        }
        let addr = first.expect("api.listen names at least one address");
        Running { port, addr, stop }
    }

    /// Serve HTTPS on one socket until `stop` is cancelled.
    fn serve_https(&self, socket: TcpListener, addr: SocketAddr, stop: &CancellationToken) {
        let (tx, rx) = mpsc::channel(64);
        // Handshakes run in their own tasks so a slow client cannot hold
        // up the others.
        let tls = self.tls.clone();
        let accepting = stop.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = tokio::select! {
                    _ = accepting.cancelled() => break,
                    accepted = socket.accept() => match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("web console HTTPS accept failed: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    },
                };
                let Some(config) = tls.load_full() else {
                    continue;
                };
                let acceptor = TlsAcceptor::from(config);
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(Ok(tls_stream)) =
                        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = tx.send((tls_stream, peer)).await;
                    }
                });
            }
        });
        let listener = TlsListener { rx, addr }.tap_io(|_| {});
        let app = self.app.clone();
        let done = stop.clone();
        tokio::spawn(async move {
            let served = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(done.cancelled_owned())
            .await;
            if let Err(e) = served {
                warn!("web console HTTPS listener error: {e}");
            }
        });
        info!(%addr, "web console listening (HTTPS)");
    }
}

/// Connections whose TLS handshake has completed, for `axum::serve`.
struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    addr: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept loop stopped: the listener is shutting down.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.addr)
    }
}

/// With both listeners on and the redirect chosen, answer every HTTP
/// request with a permanent redirect to the same path over HTTPS.
async fn redirect_to_https(
    State(settings): State<Arc<ArcSwap<WebSettings>>>,
    req: Request,
    next: Next,
) -> Response {
    let s = settings.load();
    // ACME HTTP-01 challenges are answered over plain HTTP.
    if !(s.redirect_http && s.https_enabled)
        || req.uri().path().starts_with("/.well-known/acme-challenge/")
    {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(host_without_port)
        .unwrap_or_default();
    if host.is_empty() {
        return next.run(req).await;
    }
    let port = if s.https_port == 443 {
        String::new()
    } else {
        format!(":{}", s.https_port)
    };
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    Redirect::permanent(&format!("https://{host}{port}{path}")).into_response()
}

/// `example.com:5380` -> `example.com`, `[::1]:5380` -> `[::1]`.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.split_inclusive(']').next().unwrap_or(host);
    }
    host.split(':').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::host_without_port;

    #[test]
    fn strips_the_port_from_a_host_header() {
        assert_eq!(host_without_port("dns.example.com:5380"), "dns.example.com");
        assert_eq!(host_without_port("dns.example.com"), "dns.example.com");
        assert_eq!(host_without_port("[::1]:5380"), "[::1]");
        assert_eq!(host_without_port("[::1]"), "[::1]");
        assert_eq!(host_without_port("192.168.1.2:80"), "192.168.1.2");
    }
}
