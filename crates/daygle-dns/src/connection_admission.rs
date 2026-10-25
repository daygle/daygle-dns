//! Bounded TLS-over-TCP connection admission (DoT and DoH).
//!
//! Hickory's TLS listeners accept a Tokio TCP listener and start a task for
//! each socket. This front rejects excess sockets before forwarding admitted
//! connections to a private listener served by Hickory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::proxy_protocol;

/// The Hickory listener and the address of the public admission socket.
pub struct ConnectionAdmission {
    /// Private listener to register with Hickory.
    pub backend: TcpListener,
    /// Address clients connect to.
    pub public_addr: SocketAddr,
    /// Task that owns the front listener and in-flight bridges.
    pub task: tokio::task::JoinHandle<()>,
}

impl ConnectionAdmission {
    /// Start a capped front for `public` and return the listener Hickory serves.
    pub fn new(
        public: TcpListener,
        max_connections: usize,
        shutdown: CancellationToken,
        proxy_trusted: Option<Arc<Vec<ipnet::IpNet>>>,
    ) -> std::io::Result<Self> {
        let public_addr = public.local_addr()?;
        let backend_std = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        backend_std.set_nonblocking(true)?;
        let backend = TcpListener::from_std(backend_std)?;
        let backend_addr = backend.local_addr()?;
        let permits = Arc::new(Semaphore::new(max_connections));

        // Dropping the JoinHandle detaches this task. Its listener and every
        // in-flight bridge are nevertheless closed on generation shutdown.
        let task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {},
                    accepted = public.accept() => {
                        let (frontend, peer) = match accepted {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::warn!(%error, "TLS listener accept failed");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };
                        let permit = match permits.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                tracing::debug!(%peer, "DoT connection rejected: capacity exhausted");
                                drop(frontend);
                                continue;
                            }
                        };
                        let trusted = proxy_trusted.clone();
                        sessions.spawn(async move {
                            let _permit = permit;
                            if let Err(error) =
                                bridge(frontend, backend_addr, trusted.as_deref().map(Vec::as_slice))
                                    .await
                            {
                                tracing::debug!(%peer, %error, "DoT connection ended");
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            backend,
            public_addr,
            task,
        })
    }
}

async fn bridge(
    mut frontend: TcpStream,
    backend_addr: SocketAddr,
    trusted: Option<&[ipnet::IpNet]>,
) -> std::io::Result<()> {
    let peer = frontend.peer_addr()?;
    let client = match trusted {
        Some(networks)
            if networks
                .iter()
                .any(|net| net.contains(&peer.ip().to_canonical())) =>
        {
            tokio::time::timeout(
                Duration::from_secs(5),
                proxy_protocol::read_header(&mut frontend),
            )
            .await
            .map_err(|_| std::io::Error::other("no PROXY header in time"))??
            .unwrap_or(peer)
        }
        _ => peer,
    };
    let mut backend = TcpStream::connect(backend_addr).await?;
    let backend_local = backend.local_addr()?;
    proxy_protocol::register_client(backend_local, client);
    let result = tokio::io::copy_bidirectional(&mut frontend, &mut backend).await;
    proxy_protocol::unregister_client(backend_local);
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn rejects_over_capacity_and_admits_after_session_ends() {
        let public = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let shutdown = CancellationToken::new();
        let admission = ConnectionAdmission::new(public, 1, shutdown.clone(), None).unwrap();

        let first = TcpStream::connect(admission.public_addr).await.unwrap();
        let (backend_stream, backend_peer) =
            tokio::time::timeout(Duration::from_secs(1), admission.backend.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            proxy_protocol::real_client(backend_peer),
            first.local_addr().unwrap()
        );

        let mut excess = TcpStream::connect(admission.public_addr).await.unwrap();
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .expect("excess connection should be closed promptly")
            .unwrap();
        assert_eq!(result, 0, "excess connection must be rejected");

        drop(first);
        drop(backend_stream);
        let admitted_again = TcpStream::connect(admission.public_addr).await.unwrap();
        let (backend_again, _) =
            tokio::time::timeout(Duration::from_secs(1), admission.backend.accept())
                .await
                .unwrap()
                .unwrap();
        drop(admitted_again);
        drop(backend_again);
        shutdown.cancel();
        admission.task.abort();
    }
}
