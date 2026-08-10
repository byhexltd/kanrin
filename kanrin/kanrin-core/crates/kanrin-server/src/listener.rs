use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig;
use crate::session::ClientSession;

/// TLS/TCP listener for incoming client connections.
pub struct KanrinListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    config: Arc<ServerConfig>,
}

impl KanrinListener {
    pub async fn bind(config: Arc<ServerConfig>) -> anyhow::Result<Self> {
        // Load TLS certificate and key
        let certs = load_certs(&config.tls_cert)?;
        let key = load_key(&config.tls_key)?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let tcp_listener = TcpListener::bind(config.listen).await?;
        tracing::info!(addr = %config.listen, "server listening");

        Ok(Self {
            tcp_listener,
            tls_acceptor,
            config,
        })
    }

    /// Accept loop — returns next client connection after TLS handshake.
    pub async fn accept(&self) -> anyhow::Result<(TlsStream<TcpStream>, SocketAddr)> {
        loop {
            let (tcp_stream, peer_addr) = self.tcp_listener.accept().await?;
            tracing::debug!(peer = %peer_addr, "tcp connection accepted");

            match self.tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    tracing::debug!(peer = %peer_addr, "tls handshake complete");
                    return Ok((tls_stream, peer_addr));
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_addr, error = %e, "tls handshake failed");
                    continue;
                }
            }
        }
    }
}

fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }

    Ok(certs)
}

fn load_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);

    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))?;

    Ok(key)
}
