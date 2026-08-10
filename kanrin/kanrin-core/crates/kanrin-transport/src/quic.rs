use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use quinn::{ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint};

use crate::error::TransportError;
use crate::traits::{Connection, Endpoint, ProbeResult, Transport};

/// QUIC transport — Priority 1 (fastest, supports 0-RTT, connection migration).
pub struct QuicTransport {
    config: QuicConfig,
}

pub struct QuicConfig {
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Enable 0-RTT reconnection.
    pub enable_0rtt: bool,
    /// Idle timeout before connection is considered dead.
    pub idle_timeout_secs: u64,
    /// Initial congestion window size.
    pub initial_window: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 5_000,
            enable_0rtt: true,
            idle_timeout_secs: 30,
            initial_window: 14720,
        }
    }
}

impl QuicTransport {
    pub fn new(config: QuicConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(QuicConfig::default())
    }

    fn build_client_config(&self) -> Result<ClientConfig, TransportError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(self.config.idle_timeout_secs))
                .unwrap(),
        ));
        transport_config.initial_mtu(1200);

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| TransportError::Tls(format!("quic tls config: {}", e)))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }
}

#[async_trait]
impl Transport for QuicTransport {
    fn name(&self) -> &str {
        "quic"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn probe(&self, endpoint: &Endpoint) -> ProbeResult {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        // Try to establish a QUIC connection as a probe
        match tokio::time::timeout(timeout, self.connect(endpoint)).await {
            Ok(Ok(mut conn)) => {
                let latency = start.elapsed().as_millis() as u32;
                let _ = conn.close().await;
                ProbeResult::Available { latency_ms: latency }
            }
            Ok(Err(e)) => ProbeResult::Blocked {
                reason: format!("quic probe failed: {}", e),
            },
            Err(_) => ProbeResult::Blocked {
                reason: "quic probe timeout".into(),
            },
        }
    }

    async fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Connection>, TransportError> {
        let client_config = self.build_client_config()?;

        // Bind to any local address
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut quinn_endpoint = QuinnEndpoint::client(local_addr)
            .map_err(|e| TransportError::Io(e))?;
        quinn_endpoint.set_default_client_config(client_config);

        // Resolve server address
        let server_addr: SocketAddr = tokio::net::lookup_host(endpoint.addr_string())
            .await
            .map_err(|e| TransportError::DnsFailure(e.to_string()))?
            .next()
            .ok_or_else(|| TransportError::DnsFailure("no addresses found".into()))?;

        // SNI
        let sni = endpoint.sni.as_deref().unwrap_or(&endpoint.host);

        // Connect with timeout
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);
        let connecting = quinn_endpoint
            .connect(server_addr, sni)
            .map_err(|e| TransportError::ConnectionRefused(e.to_string()))?;

        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| TransportError::Timeout(self.config.connect_timeout_ms))?
            .map_err(|e| TransportError::ConnectionRefused(e.to_string()))?;

        let local_addr = quinn_endpoint.local_addr().ok();
        let remote_addr = Some(connection.remote_address());

        Ok(Box::new(QuicConnection {
            connection,
            _endpoint: quinn_endpoint,
            alive: true,
            local_addr,
            remote_addr,
        }))
    }

    fn estimated_latency(&self) -> u32 {
        20
    }

    fn supports_zero_rtt(&self) -> bool {
        self.config.enable_0rtt
    }
}

/// A live QUIC connection using a bidirectional stream.
pub struct QuicConnection {
    connection: QuinnConnection,
    _endpoint: QuinnEndpoint,
    alive: bool,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

#[async_trait]
impl Connection for QuicConnection {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let (mut send, _recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionRefused(format!("open stream: {}", e)))?;

        // Length-prefix framing
        let len_bytes = (data.len() as u32).to_be_bytes();
        send.write_all(&len_bytes)
            .await
            .map_err(|e| TransportError::ConnectionRefused(format!("write: {}", e)))?;
        send.write_all(data)
            .await
            .map_err(|e| TransportError::ConnectionRefused(format!("write: {}", e)))?;
        send.finish()
            .map_err(|e| TransportError::ConnectionRefused(format!("finish: {}", e)))?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let (_send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| {
                self.alive = false;
                TransportError::ConnectionClosed
            })?;

        // Read length prefix
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| TransportError::ConnectionRefused(format!("read len: {}", e)))?;

        let length = u32::from_be_bytes(len_buf) as usize;
        if length > 1024 * 1024 {
            self.alive = false;
            return Err(TransportError::Protocol(
                kanrin_protocol::ProtocolError::InvalidChunk("frame too large".into()),
            ));
        }

        let mut buf = vec![0u8; length];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| TransportError::ConnectionRefused(format!("read data: {}", e)))?;

        Ok(buf)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.alive = false;
        self.connection.close(0u32.into(), b"done");
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive && !self.connection.close_reason().is_some()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}
