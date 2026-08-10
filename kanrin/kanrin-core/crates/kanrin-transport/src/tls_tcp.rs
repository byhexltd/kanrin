use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::TransportError;
use crate::traits::{Connection, Endpoint, ProbeResult, Transport};

/// Custom certificate verifier that accepts any certificate (for self-signed certs).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS/TCP transport — Priority 2 (direct, reliable, works when UDP blocked).
pub struct TlsTcpTransport {
    config: TlsTcpConfig,
}

pub struct TlsTcpConfig {
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Enable TCP keepalive.
    pub keepalive: bool,
    /// Keepalive interval in seconds.
    pub keepalive_interval_secs: u64,
    /// TLS ALPN protocols to advertise.
    pub alpn: Vec<String>,
    /// Skip TLS certificate verification (for self-signed certs).
    pub skip_cert_verify: bool,
}

impl Default for TlsTcpConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            keepalive: true,
            keepalive_interval_secs: 30,
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: true,
        }
    }
}

impl TlsTcpTransport {
    pub fn new(config: TlsTcpConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(TlsTcpConfig::default())
    }

    fn build_tls_config(&self) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        let mut config = if self.config.skip_cert_verify {
            let mut cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
                .with_no_client_auth();
            cfg
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Set ALPN protocols
        config.alpn_protocols = self
            .config
            .alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        Ok(Arc::new(config))
    }
}

#[async_trait]
impl Transport for TlsTcpTransport {
    fn name(&self) -> &str {
        "tls-tcp"
    }

    fn priority(&self) -> u8 {
        2
    }

    async fn probe(&self, endpoint: &Endpoint) -> ProbeResult {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        match tokio::time::timeout(timeout, TcpStream::connect(endpoint.addr_string())).await {
            Ok(Ok(_stream)) => {
                let latency = start.elapsed().as_millis() as u32;
                ProbeResult::Available { latency_ms: latency }
            }
            Ok(Err(e)) => ProbeResult::Blocked {
                reason: format!("tcp connect failed: {}", e),
            },
            Err(_) => ProbeResult::Blocked {
                reason: "tcp connect timeout".into(),
            },
        }
    }

    async fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Connection>, TransportError> {
        let tls_config = self.build_tls_config()?;
        let connector = TlsConnector::from(tls_config);

        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        // TCP connection
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(endpoint.addr_string()))
            .await
            .map_err(|_| TransportError::Timeout(self.config.connect_timeout_ms))?
            .map_err(|e| TransportError::ConnectionRefused(e.to_string()))?;

        // Set TCP keepalive
        if self.config.keepalive {
            let socket = socket2::SockRef::from(&tcp_stream);
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(self.config.keepalive_interval_secs));
            let _ = socket.set_tcp_keepalive(&keepalive);
        }

        // Determine SNI
        let sni = endpoint
            .sni
            .as_deref()
            .unwrap_or(&endpoint.host);
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| TransportError::Tls(format!("invalid SNI: {}", e)))?;

        // TLS handshake
        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| TransportError::Timeout(self.config.connect_timeout_ms))?
            .map_err(|e| TransportError::Tls(format!("handshake failed: {}", e)))?;

        let local_addr = tls_stream.get_ref().0.local_addr().ok();
        let remote_addr = tls_stream.get_ref().0.peer_addr().ok();

        Ok(Box::new(TlsTcpConnection {
            stream: tls_stream,
            alive: true,
            local_addr,
            remote_addr,
            read_buf: Vec::new(),
        }))
    }

    fn estimated_latency(&self) -> u32 {
        40
    }

    fn supports_zero_rtt(&self) -> bool {
        false
    }
}

/// A live TLS/TCP connection.
pub struct TlsTcpConnection {
    stream: TlsStream<TcpStream>,
    alive: bool,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    /// Bytes received but not yet forming a complete frame.
    ///
    /// Partial frames must live here rather than inside the `recv` future,
    /// otherwise dropping that future (e.g. a losing `select!` branch) discards
    /// them and permanently desynchronises the length-prefixed framing.
    read_buf: Vec<u8>,
}

#[async_trait]
impl Connection for TlsTcpConnection {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        // Length-prefix framing: [u32 big-endian length][data]
        let len_bytes = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one length-prefixed frame: `[u32 big-endian length][data]`.
    ///
    /// Cancel-safe: progress is kept in `self.read_buf`, and the only await
    /// point is a single `read` call, which consumes nothing if it is dropped
    /// while still pending.
    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut chunk = [0u8; 16 * 1024];

        loop {
            // Serve a frame from the buffer as soon as one is complete.
            if self.read_buf.len() >= 4 {
                let length = u32::from_be_bytes([
                    self.read_buf[0],
                    self.read_buf[1],
                    self.read_buf[2],
                    self.read_buf[3],
                ]) as usize;

                if length > 1024 * 1024 {
                    // Sanity check: reject frames > 1MB
                    self.alive = false;
                    return Err(TransportError::Protocol(
                        kanrin_protocol::ProtocolError::InvalidChunk("frame too large".into()),
                    ));
                }

                if self.read_buf.len() >= 4 + length {
                    let frame = self.read_buf[4..4 + length].to_vec();
                    self.read_buf.drain(..4 + length);
                    return Ok(frame);
                }
            }

            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                self.alive = false;
                return Err(TransportError::ConnectionClosed);
            }

            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.alive = false;
        self.stream.shutdown().await?;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}
