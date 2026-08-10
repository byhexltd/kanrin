use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::TransportError;

/// Result of probing a transport's availability.
#[derive(Debug, Clone)]
pub enum ProbeResult {
    Available { latency_ms: u32 },
    Blocked { reason: String },
    Unknown,
}

/// Remote endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// Override SNI for TLS connections (stealth).
    pub sni: Option<String>,
    /// Expected server certificate fingerprint (pin).
    pub fingerprint: Option<String>,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            sni: None,
            fingerprint: None,
        }
    }

    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Core transport trait. Every transport (QUIC, TLS, WS, etc.) implements this.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Human-readable transport name (for logging/UI).
    fn name(&self) -> &str;

    /// Priority (lower = preferred). Used by auto-select.
    fn priority(&self) -> u8;

    /// Probe whether this transport can reach the server.
    async fn probe(&self, endpoint: &Endpoint) -> ProbeResult;

    /// Establish a connection to the endpoint.
    async fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Connection>, TransportError>;

    /// Estimated additional latency (ms) over a direct connection.
    fn estimated_latency(&self) -> u32;

    /// Whether this transport supports 0-RTT reconnection.
    fn supports_zero_rtt(&self) -> bool;
}

/// A live connection through a transport.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send data through the connection.
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Receive data from the connection.
    async fn recv(&mut self) -> Result<Vec<u8>, TransportError>;

    /// Close the connection gracefully.
    async fn close(&mut self) -> Result<(), TransportError>;

    /// Check if the connection is still alive.
    fn is_alive(&self) -> bool;

    /// Local address (if known).
    fn local_addr(&self) -> Option<SocketAddr>;

    /// Remote address (if known).
    fn remote_addr(&self) -> Option<SocketAddr>;
}

/// Registry of all available transports, sorted by priority.
pub struct TransportRegistry {
    transports: Vec<Box<dyn Transport>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Register a transport.
    pub fn register(&mut self, transport: Box<dyn Transport>) {
        self.transports.push(transport);
        self.transports.sort_by_key(|t| t.priority());
    }

    /// Get all registered transports (sorted by priority).
    pub fn all(&self) -> &[Box<dyn Transport>] {
        &self.transports
    }

    /// Try each transport in priority order, return first working connection.
    pub async fn auto_connect(&self, endpoint: &Endpoint) -> Result<(Box<dyn Connection>, &str), TransportError> {
        let mut last_error = None;

        for transport in &self.transports {
            match transport.connect(endpoint).await {
                Ok(conn) => return Ok((conn, transport.name())),
                Err(e) => {
                    tracing::debug!(
                        transport = transport.name(),
                        error = %e,
                        "transport connect failed, trying next"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(TransportError::Blocked("no transports available".into())))
    }

    /// Probe all transports and return results.
    pub async fn probe_all(&self, endpoint: &Endpoint) -> Vec<(&str, ProbeResult)> {
        let mut results = Vec::new();
        for transport in &self.transports {
            let result = transport.probe(endpoint).await;
            results.push((transport.name(), result));
        }
        results
    }
}
