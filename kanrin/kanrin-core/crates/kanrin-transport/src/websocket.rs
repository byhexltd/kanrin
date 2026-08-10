use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::TransportError;
use crate::traits::{Connection, Endpoint, ProbeResult, Transport};

/// CloudFlare Worker WebSocket transport — Priority 3.
/// Routes traffic through CF Workers to bypass IP-based blocking.
pub struct WebSocketTransport {
    config: WebSocketConfig,
}

pub struct WebSocketConfig {
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// WebSocket path (e.g. "/ws").
    pub path: String,
    /// Additional headers to send (look like a browser).
    pub extra_headers: Vec<(String, String)>,
    /// Ping interval for keepalive.
    pub ping_interval_secs: u64,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 15_000,
            path: "/ws".into(),
            extra_headers: vec![
                ("User-Agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into()),
                ("Origin".into(), "https://example.com".into()),
            ],
            ping_interval_secs: 25,
        }
    }
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(WebSocketConfig::default())
    }

    fn build_url(&self, endpoint: &Endpoint) -> String {
        format!("wss://{}:{}{}", endpoint.host, endpoint.port, self.config.path)
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    fn name(&self) -> &str {
        "websocket"
    }

    fn priority(&self) -> u8 {
        3
    }

    async fn probe(&self, endpoint: &Endpoint) -> ProbeResult {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        let url = self.build_url(endpoint);
        match tokio::time::timeout(timeout, connect_async(&url)).await {
            Ok(Ok((mut ws, _response))) => {
                let latency = start.elapsed().as_millis() as u32;
                let _ = ws.close(None).await;
                ProbeResult::Available { latency_ms: latency }
            }
            Ok(Err(e)) => ProbeResult::Blocked {
                reason: format!("websocket connect failed: {}", e),
            },
            Err(_) => ProbeResult::Blocked {
                reason: "websocket connect timeout".into(),
            },
        }
    }

    async fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Connection>, TransportError> {
        let url = self.build_url(endpoint);
        let timeout = Duration::from_millis(self.config.connect_timeout_ms);

        let (ws_stream, _response) = tokio::time::timeout(timeout, connect_async(&url))
            .await
            .map_err(|_| TransportError::Timeout(self.config.connect_timeout_ms))?
            .map_err(|e| TransportError::ConnectionRefused(format!("websocket: {}", e)))?;

        let (write, read) = ws_stream.split();

        Ok(Box::new(WebSocketConnection {
            write,
            read,
            alive: true,
        }))
    }

    fn estimated_latency(&self) -> u32 {
        60
    }

    fn supports_zero_rtt(&self) -> bool {
        false
    }
}

/// A live WebSocket connection.
pub struct WebSocketConnection {
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    alive: bool,
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.write
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(|e| {
                self.alive = false;
                TransportError::ConnectionRefused(format!("ws send: {}", e))
            })?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            match self.read.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(data.to_vec()),
                Some(Ok(Message::Ping(_))) => {
                    // Handled automatically by tungstenite
                    continue;
                }
                Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) => {
                    self.alive = false;
                    return Err(TransportError::ConnectionClosed);
                }
                Some(Ok(_)) => continue, // Skip text/other frames
                Some(Err(e)) => {
                    self.alive = false;
                    return Err(TransportError::ConnectionRefused(format!("ws recv: {}", e)));
                }
                None => {
                    self.alive = false;
                    return Err(TransportError::ConnectionClosed);
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.alive = false;
        let _ = self.write.close().await;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        None // WebSocket doesn't easily expose this
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}
