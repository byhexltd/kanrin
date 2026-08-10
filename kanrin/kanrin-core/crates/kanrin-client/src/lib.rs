pub mod config;
pub mod pipeline;
pub mod events;
pub mod ffi;

use std::sync::Arc;

use config::KanrinConfig;
use events::KanrinEvent;
use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};

/// Current state of the Kanrin VPN client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error,
}

/// Public API — the single entry point for controlling Kanrin.
pub struct KanrinClient {
    state: Arc<RwLock<ClientState>>,
    config: Arc<RwLock<KanrinConfig>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    event_rx: Option<mpsc::UnboundedReceiver<KanrinEvent>>,
    event_tx: mpsc::UnboundedSender<KanrinEvent>,
    runtime: Option<tokio::runtime::Runtime>,
}

/// Statistics about the current connection.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime_secs: u64,
    pub current_transport: String,
    pub current_endpoint: String,
    pub latency_ms: u32,
    pub transport_switches: u32,
}

impl KanrinClient {
    /// Create a new client instance (does not connect).
    pub fn new(config: KanrinConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            config: Arc::new(RwLock::new(config)),
            shutdown_tx: None,
            event_rx: Some(event_rx),
            event_tx,
            runtime: None,
        }
    }

    /// Start the VPN connection. Non-blocking — returns immediately.
    pub fn start(&mut self) -> Result<(), ClientError> {
        let current_state = *self.state.read();
        if current_state != ClientState::Disconnected {
            return Err(ClientError::InvalidState(format!(
                "cannot start from state {:?}",
                current_state
            )));
        }

        *self.state.write() = ClientState::Connecting;
        self.event_tx.send(KanrinEvent::StateChanged(ClientState::Connecting)).ok();

        // Create runtime if needed
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("kanrin-worker")
            .build()
            .map_err(|e| ClientError::Internal(format!("runtime: {}", e)))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let state = self.state.clone();
        let config = self.config.clone();
        let event_tx = self.event_tx.clone();

        rt.spawn(async move {
            match pipeline::run_pipeline(config, state.clone(), event_tx.clone(), shutdown_rx).await {
                Ok(()) => {
                    *state.write() = ClientState::Disconnected;
                    event_tx.send(KanrinEvent::StateChanged(ClientState::Disconnected)).ok();
                }
                Err(e) => {
                    tracing::error!(error = %e, "pipeline error");
                    *state.write() = ClientState::Error;
                    event_tx.send(KanrinEvent::Error(e.to_string())).ok();
                }
            }
        });

        self.runtime = Some(rt);
        Ok(())
    }

    /// Stop the VPN connection gracefully.
    pub fn stop(&mut self) -> Result<(), ClientError> {
        let current_state = *self.state.read();
        if current_state == ClientState::Disconnected {
            return Ok(());
        }

        *self.state.write() = ClientState::Disconnecting;
        self.event_tx.send(KanrinEvent::StateChanged(ClientState::Disconnecting)).ok();

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for runtime to finish
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }

        *self.state.write() = ClientState::Disconnected;
        self.event_tx.send(KanrinEvent::StateChanged(ClientState::Disconnected)).ok();
        Ok(())
    }

    /// Get current client state.
    pub fn state(&self) -> ClientState {
        *self.state.read()
    }

    /// Get the event receiver (for UI updates).
    pub fn take_events(&mut self) -> Option<mpsc::UnboundedReceiver<KanrinEvent>> {
        self.event_rx.take()
    }

    /// Update configuration (takes effect on next reconnect).
    pub fn update_config(&self, config: KanrinConfig) {
        *self.config.write() = config;
    }

    /// Get current configuration.
    pub fn config(&self) -> KanrinConfig {
        self.config.read().clone()
    }
}

impl Drop for KanrinClient {
    fn drop(&mut self) {
        if *self.state.read() != ClientState::Disconnected {
            let _ = self.stop();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("configuration error: {0}")]
    Config(String),
}
