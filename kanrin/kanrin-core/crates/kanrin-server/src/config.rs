use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Server configuration — minimal 3-line config for operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address and port.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Authentication password (shared secret with clients).
    pub password: String,

    /// TLS certificate file (PEM).
    pub tls_cert: PathBuf,

    /// TLS private key file (PEM).
    pub tls_key: PathBuf,

    /// Maximum concurrent clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// TUN subnet for assigning client IPs (e.g. "10.10.0.0/24").
    #[serde(default = "default_subnet")]
    pub subnet: String,

    /// DNS servers to use for forwarding.
    #[serde(default = "default_dns")]
    pub dns: Vec<String>,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}

fn default_max_clients() -> usize {
    256
}

fn default_log_level() -> String {
    "info".into()
}

fn default_subnet() -> String {
    "10.10.0.0/24".into()
}

fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

impl ServerConfig {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
