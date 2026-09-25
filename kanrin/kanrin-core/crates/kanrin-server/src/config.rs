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

    /// Real origin to forward front-door requests to, e.g. `"127.0.0.1:8080"`
    /// (Phase 17.1.5).
    ///
    /// Strongly preferred over `site_root`: the responses then *are* a real
    /// server's, rather than an imitation that has to be kept current.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Directory to serve when no `upstream` is configured (17.1.4).
    #[serde(default)]
    pub site_root: Option<PathBuf>,

    /// `Server:` banner for locally generated responses. Ignored when an
    /// upstream is configured, since those responses carry the origin's own.
    #[serde(default = "default_server_banner")]
    pub server_banner: String,
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

fn default_server_banner() -> String {
    "nginx".into()
}

impl ServerConfig {
    /// Resolve the configured content source (17.1.3).
    ///
    /// One source for every client — there is deliberately no way to express
    /// "this content for probers, that content for clients", because such a
    /// setting would be exactly the divergence Phase 17.1 exists to remove.
    pub fn origin(&self) -> crate::origin::Origin {
        match (&self.upstream, &self.site_root) {
            (Some(addr), _) => crate::origin::Origin::Upstream { addr: addr.clone() },
            (None, Some(root)) => crate::origin::Origin::Static {
                root: root.clone(),
                server_banner: self.server_banner.clone(),
            },
            (None, None) => crate::origin::Origin::Empty,
        }
    }
}

impl ServerConfig {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
