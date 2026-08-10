use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level Kanrin client configuration.
/// Designed for zero-config defaults with extensive advanced options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KanrinConfig {
    /// Server connection details (minimal required config).
    pub server: ServerConfig,

    /// Transport configuration.
    #[serde(default)]
    pub transport: TransportConfig,

    /// TUN device configuration.
    #[serde(default)]
    pub tun: TunSettings,

    /// Routing configuration.
    #[serde(default)]
    pub routing: RoutingConfig,

    /// Stealth features.
    #[serde(default)]
    pub stealth: StealthConfig,

    /// Self-healing engine settings.
    #[serde(default)]
    pub engine: EngineConfig,

    /// Plugin configuration.
    #[serde(default)]
    pub plugins: PluginsConfig,

    /// Logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Minimal server configuration (the 3-line config for basic users).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server address (hostname or IP).
    pub address: String,
    /// Server port.
    pub port: u16,
    /// Authentication password.
    pub password: String,
    /// Optional: override SNI for TLS.
    pub sni: Option<String>,
}

/// Transport layer settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Preferred transport order. Empty = auto-detect.
    #[serde(default)]
    pub preferred: Vec<String>,
    /// Enable auto-switching between transports.
    #[serde(default = "default_true")]
    pub auto_switch: bool,
    /// QUIC-specific settings.
    #[serde(default)]
    pub quic: QuicSettings,
    /// TLS-specific settings.
    #[serde(default)]
    pub tls: TlsSettings,
    /// WebSocket-specific settings.
    #[serde(default)]
    pub websocket: WsSettings,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            preferred: vec![],
            auto_switch: true,
            quic: QuicSettings::default(),
            tls: TlsSettings::default(),
            websocket: WsSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicSettings {
    pub enable_0rtt: Option<bool>,
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsSettings {
    pub alpn: Option<Vec<String>>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsSettings {
    pub path: Option<String>,
    pub host: Option<String>,
}

/// TUN device settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunSettings {
    /// TUN device name.
    #[serde(default = "default_tun_name")]
    pub name: String,
    /// TUN IP address.
    #[serde(default = "default_tun_address")]
    pub address: String,
    /// MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Enable kill switch.
    #[serde(default = "default_true")]
    pub kill_switch: bool,
    /// Allow LAN access when kill switch is active.
    #[serde(default = "default_true")]
    pub allow_lan: bool,
    /// Enable FakeIP DNS.
    #[serde(default)]
    pub fake_ip: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            address: default_tun_address(),
            mtu: default_mtu(),
            kill_switch: true,
            allow_lan: true,
            fake_ip: false,
        }
    }
}

/// Routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Default route action for unmatched traffic.
    #[serde(default = "default_proxy")]
    pub default_action: String,
    /// Enable Iran bypass preset.
    #[serde(default = "default_true")]
    pub iran_preset: bool,
    /// Custom domain rules.
    #[serde(default)]
    pub domains: Vec<DomainRuleConfig>,
    /// Custom IP rules.
    #[serde(default)]
    pub ips: Vec<IpRuleConfig>,
    /// Process-based routing.
    #[serde(default)]
    pub processes: Vec<ProcessRuleConfig>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_action: "proxy".into(),
            iran_preset: true,
            domains: vec![],
            ips: vec![],
            processes: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRuleConfig {
    pub pattern: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRuleConfig {
    pub cidr: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRuleConfig {
    pub names: Vec<String>,
    pub action: String,
}

/// Stealth settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    /// Traffic pattern to mimic.
    #[serde(default = "default_pattern")]
    pub traffic_pattern: String,
    /// Enable TLS record fragmentation.
    #[serde(default = "default_true")]
    pub fragment: bool,
    /// Fragment size range.
    #[serde(default)]
    pub fragment_size: Option<(usize, usize)>,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            traffic_pattern: "adaptive".into(),
            fragment: true,
            fragment_size: None,
        }
    }
}

/// Self-healing engine settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Probe interval in seconds.
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: u64,
    /// Score threshold for switching.
    #[serde(default = "default_threshold")]
    pub switch_threshold: f64,
    /// Minimum seconds between transport switches.
    #[serde(default = "default_cooldown")]
    pub switch_cooldown_secs: u64,
    /// Enable network detection on startup.
    #[serde(default = "default_true")]
    pub detect_censorship: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            probe_interval_secs: 30,
            switch_threshold: 5.0,
            switch_cooldown_secs: 10,
            detect_censorship: true,
        }
    }
}

/// Plugin settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginsConfig {
    /// Paths to .wasm plugin files.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Enable plugin system.
    #[serde(default)]
    pub enabled: bool,
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log output file (None = stderr).
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            file: None,
        }
    }
}

// Default value functions for serde
fn default_true() -> bool { true }
fn default_tun_name() -> String { "kanrin0".into() }
fn default_tun_address() -> String { "10.10.0.2".into() }
fn default_mtu() -> u16 { 1400 }
fn default_proxy() -> String { "proxy".into() }
fn default_pattern() -> String { "adaptive".into() }
fn default_probe_interval() -> u64 { 30 }
fn default_threshold() -> f64 { 5.0 }
fn default_cooldown() -> u64 { 10 }
fn default_log_level() -> String { "info".into() }

impl KanrinConfig {
    /// Minimal configuration for basic users.
    pub fn minimal(address: &str, port: u16, password: &str) -> Self {
        Self {
            server: ServerConfig {
                address: address.into(),
                port,
                password: password.into(),
                sni: None,
            },
            transport: TransportConfig::default(),
            tun: TunSettings::default(),
            routing: RoutingConfig::default(),
            stealth: StealthConfig::default(),
            engine: EngineConfig::default(),
            plugins: PluginsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }

    /// Load config from YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read config: {}", e))?;
        serde_yaml::from_str(&content)
            .map_err(|e| format!("parse config: {}", e))
    }

    /// Save config to YAML file.
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| format!("serialize config: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("write config: {}", e))
    }
}
