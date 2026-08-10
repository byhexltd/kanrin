use serde::{Deserialize, Serialize};

/// Plugin manifest — describes a plugin's capabilities and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    /// What hooks this plugin implements.
    pub hooks: Vec<PluginHook>,
    /// Required permissions.
    pub permissions: Vec<PluginPermission>,
}

/// Available hook points in the pipeline where plugins can intercept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginHook {
    /// Called on each outgoing packet before encryption.
    PreEncrypt,
    /// Called on each incoming packet after decryption.
    PostDecrypt,
    /// Called when a routing decision is needed.
    RouteDecision,
    /// Called when a transport connection is established.
    OnConnect,
    /// Called when a transport connection is closed.
    OnDisconnect,
    /// Called periodically (for monitoring/metrics).
    OnTick,
}

/// Permissions that a plugin can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginPermission {
    /// Can read packet payloads.
    ReadPackets,
    /// Can modify packet payloads.
    ModifyPackets,
    /// Can influence routing decisions.
    Routing,
    /// Can access network information.
    NetworkInfo,
    /// Can write to log.
    Logging,
}

/// Data passed to plugins on each hook invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginEvent {
    Packet {
        direction: PacketDirection,
        data: Vec<u8>,
    },
    RouteQuery {
        domain: Option<String>,
        dst_ip: String,
        dst_port: u16,
    },
    ConnectionEvent {
        transport: String,
        endpoint: String,
        connected: bool,
    },
    Tick {
        uptime_secs: u64,
        bytes_tx: u64,
        bytes_rx: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PacketDirection {
    Outgoing,
    Incoming,
}

/// Response from a plugin after processing an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginResponse {
    /// No modification.
    Pass,
    /// Modified data.
    Modified { data: Vec<u8> },
    /// Drop the packet.
    Drop,
    /// Route decision override.
    Route { decision: String },
}
