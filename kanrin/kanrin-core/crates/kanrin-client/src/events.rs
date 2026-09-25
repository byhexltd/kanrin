use crate::ClientState;

/// Events emitted by Kanrin client for UI/logging consumption.
#[derive(Debug, Clone)]
pub enum KanrinEvent {
    /// Client state changed.
    StateChanged(ClientState),

    /// Successfully connected.
    Connected {
        transport: String,
        endpoint: String,
        latency_ms: u32,
    },

    /// Connection dropped, attempting reconnect.
    Reconnecting {
        reason: String,
        attempt: u32,
    },

    /// Transport was switched automatically.
    TransportSwitched {
        from: String,
        to: String,
        reason: String,
    },

    /// Adaptive posture changed (16.4.6).
    ///
    /// Reported as a normal state change, not a warning: escalating is the
    /// client working as intended, and labelling it as a problem would push
    /// users to disable the thing protecting them.
    PostureChanged {
        from: String,
        to: String,
        reason: String,
    },

    /// Censorship detection result.
    CensorshipDetected {
        state: String,
        suggested_transports: Vec<String>,
    },

    /// Traffic statistics update (emitted periodically).
    StatsUpdate {
        bytes_sent: u64,
        bytes_received: u64,
        uptime_secs: u64,
        latency_ms: u32,
    },

    /// Kill switch activated/deactivated.
    KillSwitchChanged {
        active: bool,
    },

    /// An error occurred.
    Error(String),

    /// A warning (non-fatal).
    Warning(String),

    /// Log message (for debug purposes).
    Log {
        level: String,
        message: String,
    },
}
