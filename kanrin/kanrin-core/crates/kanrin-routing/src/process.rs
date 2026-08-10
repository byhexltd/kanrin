use std::net::SocketAddr;

/// Detect which process owns a given socket (for per-app routing).
pub trait ProcessDetector: Send + Sync {
    /// Get the process name and path for a given local socket.
    fn detect(&self, local_addr: SocketAddr) -> Option<ProcessInfo>;
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

/// Platform-specific process detector.
pub struct NativeProcessDetector;

impl NativeProcessDetector {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(windows)]
impl ProcessDetector for NativeProcessDetector {
    fn detect(&self, local_addr: SocketAddr) -> Option<ProcessInfo> {
        // Windows: Use GetExtendedTcpTable / GetExtendedUdpTable
        // to map a local socket address to a PID, then OpenProcess + QueryFullProcessImageName
        // TODO: Implement with windows-sys crate
        None
    }
}

#[cfg(target_os = "linux")]
impl ProcessDetector for NativeProcessDetector {
    fn detect(&self, local_addr: SocketAddr) -> Option<ProcessInfo> {
        // Linux: Read /proc/net/tcp (or /proc/net/tcp6) to find inode,
        // then scan /proc/*/fd/ to find which PID owns that inode,
        // then read /proc/PID/comm for process name.
        // TODO: Implement
        None
    }
}

#[cfg(target_os = "macos")]
impl ProcessDetector for NativeProcessDetector {
    fn detect(&self, local_addr: SocketAddr) -> Option<ProcessInfo> {
        // macOS: Use proc_pidinfo or lsof equivalent
        // TODO: Implement
        None
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl ProcessDetector for NativeProcessDetector {
    fn detect(&self, _local_addr: SocketAddr) -> Option<ProcessInfo> {
        None
    }
}
