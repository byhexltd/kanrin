use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Key for NAT table entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatKey {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// NAT table entry tracking a connection.
#[derive(Debug, Clone)]
pub struct NatEntry {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub state: ConnectionState,
}

/// TCP connection state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state (SYN sent).
    SynSent,
    /// Connection established.
    Established,
    /// FIN received, closing.
    Closing,
    /// Connection closed.
    Closed,
    /// UDP "connection" (stateless, timeout-based).
    Udp,
}

/// NAT table managing all active connections through the tunnel.
pub struct NatTable {
    tcp_entries: HashMap<NatKey, NatEntry>,
    udp_entries: HashMap<NatKey, NatEntry>,
    tcp_timeout: Duration,
    udp_timeout: Duration,
}

impl NatTable {
    pub fn new(tcp_timeout: Duration, udp_timeout: Duration) -> Self {
        Self {
            tcp_entries: HashMap::new(),
            udp_entries: HashMap::new(),
            tcp_timeout,
            udp_timeout,
        }
    }

    /// Look up or create an outgoing TCP connection entry.
    pub fn tcp_outgoing(&mut self, local: SocketAddr, remote: SocketAddr) -> &mut NatEntry {
        let key = NatKey { local, remote };
        self.tcp_entries.entry(key).or_insert_with(|| NatEntry {
            local_addr: local,
            remote_addr: remote,
            created_at: Instant::now(),
            last_seen: Instant::now(),
            bytes_tx: 0,
            bytes_rx: 0,
            state: ConnectionState::SynSent,
        })
    }

    /// Look up or create an outgoing UDP entry.
    pub fn udp_outgoing(&mut self, local: SocketAddr, remote: SocketAddr) -> &mut NatEntry {
        let key = NatKey { local, remote };
        self.udp_entries.entry(key).or_insert_with(|| NatEntry {
            local_addr: local,
            remote_addr: remote,
            created_at: Instant::now(),
            last_seen: Instant::now(),
            bytes_tx: 0,
            bytes_rx: 0,
            state: ConnectionState::Udp,
        })
    }

    /// Find the local address for an incoming packet (reverse NAT).
    pub fn tcp_incoming(&self, remote: SocketAddr, local: SocketAddr) -> Option<&NatEntry> {
        let key = NatKey { local, remote };
        self.tcp_entries.get(&key)
    }

    /// Find the local address for an incoming UDP packet.
    pub fn udp_incoming(&self, remote: SocketAddr, local: SocketAddr) -> Option<&NatEntry> {
        let key = NatKey { local, remote };
        self.udp_entries.get(&key)
    }

    /// Update last_seen and byte counters for a TCP entry.
    pub fn tcp_activity(&mut self, local: SocketAddr, remote: SocketAddr, bytes: u64, is_tx: bool) {
        let key = NatKey { local, remote };
        if let Some(entry) = self.tcp_entries.get_mut(&key) {
            entry.last_seen = Instant::now();
            if is_tx {
                entry.bytes_tx += bytes;
            } else {
                entry.bytes_rx += bytes;
            }
        }
    }

    /// Update TCP connection state.
    pub fn tcp_set_state(&mut self, local: SocketAddr, remote: SocketAddr, state: ConnectionState) {
        let key = NatKey { local, remote };
        if let Some(entry) = self.tcp_entries.get_mut(&key) {
            entry.state = state;
        }
    }

    /// Remove expired entries.
    pub fn cleanup(&mut self) {
        let tcp_timeout = self.tcp_timeout;
        let udp_timeout = self.udp_timeout;

        self.tcp_entries.retain(|_, entry| {
            entry.state != ConnectionState::Closed
                && entry.last_seen.elapsed() < tcp_timeout
        });

        self.udp_entries.retain(|_, entry| {
            entry.last_seen.elapsed() < udp_timeout
        });
    }

    /// Total number of tracked connections.
    pub fn connection_count(&self) -> usize {
        self.tcp_entries.len() + self.udp_entries.len()
    }

    /// Number of established TCP connections.
    pub fn tcp_established_count(&self) -> usize {
        self.tcp_entries
            .values()
            .filter(|e| e.state == ConnectionState::Established)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_nat_tcp_outgoing() {
        let mut nat = NatTable::new(Duration::from_secs(300), Duration::from_secs(60));

        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));

        let entry = nat.tcp_outgoing(local, remote);
        assert_eq!(entry.state, ConnectionState::SynSent);
        assert_eq!(nat.connection_count(), 1);
    }

    #[test]
    fn test_nat_cleanup() {
        let mut nat = NatTable::new(Duration::from_millis(1), Duration::from_millis(1));

        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));

        nat.udp_outgoing(local, remote);
        assert_eq!(nat.connection_count(), 1);

        std::thread::sleep(Duration::from_millis(5));
        nat.cleanup();
        assert_eq!(nat.connection_count(), 0);
    }
}
