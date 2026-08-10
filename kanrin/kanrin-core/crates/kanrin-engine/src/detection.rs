use std::time::Duration;

/// Detected network censorship state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensorshipState {
    /// No censorship detected — all transports work.
    None,
    /// UDP is blocked/throttled — QUIC won't work.
    UdpBlocked,
    /// SNI filtering active — need to fragment or disguise.
    SniFiltering,
    /// IP-based blocking — need CDN/CF Workers.
    IpBlocked,
    /// HTTP/HTTPS intercepted — deep inspection active.
    DpiActive,
    /// DNS poisoned — need DoH/encrypted DNS.
    DnsPoisoned,
    /// Near-total shutdown — only DNS tunnel or pre-established connections work.
    TotalShutdown,
    /// Unknown state.
    Unknown,
}

/// Result of network detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub state: CensorshipState,
    pub udp_available: bool,
    pub tcp_available: bool,
    pub dns_clean: bool,
    pub details: String,
}

/// Network detection engine — determines what kind of censorship is active.
pub struct NetworkDetector {
    /// Test endpoint for UDP (QUIC).
    pub quic_test_endpoint: String,
    /// Test endpoint for TCP/TLS.
    pub tls_test_endpoint: String,
    /// Timeout for each test.
    pub test_timeout: Duration,
}

impl NetworkDetector {
    pub fn new() -> Self {
        Self {
            quic_test_endpoint: "1.1.1.1:443".into(),
            tls_test_endpoint: "1.1.1.1:443".into(),
            test_timeout: Duration::from_secs(5),
        }
    }

    /// Run all detection tests and determine censorship state.
    /// `server_addr` is the actual VPN server address to test UDP against.
    pub async fn detect(&self) -> DetectionResult {
        let udp_available = self.test_udp(&self.quic_test_endpoint).await;
        let tcp_available = self.test_tcp().await;
        let dns_clean = self.test_dns().await;

        let state = self.classify(udp_available, tcp_available, dns_clean);
        let details = self.describe_state(state, udp_available, tcp_available, dns_clean);

        tracing::info!(
            state = ?state,
            udp = udp_available,
            tcp = tcp_available,
            dns = dns_clean,
            "network detection complete"
        );

        DetectionResult {
            state,
            udp_available,
            tcp_available,
            dns_clean,
            details,
        }
    }

    fn classify(&self, udp: bool, tcp: bool, dns: bool) -> CensorshipState {
        match (udp, tcp, dns) {
            (true, true, true) => CensorshipState::None,
            (false, true, true) => CensorshipState::UdpBlocked,
            (_, true, false) => CensorshipState::DnsPoisoned,
            (_, false, _) => CensorshipState::TotalShutdown,
            _ => CensorshipState::Unknown,
        }
    }

    fn describe_state(&self, state: CensorshipState, udp: bool, tcp: bool, dns: bool) -> String {
        format!(
            "state={:?}, udp={}, tcp={}, dns={}",
            state, udp, tcp, dns
        )
    }

    async fn test_udp(&self, target: &str) -> bool {
        // Try to send a UDP packet to the target and get a response
        let result = tokio::time::timeout(
            self.test_timeout,
            self.udp_ping(target),
        )
        .await;

        matches!(result, Ok(true))
    }

    async fn test_tcp(&self) -> bool {
        let result = tokio::time::timeout(
            self.test_timeout,
            tokio::net::TcpStream::connect(&self.tls_test_endpoint),
        )
        .await;

        matches!(result, Ok(Ok(_)))
    }

    async fn test_dns(&self) -> bool {
        // Test if DNS resolution returns correct results
        let result = tokio::time::timeout(
            self.test_timeout,
            tokio::net::lookup_host("cloudflare.com:443"),
        )
        .await;

        match result {
            Ok(Ok(mut addrs)) => addrs.next().is_some(),
            _ => false,
        }
    }

    async fn udp_ping(&self, addr: &str) -> bool {
        // Send a UDP packet to the actual server to check if UDP path is open.
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return false,
        };

        if socket.connect(addr).await.is_err() {
            return false;
        }

        // Send a small probe packet (server will ignore it, but we check if
        // the OS/firewall lets us send and potentially receive ICMP unreachable)
        let probe = [0u8; 1];
        if socket.send(&probe).await.is_err() {
            return false;
        }

        // Also test via DNS on UDP as a secondary check
        let dns_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return false,
        };

        if dns_socket.connect("1.1.1.1:53").await.is_err() {
            return false;
        }

        // Minimal DNS query for cloudflare.com A record
        let dns_query: Vec<u8> = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0A, b'c', b'l', b'o',
            b'u', b'd', b'f', b'l', b'a', b'r', b'e', 0x03,
            b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        if dns_socket.send(&dns_query).await.is_err() {
            return false;
        }

        let mut buf = [0u8; 1024];
        match tokio::time::timeout(self.test_timeout, dns_socket.recv(&mut buf)).await {
            Ok(Ok(n)) => n > 0,
            _ => false,
        }
    }

    /// Suggest the best transport based on detected state.
    pub fn suggest_transport(&self, state: CensorshipState) -> Vec<&'static str> {
        match state {
            CensorshipState::None => vec!["quic", "tls-tcp"],
            CensorshipState::UdpBlocked => vec!["tls-tcp", "websocket"],
            CensorshipState::SniFiltering => vec!["tls-tcp", "websocket"], // + fragment
            CensorshipState::IpBlocked => vec!["websocket"], // CF Workers
            CensorshipState::DpiActive => vec!["websocket"], // + stealth
            CensorshipState::DnsPoisoned => vec!["quic", "tls-tcp"], // + DoH
            CensorshipState::TotalShutdown => vec!["websocket"], // Only CF
            CensorshipState::Unknown => vec!["tls-tcp", "websocket"],
        }
    }
}
