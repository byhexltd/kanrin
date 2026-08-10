use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// DNS cache entry.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

/// DNS interceptor that captures all DNS queries and routes them through the tunnel.
/// Also implements FakeIP mode for improved routing.
pub struct DnsInterceptor {
    /// Domain -> IP cache
    cache: HashMap<String, DnsCacheEntry>,
    /// FakeIP pool (198.18.0.0/16 by default)
    fake_ip_pool: FakeIpPool,
    /// Whether FakeIP mode is enabled
    fake_ip_enabled: bool,
    /// Maximum cache entries
    max_cache_size: usize,
}

impl DnsInterceptor {
    pub fn new(fake_ip_enabled: bool) -> Self {
        Self {
            cache: HashMap::new(),
            fake_ip_pool: FakeIpPool::new(),
            fake_ip_enabled,
            max_cache_size: 4096,
        }
    }

    /// Process a DNS query packet. Returns a fake response if FakeIP is enabled,
    /// or None if the query should be forwarded through the tunnel.
    pub fn intercept_query(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let domain = parse_dns_query_domain(query)?;

        // Check cache first
        if let Some(entry) = self.cache.get(&domain) {
            if entry.expires_at > Instant::now() {
                // Cache hit — build response from cached data
                return Some(build_dns_response(query, &entry.addresses));
            }
        }

        if self.fake_ip_enabled {
            // Allocate a fake IP and return immediately
            let fake_ip = self.fake_ip_pool.allocate(&domain);
            let response = build_dns_response(query, &[IpAddr::V4(fake_ip)]);
            return Some(response);
        }

        // No FakeIP — query must be forwarded through tunnel
        None
    }

    /// Cache a real DNS response (after tunnel resolves it).
    pub fn cache_response(&mut self, domain: &str, addresses: Vec<IpAddr>, ttl_secs: u32) {
        if self.cache.len() >= self.max_cache_size {
            // Evict oldest entries
            self.evict_expired();
        }

        self.cache.insert(domain.to_string(), DnsCacheEntry {
            addresses,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs as u64),
        });
    }

    /// Resolve a FakeIP back to its domain name.
    pub fn resolve_fake_ip(&self, ip: Ipv4Addr) -> Option<&str> {
        self.fake_ip_pool.lookup(ip)
    }

    /// Remove expired cache entries.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| entry.expires_at > now);
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// FakeIP pool that maps domains to IPs in the 198.18.0.0/15 range.
pub struct FakeIpPool {
    /// Domain -> FakeIP mapping
    domain_to_ip: HashMap<String, Ipv4Addr>,
    /// FakeIP -> Domain reverse mapping
    ip_to_domain: HashMap<Ipv4Addr, String>,
    /// Next IP to allocate
    next_ip: u32,
    /// Pool start (198.18.0.1)
    pool_start: u32,
    /// Pool end (198.19.255.254)
    pool_end: u32,
}

impl FakeIpPool {
    pub fn new() -> Self {
        let start = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let end = u32::from(Ipv4Addr::new(198, 19, 255, 254));
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            next_ip: start,
            pool_start: start,
            pool_end: end,
        }
    }

    /// Allocate a fake IP for a domain (or return existing).
    pub fn allocate(&mut self, domain: &str) -> Ipv4Addr {
        if let Some(&ip) = self.domain_to_ip.get(domain) {
            return ip;
        }

        let ip = Ipv4Addr::from(self.next_ip);
        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_domain.insert(ip, domain.to_string());

        self.next_ip += 1;
        if self.next_ip > self.pool_end {
            // Wrap around (evict oldest)
            self.next_ip = self.pool_start;
        }

        ip
    }

    /// Look up domain from fake IP.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_domain.get(&ip).map(|s| s.as_str())
    }
}

/// Parse the queried domain name from a raw DNS query packet.
fn parse_dns_query_domain(packet: &[u8]) -> Option<String> {
    // DNS header is 12 bytes
    if packet.len() < 12 {
        return None;
    }

    let mut pos = 12; // Start of question section
    let mut domain_parts = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos] as usize;
        if label_len == 0 {
            break; // End of domain name
        }

        pos += 1;
        if pos + label_len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + label_len]).ok()?;
        domain_parts.push(label.to_string());
        pos += label_len;
    }

    if domain_parts.is_empty() {
        return None;
    }

    Some(domain_parts.join("."))
}

/// Build a minimal DNS response with A records.
fn build_dns_response(query: &[u8], addresses: &[IpAddr]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }

    let mut response = query.to_vec();

    // Set response flags: QR=1, AA=1, RA=1
    response[2] = 0x81; // QR=1, OPCODE=0, AA=0, TC=0, RD=1
    response[3] = 0x80; // RA=1, RCODE=0 (no error)

    // Set answer count
    let answer_count = addresses.iter().filter(|a| a.is_ipv4()).count() as u16;
    response[6] = (answer_count >> 8) as u8;
    response[7] = (answer_count & 0xFF) as u8;

    // Find end of question section
    let mut pos = 12;
    while pos < response.len() && response[pos] != 0 {
        pos += response[pos] as usize + 1;
    }
    pos += 5; // Skip null byte + QTYPE(2) + QCLASS(2)

    // Append A record answers
    for addr in addresses {
        if let IpAddr::V4(ipv4) = addr {
            // Name pointer to question (0xC00C = pointer to offset 12)
            response.push(0xC0);
            response.push(0x0C);
            // Type A (1)
            response.push(0x00);
            response.push(0x01);
            // Class IN (1)
            response.push(0x00);
            response.push(0x01);
            // TTL (60 seconds)
            response.push(0x00);
            response.push(0x00);
            response.push(0x00);
            response.push(0x3C);
            // RDLENGTH (4 for IPv4)
            response.push(0x00);
            response.push(0x04);
            // RDATA (IP address)
            let octets = ipv4.octets();
            response.extend_from_slice(&octets);
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_domain() {
        // Raw DNS query for "example.com"
        #[rustfmt::skip]
        let query: Vec<u8> = vec![
            // Header (12 bytes)
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];

        let domain = parse_dns_query_domain(&query).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_fake_ip_pool() {
        let mut pool = FakeIpPool::new();

        let ip1 = pool.allocate("google.com");
        let ip2 = pool.allocate("facebook.com");
        let ip3 = pool.allocate("google.com"); // Should return same as ip1

        assert_ne!(ip1, ip2);
        assert_eq!(ip1, ip3);
        assert_eq!(pool.lookup(ip1), Some("google.com"));
        assert_eq!(pool.lookup(ip2), Some("facebook.com"));
    }

    #[test]
    fn test_dns_interceptor_fakeip() {
        let mut interceptor = DnsInterceptor::new(true);

        #[rustfmt::skip]
        let query: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        ];

        let response = interceptor.intercept_query(&query);
        assert!(response.is_some());
    }
}
