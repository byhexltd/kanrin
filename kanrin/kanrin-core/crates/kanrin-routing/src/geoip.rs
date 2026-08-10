use std::net::IpAddr;

/// Country code (ISO 3166-1 alpha-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    pub fn new(code: &str) -> Option<Self> {
        if code.len() != 2 {
            return None;
        }
        let bytes = code.as_bytes();
        Some(Self([bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()]))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("??")
    }

    pub fn iran() -> Self {
        Self([b'I', b'R'])
    }
}

/// GeoIP database for IP-to-country lookups.
pub struct GeoIpDatabase {
    /// IPv4 ranges sorted by start address for binary search.
    ipv4_ranges: Vec<Ipv4Range>,
}

struct Ipv4Range {
    start: u32,
    end: u32,
    country: CountryCode,
}

impl GeoIpDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            ipv4_ranges: Vec::new(),
        }
    }

    /// Add an IPv4 CIDR range.
    pub fn add_ipv4_range(&mut self, network: u32, prefix_len: u8, country: CountryCode) {
        let mask = if prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let start = network & mask;
        let end = start | !mask;

        self.ipv4_ranges.push(Ipv4Range { start, end, country });
    }

    /// Sort ranges for binary search (call after loading all ranges).
    pub fn finalize(&mut self) {
        self.ipv4_ranges.sort_by_key(|r| r.start);
    }

    /// Look up the country for an IP address.
    pub fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_num = u32::from(ipv4);
                // Binary search for the range containing this IP
                let idx = self.ipv4_ranges.partition_point(|r| r.start <= ip_num);
                if idx == 0 {
                    return None;
                }
                let range = &self.ipv4_ranges[idx - 1];
                if ip_num >= range.start && ip_num <= range.end {
                    Some(range.country)
                } else {
                    None
                }
            }
            IpAddr::V6(_) => {
                // TODO: IPv6 GeoIP support
                None
            }
        }
    }

    /// Check if an IP belongs to a specific country.
    pub fn is_country(&self, ip: IpAddr, country: CountryCode) -> bool {
        self.lookup(ip) == Some(country)
    }

    /// Number of loaded ranges.
    pub fn range_count(&self) -> usize {
        self.ipv4_ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_geoip_lookup() {
        let mut db = GeoIpDatabase::new();
        // Add a test range: 5.22.0.0/16 -> IR
        db.add_ipv4_range(u32::from(Ipv4Addr::new(5, 22, 0, 0)), 16, CountryCode::iran());
        db.finalize();

        let ip: IpAddr = "5.22.100.50".parse().unwrap();
        assert_eq!(db.lookup(ip), Some(CountryCode::iran()));

        let foreign: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(db.lookup(foreign), None);
    }

    #[test]
    fn test_country_code() {
        let ir = CountryCode::new("IR").unwrap();
        assert_eq!(ir.as_str(), "IR");
        assert_eq!(ir, CountryCode::iran());
    }
}
