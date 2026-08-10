use std::net::{Ipv4Addr, Ipv6Addr};

/// IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }
}

impl IpProtocol {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmpv6 => 58,
            Self::Other(v) => *v,
        }
    }
}

/// Parsed IP packet (v4 or v6).
#[derive(Debug, Clone)]
pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

impl IpPacket {
    /// Parse raw bytes from TUN device into an IpPacket.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        match version {
            4 => Ipv4Packet::parse(data).map(IpPacket::V4),
            6 => Ipv6Packet::parse(data).map(IpPacket::V6),
            _ => None,
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        match self {
            Self::V4(p) => p.dst_port(),
            Self::V6(p) => p.dst_port(),
        }
    }

    pub fn src_port(&self) -> Option<u16> {
        match self {
            Self::V4(p) => p.src_port(),
            Self::V6(p) => p.src_port(),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match self {
            Self::V4(p) => p.protocol,
            Self::V6(p) => p.next_header,
        }
    }

    pub fn raw(&self) -> &[u8] {
        match self {
            Self::V4(p) => &p.raw,
            Self::V6(p) => &p.raw,
        }
    }

    /// Check if this is a DNS query (UDP port 53).
    pub fn is_dns_query(&self) -> bool {
        self.protocol() == IpProtocol::Udp && self.dst_port() == Some(53)
    }
}

/// Parsed IPv4 packet.
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub header_len: usize,
    pub total_len: usize,
    pub raw: Vec<u8>,
}

impl Ipv4Packet {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl {
            return None;
        }

        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let protocol = IpProtocol::from(data[9]);
        let ttl = data[8];
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Some(Self {
            src,
            dst,
            protocol,
            ttl,
            header_len: ihl,
            total_len,
            raw: data.to_vec(),
        })
    }

    /// Get transport layer payload (after IP header).
    pub fn payload(&self) -> &[u8] {
        if self.raw.len() > self.header_len {
            &self.raw[self.header_len..]
        } else {
            &[]
        }
    }

    /// Get destination port from TCP/UDP header.
    pub fn dst_port(&self) -> Option<u16> {
        let payload = self.payload();
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                if payload.len() >= 4 {
                    Some(u16::from_be_bytes([payload[2], payload[3]]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get source port from TCP/UDP header.
    pub fn src_port(&self) -> Option<u16> {
        let payload = self.payload();
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                if payload.len() >= 2 {
                    Some(u16::from_be_bytes([payload[0], payload[1]]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Parsed IPv6 packet.
#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub payload_len: usize,
    pub raw: Vec<u8>,
}

impl Ipv6Packet {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let next_header = IpProtocol::from(data[6]);
        let hop_limit = data[7];

        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);

        Some(Self {
            src,
            dst,
            next_header,
            hop_limit,
            payload_len,
            raw: data.to_vec(),
        })
    }

    pub fn payload(&self) -> &[u8] {
        if self.raw.len() > 40 {
            &self.raw[40..]
        } else {
            &[]
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        let payload = self.payload();
        match self.next_header {
            IpProtocol::Tcp | IpProtocol::Udp => {
                if payload.len() >= 4 {
                    Some(u16::from_be_bytes([payload[2], payload[3]]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn src_port(&self) -> Option<u16> {
        let payload = self.payload();
        match self.next_header {
            IpProtocol::Tcp | IpProtocol::Udp => {
                if payload.len() >= 2 {
                    Some(u16::from_be_bytes([payload[0], payload[1]]))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp_syn() {
        // Minimal IPv4 TCP packet (SYN to 1.1.1.1:443 from 192.168.1.100:12345)
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // version/IHL, DSCP, total_len=40
            0x00, 0x01, 0x00, 0x00, // ID, flags/frag
            0x40, 0x06, 0x00, 0x00, // TTL=64, protocol=TCP, checksum
            0xC0, 0xA8, 0x01, 0x64, // src: 192.168.1.100
            0x01, 0x01, 0x01, 0x01, // dst: 1.1.1.1
            // TCP header (20 bytes)
            0x30, 0x39, 0x01, 0xBB, // src_port=12345, dst_port=443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xFF, 0xFF, // data offset, SYN flag, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ];

        let parsed = IpPacket::parse(&packet).unwrap();
        match parsed {
            IpPacket::V4(p) => {
                assert_eq!(p.src, Ipv4Addr::new(192, 168, 1, 100));
                assert_eq!(p.dst, Ipv4Addr::new(1, 1, 1, 1));
                assert_eq!(p.protocol, IpProtocol::Tcp);
                assert_eq!(p.src_port(), Some(12345));
                assert_eq!(p.dst_port(), Some(443));
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_is_dns_query() {
        #[rustfmt::skip]
        let dns_packet: Vec<u8> = vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00, // protocol=UDP(17)
            0xC0, 0xA8, 0x01, 0x64, // src
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // UDP header (8 bytes)
            0xAB, 0xCD, 0x00, 0x35, // src_port=43981, dst_port=53
            0x00, 0x10, 0x00, 0x00, // length, checksum
        ];

        let parsed = IpPacket::parse(&dns_packet).unwrap();
        assert!(parsed.is_dns_query());
    }
}
