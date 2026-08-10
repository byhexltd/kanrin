use bytes::{Buf, BufMut, BytesMut};

use crate::crypto::{self, NONCE_SIZE, TAG_SIZE};
use crate::error::ProtocolError;

/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Minimum chunk header size (version + type + payload_len + padding_len = 5 bytes)
pub const HEADER_SIZE: usize = 5;

/// Maximum payload size per chunk (64 KB)
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Maximum padding size per chunk
pub const MAX_PADDING_SIZE: usize = 255;

/// Chunk type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkType {
    Handshake = 0x01,
    Data = 0x02,
    Control = 0x03,
    Padding = 0x04,
}

impl ChunkType {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Control),
            0x04 => Ok(Self::Padding),
            _ => Err(ProtocolError::InvalidChunk(format!(
                "unknown chunk type: 0x{:02x}",
                b
            ))),
        }
    }
}

/// Wire chunk header
#[derive(Debug, Clone)]
pub struct ChunkHeader {
    pub version: u8,
    pub chunk_type: ChunkType,
    pub payload_length: u16,
    pub padding_length: u8,
}

impl ChunkHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.chunk_type as u8);
        buf.put_u16(self.payload_length);
        buf.put_u8(self.padding_length);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::BufferTooShort {
                need: HEADER_SIZE,
                got: buf.len(),
            });
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let chunk_type = ChunkType::from_byte(buf[1])?;
        let payload_length = u16::from_be_bytes([buf[2], buf[3]]);
        let padding_length = buf[4];

        buf.advance(HEADER_SIZE);

        Ok(Self {
            version,
            chunk_type,
            payload_length,
            padding_length,
        })
    }

    /// Total size of the body following this header (payload + padding + tag)
    pub fn body_size(&self) -> usize {
        self.payload_length as usize + self.padding_length as usize + TAG_SIZE
    }
}

/// A complete wire chunk (header + encrypted payload + padding + tag)
#[derive(Debug, Clone)]
pub struct Chunk {
    pub header: ChunkHeader,
    pub payload: Vec<u8>,
}

impl Chunk {
    /// Create a new data chunk with random padding.
    pub fn new_data(payload: Vec<u8>) -> Self {
        let padding_len = (rand::random::<u8>() % 64) as u8; // 0-63 bytes random padding
        Self {
            header: ChunkHeader {
                version: PROTOCOL_VERSION,
                chunk_type: ChunkType::Data,
                payload_length: payload.len() as u16,
                padding_length: padding_len,
            },
            payload,
        }
    }

    /// Create a handshake chunk (no padding needed during handshake).
    pub fn new_handshake(payload: Vec<u8>) -> Self {
        Self {
            header: ChunkHeader {
                version: PROTOCOL_VERSION,
                chunk_type: ChunkType::Handshake,
                payload_length: payload.len() as u16,
                padding_length: 0,
            },
            payload,
        }
    }

    /// Create a control chunk.
    pub fn new_control(payload: Vec<u8>) -> Self {
        Self {
            header: ChunkHeader {
                version: PROTOCOL_VERSION,
                chunk_type: ChunkType::Control,
                payload_length: payload.len() as u16,
                padding_length: (rand::random::<u8>() % 32) as u8,
            },
            payload,
        }
    }

    /// Create a pure padding chunk (cover traffic).
    pub fn new_padding(size: u8) -> Self {
        Self {
            header: ChunkHeader {
                version: PROTOCOL_VERSION,
                chunk_type: ChunkType::Padding,
                payload_length: 0,
                padding_length: size,
            },
            payload: Vec::new(),
        }
    }

    /// Encode chunk into bytes, encrypting payload with given key/nonce.
    /// Format: [header(5)] [encrypted(payload + padding)](variable) [tag(16)]
    pub fn encode_encrypted(
        &self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = BytesMut::with_capacity(
            HEADER_SIZE + self.payload.len() + self.header.padding_length as usize + TAG_SIZE,
        );

        // Encode header (sent in plaintext — it's just length info)
        self.header.encode(&mut buf);

        // Build plaintext: payload + random padding
        let padding = crypto::random_bytes_vec(self.header.padding_length as usize);
        let mut plaintext = Vec::with_capacity(self.payload.len() + padding.len());
        plaintext.extend_from_slice(&self.payload);
        plaintext.extend_from_slice(&padding);

        // AAD is the header bytes (authenticate but don't encrypt)
        let aad = &buf[..HEADER_SIZE];
        let ciphertext = crypto::encrypt(key, nonce, &plaintext, aad)?;

        buf.extend_from_slice(&ciphertext);
        Ok(buf.to_vec())
    }

    /// Decode a chunk from bytes, decrypting payload.
    pub fn decode_encrypted(
        data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Self, ProtocolError> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::BufferTooShort {
                need: HEADER_SIZE,
                got: data.len(),
            });
        }

        let mut header_slice: &[u8] = &data[..HEADER_SIZE];
        let header = ChunkHeader::decode(&mut header_slice)?;

        let expected_total = HEADER_SIZE + header.body_size();
        if data.len() < expected_total {
            return Err(ProtocolError::BufferTooShort {
                need: expected_total,
                got: data.len(),
            });
        }

        // AAD is the header bytes
        let aad = &data[..HEADER_SIZE];
        let ciphertext = &data[HEADER_SIZE..expected_total];

        let plaintext = crypto::decrypt(key, nonce, ciphertext, aad)?;

        // Split plaintext into payload and padding
        let payload = plaintext[..header.payload_length as usize].to_vec();

        Ok(Self { header, payload })
    }

    /// Total wire size of this chunk when encoded.
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + self.header.padding_length as usize + TAG_SIZE
    }
}

/// Control message types sent within Control chunks.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlMessage {
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
    ConfigUpdate { config_hash: [u8; 32], url: String },
    ScoreReport { node_id: String, score: f32 },
    SessionMigrate { new_token: Vec<u8> },
    Disconnect { reason: DisconnectReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    ClientClose = 0x00,
    ServerClose = 0x01,
    AuthFailed = 0x02,
    TrafficExceeded = 0x03,
    Expired = 0x04,
    Timeout = 0x05,
}

impl ControlMessage {
    /// Encode control message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Ping { timestamp } => {
                buf.push(0x01);
                buf.extend_from_slice(&timestamp.to_be_bytes());
            }
            Self::Pong { timestamp } => {
                buf.push(0x02);
                buf.extend_from_slice(&timestamp.to_be_bytes());
            }
            Self::ConfigUpdate { config_hash, url } => {
                buf.push(0x03);
                buf.extend_from_slice(config_hash);
                let url_bytes = url.as_bytes();
                buf.extend_from_slice(&(url_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(url_bytes);
            }
            Self::ScoreReport { node_id, score } => {
                buf.push(0x04);
                let id_bytes = node_id.as_bytes();
                buf.push(id_bytes.len() as u8);
                buf.extend_from_slice(id_bytes);
                buf.extend_from_slice(&score.to_be_bytes());
            }
            Self::SessionMigrate { new_token } => {
                buf.push(0x05);
                buf.extend_from_slice(&(new_token.len() as u16).to_be_bytes());
                buf.extend_from_slice(new_token);
            }
            Self::Disconnect { reason } => {
                buf.push(0x06);
                buf.push(*reason as u8);
            }
        }
        buf
    }

    /// Decode control message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::InvalidChunk("empty control message".into()));
        }

        match data[0] {
            0x01 => {
                if data.len() < 9 {
                    return Err(ProtocolError::BufferTooShort { need: 9, got: data.len() });
                }
                let timestamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
                Ok(Self::Ping { timestamp })
            }
            0x02 => {
                if data.len() < 9 {
                    return Err(ProtocolError::BufferTooShort { need: 9, got: data.len() });
                }
                let timestamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
                Ok(Self::Pong { timestamp })
            }
            0x06 => {
                if data.len() < 2 {
                    return Err(ProtocolError::BufferTooShort { need: 2, got: data.len() });
                }
                let reason = match data[1] {
                    0x00 => DisconnectReason::ClientClose,
                    0x01 => DisconnectReason::ServerClose,
                    0x02 => DisconnectReason::AuthFailed,
                    0x03 => DisconnectReason::TrafficExceeded,
                    0x04 => DisconnectReason::Expired,
                    0x05 => DisconnectReason::Timeout,
                    _ => return Err(ProtocolError::InvalidChunk("unknown disconnect reason".into())),
                };
                Ok(Self::Disconnect { reason })
            }
            _ => Err(ProtocolError::InvalidChunk(format!(
                "unknown control message type: 0x{:02x}",
                data[0]
            ))),
        }
    }
}

/// Proxy request types (sent as Data chunk payloads).
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyRequest {
    TcpConnect { address: String, port: u16 },
    UdpDatagram { session_id: u32, address: String, port: u16, data: Vec<u8> },
    DnsQuery { id: u16, query: Vec<u8> },
}

impl ProxyRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::TcpConnect { address, port } => {
                buf.push(0x01);
                let addr_bytes = address.as_bytes();
                buf.push(addr_bytes.len() as u8);
                buf.extend_from_slice(addr_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::UdpDatagram { session_id, address, port, data } => {
                buf.push(0x02);
                buf.extend_from_slice(&session_id.to_be_bytes());
                let addr_bytes = address.as_bytes();
                buf.push(addr_bytes.len() as u8);
                buf.extend_from_slice(addr_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
            }
            Self::DnsQuery { id, query } => {
                buf.push(0x03);
                buf.extend_from_slice(&id.to_be_bytes());
                buf.extend_from_slice(&(query.len() as u16).to_be_bytes());
                buf.extend_from_slice(query);
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::InvalidChunk("empty proxy request".into()));
        }
        match data[0] {
            0x01 => {
                if data.len() < 4 {
                    return Err(ProtocolError::BufferTooShort { need: 4, got: data.len() });
                }
                let addr_len = data[1] as usize;
                if data.len() < 2 + addr_len + 2 {
                    return Err(ProtocolError::BufferTooShort {
                        need: 2 + addr_len + 2,
                        got: data.len(),
                    });
                }
                let address = String::from_utf8_lossy(&data[2..2 + addr_len]).to_string();
                let port = u16::from_be_bytes([data[2 + addr_len], data[3 + addr_len]]);
                Ok(Self::TcpConnect { address, port })
            }
            0x02 => {
                if data.len() < 8 {
                    return Err(ProtocolError::BufferTooShort { need: 8, got: data.len() });
                }
                let session_id = u32::from_be_bytes(data[1..5].try_into().unwrap());
                let addr_len = data[5] as usize;
                let offset = 6 + addr_len;
                if data.len() < offset + 4 {
                    return Err(ProtocolError::BufferTooShort {
                        need: offset + 4,
                        got: data.len(),
                    });
                }
                let address = String::from_utf8_lossy(&data[6..6 + addr_len]).to_string();
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                let payload_start = offset + 4;
                if data.len() < payload_start + data_len {
                    return Err(ProtocolError::BufferTooShort {
                        need: payload_start + data_len,
                        got: data.len(),
                    });
                }
                let payload = data[payload_start..payload_start + data_len].to_vec();
                Ok(Self::UdpDatagram { session_id, address, port, data: payload })
            }
            0x03 => {
                if data.len() < 5 {
                    return Err(ProtocolError::BufferTooShort { need: 5, got: data.len() });
                }
                let id = u16::from_be_bytes([data[1], data[2]]);
                let query_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if data.len() < 5 + query_len {
                    return Err(ProtocolError::BufferTooShort {
                        need: 5 + query_len,
                        got: data.len(),
                    });
                }
                let query = data[5..5 + query_len].to_vec();
                Ok(Self::DnsQuery { id, query })
            }
            _ => Err(ProtocolError::InvalidChunk(format!(
                "unknown proxy request type: 0x{:02x}",
                data[0]
            ))),
        }
    }
}

/// Frame a chunk for stream transports (length-prefixed).
/// Format: [total_length: u32][chunk_data]
pub fn frame_chunk(chunk_data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + chunk_data.len());
    framed.extend_from_slice(&(chunk_data.len() as u32).to_be_bytes());
    framed.extend_from_slice(chunk_data);
    framed
}

/// Read a framed chunk from a buffer. Returns (chunk_data, bytes_consumed) or None if incomplete.
pub fn deframe_chunk(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + length {
        return None;
    }
    Some((&buf[4..4 + length], 4 + length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_chunk_encrypt_decrypt_roundtrip() {
        let key = crypto::random_bytes::<32>();
        let nonce = crypto::random_bytes::<12>();
        let payload = b"test proxy data payload".to_vec();

        let chunk = Chunk::new_data(payload.clone());
        let encoded = chunk.encode_encrypted(&key, &nonce).unwrap();
        let decoded = Chunk::decode_encrypted(&encoded, &key, &nonce).unwrap();

        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.header.chunk_type, ChunkType::Data);
    }

    #[test]
    fn test_handshake_chunk() {
        let key = crypto::random_bytes::<32>();
        let nonce = crypto::random_bytes::<12>();
        let payload = b"client hello data".to_vec();

        let chunk = Chunk::new_handshake(payload.clone());
        let encoded = chunk.encode_encrypted(&key, &nonce).unwrap();
        let decoded = Chunk::decode_encrypted(&encoded, &key, &nonce).unwrap();

        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.header.chunk_type, ChunkType::Handshake);
        assert_eq!(decoded.header.padding_length, 0);
    }

    #[test]
    fn test_control_message_roundtrip() {
        let msg = ControlMessage::Ping { timestamp: 1234567890 };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_proxy_request_tcp_connect() {
        let req = ProxyRequest::TcpConnect {
            address: "example.com".to_string(),
            port: 443,
        };
        let encoded = req.encode();
        let decoded = ProxyRequest::decode(&encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_proxy_request_udp() {
        let req = ProxyRequest::UdpDatagram {
            session_id: 42,
            address: "8.8.8.8".to_string(),
            port: 53,
            data: vec![0x01, 0x02, 0x03],
        };
        let encoded = req.encode();
        let decoded = ProxyRequest::decode(&encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_frame_deframe() {
        let data = b"some chunk data";
        let framed = frame_chunk(data);
        let (deframed, consumed) = deframe_chunk(&framed).unwrap();
        assert_eq!(deframed, data);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn test_deframe_incomplete() {
        let data = b"some data";
        let framed = frame_chunk(data);
        // Only provide partial frame
        assert!(deframe_chunk(&framed[..3]).is_none());
        assert!(deframe_chunk(&framed[..5]).is_none());
    }
}
