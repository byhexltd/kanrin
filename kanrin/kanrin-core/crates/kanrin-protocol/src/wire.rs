use bytes::{Buf, BufMut, BytesMut};

use crate::crypto::{self, NONCE_SIZE, TAG_SIZE};
use crate::error::ProtocolError;

/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Chunk header size on the wire:
/// version(1) + type(1) + sequence(8) + payload_len(2) + padding_len(1) = 13 bytes.
///
/// The sequence is carried explicitly so the receiver can derive the decryption
/// nonce from it (see `crypto::nonce_from_sequence`) regardless of the order in
/// which chunks arrive. It is authenticated as AAD, so it cannot be forged or
/// altered without failing decryption.
pub const HEADER_SIZE: usize = 13;

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
    /// Carries the resumption handshake of 16.1.6.
    ///
    /// A distinct type rather than a discriminator inside the payload: it lets
    /// the server tell "attach to an existing session" from "start a new one"
    /// by reading the chunk header alone, with no ambiguity between a
    /// `ClientHello` and a `ResumeRequest` whose leading bytes are random.
    Resume = 0x05,
}

impl ChunkType {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Control),
            0x04 => Ok(Self::Padding),
            0x05 => Ok(Self::Resume),
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
    /// Monotonic, per-direction sequence number. Scopes the chunk to the session
    /// independently of transport, and seeds the AEAD nonce.
    pub sequence: u64,
    pub payload_length: u16,
    pub padding_length: u8,
}

impl ChunkHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.chunk_type as u8);
        buf.put_u64(self.sequence);
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
        let sequence = u64::from_be_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        let payload_length = u16::from_be_bytes([buf[10], buf[11]]);
        let padding_length = buf[12];

        buf.advance(HEADER_SIZE);

        Ok(Self {
            version,
            chunk_type,
            sequence,
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
                sequence: 0,
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
                sequence: 0,
                payload_length: payload.len() as u16,
                padding_length: 0,
            },
            payload,
        }
    }

    /// Create a resumption chunk (no padding — like the handshake, it is sent
    /// before any session sequence exists).
    pub fn new_resume(payload: Vec<u8>) -> Self {
        Self {
            header: ChunkHeader {
                version: PROTOCOL_VERSION,
                chunk_type: ChunkType::Resume,
                sequence: 0,
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
                sequence: 0,
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
                sequence: 0,
                payload_length: 0,
                padding_length: size,
            },
            payload: Vec::new(),
        }
    }

    /// Encode chunk into bytes, encrypting payload with given key/nonce.
    /// Format: [header(13)] [encrypted(payload + padding)](variable) [tag(16)]
    ///
    /// This is the low-level primitive with an explicit nonce, used by the
    /// handshake (which has no session sequence yet). Data-plane traffic goes
    /// through `encode_sequenced` / `decode_sequenced`, which derive the nonce
    /// from the carried sequence.
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

    /// Encode a data-plane chunk under the given sequence number, deriving the
    /// AEAD nonce from that sequence. The sequence is written into the header
    /// (overriding whatever `self.header.sequence` held) and authenticated as
    /// AAD, so it is bound cryptographically to the ciphertext.
    ///
    /// This is the encode path for all post-handshake traffic. The carried
    /// sequence is what allows the peer to decrypt out of order, after a
    /// transport switch, or across multiple paths.
    pub fn encode_sequenced(
        &self,
        key: &[u8; 32],
        sequence: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut header = self.header.clone();
        header.sequence = sequence;
        let chunk = Chunk {
            header,
            payload: self.payload.clone(),
        };
        let nonce = crypto::nonce_from_sequence(sequence);
        chunk.encode_encrypted(key, &nonce)
    }

    /// Decode a data-plane chunk, deriving the AEAD nonce from the sequence
    /// carried in the (authenticated) header. Because the nonce comes from the
    /// wire and not from a positional counter, chunks may be decoded in any
    /// order without desynchronising.
    pub fn decode_sequenced(data: &[u8], key: &[u8; 32]) -> Result<Self, ProtocolError> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::BufferTooShort {
                need: HEADER_SIZE,
                got: data.len(),
            });
        }

        let mut header_slice: &[u8] = &data[..HEADER_SIZE];
        let header = ChunkHeader::decode(&mut header_slice)?;

        let nonce = crypto::nonce_from_sequence(header.sequence);
        Chunk::decode_encrypted(data, key, &nonce)
    }

    /// Total wire size of this chunk when encoded.
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + self.header.padding_length as usize + TAG_SIZE
    }
}

/// Maximum number of selective-ack ranges carried in a single `Ack`.
///
/// Bounds the decode cost and keeps an `Ack` well inside one control chunk
/// (1 + 8 + 1 + 32 * 16 = 522 bytes). A receiver with more holes than this
/// reports the lowest ones; the rest are covered by later acks or by replay.
pub const MAX_SACK_RANGES: usize = 32;

/// An inclusive range `[start, end]` of sequences received above the
/// cumulative point of an `Ack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackRange {
    pub start: u64,
    pub end: u64,
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
    /// Cumulative + selective acknowledgement (16.1.3).
    ///
    /// `next_expected`: every sequence strictly below it has been received
    /// (TCP-style, so "nothing received yet" is simply `0`).
    /// `ranges`: sequences received beyond the first hole, ascending, disjoint,
    /// non-adjacent, each starting above `next_expected`.
    ///
    /// Acks are idempotent and monotonic in effect — applying a stale or
    /// duplicated ack never un-acknowledges anything — so they are safe to
    /// replay or reorder.
    Ack { next_expected: u64, ranges: Vec<SackRange> },
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
            Self::Ack { next_expected, ranges } => {
                debug_assert!(ranges.len() <= MAX_SACK_RANGES);
                buf.push(0x07);
                buf.extend_from_slice(&next_expected.to_be_bytes());
                buf.push(ranges.len() as u8);
                for r in ranges {
                    buf.extend_from_slice(&r.start.to_be_bytes());
                    buf.extend_from_slice(&r.end.to_be_bytes());
                }
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
            0x07 => {
                if data.len() < 10 {
                    return Err(ProtocolError::BufferTooShort { need: 10, got: data.len() });
                }
                let next_expected = u64::from_be_bytes(data[1..9].try_into().unwrap());
                let count = data[9] as usize;
                if count > MAX_SACK_RANGES {
                    return Err(ProtocolError::InvalidChunk(format!(
                        "too many sack ranges: {count}"
                    )));
                }
                let need = 10 + count * 16;
                if data.len() < need {
                    return Err(ProtocolError::BufferTooShort { need, got: data.len() });
                }
                let ranges: Vec<SackRange> = data[10..need]
                    .chunks_exact(16)
                    .map(|b| SackRange {
                        start: u64::from_be_bytes(b[..8].try_into().unwrap()),
                        end: u64::from_be_bytes(b[8..].try_into().unwrap()),
                    })
                    .collect();
                validate_sack_ranges(next_expected, &ranges)?;
                Ok(Self::Ack { next_expected, ranges })
            }
            _ => Err(ProtocolError::InvalidChunk(format!(
                "unknown control message type: 0x{:02x}",
                data[0]
            ))),
        }
    }
}

/// Enforce the canonical form of an `Ack`'s ranges: each range well-formed,
/// strictly above `next_expected` (a range touching it means the cumulative
/// point should have advanced), and ascending with a gap between neighbours.
///
/// Rejecting non-canonical acks keeps the peer's input space small and makes
/// processing cost linear in the (bounded) range count.
fn validate_sack_ranges(next_expected: u64, ranges: &[SackRange]) -> Result<(), ProtocolError> {
    let invalid = |why: &str| Err(ProtocolError::InvalidChunk(format!("invalid sack: {why}")));
    // Next range must start strictly above `floor`. u128 so `end + 1` cannot
    // overflow at the top of the sequence space.
    let mut floor = next_expected as u128;
    for r in ranges {
        if r.start > r.end {
            return invalid("range start > end");
        }
        if (r.start as u128) <= floor {
            return invalid("range not ascending/disjoint above cumulative point");
        }
        floor = r.end as u128 + 1;
    }
    Ok(())
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
    fn test_sequenced_roundtrip_and_carries_sequence() {
        let key = crypto::random_bytes::<32>();
        let payload = b"sequenced payload".to_vec();

        let chunk = Chunk::new_data(payload.clone());
        let encoded = chunk.encode_sequenced(&key, 42).unwrap();
        let decoded = Chunk::decode_sequenced(&encoded, &key).unwrap();

        assert_eq!(decoded.payload, payload);
        // The sequence assigned at encode time is recoverable from the wire.
        assert_eq!(decoded.header.sequence, 42);
    }

    #[test]
    fn test_sequence_is_authenticated() {
        // The sequence lives in the header, which is AAD. Flipping a byte of it
        // must fail decryption — otherwise an attacker could reorder or replay
        // chunks by rewriting the sequence.
        let key = crypto::random_bytes::<32>();
        let mut encoded = Chunk::new_data(b"data".to_vec())
            .encode_sequenced(&key, 7)
            .unwrap();

        // Byte index 2 is the first byte of the u64 sequence in the header.
        encoded[9] ^= 0x01;
        assert!(Chunk::decode_sequenced(&encoded, &key).is_err());
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
    fn test_chunk_types_roundtrip_through_a_byte() {
        // Every type must survive the wire, and unknown ones must be rejected
        // rather than silently treated as data.
        for t in [
            ChunkType::Handshake,
            ChunkType::Data,
            ChunkType::Control,
            ChunkType::Padding,
            ChunkType::Resume,
        ] {
            assert_eq!(ChunkType::from_byte(t as u8).unwrap(), t);
        }
        assert!(ChunkType::from_byte(0x06).is_err());
    }

    #[test]
    fn test_resume_chunk_is_identifiable_from_the_header_alone() {
        let key = crypto::random_bytes::<32>();
        let nonce = crypto::random_bytes::<12>();
        let encoded = Chunk::new_resume(b"resume payload".to_vec())
            .encode_encrypted(&key, &nonce)
            .unwrap();

        // The header is plaintext, so the server can route the chunk before
        // it knows which session's keys to use.
        let header = ChunkHeader::decode(&mut &encoded[..HEADER_SIZE]).unwrap();
        assert_eq!(header.chunk_type, ChunkType::Resume);

        let decoded = Chunk::decode_encrypted(&encoded, &key, &nonce).unwrap();
        assert_eq!(decoded.payload, b"resume payload");
    }

    #[test]
    fn test_control_message_roundtrip() {
        let msg = ControlMessage::Ping { timestamp: 1234567890 };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    fn ack(next_expected: u64, ranges: &[(u64, u64)]) -> ControlMessage {
        ControlMessage::Ack {
            next_expected,
            ranges: ranges.iter().map(|&(start, end)| SackRange { start, end }).collect(),
        }
    }

    #[test]
    fn test_ack_roundtrip() {
        for msg in [
            ack(0, &[]),
            ack(5, &[(7, 9), (12, 12)]),
            ack(0, &[(u64::MAX, u64::MAX)]),
        ] {
            let decoded = ControlMessage::decode(&msg.encode()).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_ack_max_ranges_roundtrip_fits_one_chunk() {
        let ranges: Vec<(u64, u64)> =
            (0..MAX_SACK_RANGES as u64).map(|i| (10 + i * 3, 11 + i * 3)).collect();
        let msg = ack(0, &ranges);
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 10 + MAX_SACK_RANGES * 16);
        assert!(encoded.len() <= MAX_PAYLOAD_SIZE);
        assert_eq!(ControlMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn test_ack_rejects_non_canonical_ranges() {
        for bad in [
            ack(5, &[(9, 7)]),           // start > end
            ack(5, &[(5, 6)]),           // touches cumulative point
            ack(5, &[(3, 4)]),           // below cumulative point
            ack(0, &[(5, 8), (7, 10)]),  // overlapping
            ack(0, &[(5, 8), (9, 10)]),  // adjacent (should be merged)
            ack(0, &[(9, 10), (5, 6)]),  // descending
            ack(0, &[(u64::MAX, u64::MAX), (1, 2)]),
        ] {
            assert!(ControlMessage::decode(&bad.encode()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_ack_rejects_too_many_ranges_and_truncation() {
        let mut encoded = ack(0, &[]).encode();
        encoded[9] = (MAX_SACK_RANGES + 1) as u8;
        assert!(ControlMessage::decode(&encoded).is_err());

        let encoded = ack(0, &[(3, 4), (8, 9)]).encode();
        assert!(ControlMessage::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(ControlMessage::decode(&encoded[..9]).is_err());
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
