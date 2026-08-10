use std::time::{SystemTime, UNIX_EPOCH};

use x25519_dalek::PublicKey;

use crate::crypto::{self, KeyPair, SessionKeys};
use crate::error::ProtocolError;

/// Maximum allowed timestamp drift (30 seconds) for anti-replay.
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Handshake phase tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Initial,
    HelloSent,
    HelloReceived,
    Finished,
}

/// Authentication status returned by server after handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthStatus {
    Ok = 0x00,
    InvalidCredentials = 0x01,
    RateLimited = 0x02,
    ServerFull = 0x03,
}

impl AuthStatus {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::InvalidCredentials),
            0x02 => Ok(Self::RateLimited),
            0x03 => Ok(Self::ServerFull),
            _ => Err(ProtocolError::HandshakeFailed(format!("unknown auth status: 0x{:02x}", b))),
        }
    }
}

/// Client Hello message (sent first by client).
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub protocol_version: u8,
    pub ephemeral_public: [u8; 32],
    pub timestamp: u64,
    pub random: [u8; 32],
}

impl ClientHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 8 + 32);
        buf.push(self.protocol_version);
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.random);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 73 {
            return Err(ProtocolError::BufferTooShort { need: 73, got: data.len() });
        }
        let protocol_version = data[0];
        let ephemeral_public: [u8; 32] = data[1..33].try_into().unwrap();
        let timestamp = u64::from_be_bytes(data[33..41].try_into().unwrap());
        let random: [u8; 32] = data[41..73].try_into().unwrap();

        Ok(Self {
            protocol_version,
            ephemeral_public,
            timestamp,
            random,
        })
    }
}

/// Server Hello message (response to ClientHello).
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub ephemeral_public: [u8; 32],
    pub encrypted_session_token: Vec<u8>,
    pub server_random: [u8; 32],
}

impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 2 + self.encrypted_session_token.len() + 32);
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&(self.encrypted_session_token.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.encrypted_session_token);
        buf.extend_from_slice(&self.server_random);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 66 {
            return Err(ProtocolError::BufferTooShort { need: 66, got: data.len() });
        }
        let ephemeral_public: [u8; 32] = data[..32].try_into().unwrap();
        let token_len = u16::from_be_bytes([data[32], data[33]]) as usize;
        if data.len() < 34 + token_len + 32 {
            return Err(ProtocolError::BufferTooShort {
                need: 34 + token_len + 32,
                got: data.len(),
            });
        }
        let encrypted_session_token = data[34..34 + token_len].to_vec();
        let server_random: [u8; 32] = data[34 + token_len..66 + token_len].try_into().unwrap();

        Ok(Self {
            ephemeral_public,
            encrypted_session_token,
            server_random,
        })
    }
}

/// Client Finished message (encrypted auth credentials).
#[derive(Debug, Clone)]
pub struct ClientFinished {
    pub encrypted_auth: Vec<u8>,
}

impl ClientFinished {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.encrypted_auth.len());
        buf.extend_from_slice(&(self.encrypted_auth.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.encrypted_auth);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::BufferTooShort { need: 2, got: data.len() });
        }
        let auth_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + auth_len {
            return Err(ProtocolError::BufferTooShort {
                need: 2 + auth_len,
                got: data.len(),
            });
        }
        Ok(Self {
            encrypted_auth: data[2..2 + auth_len].to_vec(),
        })
    }
}

/// Server Finished message (auth result).
#[derive(Debug, Clone)]
pub struct ServerFinished {
    pub status: AuthStatus,
    pub session_token: Option<Vec<u8>>,
}

impl ServerFinished {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.status as u8);
        if let Some(ref token) = self.session_token {
            buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
            buf.extend_from_slice(token);
        } else {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 3 {
            return Err(ProtocolError::BufferTooShort { need: 3, got: data.len() });
        }
        let status = AuthStatus::from_byte(data[0])?;
        let token_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        let session_token = if token_len > 0 {
            if data.len() < 3 + token_len {
                return Err(ProtocolError::BufferTooShort {
                    need: 3 + token_len,
                    got: data.len(),
                });
            }
            Some(data[3..3 + token_len].to_vec())
        } else {
            None
        };

        Ok(Self { status, session_token })
    }
}

/// Client-side handshake state machine.
pub struct ClientHandshake {
    phase: HandshakePhase,
    keypair: Option<KeyPair>,
    shared_secret: Option<[u8; 32]>,
    session_token: Option<Vec<u8>>,
}

impl ClientHandshake {
    pub fn new() -> Self {
        Self {
            phase: HandshakePhase::Initial,
            keypair: Some(KeyPair::generate()),
            shared_secret: None,
            session_token: None,
        }
    }

    /// Generate the ClientHello message.
    pub fn client_hello(&self) -> Result<ClientHello, ProtocolError> {
        let keypair = self.keypair.as_ref()
            .ok_or_else(|| ProtocolError::HandshakeFailed("keypair consumed".into()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(ClientHello {
            protocol_version: crate::wire::PROTOCOL_VERSION,
            ephemeral_public: keypair.public_bytes(),
            timestamp,
            random: crypto::random_bytes(),
        })
    }

    /// Process the ServerHello and derive shared secret.
    pub fn process_server_hello(&mut self, server_hello: &ServerHello) -> Result<SessionKeys, ProtocolError> {
        let keypair = self.keypair.take()
            .ok_or_else(|| ProtocolError::HandshakeFailed("keypair already consumed".into()))?;

        let peer_public = PublicKey::from(server_hello.ephemeral_public);
        let shared_secret = keypair.diffie_hellman(&peer_public);

        // Derive session keys
        let salt = [
            &server_hello.server_random[..],
        ].concat();

        let keys = crypto::derive_session_keys(&shared_secret, &salt)?;

        self.shared_secret = Some(shared_secret);
        self.session_token = Some(server_hello.encrypted_session_token.clone());
        self.phase = HandshakePhase::HelloReceived;

        Ok(keys)
    }

    /// Create the ClientFinished message with encrypted auth.
    pub fn client_finished(&self, password: &str, keys: &SessionKeys) -> Result<ClientFinished, ProtocolError> {
        let auth_payload = password.as_bytes();
        let nonce = crypto::random_bytes::<12>();

        // Encrypt password with client write key
        let encrypted = crypto::encrypt(
            &keys.client_write_key,
            &nonce,
            auth_payload,
            b"kanrin-auth",
        )?;

        // Prepend nonce to encrypted auth
        let mut encrypted_auth = Vec::with_capacity(12 + encrypted.len());
        encrypted_auth.extend_from_slice(&nonce);
        encrypted_auth.extend_from_slice(&encrypted);

        Ok(ClientFinished { encrypted_auth })
    }

    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }
}

/// Server-side handshake state machine.
pub struct ServerHandshake {
    phase: HandshakePhase,
    keypair: Option<KeyPair>,
    shared_secret: Option<[u8; 32]>,
    server_random: [u8; 32],
}

impl ServerHandshake {
    pub fn new() -> Self {
        Self {
            phase: HandshakePhase::Initial,
            keypair: Some(KeyPair::generate()),
            shared_secret: None,
            server_random: crypto::random_bytes(),
        }
    }

    /// Process ClientHello and generate ServerHello.
    pub fn process_client_hello(
        &mut self,
        client_hello: &ClientHello,
    ) -> Result<(ServerHello, SessionKeys), ProtocolError> {
        // Anti-replay: check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let drift = if now > client_hello.timestamp {
            now - client_hello.timestamp
        } else {
            client_hello.timestamp - now
        };

        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(ProtocolError::ReplayDetected);
        }

        // Version check
        if client_hello.protocol_version != crate::wire::PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(client_hello.protocol_version));
        }

        let keypair = self.keypair.take()
            .ok_or_else(|| ProtocolError::HandshakeFailed("keypair consumed".into()))?;

        let server_public = keypair.public_bytes();
        let peer_public = PublicKey::from(client_hello.ephemeral_public);
        let shared_secret = keypair.diffie_hellman(&peer_public);

        // Generate session token
        let session_token = crypto::random_bytes::<32>().to_vec();

        // Derive keys
        let salt = [&self.server_random[..]].concat();
        let keys = crypto::derive_session_keys(&shared_secret, &salt)?;

        self.shared_secret = Some(shared_secret);
        self.phase = HandshakePhase::HelloReceived;

        let server_hello = ServerHello {
            ephemeral_public: server_public,
            encrypted_session_token: session_token,
            server_random: self.server_random,
        };

        Ok((server_hello, keys))
    }

    /// Verify client auth credentials (constant-time).
    pub fn verify_auth(
        &self,
        client_finished: &ClientFinished,
        keys: &SessionKeys,
        expected_password: &str,
    ) -> Result<AuthStatus, ProtocolError> {
        let encrypted_auth = &client_finished.encrypted_auth;
        if encrypted_auth.len() < 12 {
            return Ok(AuthStatus::InvalidCredentials);
        }

        // Extract nonce and ciphertext
        let nonce: [u8; 12] = encrypted_auth[..12].try_into().unwrap();
        let ciphertext = &encrypted_auth[12..];

        // Decrypt
        let plaintext = match crypto::decrypt(
            &keys.client_write_key,
            &nonce,
            ciphertext,
            b"kanrin-auth",
        ) {
            Ok(p) => p,
            Err(_) => return Ok(AuthStatus::InvalidCredentials),
        };

        // Constant-time password comparison
        if crypto::constant_time_eq(&plaintext, expected_password.as_bytes()) {
            Ok(AuthStatus::Ok)
        } else {
            Ok(AuthStatus::InvalidCredentials)
        }
    }

    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }
}

/// Utility: get current unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_encode_decode() {
        let hello = ClientHello {
            protocol_version: 1,
            ephemeral_public: crypto::random_bytes(),
            timestamp: 1234567890,
            random: crypto::random_bytes(),
        };
        let encoded = hello.encode();
        let decoded = ClientHello::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, hello.protocol_version);
        assert_eq!(decoded.ephemeral_public, hello.ephemeral_public);
        assert_eq!(decoded.timestamp, hello.timestamp);
    }

    #[test]
    fn test_full_handshake() {
        // Client initiates
        let mut client = ClientHandshake::new();
        let client_hello = client.client_hello().unwrap();

        // Server processes and responds
        let mut server = ServerHandshake::new();
        let (server_hello, server_keys) = server.process_client_hello(&client_hello).unwrap();

        // Client processes server hello
        let client_keys = client.process_server_hello(&server_hello).unwrap();

        // Both sides should have the same keys
        assert_eq!(client_keys.client_write_key, server_keys.client_write_key);
        assert_eq!(client_keys.server_write_key, server_keys.server_write_key);
    }

    #[test]
    fn test_auth_success() {
        let password = "my-secret-password";

        let mut client = ClientHandshake::new();
        let client_hello = client.client_hello().unwrap();

        let mut server = ServerHandshake::new();
        let (server_hello, keys) = server.process_client_hello(&client_hello).unwrap();

        let _client_keys = client.process_server_hello(&server_hello).unwrap();
        let finished = client.client_finished(password, &keys).unwrap();

        let status = server.verify_auth(&finished, &keys, password).unwrap();
        assert_eq!(status, AuthStatus::Ok);
    }

    #[test]
    fn test_auth_wrong_password() {
        let mut client = ClientHandshake::new();
        let client_hello = client.client_hello().unwrap();

        let mut server = ServerHandshake::new();
        let (server_hello, keys) = server.process_client_hello(&client_hello).unwrap();

        let _client_keys = client.process_server_hello(&server_hello).unwrap();
        let finished = client.client_finished("wrong-password", &keys).unwrap();

        let status = server.verify_auth(&finished, &keys, "correct-password").unwrap();
        assert_eq!(status, AuthStatus::InvalidCredentials);
    }

    #[test]
    fn test_replay_detection() {
        let client_hello = ClientHello {
            protocol_version: 1,
            ephemeral_public: crypto::random_bytes(),
            timestamp: 1000, // Very old timestamp
            random: crypto::random_bytes(),
        };

        let mut server = ServerHandshake::new();
        let result = server.process_client_hello(&client_hello);
        assert!(matches!(result, Err(ProtocolError::ReplayDetected)));
    }
}
