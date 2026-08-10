use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::crypto::{self, NonceCounter, SessionKeys, NONCE_SIZE};
use crate::error::ProtocolError;
use crate::wire::Chunk;

/// Unique session identifier (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn generate() -> Self {
        Self(crypto::random_bytes())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Session state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    Active,
    Migrating,
    Suspended,
    Closed,
}

/// An established encrypted session between client and server.
pub struct Session {
    pub id: SessionId,
    pub state: SessionState,
    keys: SessionKeys,
    send_nonce: NonceCounter,
    recv_nonce: NonceCounter,
    created_at: Instant,
    last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    migration_token: Option<Vec<u8>>,
}

impl Session {
    /// Create a new active session with derived keys.
    pub fn new(id: SessionId, keys: SessionKeys) -> Self {
        let now = Instant::now();
        Self {
            id,
            state: SessionState::Active,
            keys,
            send_nonce: NonceCounter::new(),
            recv_nonce: NonceCounter::new(),
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            migration_token: None,
        }
    }

    /// Encrypt and encode an outgoing chunk.
    /// Uses the client_write_key (if we are client) or server_write_key (if server).
    pub fn encrypt_outgoing(&mut self, chunk: &Chunk, is_client: bool) -> Result<Vec<u8>, ProtocolError> {
        let key = if is_client {
            &self.keys.client_write_key
        } else {
            &self.keys.server_write_key
        };

        let nonce = self.send_nonce.next()?;
        let encoded = chunk.encode_encrypted(key, &nonce)?;

        self.bytes_sent += encoded.len() as u64;
        self.last_activity = Instant::now();

        Ok(encoded)
    }

    /// Decrypt an incoming chunk.
    pub fn decrypt_incoming(&mut self, data: &[u8], is_client: bool) -> Result<Chunk, ProtocolError> {
        // When receiving: client reads with server_write_key, server reads with client_write_key
        let key = if is_client {
            &self.keys.server_write_key
        } else {
            &self.keys.client_write_key
        };

        let nonce = self.recv_nonce.next()?;
        let chunk = Chunk::decode_encrypted(data, key, &nonce)?;

        self.bytes_received += data.len() as u64;
        self.last_activity = Instant::now();

        Ok(chunk)
    }

    /// Generate a migration token for reconnecting to a different transport.
    pub fn generate_migration_token(&mut self) -> Vec<u8> {
        let token = crypto::random_bytes::<32>().to_vec();
        self.migration_token = Some(token.clone());
        token
    }

    /// Validate a migration token for session resumption.
    pub fn validate_migration_token(&self, token: &[u8]) -> bool {
        match &self.migration_token {
            Some(expected) => crypto::constant_time_eq(expected, token),
            None => false,
        }
    }

    /// Duration since session was created.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Duration since last activity.
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Check if session should be considered idle.
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.idle_time() > timeout
    }

    /// Mark session as migrating (transport switch in progress).
    pub fn begin_migration(&mut self) {
        self.state = SessionState::Migrating;
    }

    /// Complete migration (new transport established).
    pub fn complete_migration(&mut self) {
        self.state = SessionState::Active;
        self.migration_token = None;
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Get current send nonce value (for diagnostics).
    pub fn send_nonce_value(&self) -> u64 {
        self.send_nonce.current()
    }

    /// Get current recv nonce value (for diagnostics).
    pub fn recv_nonce_value(&self) -> u64 {
        self.recv_nonce.current()
    }
}

/// Manages multiple concurrent sessions.
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    max_sessions: usize,
    idle_timeout: Duration,
}

impl SessionManager {
    pub fn new(max_sessions: usize, idle_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
            idle_timeout,
        }
    }

    /// Create and register a new session.
    pub fn create_session(&mut self, keys: SessionKeys) -> Result<SessionId, ProtocolError> {
        if self.sessions.len() >= self.max_sessions {
            // Try to clean up idle sessions first
            self.cleanup_idle();
            if self.sessions.len() >= self.max_sessions {
                return Err(ProtocolError::Session("max sessions reached".into()));
            }
        }

        let id = SessionId::generate();
        let session = Session::new(id, keys);
        self.sessions.insert(id, session);
        Ok(id)
    }

    /// Get a mutable reference to a session.
    pub fn get_session_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Get an immutable reference to a session.
    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Remove a session.
    pub fn remove_session(&mut self, id: &SessionId) -> Option<Session> {
        self.sessions.remove(id)
    }

    /// Remove all idle sessions.
    pub fn cleanup_idle(&mut self) {
        let timeout = self.idle_timeout;
        self.sessions.retain(|_, session| {
            !session.is_idle(timeout) && session.state != SessionState::Closed
        });
    }

    /// Number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }

    /// Total number of sessions (including non-active).
    pub fn total_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> SessionKeys {
        SessionKeys {
            client_write_key: crypto::random_bytes(),
            server_write_key: crypto::random_bytes(),
        }
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let keys = test_keys();
        let mut client_session = Session::new(SessionId::generate(), keys.clone());
        let mut server_session = Session::new(SessionId::generate(), keys);

        let chunk = Chunk::new_data(b"hello server".to_vec());
        let encrypted = client_session.encrypt_outgoing(&chunk, true).unwrap();
        let decrypted = server_session.decrypt_incoming(&encrypted, false).unwrap();

        assert_eq!(decrypted.payload, b"hello server");
    }

    #[test]
    fn test_session_bidirectional() {
        let keys = test_keys();
        let mut client_session = Session::new(SessionId::generate(), keys.clone());
        let mut server_session = Session::new(SessionId::generate(), keys);

        // Client -> Server
        let c2s = Chunk::new_data(b"request".to_vec());
        let encrypted = client_session.encrypt_outgoing(&c2s, true).unwrap();
        let decrypted = server_session.decrypt_incoming(&encrypted, false).unwrap();
        assert_eq!(decrypted.payload, b"request");

        // Server -> Client
        let s2c = Chunk::new_data(b"response".to_vec());
        let encrypted = server_session.encrypt_outgoing(&s2c, false).unwrap();
        let decrypted = client_session.decrypt_incoming(&encrypted, true).unwrap();
        assert_eq!(decrypted.payload, b"response");
    }

    #[test]
    fn test_migration_token() {
        let keys = test_keys();
        let mut session = Session::new(SessionId::generate(), keys);

        let token = session.generate_migration_token();
        assert!(session.validate_migration_token(&token));
        assert!(!session.validate_migration_token(b"wrong-token"));
    }

    #[test]
    fn test_session_manager_create_and_get() {
        let mut manager = SessionManager::new(10, Duration::from_secs(60));
        let keys = test_keys();
        let id = manager.create_session(keys).unwrap();
        assert!(manager.get_session(&id).is_some());
        assert_eq!(manager.total_count(), 1);
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let mut manager = SessionManager::new(2, Duration::from_secs(60));
        manager.create_session(test_keys()).unwrap();
        manager.create_session(test_keys()).unwrap();
        let result = manager.create_session(test_keys());
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_never_repeats() {
        let keys = test_keys();
        let mut session = Session::new(SessionId::generate(), keys);

        let chunk = Chunk::new_data(b"data".to_vec());
        session.encrypt_outgoing(&chunk, true).unwrap();
        session.encrypt_outgoing(&chunk, true).unwrap();
        session.encrypt_outgoing(&chunk, true).unwrap();

        assert_eq!(session.send_nonce_value(), 3);
    }
}
