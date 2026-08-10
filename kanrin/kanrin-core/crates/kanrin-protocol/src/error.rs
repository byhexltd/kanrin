use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("invalid chunk: {0}")]
    InvalidChunk(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("replay attack detected")]
    ReplayDetected,

    #[error("nonce exhausted — must rotate keys")]
    NonceExhausted,

    #[error("buffer too short: need {need} bytes, got {got}")]
    BufferTooShort { need: usize, got: usize },

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("rate limited")]
    RateLimited,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
