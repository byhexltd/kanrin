use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    #[error("connection timeout after {0}ms")]
    Timeout(u64),

    #[error("transport blocked: {0}")]
    Blocked(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("dns resolution failed: {0}")]
    DnsFailure(String),

    #[error("probe failed: {0}")]
    ProbeFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] kanrin_protocol::ProtocolError),
}
