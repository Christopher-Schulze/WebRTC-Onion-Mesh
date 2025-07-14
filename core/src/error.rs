//! Error types for zMesh

use thiserror::Error;

/// Main error type for zMesh operations
#[derive(Error, Debug, Clone)]
pub enum zMeshError {
    #[error("Transport error: {0}")]
    Transport(String),
    
    #[error("Onion routing error: {0}")]
    Onion(String),
    
    #[error("FEC error: {0}")]
    Fec(String),
    
    #[error("Mesh networking error: {0}")]
    Mesh(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Peer error: {0}")]
    Peer(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Timeout error: operation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    
    #[error("Invalid hop count: {count} (must be between {min} and {max})")]
    InvalidHopCount { count: u8, min: u8, max: u8 },
    
    #[error("Peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },
    
    #[error("Path not available: no suitable peers found")]
    PathNotAvailable,
    
    #[error("Exit node error: {0}")]
    ExitNode(String),
    
    #[error("WebPush signaling error: {0}")]
    WebPush(String),
    
    #[error("WASM binding error: {0}")]
    Wasm(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Memory error: {0}")]
    Memory(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Result type alias for zMesh operations
pub type zMeshResult<T> = Result<T, zMeshError>;

/// Transport-specific errors
#[derive(Error, Debug, Clone)]
pub enum TransportError {
    #[error("WebRTC connection failed: {0}")]
    WebRtcFailed(String),
    
    #[error("WebSocket connection failed: {0}")]
    WebSocketFailed(String),
    
    #[error("NAT traversal failed")]
    NatTraversalFailed,
    
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
    
    #[error("Send buffer full")]
    SendBufferFull,
}

/// Onion routing specific errors
#[derive(Error, Debug, Clone)]
pub enum OnionError {
    #[error("Invalid onion packet format")]
    InvalidPacketFormat,
    
    #[error("Decryption failed at hop {hop}")]
    DecryptionFailed { hop: u8 },
    
    #[error("Invalid hop count in packet")]
    InvalidHopCount,
    
    #[error("Circuit build failed")]
    CircuitBuildFailed,
    
    #[error("Key exchange failed")]
    KeyExchangeFailed,
}

/// FEC specific errors
#[derive(Error, Debug, Clone)]
pub enum FecError {
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    
    #[error("Decoding failed: insufficient packets")]
    InsufficientPackets,
    
    #[error("Invalid repair symbol")]
    InvalidRepairSymbol,
    
    #[error("Window size exceeded")]
    WindowSizeExceeded,
}

impl From<TransportError> for zMeshError {
    fn from(err: TransportError) -> Self {
        zMeshError::Transport(err.to_string())
    }
}

impl From<OnionError> for zMeshError {
    fn from(err: OnionError) -> Self {
        zMeshError::Onion(err.to_string())
    }
}

impl From<FecError> for zMeshError {
    fn from(err: FecError) -> Self {
        zMeshError::Fec(err.to_string())
    }
}