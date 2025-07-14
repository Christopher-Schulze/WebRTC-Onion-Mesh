//! Transport layer error types

use thiserror::Error;

/// Transport-specific errors
#[derive(Error, Debug, Clone)]
pub enum TransportError {
    #[error("WebRTC error: {0}")]
    WebRtc(String),
    
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Connection closed: {0}")]
    ConnectionClosed(String),
    
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("IO error: {0}")]
    Io(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Not supported: {0}")]
    NotSupported(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for TransportError {
    fn from(err: serde_json::Error) -> Self {
        TransportError::Serialization(err.to_string())
    }
}

impl From<bincode::Error> for TransportError {
    fn from(err: bincode::Error) -> Self {
        TransportError::Serialization(err.to_string())
    }
}

impl From<tungstenite::Error> for TransportError {
    fn from(err: tungstenite::Error) -> Self {
        TransportError::WebSocket(err.to_string())
    }
}

impl From<url::ParseError> for TransportError {
    fn from(err: url::ParseError) -> Self {
        TransportError::InvalidAddress(err.to_string())
    }
}

/// Convert transport error to core error
impl From<TransportError> for zMesh_core::zMeshError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::WebRtc(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::WebRtcError(msg)
                )
            }
            TransportError::WebSocket(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::WebSocketError(msg)
                )
            }
            TransportError::ConnectionFailed(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::ConnectionFailed(msg)
                )
            }
            TransportError::ConnectionClosed(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::ConnectionClosed(msg)
                )
            }
            TransportError::InvalidAddress(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::InvalidAddress(msg)
                )
            }
            TransportError::Timeout(msg) => {
                zMesh_core::zMeshError::Timeout(msg)
            }
            TransportError::Io(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::IoError(msg)
                )
            }
            TransportError::Serialization(msg) => {
                zMesh_core::zMeshError::Serialization(msg)
            }
            TransportError::Config(msg) => {
                zMesh_core::zMeshError::Config(msg)
            }
            TransportError::NotSupported(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::NotSupported(msg)
                )
            }
            TransportError::Internal(msg) => {
                zMesh_core::zMeshError::Transport(
                    zMesh_core::transport::TransportError::InternalError(msg)
                )
            }
        }
    }
}

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;