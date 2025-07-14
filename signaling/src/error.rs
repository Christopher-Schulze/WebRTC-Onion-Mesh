//! Error types for the signaling module

use zMesh_core::error::zMeshError;
use std::fmt;

/// Result type for signaling operations
pub type SignalingResult<T> = Result<T, SignalingError>;

/// Main error type for signaling operations
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// Server-related errors
    #[error("Server error: {0}")]
    Server(#[from] ServerError),
    
    /// Client-related errors
    #[error("Client error: {0}")]
    Client(#[from] ClientError),
    
    /// Discovery-related errors
    #[error("Discovery error: {0}")]
    Discovery(#[from] DiscoveryError),
    
    /// Connection brokering errors
    #[error("Broker error: {0}")]
    Broker(#[from] BrokerError),
    
    /// Registry errors
    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),
    
    /// Message parsing/serialization errors
    #[error("Message error: {0}")]
    Message(#[from] MessageError),
    
    /// Security/authentication errors
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),
    
    /// Network/transport errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Timeout errors
    #[error("Operation timed out: {0}")]
    Timeout(String),
    
    /// Rate limiting errors
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    /// Invalid peer ID
    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),
    
    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    ProtocolMismatch { expected: String, actual: String },
    
    /// Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Server-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Failed to bind to address {address}: {source}")]
    BindFailed {
        address: String,
        #[source]
        source: std::io::Error,
    },
    
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    
    #[error("Certificate error: {0}")]
    Certificate(String),
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    
    #[error("HTTP error: {0}")]
    Http(String),
    
    #[error("Connection limit exceeded")]
    ConnectionLimitExceeded,
    
    #[error("Server not running")]
    NotRunning,
    
    #[error("Server already running")]
    AlreadyRunning,
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Client-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Connection failed to {address}: {source}")]
    ConnectionFailed {
        address: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    
    #[error("Not connected to any signaling server")]
    NotConnected,
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("Request timeout")]
    RequestTimeout,
    
    #[error("Invalid server response: {0}")]
    InvalidResponse(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Server rejected request: {0}")]
    RequestRejected(String),
    
    #[error("Connection lost to server {0}")]
    ConnectionLost(String),
    
    #[error("Retry limit exceeded")]
    RetryLimitExceeded,
}

/// Discovery-specific errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")]
    Mdns(String),
    
    #[error("DHT error: {0}")]
    Dht(String),
    
    #[error("Service registration failed: {0}")]
    ServiceRegistration(String),
    
    #[error("Service discovery failed: {0}")]
    ServiceDiscovery(String),
    
    #[error("Invalid service name: {0}")]
    InvalidServiceName(String),
    
    #[error("Network interface error: {0}")]
    NetworkInterface(String),
    
    #[error("Discovery not started")]
    NotStarted,
    
    #[error("Discovery already started")]
    AlreadyStarted,
    
    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(String),
}

/// Connection broker errors
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("Connection request failed: {0}")]
    ConnectionRequestFailed(String),
    
    #[error("No suitable peers found for connection")]
    NoSuitablePeers,
    
    #[error("Connection negotiation failed: {0}")]
    NegotiationFailed(String),
    
    #[error("Transport not supported: {0:?}")]
    TransportNotSupported(zMesh_core::transport::TransportType),
    
    #[error("Connection already exists with peer {0}")]
    ConnectionExists(String),
    
    #[error("Connection limit reached")]
    ConnectionLimitReached,
    
    #[error("Peer capabilities mismatch: {0}")]
    CapabilitiesMismatch(String),
    
    #[error("Connection timeout")]
    ConnectionTimeout,
}

/// Registry-specific errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Peer already exists: {0}")]
    PeerExists(String),
    
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    #[error("Invalid peer information: {0}")]
    InvalidPeerInfo(String),
    
    #[error("Registry full: cannot add more peers")]
    RegistryFull,
    
    #[error("Concurrent modification detected")]
    ConcurrentModification,
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

/// Message-related errors
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    
    #[error("Message too large: {size} bytes (max: {max})")]
    TooLarge { size: usize, max: usize },
    
    #[error("Unsupported message type: {0}")]
    UnsupportedType(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Binary serialization error: {0}")]
    Binary(#[from] bincode::Error),
    
    #[error("Message validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Compression error: {0}")]
    Compression(String),
    
    #[error("Decompression error: {0}")]
    Decompression(String),
}

/// Security-related errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    
    #[error("Certificate expired")]
    CertificateExpired,
    
    #[error("Untrusted peer: {0}")]
    UntrustedPeer(String),
    
    #[error("Authentication required")]
    AuthenticationRequired,
    
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

/// Network-related errors
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),
    
    #[error("Network unreachable: {0}")]
    NetworkUnreachable(String),
    
    #[error("Address in use: {0}")]
    AddressInUse(String),
    
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,
    
    #[error("Network partition detected")]
    NetworkPartition,
}

// Conversion implementations
impl From<SignalingError> for zMeshError {
    fn from(err: SignalingError) -> Self {
        match err {
            SignalingError::Server(e) => zMeshError::Transport(format!("Signaling server error: {}", e)),
            SignalingError::Client(e) => zMeshError::Transport(format!("Signaling client error: {}", e)),
            SignalingError::Discovery(e) => zMeshError::Peer(format!("Peer discovery error: {}", e)),
            SignalingError::Broker(e) => zMeshError::Transport(format!("Connection broker error: {}", e)),
            SignalingError::Registry(e) => zMeshError::Peer(format!("Peer registry error: {}", e)),
            SignalingError::Message(e) => zMeshError::Serialization(format!("Message error: {}", e)),
            SignalingError::Security(e) => zMeshError::Crypto(format!("Security error: {}", e)),
            SignalingError::Network(e) => zMeshError::Transport(format!("Network error: {}", e)),
            SignalingError::Config(e) => zMeshError::Config(format!("Signaling config error: {}", e)),
            SignalingError::Timeout(e) => zMeshError::Timeout(format!("Signaling timeout: {}", e)),
            SignalingError::RateLimit(e) => zMeshError::Transport(format!("Rate limit: {}", e)),
            SignalingError::InvalidPeerId(e) => zMeshError::Peer(format!("Invalid peer ID: {}", e)),
            SignalingError::PeerNotFound(e) => zMeshError::PeerNotFound(e),
            SignalingError::ServiceUnavailable(e) => zMeshError::Transport(format!("Service unavailable: {}", e)),
            SignalingError::ProtocolMismatch { expected, actual } => {
                zMeshError::Transport(format!("Protocol mismatch: expected {}, got {}", expected, actual))
            }
            SignalingError::Internal(e) => zMeshError::Transport(format!("Internal signaling error: {}", e)),
        }
    }
}

impl From<std::io::Error> for SignalingError {
    fn from(err: std::io::Error) -> Self {
        SignalingError::Network(NetworkError::Io(err))
    }
}

impl From<serde_json::Error> for SignalingError {
    fn from(err: serde_json::Error) -> Self {
        SignalingError::Message(MessageError::Json(err))
    }
}

impl From<url::ParseError> for SignalingError {
    fn from(err: url::ParseError) -> Self {
        SignalingError::Network(NetworkError::InvalidAddress(err.to_string()))
    }
}

impl From<tokio::time::error::Elapsed> for SignalingError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        SignalingError::Timeout("Operation timed out".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_conversion() {
        let signaling_err = SignalingError::PeerNotFound("test-peer".to_string());
        let zMesh_err: zMeshError = signaling_err.into();
        
        match zMesh_err {
            zMeshError::PeerNotFound(msg) => assert_eq!(msg, "test-peer"),
            _ => panic!("Unexpected error type"),
        }
    }
    
    #[test]
    fn test_error_display() {
        let err = SignalingError::Config("Invalid port".to_string());
        assert_eq!(err.to_string(), "Configuration error: Invalid port");
        
        let err = SignalingError::ProtocolMismatch {
            expected: "1.0".to_string(),
            actual: "2.0".to_string(),
        };
        assert_eq!(err.to_string(), "Protocol version mismatch: expected 1.0, got 2.0");
    }
    
    #[test]
    fn test_nested_errors() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused");
        let network_err = NetworkError::Io(io_err);
        let signaling_err = SignalingError::Network(network_err);
        
        assert!(signaling_err.to_string().contains("Network error"));
        assert!(signaling_err.to_string().contains("Connection refused"));
    }
}