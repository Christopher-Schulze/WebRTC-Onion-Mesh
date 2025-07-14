//! Error types for the onion routing module

use zMesh_core::error::zMeshError;
use std::fmt;

/// Result type for onion routing operations
pub type OnionResult<T> = Result<T, OnionError>;

/// Main error type for onion routing operations
#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    /// Circuit-related errors
    #[error("Circuit error: {0}")]
    Circuit(#[from] CircuitError),
    
    /// Cryptographic errors
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    /// Path selection errors
    #[error("Path error: {0}")]
    Path(#[from] PathError),
    
    /// Packet processing errors
    #[error("Packet error: {0}")]
    Packet(#[from] PacketError),
    
    /// Relay node errors
    #[error("Relay error: {0}")]
    Relay(#[from] RelayError),
    
    /// Exit node errors
    #[error("Exit error: {0}")]
    Exit(#[from] ExitError),
    
    /// Transport errors
    #[error("Transport error: {0}")]
    Transport(#[from] zMesh_transport::TransportError),
    
    /// Signaling errors
    #[error("Signaling error: {0}")]
    Signaling(#[from] zMesh_signaling::SignalingError),
    
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Invalid hop count
    #[error("Invalid hop count: {count} (must be between {min} and {max})")]
    InvalidHopCount { count: u8, min: u8, max: u8 },
    
    /// Circuit not found
    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),
    
    /// Node not found
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    
    /// Path not available
    #[error("No suitable path available: {0}")]
    PathNotAvailable(String),
    
    /// Timeout errors
    #[error("Operation timed out: {0}")]
    Timeout(String),
    
    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Resource exhaustion
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    /// Security violation
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Circuit-specific errors
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("Circuit build failed: {0}")]
    BuildFailed(String),
    
    #[error("Circuit extend failed: {0}")]
    ExtendFailed(String),
    
    #[error("Circuit closed: {reason}")]
    CircuitClosed { reason: String },
    
    #[error("Circuit timeout: {operation}")]
    Timeout { operation: String },
    
    #[error("Circuit limit exceeded: {current}/{max}")]
    LimitExceeded { current: usize, max: usize },
    
    #[error("Invalid circuit state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },
    
    #[error("Circuit authentication failed")]
    AuthenticationFailed,
    
    #[error("Circuit key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Circuit already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Circuit not ready: {0}")]
    NotReady(String),
    
    #[error("Circuit destroyed: {0}")]
    Destroyed(String),
}

/// Cryptographic errors
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(String),
    
    #[error("Unsupported key exchange: {0}")]
    UnsupportedKeyExchange(String),
    
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    
    #[error("Cryptographic library error: {0}")]
    LibraryError(String),
}

/// Path selection errors
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("No suitable nodes found for path")]
    NoSuitableNodes,
    
    #[error("Insufficient nodes for {hops} hops: found {available}")]
    InsufficientNodes { hops: usize, available: usize },
    
    #[error("Path diversity constraint violated: {constraint}")]
    DiversityConstraintViolated { constraint: String },
    
    #[error("Latency constraint violated: {latency}ms > {max_latency}ms")]
    LatencyConstraintViolated { latency: u32, max_latency: u32 },
    
    #[error("Reliability constraint violated: {reliability} < {min_reliability}")]
    ReliabilityConstraintViolated { reliability: f32, min_reliability: f32 },
    
    #[error("Geographic constraint violated: {0}")]
    GeographicConstraintViolated(String),
    
    #[error("Network constraint violated: {0}")]
    NetworkConstraintViolated(String),
    
    #[error("Path selection timeout")]
    SelectionTimeout,
    
    #[error("Invalid path strategy: {0}")]
    InvalidStrategy(String),
    
    #[error("Path validation failed: {0}")]
    ValidationFailed(String),
}

/// Packet processing errors
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("Invalid packet format: {0}")]
    InvalidFormat(String),
    
    #[error("Packet too large: {size} bytes (max: {max})")]
    TooLarge { size: usize, max: usize },
    
    #[error("Packet too small: {size} bytes (min: {min})")]
    TooSmall { size: usize, min: usize },
    
    #[error("Invalid packet header: {0}")]
    InvalidHeader(String),
    
    #[error("Invalid packet payload: {0}")]
    InvalidPayload(String),
    
    #[error("Packet decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Packet authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Packet replay detected: {0}")]
    ReplayDetected(String),
    
    #[error("Packet sequence error: expected {expected}, got {actual}")]
    SequenceError { expected: u32, actual: u32 },
    
    #[error("Packet fragmentation error: {0}")]
    FragmentationError(String),
    
    #[error("Packet reassembly failed: {0}")]
    ReassemblyFailed(String),
}

/// Relay node errors
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Relay connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Relay authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Relay overloaded: {0}")]
    Overloaded(String),
    
    #[error("Relay unavailable: {0}")]
    Unavailable(String),
    
    #[error("Relay protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Relay timeout: {0}")]
    Timeout(String),
    
    #[error("Invalid relay command: {0}")]
    InvalidCommand(String),
    
    #[error("Relay capacity exceeded: {0}")]
    CapacityExceeded(String),
    
    #[error("Relay configuration error: {0}")]
    ConfigurationError(String),
}

/// Exit node errors
#[derive(Debug, thiserror::Error)]
pub enum ExitError {
    #[error("Exit connection failed to {destination}: {reason}")]
    ConnectionFailed { destination: String, reason: String },
    
    #[error("Exit policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Exit destination unreachable: {0}")]
    DestinationUnreachable(String),
    
    #[error("Exit DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    
    #[error("Exit timeout: {0}")]
    Timeout(String),
    
    #[error("Exit bandwidth limit exceeded")]
    BandwidthLimitExceeded,
    
    #[error("Exit connection limit exceeded")]
    ConnectionLimitExceeded,
    
    #[error("Exit protocol not supported: {0}")]
    ProtocolNotSupported(String),
    
    #[error("Exit port blocked: {0}")]
    PortBlocked(u16),
    
    #[error("Exit country blocked: {0}")]
    CountryBlocked(String),
}

// Convenience constructor for OnionError
impl OnionError {
    pub fn invalid_hop_count(count: u8) -> Self {
        Self::InvalidHopCount {
            count,
            min: 2,
            max: 3,
        }
    }
    
    pub fn circuit_not_found(circuit_id: impl fmt::Display) -> Self {
        Self::CircuitNotFound(circuit_id.to_string())
    }
    
    pub fn node_not_found(node_id: impl fmt::Display) -> Self {
        Self::NodeNotFound(node_id.to_string())
    }
    
    pub fn timeout(operation: impl fmt::Display) -> Self {
        Self::Timeout(operation.to_string())
    }
    
    pub fn protocol_error(message: impl fmt::Display) -> Self {
        Self::Protocol(message.to_string())
    }
    
    pub fn security_violation(message: impl fmt::Display) -> Self {
        Self::SecurityViolation(message.to_string())
    }
    
    pub fn internal_error(message: impl fmt::Display) -> Self {
        Self::Internal(message.to_string())
    }
}

// Conversion implementations
impl From<OnionError> for zMeshError {
    fn from(err: OnionError) -> Self {
        match err {
            OnionError::Circuit(e) => zMeshError::Onion(format!("Circuit error: {}", e)),
            OnionError::Crypto(e) => zMeshError::Crypto(format!("Onion crypto error: {}", e)),
            OnionError::Path(e) => zMeshError::Onion(format!("Path error: {}", e)),
            OnionError::Packet(e) => zMeshError::Onion(format!("Packet error: {}", e)),
            OnionError::Relay(e) => zMeshError::Onion(format!("Relay error: {}", e)),
            OnionError::Exit(e) => zMeshError::ExitNode(format!("Exit error: {}", e)),
            OnionError::Transport(e) => zMeshError::Transport(format!("Onion transport error: {}", e)),
            OnionError::Signaling(e) => zMeshError::Transport(format!("Onion signaling error: {}", e)),
            OnionError::Config(e) => zMeshError::Config(format!("Onion config error: {}", e)),
            OnionError::InvalidHopCount { count, min, max } => {
                zMeshError::InvalidHopCount(format!("Invalid hop count: {} (must be between {} and {})", count, min, max))
            }
            OnionError::CircuitNotFound(e) => zMeshError::Onion(format!("Circuit not found: {}", e)),
            OnionError::NodeNotFound(e) => zMeshError::PeerNotFound(e),
            OnionError::PathNotAvailable(e) => zMeshError::PathNotAvailable(e),
            OnionError::Timeout(e) => zMeshError::Timeout(format!("Onion timeout: {}", e)),
            OnionError::Protocol(e) => zMeshError::Onion(format!("Protocol error: {}", e)),
            OnionError::ResourceExhausted(e) => zMeshError::Onion(format!("Resource exhausted: {}", e)),
            OnionError::SecurityViolation(e) => zMeshError::Crypto(format!("Security violation: {}", e)),
            OnionError::Internal(e) => zMeshError::Onion(format!("Internal error: {}", e)),
        }
    }
}

impl From<std::io::Error> for OnionError {
    fn from(err: std::io::Error) -> Self {
        OnionError::Transport(zMesh_transport::TransportError::Io(err))
    }
}

impl From<serde_json::Error> for OnionError {
    fn from(err: serde_json::Error) -> Self {
        OnionError::Packet(PacketError::InvalidFormat(err.to_string()))
    }
}

impl From<bincode::Error> for OnionError {
    fn from(err: bincode::Error) -> Self {
        OnionError::Packet(PacketError::InvalidFormat(err.to_string()))
    }
}

impl From<tokio::time::error::Elapsed> for OnionError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        OnionError::Timeout("Operation timed out".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let err = OnionError::invalid_hop_count(5);
        match err {
            OnionError::InvalidHopCount { count, min, max } => {
                assert_eq!(count, 5);
                assert_eq!(min, 2);
                assert_eq!(max, 3);
            }
            _ => panic!("Unexpected error type"),
        }
    }
    
    #[test]
    fn test_error_display() {
        let err = OnionError::circuit_not_found("test-circuit-123");
        assert_eq!(err.to_string(), "Circuit not found: test-circuit-123");
        
        let err = OnionError::timeout("circuit build");
        assert_eq!(err.to_string(), "Operation timed out: circuit build");
    }
    
    #[test]
    fn test_error_conversion() {
        let onion_err = OnionError::invalid_hop_count(4);
        let zMesh_err: zMeshError = onion_err.into();
        
        match zMesh_err {
            zMeshError::InvalidHopCount(msg) => {
                assert!(msg.contains("Invalid hop count: 4"));
            }
            _ => panic!("Unexpected error type"),
        }
    }
    
    #[test]
    fn test_nested_errors() {
        let circuit_err = CircuitError::BuildFailed("Network unreachable".to_string());
        let onion_err = OnionError::Circuit(circuit_err);
        
        assert!(onion_err.to_string().contains("Circuit error"));
        assert!(onion_err.to_string().contains("Build failed"));
        assert!(onion_err.to_string().contains("Network unreachable"));
    }
    
    #[test]
    fn test_crypto_error_chain() {
        let crypto_err = CryptoError::EncryptionFailed("Invalid key size".to_string());
        let onion_err = OnionError::Crypto(crypto_err);
        let zMesh_err: zMeshError = onion_err.into();
        
        match zMesh_err {
            zMeshError::Crypto(msg) => {
                assert!(msg.contains("Onion crypto error"));
                assert!(msg.contains("Encryption failed"));
                assert!(msg.contains("Invalid key size"));
            }
            _ => panic!("Unexpected error type"),
        }
    }
}