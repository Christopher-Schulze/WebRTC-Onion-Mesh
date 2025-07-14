//! Signaling protocol messages
//!
//! This module defines all message types used in the zMesh signaling protocol.
//! Messages are designed to be efficient, extensible, and secure.

use zMesh_core::{
    peer::{PeerId, PeerInfo, PeerCapabilities},
    transport::TransportType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Message ID type
pub type MessageId = Uuid;

/// Signaling message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    /// Message ID for request/response correlation
    pub id: MessageId,
    
    /// Protocol version
    pub version: String,
    
    /// Message timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,
    
    /// Sender peer ID
    pub sender: PeerId,
    
    /// Target peer ID (optional for broadcast messages)
    pub target: Option<PeerId>,
    
    /// Message type and payload
    pub payload: MessagePayload,
    
    /// Message signature (optional)
    pub signature: Option<Vec<u8>>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Message payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessagePayload {
    // Peer management
    PeerAnnouncement(PeerAnnouncementData),
    PeerQuery(PeerQueryData),
    PeerResponse(PeerResponseData),
    PeerUpdate(PeerUpdateData),
    PeerGoodbye(PeerGoodbyeData),
    
    // Connection management
    ConnectionRequest(ConnectionRequestData),
    ConnectionResponse(ConnectionResponseData),
    ConnectionOffer(ConnectionOfferData),
    ConnectionAnswer(ConnectionAnswerData),
    ConnectionCandidate(ConnectionCandidateData),
    ConnectionEstablished(ConnectionEstablishedData),
    ConnectionClosed(ConnectionClosedData),
    
    // Server management
    ServerStatus(ServerStatusData),
    ServerStats(ServerStatsData),
    
    // Error handling
    Error(ErrorData),
    
    // Keep-alive
    Ping(PingData),
    Pong(PongData),
    
    // Custom/extension messages
    Custom(CustomData),
}

// Peer management messages

/// Peer announcement data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncementData {
    pub peer_info: PeerInfo,
    pub ttl: Option<u64>, // Time-to-live in seconds
}

/// Peer query data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerQueryData {
    pub capabilities: Option<PeerCapabilities>,
    pub transport_types: Option<Vec<TransportType>>,
    pub max_results: Option<usize>,
    pub include_self: bool,
}

/// Peer response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerResponseData {
    pub peers: Vec<PeerInfo>,
    pub total_count: usize,
    pub has_more: bool,
}

/// Peer update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerUpdateData {
    pub peer_id: PeerId,
    pub updates: PeerUpdates,
}

/// Peer update fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerUpdates {
    pub addresses: Option<Vec<String>>,
    pub capabilities: Option<PeerCapabilities>,
    pub public_key: Option<Vec<u8>>,
    pub last_seen: Option<u64>,
    pub latency: Option<u32>,
    pub reliability: Option<f32>,
}

/// Peer goodbye data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGoodbyeData {
    pub reason: String,
    pub graceful: bool,
}

// Connection management messages

/// Connection request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRequestData {
    pub target_peer: PeerId,
    pub transport_type: TransportType,
    pub connection_id: Uuid,
    pub initiator_info: PeerInfo,
    pub offer_data: Option<serde_json::Value>, // Transport-specific offer data
}

/// Connection response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionResponseData {
    pub connection_id: Uuid,
    pub accepted: bool,
    pub reason: Option<String>,
    pub responder_info: Option<PeerInfo>,
    pub answer_data: Option<serde_json::Value>, // Transport-specific answer data
}

/// Connection offer data (WebRTC SDP offer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionOfferData {
    pub connection_id: Uuid,
    pub offer: serde_json::Value, // SDP offer or transport-specific data
    pub transport_type: TransportType,
}

/// Connection answer data (WebRTC SDP answer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAnswerData {
    pub connection_id: Uuid,
    pub answer: serde_json::Value, // SDP answer or transport-specific data
}

/// Connection candidate data (ICE candidates)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionCandidateData {
    pub connection_id: Uuid,
    pub candidate: serde_json::Value, // ICE candidate or transport-specific data
}

/// Connection established data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEstablishedData {
    pub connection_id: Uuid,
    pub peer_id: PeerId,
    pub transport_type: TransportType,
    pub local_address: String,
    pub remote_address: String,
}

/// Connection closed data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionClosedData {
    pub connection_id: Uuid,
    pub reason: String,
    pub error_code: Option<u32>,
}

// Server management messages

/// Server status data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusData {
    pub server_id: String,
    pub version: String,
    pub uptime: u64,
    pub connected_peers: usize,
    pub load: f32, // 0.0 to 1.0
    pub features: Vec<String>,
}

/// Server statistics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatsData {
    pub messages_processed: u64,
    pub connections_established: u64,
    pub bytes_transferred: u64,
    pub error_count: u64,
    pub average_latency: f32,
}

// Error handling

/// Error data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorData {
    pub error_code: u32,
    pub error_message: String,
    pub details: Option<serde_json::Value>,
    pub retry_after: Option<u64>, // Seconds
}

// Keep-alive messages

/// Ping data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingData {
    pub timestamp: u64,
    pub sequence: u32,
}

/// Pong data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongData {
    pub timestamp: u64,
    pub sequence: u32,
    pub ping_timestamp: u64,
}

// Custom messages

/// Custom message data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomData {
    pub message_type: String,
    pub data: serde_json::Value,
}

// Error codes

/// Standard error codes
pub mod error_codes {
    pub const INVALID_MESSAGE: u32 = 1000;
    pub const UNSUPPORTED_VERSION: u32 = 1001;
    pub const AUTHENTICATION_FAILED: u32 = 1002;
    pub const AUTHORIZATION_FAILED: u32 = 1003;
    pub const RATE_LIMITED: u32 = 1004;
    pub const PEER_NOT_FOUND: u32 = 1005;
    pub const CONNECTION_FAILED: u32 = 1006;
    pub const TRANSPORT_NOT_SUPPORTED: u32 = 1007;
    pub const SERVER_OVERLOADED: u32 = 1008;
    pub const INVALID_REQUEST: u32 = 1009;
    pub const TIMEOUT: u32 = 1010;
    pub const INTERNAL_ERROR: u32 = 1011;
}

impl SignalingMessage {
    /// Create a new signaling message
    pub fn new(
        sender: PeerId,
        target: Option<PeerId>,
        payload: MessagePayload,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            version: PROTOCOL_VERSION.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sender,
            target,
            payload,
            signature: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Create a response message
    pub fn response(
        original: &SignalingMessage,
        sender: PeerId,
        payload: MessagePayload,
    ) -> Self {
        Self {
            id: original.id, // Same ID for correlation
            version: PROTOCOL_VERSION.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sender,
            target: Some(original.sender.clone()),
            payload,
            signature: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Create an error response
    pub fn error_response(
        original: &SignalingMessage,
        sender: PeerId,
        error_code: u32,
        error_message: String,
    ) -> Self {
        let error_data = ErrorData {
            error_code,
            error_message,
            details: None,
            retry_after: None,
        };
        
        Self::response(original, sender, MessagePayload::Error(error_data))
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Set signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
    
    /// Check if message is a response
    pub fn is_response(&self) -> bool {
        matches!(
            self.payload,
            MessagePayload::PeerResponse(_)
                | MessagePayload::ConnectionResponse(_)
                | MessagePayload::ConnectionAnswer(_)
                | MessagePayload::Pong(_)
                | MessagePayload::Error(_)
        )
    }
    
    /// Check if message requires response
    pub fn requires_response(&self) -> bool {
        matches!(
            self.payload,
            MessagePayload::PeerQuery(_)
                | MessagePayload::ConnectionRequest(_)
                | MessagePayload::ConnectionOffer(_)
                | MessagePayload::Ping(_)
        )
    }
    
    /// Get message size in bytes (approximate)
    pub fn size(&self) -> usize {
        // This is an approximation - actual size depends on serialization format
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
    
    /// Validate message
    pub fn validate(&self) -> Result<(), String> {
        // Check protocol version
        if self.version != PROTOCOL_VERSION {
            return Err(format!(
                "Unsupported protocol version: {} (expected: {})",
                self.version, PROTOCOL_VERSION
            ));
        }
        
        // Check message size
        if self.size() > MAX_MESSAGE_SIZE {
            return Err(format!(
                "Message too large: {} bytes (max: {})",
                self.size(),
                MAX_MESSAGE_SIZE
            ));
        }
        
        // Check timestamp (not too old or too far in future)
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let age = now.saturating_sub(self.timestamp);
        let future = self.timestamp.saturating_sub(now);
        
        if age > 300_000 { // 5 minutes
            return Err("Message too old".to_string());
        }
        
        if future > 60_000 { // 1 minute
            return Err("Message timestamp too far in future".to_string());
        }
        
        // Validate payload-specific fields
        self.validate_payload()?;
        
        Ok(())
    }
    
    /// Validate payload-specific fields
    fn validate_payload(&self) -> Result<(), String> {
        match &self.payload {
            MessagePayload::PeerQuery(data) => {
                if let Some(max_results) = data.max_results {
                    if max_results == 0 || max_results > 1000 {
                        return Err("Invalid max_results value".to_string());
                    }
                }
            }
            MessagePayload::ConnectionRequest(data) => {
                if data.target_peer == self.sender {
                    return Err("Cannot request connection to self".to_string());
                }
            }
            MessagePayload::Error(data) => {
                if data.error_message.is_empty() {
                    return Err("Error message cannot be empty".to_string());
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

/// Message builder for convenient message construction
pub struct MessageBuilder {
    sender: PeerId,
    target: Option<PeerId>,
    metadata: HashMap<String, String>,
}

impl MessageBuilder {
    pub fn new(sender: PeerId) -> Self {
        Self {
            sender,
            target: None,
            metadata: HashMap::new(),
        }
    }
    
    pub fn target(mut self, target: PeerId) -> Self {
        self.target = Some(target);
        self
    }
    
    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    pub fn build(self, payload: MessagePayload) -> SignalingMessage {
        let mut message = SignalingMessage::new(self.sender, self.target, payload);
        message.metadata = self.metadata;
        message
    }
    
    // Convenience methods for common message types
    
    pub fn peer_announcement(self, peer_info: PeerInfo) -> SignalingMessage {
        let data = PeerAnnouncementData {
            peer_info,
            ttl: Some(300), // 5 minutes default TTL
        };
        self.build(MessagePayload::PeerAnnouncement(data))
    }
    
    pub fn peer_query(self, capabilities: Option<PeerCapabilities>) -> SignalingMessage {
        let data = PeerQueryData {
            capabilities,
            transport_types: None,
            max_results: Some(50),
            include_self: false,
        };
        self.build(MessagePayload::PeerQuery(data))
    }
    
    pub fn connection_request(
        self,
        target_peer: PeerId,
        transport_type: TransportType,
        initiator_info: PeerInfo,
    ) -> SignalingMessage {
        let data = ConnectionRequestData {
            target_peer,
            transport_type,
            connection_id: Uuid::new_v4(),
            initiator_info,
            offer_data: None,
        };
        self.build(MessagePayload::ConnectionRequest(data))
    }
    
    pub fn ping(self) -> SignalingMessage {
        let data = PingData {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: rand::random(),
        };
        self.build(MessagePayload::Ping(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::peer::PeerId;
    
    #[test]
    fn test_message_creation() {
        let sender = PeerId::new();
        let target = PeerId::new();
        
        let message = SignalingMessage::new(
            sender.clone(),
            Some(target.clone()),
            MessagePayload::Ping(PingData {
                timestamp: 12345,
                sequence: 1,
            }),
        );
        
        assert_eq!(message.sender, sender);
        assert_eq!(message.target, Some(target));
        assert_eq!(message.version, PROTOCOL_VERSION);
        assert!(matches!(message.payload, MessagePayload::Ping(_)));
    }
    
    #[test]
    fn test_message_builder() {
        let sender = PeerId::new();
        let target = PeerId::new();
        
        let message = MessageBuilder::new(sender.clone())
            .target(target.clone())
            .metadata("test".to_string(), "value".to_string())
            .ping();
        
        assert_eq!(message.sender, sender);
        assert_eq!(message.target, Some(target));
        assert_eq!(message.metadata.get("test"), Some(&"value".to_string()));
    }
    
    #[test]
    fn test_message_validation() {
        let sender = PeerId::new();
        let message = SignalingMessage::new(
            sender,
            None,
            MessagePayload::Ping(PingData {
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                sequence: 1,
            }),
        );
        
        assert!(message.validate().is_ok());
    }
    
    #[test]
    fn test_message_serialization() {
        let sender = PeerId::new();
        let message = SignalingMessage::new(
            sender,
            None,
            MessagePayload::Ping(PingData {
                timestamp: 12345,
                sequence: 1,
            }),
        );
        
        // Test JSON serialization
        let json = serde_json::to_string(&message).unwrap();
        let deserialized: SignalingMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(message.id, deserialized.id);
        
        // Test binary serialization
        let binary = bincode::serialize(&message).unwrap();
        let deserialized: SignalingMessage = bincode::deserialize(&binary).unwrap();
        assert_eq!(message.id, deserialized.id);
    }
    
    #[test]
    fn test_error_response() {
        let sender = PeerId::new();
        let original = SignalingMessage::new(
            sender.clone(),
            None,
            MessagePayload::Ping(PingData {
                timestamp: 12345,
                sequence: 1,
            }),
        );
        
        let error_response = SignalingMessage::error_response(
            &original,
            sender,
            error_codes::INVALID_MESSAGE,
            "Test error".to_string(),
        );
        
        assert_eq!(error_response.id, original.id);
        assert!(matches!(error_response.payload, MessagePayload::Error(_)));
    }
}