//! Packet handling for onion routing
//! Implements onion packet format and processing

use crate::crypto::{OnionEncryptedData, OnionKey};
use crate::error::{OnionResult, PacketError};
use zMesh_core::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Onion packet identifier
pub type PacketId = String;

/// Circuit identifier for packet routing
pub type CircuitId = String;

/// Onion packet command types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnionCommand {
    /// Extend circuit to next hop
    Extend,
    /// Extended response
    Extended,
    /// Begin data stream
    Begin,
    /// Data payload
    Data,
    /// End data stream
    End,
    /// Relay data to next hop
    Relay,
    /// Relay response
    RelayResponse,
    /// Destroy circuit
    Destroy,
    /// Keep-alive ping
    Ping,
    /// Keep-alive pong
    Pong,
    /// Error response
    Error,
}

/// Onion packet header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionHeader {
    /// Packet identifier
    pub packet_id: PacketId,
    /// Circuit identifier
    pub circuit_id: CircuitId,
    /// Command type
    pub command: OnionCommand,
    /// Hop index (0-based)
    pub hop_index: u8,
    /// Packet sequence number
    pub sequence: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Payload length
    pub payload_length: u32,
    /// Flags
    pub flags: u8,
    /// Checksum
    pub checksum: u32,
}

impl OnionHeader {
    /// Create a new onion header
    pub fn new(
        circuit_id: CircuitId,
        command: OnionCommand,
        hop_index: u8,
        sequence: u32,
        payload_length: u32,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            packet_id: Uuid::new_v4().to_string(),
            circuit_id,
            command,
            hop_index,
            sequence,
            timestamp,
            payload_length,
            flags: 0,
            checksum: 0, // Will be calculated later
        }
    }
    
    /// Calculate and set checksum
    pub fn calculate_checksum(&mut self, payload: &[u8]) {
        // Simple CRC32-like checksum
        let mut checksum = 0u32;
        
        // Include header fields in checksum
        checksum = checksum.wrapping_add(self.hop_index as u32);
        checksum = checksum.wrapping_add(self.sequence);
        checksum = checksum.wrapping_add(self.timestamp as u32);
        checksum = checksum.wrapping_add(self.payload_length);
        checksum = checksum.wrapping_add(self.flags as u32);
        
        // Include payload in checksum
        for byte in payload {
            checksum = checksum.wrapping_add(*byte as u32);
        }
        
        self.checksum = checksum;
    }
    
    /// Verify checksum
    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        let mut expected_checksum = 0u32;
        
        expected_checksum = expected_checksum.wrapping_add(self.hop_index as u32);
        expected_checksum = expected_checksum.wrapping_add(self.sequence);
        expected_checksum = expected_checksum.wrapping_add(self.timestamp as u32);
        expected_checksum = expected_checksum.wrapping_add(self.payload_length);
        expected_checksum = expected_checksum.wrapping_add(self.flags as u32);
        
        for byte in payload {
            expected_checksum = expected_checksum.wrapping_add(*byte as u32);
        }
        
        self.checksum == expected_checksum
    }
    
    /// Get packet age
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Duration::from_secs(now.saturating_sub(self.timestamp))
    }
    
    /// Check if packet is expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.age() > max_age
    }
}

/// Onion packet payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnionPayload {
    /// Extend request with public key
    ExtendRequest {
        target_peer: PeerId,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    },
    /// Extended response with public key
    ExtendedResponse {
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    },
    /// Begin stream request
    BeginRequest {
        destination: String,
        port: u16,
        flags: u32,
    },
    /// Data payload
    Data {
        stream_id: u16,
        data: Vec<u8>,
    },
    /// End stream
    EndStream {
        stream_id: u16,
        reason: u8,
    },
    /// Relay payload (encrypted for next hop)
    Relay {
        encrypted_payload: OnionEncryptedData,
    },
    /// Error response
    Error {
        error_code: u16,
        message: String,
    },
    /// Keep-alive ping
    Ping {
        nonce: Vec<u8>,
    },
    /// Keep-alive pong
    Pong {
        nonce: Vec<u8>,
    },
    /// Raw bytes
    Raw(Vec<u8>),
}

/// Complete onion packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// Packet header
    pub header: OnionHeader,
    /// Packet payload
    pub payload: OnionPayload,
}

impl OnionPacket {
    /// Create a new onion packet
    pub fn new(
        circuit_id: CircuitId,
        command: OnionCommand,
        hop_index: u8,
        sequence: u32,
        payload: OnionPayload,
    ) -> OnionResult<Self> {
        let payload_bytes = bincode::serialize(&payload)
            .map_err(|e| PacketError::InvalidPayload(e.to_string()))?;
        
        let mut header = OnionHeader::new(
            circuit_id,
            command,
            hop_index,
            sequence,
            payload_bytes.len() as u32,
        );
        
        header.calculate_checksum(&payload_bytes);
        
        Ok(Self { header, payload })
    }
    
    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> OnionResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| PacketError::InvalidFormat(e.to_string()).into())
    }
    
    /// Deserialize packet from bytes
    pub fn from_bytes(bytes: &[u8]) -> OnionResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| PacketError::InvalidFormat(e.to_string()).into())
    }
    
    /// Validate packet integrity
    pub fn validate(&self) -> OnionResult<()> {
        // Check payload length
        let payload_bytes = bincode::serialize(&self.payload)
            .map_err(|e| PacketError::InvalidPayload(e.to_string()))?;
        
        if payload_bytes.len() as u32 != self.header.payload_length {
            return Err(PacketError::InvalidHeader(
                "Payload length mismatch".to_string()
            ).into());
        }
        
        // Verify checksum
        if !self.header.verify_checksum(&payload_bytes) {
            return Err(PacketError::AuthenticationFailed(
                "Checksum verification failed".to_string()
            ).into());
        }
        
        Ok(())
    }
    
    /// Get packet size in bytes
    pub fn size(&self) -> OnionResult<usize> {
        Ok(self.to_bytes()?.len())
    }
    
    /// Check if packet is expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.header.is_expired(max_age)
    }
    
    /// Get packet ID
    pub fn id(&self) -> &str {
        &self.header.packet_id
    }
    
    /// Get circuit ID
    pub fn circuit_id(&self) -> &str {
        &self.header.circuit_id
    }
    
    /// Get command
    pub fn command(&self) -> &OnionCommand {
        &self.header.command
    }
    
    /// Get hop index
    pub fn hop_index(&self) -> u8 {
        self.header.hop_index
    }
    
    /// Get sequence number
    pub fn sequence(&self) -> u32 {
        self.header.sequence
    }
}

/// Packet processing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketStats {
    /// Total packets processed
    pub packets_processed: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Invalid packets
    pub invalid_packets: u64,
    /// Expired packets
    pub expired_packets: u64,
    /// Duplicate packets
    pub duplicate_packets: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Total bytes processed
    pub total_bytes: u64,
}

/// Packet processor for handling onion packets
pub struct PacketProcessor {
    /// Maximum packet size
    max_packet_size: usize,
    /// Maximum packet age
    max_packet_age: Duration,
    /// Sequence tracking per circuit
    sequence_tracker: HashMap<CircuitId, u32>,
    /// Duplicate detection cache
    duplicate_cache: HashMap<PacketId, SystemTime>,
    /// Processing statistics
    stats: PacketStats,
}

impl PacketProcessor {
    /// Create a new packet processor
    pub fn new(max_packet_size: usize, max_packet_age: Duration) -> Self {
        Self {
            max_packet_size,
            max_packet_age,
            sequence_tracker: HashMap::new(),
            duplicate_cache: HashMap::new(),
            stats: PacketStats::default(),
        }
    }
    
    /// Process an incoming packet
    pub fn process_packet(&mut self, packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        self.stats.packets_processed += 1;
        
        // Validate packet
        packet.validate()?;
        
        // Check packet size
        let packet_size = packet.size()?;
        if packet_size > self.max_packet_size {
            self.stats.packets_dropped += 1;
            return Err(PacketError::TooLarge {
                size: packet_size,
                max: self.max_packet_size,
            }.into());
        }
        
        // Check packet age
        if packet.is_expired(self.max_packet_age) {
            self.stats.expired_packets += 1;
            return Err(PacketError::ReplayDetected(
                "Packet expired".to_string()
            ).into());
        }
        
        // Check for duplicates
        if self.is_duplicate(packet) {
            self.stats.duplicate_packets += 1;
            return Err(PacketError::ReplayDetected(
                "Duplicate packet".to_string()
            ).into());
        }
        
        // Check sequence number
        self.check_sequence(packet)?;
        
        // Update statistics
        self.update_stats(packet_size);
        
        // Process based on command
        let result = match packet.command() {
            OnionCommand::Extend => self.process_extend(packet),
            OnionCommand::Extended => self.process_extended(packet),
            OnionCommand::Begin => self.process_begin(packet),
            OnionCommand::Data => self.process_data(packet),
            OnionCommand::End => self.process_end(packet),
            OnionCommand::Relay => self.process_relay(packet),
            OnionCommand::RelayResponse => self.process_relay_response(packet),
            OnionCommand::Destroy => self.process_destroy(packet),
            OnionCommand::Ping => self.process_ping(packet),
            OnionCommand::Pong => self.process_pong(packet),
            OnionCommand::Error => self.process_error(packet),
        };
        
        // Cache packet ID for duplicate detection
        self.cache_packet_id(packet);
        
        result
    }
    
    /// Check if packet is a duplicate
    fn is_duplicate(&self, packet: &OnionPacket) -> bool {
        self.duplicate_cache.contains_key(packet.id())
    }
    
    /// Check packet sequence number
    fn check_sequence(&mut self, packet: &OnionPacket) -> OnionResult<()> {
        let circuit_id = packet.circuit_id();
        let sequence = packet.sequence();
        
        if let Some(&expected_sequence) = self.sequence_tracker.get(circuit_id) {
            if sequence != expected_sequence {
                return Err(PacketError::SequenceError {
                    expected: expected_sequence,
                    actual: sequence,
                }.into());
            }
        }
        
        // Update expected sequence
        self.sequence_tracker.insert(circuit_id.to_string(), sequence + 1);
        
        Ok(())
    }
    
    /// Cache packet ID for duplicate detection
    fn cache_packet_id(&mut self, packet: &OnionPacket) {
        self.duplicate_cache.insert(
            packet.id().to_string(),
            SystemTime::now(),
        );
        
        // Clean old entries
        self.cleanup_duplicate_cache();
    }
    
    /// Clean up old entries from duplicate cache
    fn cleanup_duplicate_cache(&mut self) {
        let cutoff = SystemTime::now() - self.max_packet_age;
        self.duplicate_cache.retain(|_, &mut timestamp| timestamp > cutoff);
    }
    
    /// Update processing statistics
    fn update_stats(&mut self, packet_size: usize) {
        self.stats.total_bytes += packet_size as u64;
        
        // Update average packet size
        let total_packets = self.stats.packets_processed;
        self.stats.avg_packet_size = 
            (self.stats.avg_packet_size * (total_packets - 1) as f64 + packet_size as f64) / total_packets as f64;
    }
    
    /// Process extend command
    fn process_extend(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Implement extend processing
        Ok(ProcessingResult::Forward)
    }
    
    /// Process extended command
    fn process_extended(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Implement extended processing
        Ok(ProcessingResult::Consume)
    }
    
    /// Process begin command
    fn process_begin(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Implement begin processing
        Ok(ProcessingResult::Forward)
    }
    
    /// Process data command
    fn process_data(&mut self, packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        self.stats.packets_received += 1;
        
        match &packet.payload {
            OnionPayload::Data { stream_id, data } => {
                // TODO: Handle data payload
                Ok(ProcessingResult::Data {
                    stream_id: *stream_id,
                    data: data.clone(),
                })
            }
            _ => Err(PacketError::InvalidPayload(
                "Expected data payload".to_string()
            ).into()),
        }
    }
    
    /// Process end command
    fn process_end(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Implement end processing
        Ok(ProcessingResult::Consume)
    }
    
    /// Process relay command
    fn process_relay(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        self.stats.packets_forwarded += 1;
        // TODO: Implement relay processing
        Ok(ProcessingResult::Forward)
    }
    
    /// Process relay response command
    fn process_relay_response(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Implement relay response processing
        Ok(ProcessingResult::Consume)
    }
    
    /// Process destroy command
    fn process_destroy(&mut self, packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // Remove circuit from tracking
        self.sequence_tracker.remove(packet.circuit_id());
        Ok(ProcessingResult::Destroy)
    }
    
    /// Process ping command
    fn process_ping(&mut self, packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        match &packet.payload {
            OnionPayload::Ping { nonce } => {
                Ok(ProcessingResult::Pong {
                    nonce: nonce.clone(),
                })
            }
            _ => Err(PacketError::InvalidPayload(
                "Expected ping payload".to_string()
            ).into()),
        }
    }
    
    /// Process pong command
    fn process_pong(&mut self, _packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        // TODO: Handle pong response
        Ok(ProcessingResult::Consume)
    }
    
    /// Process error command
    fn process_error(&mut self, packet: &OnionPacket) -> OnionResult<ProcessingResult> {
        match &packet.payload {
            OnionPayload::Error { error_code, message } => {
                Ok(ProcessingResult::Error {
                    code: *error_code,
                    message: message.clone(),
                })
            }
            _ => Err(PacketError::InvalidPayload(
                "Expected error payload".to_string()
            ).into()),
        }
    }
    
    /// Get processing statistics
    pub fn get_stats(&self) -> &PacketStats {
        &self.stats
    }
    
    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = PacketStats::default();
    }
    
    /// Get circuit count
    pub fn circuit_count(&self) -> usize {
        self.sequence_tracker.len()
    }
    
    /// Remove circuit tracking
    pub fn remove_circuit(&mut self, circuit_id: &str) {
        self.sequence_tracker.remove(circuit_id);
    }
}

/// Packet processing result
#[derive(Debug, Clone)]
pub enum ProcessingResult {
    /// Forward packet to next hop
    Forward,
    /// Consume packet (don't forward)
    Consume,
    /// Destroy circuit
    Destroy,
    /// Data payload extracted
    Data {
        stream_id: u16,
        data: Vec<u8>,
    },
    /// Send pong response
    Pong {
        nonce: Vec<u8>,
    },
    /// Error occurred
    Error {
        code: u16,
        message: String,
    },
}

/// Packet builder for creating onion packets
pub struct PacketBuilder {
    circuit_id: CircuitId,
    hop_index: u8,
    sequence: u32,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub fn new(circuit_id: CircuitId, hop_index: u8, sequence: u32) -> Self {
        Self {
            circuit_id,
            hop_index,
            sequence,
        }
    }
    
    /// Build an extend packet
    pub fn extend(
        self,
        target_peer: PeerId,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> OnionResult<OnionPacket> {
        let payload = OnionPayload::ExtendRequest {
            target_peer,
            public_key,
            nonce,
        };
        
        OnionPacket::new(
            self.circuit_id,
            OnionCommand::Extend,
            self.hop_index,
            self.sequence,
            payload,
        )
    }
    
    /// Build an extended packet
    pub fn extended(
        self,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> OnionResult<OnionPacket> {
        let payload = OnionPayload::ExtendedResponse {
            public_key,
            nonce,
        };
        
        OnionPacket::new(
            self.circuit_id,
            OnionCommand::Extended,
            self.hop_index,
            self.sequence,
            payload,
        )
    }
    
    /// Build a data packet
    pub fn data(
        self,
        stream_id: u16,
        data: Vec<u8>,
    ) -> OnionResult<OnionPacket> {
        let payload = OnionPayload::Data { stream_id, data };
        
        OnionPacket::new(
            self.circuit_id,
            OnionCommand::Data,
            self.hop_index,
            self.sequence,
            payload,
        )
    }
    
    /// Build a ping packet
    pub fn ping(self, nonce: Vec<u8>) -> OnionResult<OnionPacket> {
        let payload = OnionPayload::Ping { nonce };
        
        OnionPacket::new(
            self.circuit_id,
            OnionCommand::Ping,
            self.hop_index,
            self.sequence,
            payload,
        )
    }
    
    /// Build a destroy packet
    pub fn destroy(self) -> OnionResult<OnionPacket> {
        let payload = OnionPayload::Raw(vec![]);
        
        OnionPacket::new(
            self.circuit_id,
            OnionCommand::Destroy,
            self.hop_index,
            self.sequence,
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_onion_header_creation() {
        let header = OnionHeader::new(
            "circuit-123".to_string(),
            OnionCommand::Data,
            1,
            42,
            1024,
        );
        
        assert_eq!(header.circuit_id, "circuit-123");
        assert_eq!(header.command, OnionCommand::Data);
        assert_eq!(header.hop_index, 1);
        assert_eq!(header.sequence, 42);
        assert_eq!(header.payload_length, 1024);
    }
    
    #[test]
    fn test_checksum_calculation() {
        let mut header = OnionHeader::new(
            "circuit-123".to_string(),
            OnionCommand::Data,
            1,
            42,
            4,
        );
        
        let payload = b"test";
        header.calculate_checksum(payload);
        
        assert!(header.verify_checksum(payload));
        assert!(!header.verify_checksum(b"different"));
    }
    
    #[test]
    fn test_packet_creation() {
        let payload = OnionPayload::Data {
            stream_id: 1,
            data: b"Hello, World!".to_vec(),
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Data,
            1,
            42,
            payload,
        ).unwrap();
        
        assert_eq!(packet.circuit_id(), "circuit-123");
        assert_eq!(packet.command(), &OnionCommand::Data);
        assert_eq!(packet.hop_index(), 1);
        assert_eq!(packet.sequence(), 42);
    }
    
    #[test]
    fn test_packet_serialization() {
        let payload = OnionPayload::Ping {
            nonce: vec![1, 2, 3, 4],
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Ping,
            0,
            1,
            payload,
        ).unwrap();
        
        let bytes = packet.to_bytes().unwrap();
        let deserialized = OnionPacket::from_bytes(&bytes).unwrap();
        
        assert_eq!(packet.circuit_id(), deserialized.circuit_id());
        assert_eq!(packet.command(), deserialized.command());
        assert_eq!(packet.sequence(), deserialized.sequence());
    }
    
    #[test]
    fn test_packet_validation() {
        let payload = OnionPayload::Data {
            stream_id: 1,
            data: b"test data".to_vec(),
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Data,
            1,
            42,
            payload,
        ).unwrap();
        
        assert!(packet.validate().is_ok());
    }
    
    #[test]
    fn test_packet_processor() {
        let mut processor = PacketProcessor::new(
            8192, // 8KB max packet size
            Duration::from_secs(60), // 60 second max age
        );
        
        let payload = OnionPayload::Ping {
            nonce: vec![1, 2, 3, 4],
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Ping,
            0,
            0, // First packet
            payload,
        ).unwrap();
        
        let result = processor.process_packet(&packet).unwrap();
        
        match result {
            ProcessingResult::Pong { nonce } => {
                assert_eq!(nonce, vec![1, 2, 3, 4]);
            }
            _ => panic!("Expected Pong result"),
        }
        
        assert_eq!(processor.get_stats().packets_processed, 1);
    }
    
    #[test]
    fn test_packet_builder() {
        let builder = PacketBuilder::new(
            "circuit-123".to_string(),
            1,
            42,
        );
        
        let packet = builder.data(1, b"Hello, World!".to_vec()).unwrap();
        
        assert_eq!(packet.circuit_id(), "circuit-123");
        assert_eq!(packet.command(), &OnionCommand::Data);
        assert_eq!(packet.hop_index(), 1);
        assert_eq!(packet.sequence(), 42);
        
        match &packet.payload {
            OnionPayload::Data { stream_id, data } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(data, b"Hello, World!");
            }
            _ => panic!("Expected data payload"),
        }
    }
    
    #[test]
    fn test_duplicate_detection() {
        let mut processor = PacketProcessor::new(
            8192,
            Duration::from_secs(60),
        );
        
        let payload = OnionPayload::Ping {
            nonce: vec![1, 2, 3, 4],
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Ping,
            0,
            0,
            payload,
        ).unwrap();
        
        // First processing should succeed
        assert!(processor.process_packet(&packet).is_ok());
        
        // Second processing should fail (duplicate)
        assert!(processor.process_packet(&packet).is_err());
    }
}