//! Onion relay implementation
//! Handles packet relaying between hops in the onion network

use crate::circuit::{CircuitId, CircuitState};
use crate::crypto::{OnionCrypto, OnionEncryptedData, HopKeys};
use crate::error::{OnionResult, RelayError};
use crate::packet::{
    OnionPacket, OnionCommand, OnionPayload, PacketBuilder, PacketProcessor
};
use crnet_core::peer::PeerId;
use crnet_transport::TransportManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use uuid::Uuid;

/// Relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum concurrent relays
    pub max_relays: usize,
    /// Relay timeout
    pub relay_timeout: Duration,
    /// Buffer size for packet queues
    pub buffer_size: usize,
    /// Maximum packet size to relay
    pub max_packet_size: usize,
    /// Enable packet validation
    pub validate_packets: bool,
    /// Enable bandwidth limiting
    pub enable_bandwidth_limit: bool,
    /// Bandwidth limit in bytes per second
    pub bandwidth_limit: u64,
    /// Enable relay statistics
    pub collect_stats: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_relays: 1000,
            relay_timeout: Duration::from_secs(30),
            buffer_size: 1000,
            max_packet_size: 8192,
            validate_packets: true,
            enable_bandwidth_limit: false,
            bandwidth_limit: 1024 * 1024, // 1 MB/s
            collect_stats: true,
        }
    }
}

/// Relay statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayStats {
    /// Total packets relayed
    pub packets_relayed: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Total bytes relayed
    pub bytes_relayed: u64,
    /// Active relay sessions
    pub active_relays: usize,
    /// Relay errors
    pub relay_errors: u64,
    /// Average relay latency
    pub avg_latency: Duration,
    /// Bandwidth usage
    pub bandwidth_usage: u64,
    /// Last update timestamp
    pub last_update: Instant,
}

/// Relay session information
#[derive(Debug, Clone)]
struct RelaySession {
    /// Session ID
    id: String,
    /// Circuit ID
    circuit_id: CircuitId,
    /// Previous hop peer
    prev_hop: PeerId,
    /// Next hop peer
    next_hop: PeerId,
    /// Hop keys for encryption/decryption
    hop_keys: HopKeys,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Packets relayed in this session
    packets_relayed: u64,
    /// Bytes relayed in this session
    bytes_relayed: u64,
}

impl RelaySession {
    /// Create a new relay session
    fn new(
        circuit_id: CircuitId,
        prev_hop: PeerId,
        next_hop: PeerId,
        hop_keys: HopKeys,
    ) -> Self {
        let now = Instant::now();
        
        Self {
            id: Uuid::new_v4().to_string(),
            circuit_id,
            prev_hop,
            next_hop,
            hop_keys,
            created_at: now,
            last_activity: now,
            packets_relayed: 0,
            bytes_relayed: 0,
        }
    }
    
    /// Update activity timestamp
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Check if session is expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
    
    /// Get session age
    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
    
    /// Record relayed packet
    fn record_packet(&mut self, size: usize) {
        self.packets_relayed += 1;
        self.bytes_relayed += size as u64;
        self.update_activity();
    }
}

/// Bandwidth limiter for relay operations
struct BandwidthLimiter {
    /// Bandwidth limit in bytes per second
    limit: u64,
    /// Current usage in the current window
    current_usage: u64,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter
    fn new(limit: u64) -> Self {
        Self {
            limit,
            current_usage: 0,
            window_start: Instant::now(),
            window_duration: Duration::from_secs(1),
        }
    }
    
    /// Check if we can send the given amount of data
    fn can_send(&mut self, size: u64) -> bool {
        self.update_window();
        
        if self.current_usage + size <= self.limit {
            self.current_usage += size;
            true
        } else {
            false
        }
    }
    
    /// Update the bandwidth window
    fn update_window(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_duration {
            self.current_usage = 0;
            self.window_start = now;
        }
    }
    
    /// Get current usage percentage
    fn usage_percentage(&mut self) -> f64 {
        self.update_window();
        (self.current_usage as f64 / self.limit as f64) * 100.0
    }
}

/// Onion relay implementation
pub struct OnionRelay {
    /// Relay configuration
    config: RelayConfig,
    /// Active relay sessions
    sessions: Arc<RwLock<HashMap<CircuitId, RelaySession>>>,
    /// Cryptographic operations
    crypto: Arc<OnionCrypto>,
    /// Transport manager
    transport: Arc<TransportManager>,
    /// Packet processor
    packet_processor: Arc<RwLock<PacketProcessor>>,
    /// Bandwidth limiter
    bandwidth_limiter: Arc<RwLock<BandwidthLimiter>>,
    /// Relay statistics
    stats: Arc<RwLock<RelayStats>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl OnionRelay {
    /// Create a new onion relay
    pub async fn new(
        config: RelayConfig,
        crypto: Arc<OnionCrypto>,
        transport: Arc<TransportManager>,
    ) -> OnionResult<Self> {
        let packet_processor = Arc::new(RwLock::new(
            PacketProcessor::new(config.max_packet_size, config.relay_timeout)
        ));
        
        let bandwidth_limiter = Arc::new(RwLock::new(
            BandwidthLimiter::new(config.bandwidth_limit)
        ));
        
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            crypto,
            transport,
            packet_processor,
            bandwidth_limiter,
            stats: Arc::new(RwLock::new(RelayStats::default())),
            shutdown_tx: None,
        })
    }
    
    /// Start the relay
    pub async fn start(&mut self) -> OnionResult<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        // Start background tasks
        self.start_cleanup_task().await;
        self.start_stats_task().await;
        
        // Wait for shutdown signal
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Relay shutdown requested");
            }
        }
        
        Ok(())
    }
    
    /// Stop the relay
    pub async fn stop(&mut self) -> OnionResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Clear all sessions
        let mut sessions = self.sessions.write().await;
        sessions.clear();
        
        Ok(())
    }
    
    /// Create a new relay session
    pub async fn create_session(
        &self,
        circuit_id: CircuitId,
        prev_hop: PeerId,
        next_hop: PeerId,
        hop_keys: HopKeys,
    ) -> OnionResult<String> {
        let mut sessions = self.sessions.write().await;
        
        if sessions.len() >= self.config.max_relays {
            return Err(RelayError::TooManyRelays {
                current: sessions.len(),
                max: self.config.max_relays,
            }.into());
        }
        
        let session = RelaySession::new(circuit_id.clone(), prev_hop, next_hop, hop_keys);
        let session_id = session.id.clone();
        
        sessions.insert(circuit_id, session);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.active_relays = sessions.len();
        
        Ok(session_id)
    }
    
    /// Remove a relay session
    pub async fn remove_session(&self, circuit_id: &str) -> OnionResult<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(circuit_id);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.active_relays = sessions.len();
        
        Ok(())
    }
    
    /// Relay a packet
    pub async fn relay_packet(&self, packet: OnionPacket, from_peer: PeerId) -> OnionResult<()> {
        let circuit_id = packet.circuit_id().to_string();
        
        // Validate packet if enabled
        if self.config.validate_packets {
            packet.validate()?;
        }
        
        // Check bandwidth limit
        if self.config.enable_bandwidth_limit {
            let packet_size = packet.size()? as u64;
            let mut limiter = self.bandwidth_limiter.write().await;
            
            if !limiter.can_send(packet_size) {
                let mut stats = self.stats.write().await;
                stats.packets_dropped += 1;
                
                return Err(RelayError::BandwidthLimitExceeded {
                    usage: limiter.usage_percentage(),
                }.into());
            }
        }
        
        // Get relay session
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(&circuit_id)
            .ok_or_else(|| RelayError::SessionNotFound(circuit_id.clone()))?;
        
        // Verify the packet came from the expected peer
        if session.prev_hop != from_peer {
            return Err(RelayError::UnauthorizedRelay {
                expected: session.prev_hop.clone(),
                actual: from_peer,
            }.into());
        }
        
        // Process the packet based on command
        let processed_packet = match packet.command() {
            OnionCommand::Relay => {
                self.process_relay_packet(packet, session).await?
            }
            OnionCommand::Data => {
                self.process_data_packet(packet, session).await?
            }
            OnionCommand::Destroy => {
                // Circuit is being destroyed, remove session
                let circuit_id = session.circuit_id.clone();
                drop(sessions); // Release lock before async call
                
                self.remove_session(&circuit_id).await?;
                return Ok(());
            }
            _ => {
                // Forward other commands as-is
                packet
            }
        };
        
        // Forward packet to next hop
        let next_hop = session.next_hop.clone();
        let packet_size = processed_packet.size()?;
        
        // Record packet in session
        session.record_packet(packet_size);
        
        drop(sessions); // Release lock before async call
        
        // Send packet to next hop
        let packet_bytes = processed_packet.to_bytes()?;
        self.transport.send(&next_hop, &packet_bytes).await
            .map_err(|e| RelayError::ForwardingFailed(e.to_string()))?;
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.packets_relayed += 1;
        stats.bytes_relayed += packet_size as u64;
        
        Ok(())
    }
    
    /// Process relay packet (decrypt one layer)
    async fn process_relay_packet(
        &self,
        packet: OnionPacket,
        session: &RelaySession,
    ) -> OnionResult<OnionPacket> {
        match &packet.payload {
            OnionPayload::Relay { encrypted_payload } => {
                // Decrypt one layer using hop keys
                let decrypted_data = self.crypto.decrypt(
                    encrypted_payload,
                    &session.hop_keys.decryption_key,
                ).await?;
                
                // Parse decrypted data as new packet
                let inner_packet = OnionPacket::from_bytes(&decrypted_data)?;
                
                Ok(inner_packet)
            }
            _ => Err(RelayError::InvalidPacketType(
                "Expected relay payload".to_string()
            ).into()),
        }
    }
    
    /// Process data packet
    async fn process_data_packet(
        &self,
        packet: OnionPacket,
        _session: &RelaySession,
    ) -> OnionResult<OnionPacket> {
        // Data packets are forwarded as-is in relay mode
        // The exit node will handle final decryption
        Ok(packet)
    }
    
    /// Get relay statistics
    pub async fn get_stats(&self) -> RelayStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = RelayStats::default();
    }
    
    /// Get active sessions
    pub async fn get_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
    
    /// Get session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }
    
    /// Get bandwidth usage
    pub async fn get_bandwidth_usage(&self) -> f64 {
        let mut limiter = self.bandwidth_limiter.write().await;
        limiter.usage_percentage()
    }
    
    /// Start cleanup task for expired sessions
    async fn start_cleanup_task(&self) {
        let sessions = Arc::clone(&self.sessions);
        let stats = Arc::clone(&self.stats);
        let timeout = self.config.relay_timeout;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Remove expired sessions
                let mut sessions_guard = sessions.write().await;
                let initial_count = sessions_guard.len();
                
                sessions_guard.retain(|_, session| !session.is_expired(timeout));
                
                let removed_count = initial_count - sessions_guard.len();
                
                if removed_count > 0 {
                    println!("Cleaned up {} expired relay sessions", removed_count);
                    
                    // Update statistics
                    let mut stats_guard = stats.write().await;
                    stats_guard.active_relays = sessions_guard.len();
                }
            }
        });
    }
    
    /// Start statistics collection task
    async fn start_stats_task(&self) {
        let stats = Arc::clone(&self.stats);
        let sessions = Arc::clone(&self.sessions);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Update statistics
                let mut stats_guard = stats.write().await;
                let sessions_guard = sessions.read().await;
                
                stats_guard.active_relays = sessions_guard.len();
                stats_guard.last_update = Instant::now();
                
                // Calculate average latency (placeholder)
                // In a real implementation, this would track actual latencies
                if stats_guard.packets_relayed > 0 {
                    stats_guard.avg_latency = Duration::from_millis(50); // Placeholder
                }
            }
        });
    }
}

/// Relay packet queue for buffering
pub struct RelayQueue {
    /// Packet queue
    queue: mpsc::Receiver<OnionPacket>,
    /// Queue sender
    sender: mpsc::Sender<OnionPacket>,
    /// Maximum queue size
    max_size: usize,
}

impl RelayQueue {
    /// Create a new relay queue
    pub fn new(max_size: usize) -> Self {
        let (sender, queue) = mpsc::channel(max_size);
        
        Self {
            queue,
            sender,
            max_size,
        }
    }
    
    /// Add packet to queue
    pub async fn enqueue(&self, packet: OnionPacket) -> OnionResult<()> {
        self.sender.send(packet).await
            .map_err(|_| RelayError::QueueFull(self.max_size).into())
    }
    
    /// Get next packet from queue
    pub async fn dequeue(&mut self) -> Option<OnionPacket> {
        self.queue.recv().await
    }
    
    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.sender.is_closed()
    }
    
    /// Get queue capacity
    pub fn capacity(&self) -> usize {
        self.max_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{OnionKey, OnionCipherSuite, OnionKeyExchange};
    
    #[test]
    fn test_relay_session_creation() {
        let hop_keys = HopKeys {
            encryption_key: OnionKey::new(vec![0; 32]),
            decryption_key: OnionKey::new(vec![1; 32]),
            mac_key: OnionKey::new(vec![2; 32]),
        };
        
        let session = RelaySession::new(
            "circuit-123".to_string(),
            "peer-1".to_string(),
            "peer-2".to_string(),
            hop_keys,
        );
        
        assert_eq!(session.circuit_id, "circuit-123");
        assert_eq!(session.prev_hop, "peer-1");
        assert_eq!(session.next_hop, "peer-2");
        assert_eq!(session.packets_relayed, 0);
        assert_eq!(session.bytes_relayed, 0);
    }
    
    #[test]
    fn test_relay_session_activity() {
        let hop_keys = HopKeys {
            encryption_key: OnionKey::new(vec![0; 32]),
            decryption_key: OnionKey::new(vec![1; 32]),
            mac_key: OnionKey::new(vec![2; 32]),
        };
        
        let mut session = RelaySession::new(
            "circuit-123".to_string(),
            "peer-1".to_string(),
            "peer-2".to_string(),
            hop_keys,
        );
        
        let initial_activity = session.last_activity;
        
        session.record_packet(1024);
        
        assert_eq!(session.packets_relayed, 1);
        assert_eq!(session.bytes_relayed, 1024);
        assert!(session.last_activity > initial_activity);
    }
    
    #[test]
    fn test_bandwidth_limiter() {
        let mut limiter = BandwidthLimiter::new(1000); // 1000 bytes/sec
        
        // Should allow sending within limit
        assert!(limiter.can_send(500));
        assert!(limiter.can_send(400));
        
        // Should reject sending over limit
        assert!(!limiter.can_send(200));
        
        // Usage should be at 90%
        assert!((limiter.usage_percentage() - 90.0).abs() < 1.0);
    }
    
    #[tokio::test]
    async fn test_relay_creation() {
        let config = RelayConfig::default();
        let crypto = Arc::new(OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
        ));
        let transport = Arc::new(TransportManager::new());
        
        let relay = OnionRelay::new(config, crypto, transport).await.unwrap();
        
        let stats = relay.get_stats().await;
        assert_eq!(stats.active_relays, 0);
        assert_eq!(stats.packets_relayed, 0);
    }
    
    #[tokio::test]
    async fn test_session_management() {
        let config = RelayConfig::default();
        let crypto = Arc::new(OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
        ));
        let transport = Arc::new(TransportManager::new());
        let relay = OnionRelay::new(config, crypto, transport).await.unwrap();
        
        let hop_keys = HopKeys {
            encryption_key: OnionKey::new(vec![0; 32]),
            decryption_key: OnionKey::new(vec![1; 32]),
            mac_key: OnionKey::new(vec![2; 32]),
        };
        
        // Create session
        let session_id = relay.create_session(
            "circuit-123".to_string(),
            "peer-1".to_string(),
            "peer-2".to_string(),
            hop_keys,
        ).await.unwrap();
        
        assert_eq!(relay.session_count().await, 1);
        
        // Remove session
        relay.remove_session("circuit-123").await.unwrap();
        assert_eq!(relay.session_count().await, 0);
    }
    
    #[tokio::test]
    async fn test_relay_queue() {
        let mut queue = RelayQueue::new(10);
        
        let payload = OnionPayload::Data {
            stream_id: 1,
            data: b"test".to_vec(),
        };
        
        let packet = OnionPacket::new(
            "circuit-123".to_string(),
            OnionCommand::Data,
            1,
            42,
            payload,
        ).unwrap();
        
        // Enqueue packet
        queue.enqueue(packet.clone()).await.unwrap();
        
        // Dequeue packet
        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.circuit_id(), packet.circuit_id());
        assert_eq!(dequeued.sequence(), packet.sequence());
    }
    
    #[test]
    fn test_relay_config() {
        let config = RelayConfig::default();
        
        assert_eq!(config.max_relays, 1000);
        assert_eq!(config.buffer_size, 1000);
        assert!(config.validate_packets);
        assert!(config.collect_stats);
        assert!(!config.enable_bandwidth_limit);
    }
}