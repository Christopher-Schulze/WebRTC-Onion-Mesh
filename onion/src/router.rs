//! Onion router implementation
//! Handles packet routing and circuit management

use crate::circuit::{Circuit, CircuitId, CircuitManager, CircuitState};
use crate::crypto::{OnionCrypto, OnionCipherSuite, OnionKeyExchange};
use crate::error::{OnionResult, RouterError};
use crate::packet::{
    OnionPacket, OnionCommand, OnionPayload, PacketProcessor, ProcessingResult
};
use crnet_core::peer::PeerId;
use crnet_transport::{Transport, TransportManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use uuid::Uuid;

/// Router configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Maximum number of circuits
    pub max_circuits: usize,
    /// Maximum packet size
    pub max_packet_size: usize,
    /// Maximum packet age
    pub max_packet_age: Duration,
    /// Circuit cleanup interval
    pub cleanup_interval: Duration,
    /// Keep-alive interval
    pub keepalive_interval: Duration,
    /// Maximum hops per circuit (2 or 3 as requested)
    pub max_hops: u8,
    /// Default cipher suite
    pub cipher_suite: OnionCipherSuite,
    /// Default key exchange
    pub key_exchange: OnionKeyExchange,
    /// Enable packet validation
    pub validate_packets: bool,
    /// Enable statistics collection
    pub collect_stats: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            max_circuits: 1000,
            max_packet_size: 8192, // 8KB
            max_packet_age: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(30),
            max_hops: 3, // User can choose 2 or 3
            cipher_suite: OnionCipherSuite::ChaCha20Poly1305,
            key_exchange: OnionKeyExchange::X25519,
            validate_packets: true,
            collect_stats: true,
        }
    }
}

/// Router statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterStats {
    /// Total packets routed
    pub packets_routed: u64,
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Active circuits
    pub active_circuits: usize,
    /// Total circuits created
    pub circuits_created: u64,
    /// Circuits destroyed
    pub circuits_destroyed: u64,
    /// Average circuit lifetime
    pub avg_circuit_lifetime: Duration,
    /// Total bytes routed
    pub total_bytes: u64,
    /// Routing errors
    pub routing_errors: u64,
    /// Last update timestamp
    pub last_update: Instant,
}

/// Router event types
#[derive(Debug, Clone)]
pub enum RouterEvent {
    /// Circuit created
    CircuitCreated {
        circuit_id: CircuitId,
        peer_id: PeerId,
        hops: u8,
    },
    /// Circuit destroyed
    CircuitDestroyed {
        circuit_id: CircuitId,
        reason: String,
    },
    /// Packet routed
    PacketRouted {
        circuit_id: CircuitId,
        command: OnionCommand,
        size: usize,
    },
    /// Routing error
    RoutingError {
        circuit_id: Option<CircuitId>,
        error: String,
    },
    /// Peer connected
    PeerConnected {
        peer_id: PeerId,
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: PeerId,
    },
}

/// Router event handler trait
pub trait RouterEventHandler: Send + Sync {
    /// Handle router event
    fn handle_event(&self, event: RouterEvent);
}

/// Onion router implementation
pub struct OnionRouter {
    /// Router configuration
    config: RouterConfig,
    /// Circuit manager
    circuit_manager: Arc<RwLock<CircuitManager>>,
    /// Packet processor
    packet_processor: Arc<RwLock<PacketProcessor>>,
    /// Cryptographic operations
    crypto: Arc<OnionCrypto>,
    /// Transport manager
    transport: Arc<TransportManager>,
    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Routing table (circuit_id -> next_hop)
    routing_table: Arc<RwLock<HashMap<CircuitId, PeerId>>>,
    /// Event handlers
    event_handlers: Arc<RwLock<Vec<Arc<dyn RouterEventHandler>>>>,
    /// Router statistics
    stats: Arc<RwLock<RouterStats>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl OnionRouter {
    /// Create a new onion router
    pub async fn new(
        config: RouterConfig,
        transport: Arc<TransportManager>,
    ) -> OnionResult<Self> {
        let circuit_manager = Arc::new(RwLock::new(
            CircuitManager::new(config.max_circuits)
        ));
        
        let packet_processor = Arc::new(RwLock::new(
            PacketProcessor::new(config.max_packet_size, config.max_packet_age)
        ));
        
        let crypto = Arc::new(OnionCrypto::new(
            config.cipher_suite.clone(),
            config.key_exchange.clone(),
        ));
        
        Ok(Self {
            config,
            circuit_manager,
            packet_processor,
            crypto,
            transport,
            peers: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(RouterStats::default())),
            shutdown_tx: None,
        })
    }
    
    /// Start the router
    pub async fn start(&mut self) -> OnionResult<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        // Start background tasks
        self.start_cleanup_task().await;
        self.start_keepalive_task().await;
        self.start_stats_task().await;
        
        // Wait for shutdown signal
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Router shutdown requested");
            }
        }
        
        Ok(())
    }
    
    /// Stop the router
    pub async fn stop(&mut self) -> OnionResult<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Close all circuits
        let mut circuit_manager = self.circuit_manager.write().await;
        let circuit_ids: Vec<_> = circuit_manager.list_circuits().iter().cloned().collect();
        
        for circuit_id in circuit_ids {
            if let Err(e) = circuit_manager.close_circuit(&circuit_id).await {
                eprintln!("Error closing circuit {}: {}", circuit_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Create a new circuit
    pub async fn create_circuit(
        &self,
        target_peer: PeerId,
        hops: Option<u8>,
    ) -> OnionResult<CircuitId> {
        let hops = hops.unwrap_or(self.config.max_hops).min(self.config.max_hops);
        
        if hops < 2 || hops > 3 {
            return Err(RouterError::InvalidHopCount { hops }.into());
        }
        
        let mut circuit_manager = self.circuit_manager.write().await;
        let circuit_id = circuit_manager.create_circuit(target_peer.clone()).await?;
        
        // Emit event
        self.emit_event(RouterEvent::CircuitCreated {
            circuit_id: circuit_id.clone(),
            peer_id: target_peer,
            hops,
        }).await;
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.circuits_created += 1;
        stats.active_circuits = circuit_manager.circuit_count();
        
        Ok(circuit_id)
    }
    
    /// Destroy a circuit
    pub async fn destroy_circuit(&self, circuit_id: &str, reason: String) -> OnionResult<()> {
        let mut circuit_manager = self.circuit_manager.write().await;
        circuit_manager.close_circuit(circuit_id).await?;
        
        // Remove from routing table
        let mut routing_table = self.routing_table.write().await;
        routing_table.remove(circuit_id);
        
        // Emit event
        self.emit_event(RouterEvent::CircuitDestroyed {
            circuit_id: circuit_id.to_string(),
            reason,
        }).await;
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.circuits_destroyed += 1;
        stats.active_circuits = circuit_manager.circuit_count();
        
        Ok(())
    }
    
    /// Route a packet
    pub async fn route_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        let circuit_id = packet.circuit_id().to_string();
        
        // Validate packet if enabled
        if self.config.validate_packets {
            packet.validate()?;
        }
        
        // Process packet
        let mut processor = self.packet_processor.write().await;
        let result = processor.process_packet(&packet)?;
        
        // Handle processing result
        match result {
            ProcessingResult::Forward => {
                self.forward_packet(packet).await?
            }
            ProcessingResult::Consume => {
                // Packet consumed, no further action needed
            }
            ProcessingResult::Destroy => {
                self.destroy_circuit(&circuit_id, "Destroy command received".to_string()).await?
            }
            ProcessingResult::Data { stream_id, data } => {
                self.handle_data_packet(circuit_id, stream_id, data).await?
            }
            ProcessingResult::Pong { nonce } => {
                self.send_pong(&circuit_id, nonce).await?
            }
            ProcessingResult::Error { code, message } => {
                self.handle_error_packet(circuit_id, code, message).await?
            }
        }
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.packets_routed += 1;
        stats.total_bytes += packet.size().unwrap_or(0) as u64;
        
        // Emit event
        self.emit_event(RouterEvent::PacketRouted {
            circuit_id,
            command: packet.command().clone(),
            size: packet.size().unwrap_or(0),
        }).await;
        
        Ok(())
    }
    
    /// Forward packet to next hop
    async fn forward_packet(&self, packet: OnionPacket) -> OnionResult<()> {
        let circuit_id = packet.circuit_id();
        
        // Get next hop from routing table
        let routing_table = self.routing_table.read().await;
        let next_hop = routing_table.get(circuit_id)
            .ok_or_else(|| RouterError::CircuitNotFound(circuit_id.to_string()))?;
        
        // Send packet to next hop
        let packet_bytes = packet.to_bytes()?;
        self.transport.send(next_hop, &packet_bytes).await
            .map_err(|e| RouterError::TransportError(e.to_string()))?;
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.packets_forwarded += 1;
        
        Ok(())
    }
    
    /// Handle data packet
    async fn handle_data_packet(
        &self,
        circuit_id: String,
        stream_id: u16,
        data: Vec<u8>,
    ) -> OnionResult<()> {
        // TODO: Implement data handling based on stream type
        println!("Received data on circuit {} stream {}: {} bytes", 
                circuit_id, stream_id, data.len());
        Ok(())
    }
    
    /// Send pong response
    async fn send_pong(&self, circuit_id: &str, nonce: Vec<u8>) -> OnionResult<()> {
        // TODO: Implement pong response
        println!("Sending pong for circuit {} with nonce: {:?}", circuit_id, nonce);
        Ok(())
    }
    
    /// Handle error packet
    async fn handle_error_packet(
        &self,
        circuit_id: String,
        code: u16,
        message: String,
    ) -> OnionResult<()> {
        println!("Error on circuit {}: {} - {}", circuit_id, code, message);
        
        // Emit error event
        self.emit_event(RouterEvent::RoutingError {
            circuit_id: Some(circuit_id.clone()),
            error: format!("{}: {}", code, message),
        }).await;
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.routing_errors += 1;
        
        Ok(())
    }
    
    /// Add peer to routing table
    pub async fn add_peer(&self, peer_id: PeerId) -> OnionResult<()> {
        let mut peers = self.peers.write().await;
        peers.insert(peer_id.clone(), Instant::now());
        
        // Emit event
        self.emit_event(RouterEvent::PeerConnected { peer_id }).await;
        
        Ok(())
    }
    
    /// Remove peer from routing table
    pub async fn remove_peer(&self, peer_id: &PeerId) -> OnionResult<()> {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
        
        // Remove circuits using this peer
        let mut routing_table = self.routing_table.write().await;
        let circuits_to_remove: Vec<_> = routing_table
            .iter()
            .filter(|(_, &ref next_hop)| next_hop == peer_id)
            .map(|(circuit_id, _)| circuit_id.clone())
            .collect();
        
        for circuit_id in circuits_to_remove {
            routing_table.remove(&circuit_id);
            drop(routing_table); // Release lock before async call
            
            let _ = self.destroy_circuit(&circuit_id, "Peer disconnected".to_string()).await;
            
            routing_table = self.routing_table.write().await; // Re-acquire lock
        }
        
        // Emit event
        self.emit_event(RouterEvent::PeerDisconnected { 
            peer_id: peer_id.clone() 
        }).await;
        
        Ok(())
    }
    
    /// Add event handler
    pub async fn add_event_handler(&self, handler: Arc<dyn RouterEventHandler>) {
        let mut handlers = self.event_handlers.write().await;
        handlers.push(handler);
    }
    
    /// Emit router event
    async fn emit_event(&self, event: RouterEvent) {
        let handlers = self.event_handlers.read().await;
        for handler in handlers.iter() {
            handler.handle_event(event.clone());
        }
    }
    
    /// Get router statistics
    pub async fn get_stats(&self) -> RouterStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = RouterStats::default();
    }
    
    /// Get active circuits
    pub async fn get_circuits(&self) -> Vec<CircuitId> {
        let circuit_manager = self.circuit_manager.read().await;
        circuit_manager.list_circuits()
    }
    
    /// Get connected peers
    pub async fn get_peers(&self) -> Vec<PeerId> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }
    
    /// Start cleanup task
    async fn start_cleanup_task(&self) {
        let circuit_manager = Arc::clone(&self.circuit_manager);
        let peers = Arc::clone(&self.peers);
        let cleanup_interval = self.config.cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                // Cleanup expired circuits
                let mut manager = circuit_manager.write().await;
                if let Err(e) = manager.cleanup_expired().await {
                    eprintln!("Circuit cleanup error: {}", e);
                }
                drop(manager);
                
                // Cleanup old peer entries
                let mut peer_map = peers.write().await;
                let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
                peer_map.retain(|_, &mut last_seen| last_seen > cutoff);
            }
        });
    }
    
    /// Start keep-alive task
    async fn start_keepalive_task(&self) {
        let circuit_manager = Arc::clone(&self.circuit_manager);
        let keepalive_interval = self.config.keepalive_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(keepalive_interval);
            
            loop {
                interval.tick().await;
                
                // Send keep-alive to all active circuits
                let manager = circuit_manager.read().await;
                let circuits = manager.list_circuits();
                
                for circuit_id in circuits {
                    // TODO: Send ping packet to circuit
                    println!("Sending keep-alive to circuit: {}", circuit_id);
                }
            }
        });
    }
    
    /// Start statistics collection task
    async fn start_stats_task(&self) {
        let stats = Arc::clone(&self.stats);
        let circuit_manager = Arc::clone(&self.circuit_manager);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Update statistics
                let mut stats_guard = stats.write().await;
                let manager = circuit_manager.read().await;
                
                stats_guard.active_circuits = manager.circuit_count();
                stats_guard.last_update = Instant::now();
                
                // Calculate average circuit lifetime
                let circuit_stats = manager.get_stats();
                if circuit_stats.circuits_created > 0 {
                    stats_guard.avg_circuit_lifetime = 
                        circuit_stats.total_lifetime / circuit_stats.circuits_created as u32;
                }
            }
        });
    }
}

/// Simple event handler implementation for logging
pub struct LoggingEventHandler;

impl RouterEventHandler for LoggingEventHandler {
    fn handle_event(&self, event: RouterEvent) {
        match event {
            RouterEvent::CircuitCreated { circuit_id, peer_id, hops } => {
                println!("Circuit created: {} -> {} ({} hops)", circuit_id, peer_id, hops);
            }
            RouterEvent::CircuitDestroyed { circuit_id, reason } => {
                println!("Circuit destroyed: {} ({})", circuit_id, reason);
            }
            RouterEvent::PacketRouted { circuit_id, command, size } => {
                println!("Packet routed: {} {:?} ({} bytes)", circuit_id, command, size);
            }
            RouterEvent::RoutingError { circuit_id, error } => {
                eprintln!("Routing error on {:?}: {}", circuit_id, error);
            }
            RouterEvent::PeerConnected { peer_id } => {
                println!("Peer connected: {}", peer_id);
            }
            RouterEvent::PeerDisconnected { peer_id } => {
                println!("Peer disconnected: {}", peer_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    struct TestEventHandler {
        event_count: AtomicUsize,
    }
    
    impl TestEventHandler {
        fn new() -> Self {
            Self {
                event_count: AtomicUsize::new(0),
            }
        }
        
        fn get_event_count(&self) -> usize {
            self.event_count.load(Ordering::Relaxed)
        }
    }
    
    impl RouterEventHandler for TestEventHandler {
        fn handle_event(&self, _event: RouterEvent) {
            self.event_count.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    #[tokio::test]
    async fn test_router_creation() {
        let config = RouterConfig::default();
        let transport = Arc::new(TransportManager::new());
        
        let router = OnionRouter::new(config, transport).await.unwrap();
        
        let stats = router.get_stats().await;
        assert_eq!(stats.active_circuits, 0);
        assert_eq!(stats.packets_routed, 0);
    }
    
    #[tokio::test]
    async fn test_peer_management() {
        let config = RouterConfig::default();
        let transport = Arc::new(TransportManager::new());
        let router = OnionRouter::new(config, transport).await.unwrap();
        
        let peer_id = "test-peer".to_string();
        
        // Add peer
        router.add_peer(peer_id.clone()).await.unwrap();
        let peers = router.get_peers().await;
        assert!(peers.contains(&peer_id));
        
        // Remove peer
        router.remove_peer(&peer_id).await.unwrap();
        let peers = router.get_peers().await;
        assert!(!peers.contains(&peer_id));
    }
    
    #[tokio::test]
    async fn test_event_handling() {
        let config = RouterConfig::default();
        let transport = Arc::new(TransportManager::new());
        let router = OnionRouter::new(config, transport).await.unwrap();
        
        let handler = Arc::new(TestEventHandler::new());
        router.add_event_handler(handler.clone()).await;
        
        let peer_id = "test-peer".to_string();
        router.add_peer(peer_id.clone()).await.unwrap();
        router.remove_peer(&peer_id).await.unwrap();
        
        // Should have received 2 events (connected + disconnected)
        assert_eq!(handler.get_event_count(), 2);
    }
    
    #[test]
    fn test_router_config() {
        let config = RouterConfig::default();
        
        assert_eq!(config.max_hops, 3);
        assert_eq!(config.max_circuits, 1000);
        assert!(config.validate_packets);
        assert!(config.collect_stats);
    }
    
    #[test]
    fn test_logging_event_handler() {
        let handler = LoggingEventHandler;
        
        let event = RouterEvent::CircuitCreated {
            circuit_id: "test-circuit".to_string(),
            peer_id: "test-peer".to_string(),
            hops: 3,
        };
        
        // Should not panic
        handler.handle_event(event);
    }
}