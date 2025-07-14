//! Peer management and identification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Unique identifier for a peer in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(Uuid);

impl PeerId {
    /// Generate a new random peer ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    
    /// Create from existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
    
    /// Get the underlying UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
    
    /// Convert to string representation
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Capabilities that a peer can provide
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Can act as an onion routing hop
    pub can_relay: bool,
    /// Can act as an exit node
    pub can_exit: bool,
    /// Supports FEC (Forward Error Correction)
    pub supports_fec: bool,
    /// Can cache and reseed chunks
    pub can_cache: bool,
    /// Maximum bandwidth in bytes per second
    pub max_bandwidth: u64,
    /// Supported transport protocols
    pub transports: Vec<TransportType>,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            can_relay: true,
            can_exit: false, // Default to not being an exit node
            supports_fec: true,
            can_cache: true,
            max_bandwidth: 1024 * 1024, // 1 MB/s default
            transports: vec![TransportType::WebRtc, TransportType::WebSocket],
        }
    }
}

/// Transport protocols supported by a peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportType {
    WebRtc,
    WebSocket,
}

/// Information about a peer in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique identifier
    pub id: PeerId,
    /// Network addresses (for signaling)
    pub addresses: Vec<SocketAddr>,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Last seen timestamp
    #[serde(skip, default = "SystemTime::now")]
    pub last_seen: SystemTime,
    /// Average latency to this peer (in milliseconds)
    #[serde(skip)]
    pub avg_latency: Option<Duration>,
    /// Reliability score (0.0 to 1.0)
    pub reliability: f64,
    /// Public key for this peer (for onion routing)
    pub public_key: Vec<u8>,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            id: PeerId::new(),
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            last_seen: SystemTime::now(),
            avg_latency: None,
            reliability: 1.0,
            public_key: Vec::new(),
        }
    }
}

impl PeerInfo {
    /// Create new peer info
    pub fn new(id: PeerId, public_key: Vec<u8>) -> Self {
        Self {
            id,
            addresses: Vec::new(),
            capabilities: PeerCapabilities::default(),
            last_seen: SystemTime::now(),
            avg_latency: None,
            reliability: 1.0, // Start with perfect reliability
            public_key,
        }
    }
    
    /// Check if peer is suitable for onion routing
    pub fn can_be_hop(&self) -> bool {
        self.capabilities.can_relay && self.is_online()
    }
    
    /// Check if peer can act as exit node
    pub fn can_be_exit(&self) -> bool {
        self.capabilities.can_exit && self.is_online()
    }
    
    /// Check if peer is considered online (seen within last 5 minutes)
    pub fn is_online(&self) -> bool {
        self.last_seen
            .elapsed()
            .map(|elapsed| elapsed < Duration::from_secs(300))
            .unwrap_or(false)
    }
    
    /// Update latency measurement
    pub fn update_latency(&mut self, latency: Duration) {
        match self.avg_latency {
            Some(current) => {
                // Exponential moving average with alpha = 0.3
                let new_latency = Duration::from_nanos(
                    (current.as_nanos() as f64 * 0.7 + latency.as_nanos() as f64 * 0.3) as u64
                );
                self.avg_latency = Some(new_latency);
            }
            None => self.avg_latency = Some(latency),
        }
    }
    
    /// Update reliability score based on success/failure
    pub fn update_reliability(&mut self, success: bool) {
        let alpha = 0.1; // Learning rate
        if success {
            self.reliability = self.reliability * (1.0 - alpha) + alpha;
        } else {
            self.reliability = self.reliability * (1.0 - alpha);
        }
        // Clamp between 0.0 and 1.0
        self.reliability = self.reliability.max(0.0).min(1.0);
    }
    
    /// Calculate routing score (lower is better)
    pub fn routing_score(&self) -> f64 {
        let latency_score = self.avg_latency
            .map(|l| l.as_millis() as f64)
            .unwrap_or(1000.0); // Default to 1000ms if unknown
        
        let reliability_penalty = (1.0 - self.reliability) * 1000.0;
        
        latency_score + reliability_penalty
    }
}

/// Registry for managing known peers
#[derive(Debug, Clone)]
pub struct PeerRegistry {
    peers: HashMap<PeerId, PeerInfo>,
}

impl PeerRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
    
    /// Add or update peer information
    pub fn add_peer(&mut self, peer: PeerInfo) {
        self.peers.insert(peer.id.clone(), peer);
    }
    
    /// Get peer by ID
    pub fn get_peer(&self, id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }
    
    /// Get mutable peer by ID
    pub fn get_peer_mut(&mut self, id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(id)
    }
    
    /// Remove peer
    pub fn remove_peer(&mut self, id: &PeerId) -> Option<PeerInfo> {
        self.peers.remove(id)
    }
    
    /// Get all online peers
    pub fn online_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.is_online()).collect()
    }
    
    /// Get peers suitable for onion routing
    pub fn relay_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.can_be_hop()).collect()
    }
    
    /// Get peers that can act as exit nodes
    pub fn exit_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.can_be_exit()).collect()
    }
    
    /// Get best peers for routing (sorted by routing score)
    pub fn best_peers(&self, count: usize) -> Vec<&PeerInfo> {
        let mut peers: Vec<&PeerInfo> = self.relay_peers();
        peers.sort_by(|a, b| a.routing_score().partial_cmp(&b.routing_score()).unwrap());
        peers.into_iter().take(count).collect()
    }
    
    /// Clean up offline peers
    pub fn cleanup_offline(&mut self, max_age: Duration) {
        let cutoff = SystemTime::now() - max_age;
        self.peers.retain(|_, peer| peer.last_seen > cutoff);
    }
    
    /// Get total number of peers
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    
    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}