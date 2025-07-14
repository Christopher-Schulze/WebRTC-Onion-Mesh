//! Peer discovery implementations
//!
//! This module provides various peer discovery mechanisms including
//! local network discovery (mDNS) and distributed discovery (DHT).

use crate::{
    error::{DiscoveryError, SignalingResult},
    DiscoveryConfig,
};
use zMesh_core::{
    peer::{PeerId, PeerInfo, PeerCapabilities},
    transport::TransportType,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{RwLock, mpsc},
    time::interval,
};
use tracing::{debug, info, warn, error};

/// Discovery method types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// Local network discovery using mDNS
    Local,
    /// Distributed Hash Table discovery
    Dht,
    /// Manual peer addition
    Manual,
    /// Bootstrap from known peers
    Bootstrap,
}

/// Discovered peer information
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_info: PeerInfo,
    pub discovery_method: DiscoveryMethod,
    pub discovered_at: Instant,
    pub last_seen: Instant,
    pub confidence: f32, // 0.0 to 1.0
}

/// Discovery event types
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(DiscoveredPeer),
    PeerUpdated(DiscoveredPeer),
    PeerLost(PeerId),
    DiscoveryStarted(DiscoveryMethod),
    DiscoveryStopped(DiscoveryMethod),
    DiscoveryError(DiscoveryMethod, String),
}

/// Discovery event handler trait
#[async_trait::async_trait]
pub trait DiscoveryEventHandler: Send + Sync {
    async fn handle_event(&self, event: DiscoveryEvent);
}

/// Main peer discovery manager
#[derive(Debug)]
pub struct PeerDiscovery {
    config: DiscoveryConfig,
    discovered_peers: Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    event_handlers: Arc<RwLock<Vec<Arc<dyn DiscoveryEventHandler>>>>,
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    event_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<DiscoveryEvent>>>>,
    
    #[cfg(feature = "local-discovery")]
    mdns_discovery: Option<MdnsDiscovery>,
    
    #[cfg(feature = "dht-discovery")]
    dht_discovery: Option<DhtDiscovery>,
    
    running: Arc<RwLock<bool>>,
}

impl PeerDiscovery {
    /// Create a new peer discovery manager
    pub fn new(config: DiscoveryConfig) -> SignalingResult<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            config,
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            
            #[cfg(feature = "local-discovery")]
            mdns_discovery: None,
            
            #[cfg(feature = "dht-discovery")]
            dht_discovery: None,
            
            running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Start peer discovery
    pub async fn start(&mut self) -> SignalingResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(DiscoveryError::AlreadyStarted.into());
        }
        
        info!("Starting peer discovery");
        
        // Start event processing
        self.start_event_processing().await?;
        
        // Start local discovery if enabled
        #[cfg(feature = "local-discovery")]
        if self.config.enable_local {
            self.start_local_discovery().await?;
        }
        
        // Start DHT discovery if enabled
        #[cfg(feature = "dht-discovery")]
        if self.config.enable_dht {
            self.start_dht_discovery().await?;
        }
        
        // Start periodic tasks
        self.start_periodic_tasks().await?;
        
        *running = true;
        info!("Peer discovery started");
        Ok(())
    }
    
    /// Stop peer discovery
    pub async fn stop(&mut self) -> SignalingResult<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        info!("Stopping peer discovery");
        
        // Stop local discovery
        #[cfg(feature = "local-discovery")]
        if let Some(mdns) = &mut self.mdns_discovery {
            mdns.stop().await?;
        }
        
        // Stop DHT discovery
        #[cfg(feature = "dht-discovery")]
        if let Some(dht) = &mut self.dht_discovery {
            dht.stop().await?;
        }
        
        *running = false;
        info!("Peer discovery stopped");
        Ok(())
    }
    
    /// Add event handler
    pub async fn add_event_handler(&self, handler: Arc<dyn DiscoveryEventHandler>) {
        self.event_handlers.write().await.push(handler);
    }
    
    /// Announce this peer to the network
    pub async fn announce_peer(&self, peer_info: &PeerInfo) -> SignalingResult<()> {
        debug!("Announcing peer: {}", peer_info.id);
        
        // Announce via local discovery
        #[cfg(feature = "local-discovery")]
        if let Some(mdns) = &self.mdns_discovery {
            mdns.announce_peer(peer_info).await?;
        }
        
        // Announce via DHT
        #[cfg(feature = "dht-discovery")]
        if let Some(dht) = &self.dht_discovery {
            dht.announce_peer(peer_info).await?;
        }
        
        Ok(())
    }
    
    /// Find peers with specific capabilities
    pub async fn find_peers(
        &self,
        capabilities: &PeerCapabilities,
    ) -> SignalingResult<Vec<PeerInfo>> {
        let peers = self.discovered_peers.read().await;
        let mut matching_peers = Vec::new();
        
        for discovered_peer in peers.values() {
            if self.matches_capabilities(&discovered_peer.peer_info.capabilities, capabilities) {
                matching_peers.push(discovered_peer.peer_info.clone());
            }
        }
        
        // Sort by confidence and recency
        matching_peers.sort_by(|a, b| {
            let a_peer = peers.get(&a.id).unwrap();
            let b_peer = peers.get(&b.id).unwrap();
            
            b_peer.confidence
                .partial_cmp(&a_peer.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b_peer.last_seen.cmp(&a_peer.last_seen))
        });
        
        Ok(matching_peers)
    }
    
    /// Get all discovered peers
    pub async fn get_discovered_peers(&self) -> Vec<DiscoveredPeer> {
        self.discovered_peers.read().await.values().cloned().collect()
    }
    
    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.discovered_peers.read().await.len()
    }
    
    /// Manually add a peer
    pub async fn add_peer_manually(&self, peer_info: PeerInfo) -> SignalingResult<()> {
        let discovered_peer = DiscoveredPeer {
            peer_info: peer_info.clone(),
            discovery_method: DiscoveryMethod::Manual,
            discovered_at: Instant::now(),
            last_seen: Instant::now(),
            confidence: 1.0, // Manual additions have highest confidence
        };
        
        self.add_discovered_peer(discovered_peer).await;
        Ok(())
    }
    
    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &PeerId) -> SignalingResult<()> {
        let mut peers = self.discovered_peers.write().await;
        if peers.remove(peer_id).is_some() {
            let _ = self.event_tx.send(DiscoveryEvent::PeerLost(peer_id.clone()));
        }
        Ok(())
    }
    
    // Private methods
    
    async fn start_event_processing(&self) -> SignalingResult<()> {
        let mut event_rx_guard = self.event_rx.write().await;
        let event_rx = event_rx_guard.take()
            .ok_or_else(|| DiscoveryError::AlreadyStarted)?;
        drop(event_rx_guard);
        
        let event_handlers = self.event_handlers.clone();
        
        tokio::spawn(async move {
            let mut event_rx = event_rx;
            while let Some(event) = event_rx.recv().await {
                let handlers = event_handlers.read().await;
                for handler in handlers.iter() {
                    handler.handle_event(event.clone()).await;
                }
            }
        });
        
        Ok(())
    }
    
    #[cfg(feature = "local-discovery")]
    async fn start_local_discovery(&mut self) -> SignalingResult<()> {
        info!("Starting local discovery (mDNS)");
        
        let mut mdns = MdnsDiscovery::new(
            self.config.service_name.clone(),
            self.event_tx.clone(),
        )?;
        
        mdns.start().await?;
        self.mdns_discovery = Some(mdns);
        
        let _ = self.event_tx.send(DiscoveryEvent::DiscoveryStarted(DiscoveryMethod::Local));
        Ok(())
    }
    
    #[cfg(feature = "dht-discovery")]
    async fn start_dht_discovery(&mut self) -> SignalingResult<()> {
        info!("Starting DHT discovery");
        
        let mut dht = DhtDiscovery::new(
            self.config.dht_bootstrap_nodes.clone(),
            self.event_tx.clone(),
        )?;
        
        dht.start().await?;
        self.dht_discovery = Some(dht);
        
        let _ = self.event_tx.send(DiscoveryEvent::DiscoveryStarted(DiscoveryMethod::Dht));
        Ok(())
    }
    
    async fn start_periodic_tasks(&self) -> SignalingResult<()> {
        // Start peer cleanup task
        let discovered_peers = self.discovered_peers.clone();
        let event_tx = self.event_tx.clone();
        let peer_expiry = self.config.peer_expiry;
        let max_peers = self.config.max_discovered_peers;
        
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60)); // Cleanup every minute
            
            loop {
                cleanup_interval.tick().await;
                
                let mut peers = discovered_peers.write().await;
                let now = Instant::now();
                let mut expired_peers = Vec::new();
                
                // Find expired peers
                for (peer_id, discovered_peer) in peers.iter() {
                    if now.duration_since(discovered_peer.last_seen) > peer_expiry {
                        expired_peers.push(peer_id.clone());
                    }
                }
                
                // Remove expired peers
                for peer_id in expired_peers {
                    peers.remove(&peer_id);
                    let _ = event_tx.send(DiscoveryEvent::PeerLost(peer_id));
                }
                
                // Limit total peer count
                if peers.len() > max_peers {
                    // Remove oldest peers (by discovery time)
                    let mut peer_list: Vec<_> = peers.iter().collect();
                    peer_list.sort_by_key(|(_, peer)| peer.discovered_at);
                    
                    let to_remove = peers.len() - max_peers;
                    for (peer_id, _) in peer_list.iter().take(to_remove) {
                        let peer_id = (*peer_id).clone();
                        peers.remove(&peer_id);
                        let _ = event_tx.send(DiscoveryEvent::PeerLost(peer_id));
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn add_discovered_peer(&self, discovered_peer: DiscoveredPeer) {
        let peer_id = discovered_peer.peer_info.id.clone();
        let mut peers = self.discovered_peers.write().await;
        
        let event = if let Some(existing) = peers.get(&peer_id) {
            // Update existing peer
            let mut updated_peer = discovered_peer;
            updated_peer.discovered_at = existing.discovered_at; // Keep original discovery time
            
            peers.insert(peer_id, updated_peer.clone());
            DiscoveryEvent::PeerUpdated(updated_peer)
        } else {
            // New peer
            peers.insert(peer_id, discovered_peer.clone());
            DiscoveryEvent::PeerDiscovered(discovered_peer)
        };
        
        let _ = self.event_tx.send(event);
    }
    
    fn matches_capabilities(
        &self,
        peer_capabilities: &PeerCapabilities,
        required_capabilities: &PeerCapabilities,
    ) -> bool {
        // Check if peer can relay if required
        if required_capabilities.can_relay && !peer_capabilities.can_relay {
            return false;
        }
        
        // Check if peer can exit if required
        if required_capabilities.can_exit && !peer_capabilities.can_exit {
            return false;
        }
        
        // Check if peer supports FEC if required
        if required_capabilities.supports_fec && !peer_capabilities.supports_fec {
            return false;
        }
        
        // Check if peer can cache if required
        if required_capabilities.can_cache && !peer_capabilities.can_cache {
            return false;
        }
        
        // Check bandwidth requirements
        if peer_capabilities.max_bandwidth < required_capabilities.max_bandwidth {
            return false;
        }
        
        // Check transport support
        for required_transport in &required_capabilities.transports {
            if !peer_capabilities.transports.contains(required_transport) {
                return false;
            }
        }
        
        true
    }
}

// Placeholder implementations for discovery methods

#[cfg(feature = "local-discovery")]
struct MdnsDiscovery {
    service_name: String,
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
}

#[cfg(feature = "local-discovery")]
impl MdnsDiscovery {
    fn new(
        service_name: String,
        event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    ) -> SignalingResult<Self> {
        Ok(Self {
            service_name,
            event_tx,
        })
    }
    
    async fn start(&mut self) -> SignalingResult<()> {
        // TODO: Implement mDNS discovery using the mdns crate
        warn!("mDNS discovery not yet implemented");
        Ok(())
    }
    
    async fn stop(&mut self) -> SignalingResult<()> {
        // TODO: Stop mDNS discovery
        Ok(())
    }
    
    async fn announce_peer(&self, _peer_info: &PeerInfo) -> SignalingResult<()> {
        // TODO: Announce peer via mDNS
        Ok(())
    }
}

#[cfg(feature = "dht-discovery")]
struct DhtDiscovery {
    bootstrap_nodes: Vec<String>,
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
}

#[cfg(feature = "dht-discovery")]
impl DhtDiscovery {
    fn new(
        bootstrap_nodes: Vec<String>,
        event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    ) -> SignalingResult<Self> {
        Ok(Self {
            bootstrap_nodes,
            event_tx,
        })
    }
    
    async fn start(&mut self) -> SignalingResult<()> {
        // TODO: Implement DHT discovery using libp2p
        warn!("DHT discovery not yet implemented");
        Ok(())
    }
    
    async fn stop(&mut self) -> SignalingResult<()> {
        // TODO: Stop DHT discovery
        Ok(())
    }
    
    async fn announce_peer(&self, _peer_info: &PeerInfo) -> SignalingResult<()> {
        // TODO: Announce peer via DHT
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zMesh_core::peer::{PeerId, PeerInfo, PeerCapabilities};
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    struct TestEventHandler {
        event_count: AtomicUsize,
    }
    
    #[async_trait::async_trait]
    impl DiscoveryEventHandler for TestEventHandler {
        async fn handle_event(&self, _event: DiscoveryEvent) {
            self.event_count.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    #[tokio::test]
    async fn test_peer_discovery_creation() {
        let config = DiscoveryConfig {
            enable_local: false,
            enable_dht: false,
            discovery_interval: Duration::from_secs(30),
            announce_interval: Duration::from_secs(60),
            max_discovered_peers: 1000,
            peer_expiry: Duration::from_secs(300),
            service_name: "_test._tcp.local".to_string(),
            dht_bootstrap_nodes: Vec::new(),
        };
        
        let discovery = PeerDiscovery::new(config);
        assert!(discovery.is_ok());
    }
    
    #[tokio::test]
    async fn test_manual_peer_addition() {
        let config = DiscoveryConfig {
            enable_local: false,
            enable_dht: false,
            discovery_interval: Duration::from_secs(30),
            announce_interval: Duration::from_secs(60),
            max_discovered_peers: 1000,
            peer_expiry: Duration::from_secs(300),
            service_name: "_test._tcp.local".to_string(),
            dht_bootstrap_nodes: Vec::new(),
        };
        
        let discovery = PeerDiscovery::new(config).unwrap();
        
        let peer_info = PeerInfo {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            capabilities: PeerCapabilities::default(),
            last_seen: std::time::SystemTime::now(),
            latency: Some(10),
            reliability: Some(0.95),
            public_key: vec![],
        };
        
        assert!(discovery.add_peer_manually(peer_info.clone()).await.is_ok());
        assert_eq!(discovery.peer_count().await, 1);
        
        let discovered_peers = discovery.get_discovered_peers().await;
        assert_eq!(discovered_peers.len(), 1);
        assert_eq!(discovered_peers[0].peer_info.id, peer_info.id);
        assert_eq!(discovered_peers[0].discovery_method, DiscoveryMethod::Manual);
    }
    
    #[tokio::test]
    async fn test_capability_matching() {
        let config = DiscoveryConfig {
            enable_local: false,
            enable_dht: false,
            discovery_interval: Duration::from_secs(30),
            announce_interval: Duration::from_secs(60),
            max_discovered_peers: 1000,
            peer_expiry: Duration::from_secs(300),
            service_name: "_test._tcp.local".to_string(),
            dht_bootstrap_nodes: Vec::new(),
        };
        
        let discovery = PeerDiscovery::new(config).unwrap();
        
        // Add a relay peer
        let relay_peer = PeerInfo {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            capabilities: PeerCapabilities {
                can_relay: true,
                can_exit: false,
                supports_fec: true,
                can_cache: false,
                max_bandwidth: 1000000,
                transports: vec![TransportType::WebSocket],
            },
            last_seen: std::time::SystemTime::now(),
            latency: Some(10),
            reliability: Some(0.95),
            public_key: vec![],
        };
        
        discovery.add_peer_manually(relay_peer.clone()).await.unwrap();
        
        // Search for relay peers
        let required_capabilities = PeerCapabilities {
            can_relay: true,
            can_exit: false,
            supports_fec: false,
            can_cache: false,
            max_bandwidth: 500000,
            transports: vec![TransportType::WebSocket],
        };
        
        let matching_peers = discovery.find_peers(&required_capabilities).await.unwrap();
        assert_eq!(matching_peers.len(), 1);
        assert_eq!(matching_peers[0].id, relay_peer.id);
        
        // Search for exit peers (should find none)
        let exit_capabilities = PeerCapabilities {
            can_relay: false,
            can_exit: true,
            supports_fec: false,
            can_cache: false,
            max_bandwidth: 500000,
            transports: vec![TransportType::WebSocket],
        };
        
        let matching_peers = discovery.find_peers(&exit_capabilities).await.unwrap();
        assert_eq!(matching_peers.len(), 0);
    }
    
    #[tokio::test]
    async fn test_event_handling() {
        let config = DiscoveryConfig {
            enable_local: false,
            enable_dht: false,
            discovery_interval: Duration::from_secs(30),
            announce_interval: Duration::from_secs(60),
            max_discovered_peers: 1000,
            peer_expiry: Duration::from_secs(300),
            service_name: "_test._tcp.local".to_string(),
            dht_bootstrap_nodes: Vec::new(),
        };
        
        let mut discovery = PeerDiscovery::new(config).unwrap();
        
        let handler = Arc::new(TestEventHandler {
            event_count: AtomicUsize::new(0),
        });
        
        discovery.add_event_handler(handler.clone()).await;
        discovery.start().await.unwrap();
        
        // Add a peer to trigger an event
        let peer_info = PeerInfo {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            capabilities: PeerCapabilities::default(),
            last_seen: std::time::SystemTime::now(),
            latency: Some(10),
            reliability: Some(0.95),
            public_key: vec![],
        };
        
        discovery.add_peer_manually(peer_info).await.unwrap();
        
        // Give some time for event processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Should have received at least one event
        assert!(handler.event_count.load(Ordering::SeqCst) > 0);
        
        discovery.stop().await.unwrap();
    }
}