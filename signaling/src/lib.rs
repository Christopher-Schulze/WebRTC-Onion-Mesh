//! # zMesh Signaling Module
//!
//! This module provides signaling and peer discovery functionality for zMesh.
//! It supports multiple signaling methods and discovery mechanisms.
//!
//! ## Features
//!
//! - WebSocket-based signaling
//! - REST API signaling
//! - WebRTC signaling (optional)
//! - Local network discovery (mDNS)
//! - Distributed discovery (DHT, optional)
//! - Peer registry and management
//! - Connection brokering

use zMesh_core::{
    error::zMeshError,
    peer::{PeerId, PeerInfo},
    transport::TransportType,
};

pub mod error;
pub mod discovery;
pub mod server;
pub mod client;
pub mod broker;
pub mod registry;
pub mod messages;

#[cfg(feature = "webrtc-signaling")]
pub mod webrtc;

#[cfg(feature = "local-discovery")]
pub mod mdns_discovery;

#[cfg(feature = "dht-discovery")]
pub mod dht_discovery;

pub use error::{SignalingError, SignalingResult};
pub use discovery::{DiscoveryMethod, PeerDiscovery};
pub use server::SignalingServer;
pub use client::SignalingClient;
pub use broker::ConnectionBroker;
pub use registry::PeerRegistry;
pub use messages::*;

/// Re-export commonly used types
pub use zMesh_core::{
    peer::{PeerCapabilities, TransportType as CoreTransportType},
    transport::TransportMessage,
};

/// Signaling configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignalingConfig {
    /// Server configuration
    pub server: ServerConfig,
    
    /// Client configuration
    pub client: ClientConfig,
    
    /// Discovery configuration
    pub discovery: DiscoveryConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
}

/// Server configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    /// WebSocket server bind address
    pub websocket_bind: String,
    
    /// REST API server bind address
    pub rest_bind: String,
    
    /// Enable WebSocket signaling
    pub enable_websocket: bool,
    
    /// Enable REST API signaling
    pub enable_rest: bool,
    
    /// Maximum concurrent connections
    pub max_connections: usize,
    
    /// Connection timeout
    pub connection_timeout: std::time::Duration,
    
    /// Enable TLS
    pub enable_tls: bool,
    
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    
    /// TLS private key path
    pub tls_key_path: Option<String>,
}

/// Client configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientConfig {
    /// Default signaling servers
    pub default_servers: Vec<String>,
    
    /// Connection retry attempts
    pub retry_attempts: u32,
    
    /// Retry delay
    pub retry_delay: std::time::Duration,
    
    /// Keep-alive interval
    pub keepalive_interval: std::time::Duration,
    
    /// Request timeout
    pub request_timeout: std::time::Duration,
    
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
}

/// Discovery configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryConfig {
    /// Enable local discovery (mDNS)
    pub enable_local: bool,
    
    /// Enable DHT discovery
    pub enable_dht: bool,
    
    /// Discovery interval
    pub discovery_interval: std::time::Duration,
    
    /// Peer announcement interval
    pub announce_interval: std::time::Duration,
    
    /// Maximum discovered peers to keep
    pub max_discovered_peers: usize,
    
    /// Peer expiry time
    pub peer_expiry: std::time::Duration,
    
    /// Local discovery service name
    pub service_name: String,
    
    /// DHT bootstrap nodes
    pub dht_bootstrap_nodes: Vec<String>,
}

/// Security configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityConfig {
    /// Enable message signing
    pub enable_signing: bool,
    
    /// Enable message encryption
    pub enable_encryption: bool,
    
    /// Allowed peer verification methods
    pub verification_methods: Vec<String>,
    
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per peer
    pub max_requests_per_minute: u32,
    
    /// Maximum bandwidth per peer (bytes/sec)
    pub max_bandwidth_per_peer: u64,
    
    /// Burst allowance
    pub burst_allowance: u32,
}

/// Performance configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceConfig {
    /// Message buffer size
    pub message_buffer_size: usize,
    
    /// Worker thread count
    pub worker_threads: usize,
    
    /// Enable message compression
    pub enable_compression: bool,
    
    /// Compression threshold (bytes)
    pub compression_threshold: usize,
    
    /// Connection pool size
    pub connection_pool_size: usize,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                websocket_bind: "0.0.0.0:8080".to_string(),
                rest_bind: "0.0.0.0:8081".to_string(),
                enable_websocket: true,
                enable_rest: true,
                max_connections: 1000,
                connection_timeout: std::time::Duration::from_secs(30),
                enable_tls: false,
                tls_cert_path: None,
                tls_key_path: None,
            },
            client: ClientConfig {
                default_servers: vec![
                    "ws://localhost:8080".to_string(),
                    "http://localhost:8081".to_string(),
                ],
                retry_attempts: 3,
                retry_delay: std::time::Duration::from_secs(1),
                keepalive_interval: std::time::Duration::from_secs(30),
                request_timeout: std::time::Duration::from_secs(10),
                auto_reconnect: true,
            },
            discovery: DiscoveryConfig {
                enable_local: true,
                enable_dht: false,
                discovery_interval: std::time::Duration::from_secs(30),
                announce_interval: std::time::Duration::from_secs(60),
                max_discovered_peers: 1000,
                peer_expiry: std::time::Duration::from_secs(300),
                service_name: "_zMesh._tcp.local".to_string(),
                dht_bootstrap_nodes: Vec::new(),
            },
            security: SecurityConfig {
                enable_signing: true,
                enable_encryption: true,
                verification_methods: vec!["ed25519".to_string()],
                rate_limit: RateLimitConfig {
                    max_requests_per_minute: 60,
                    max_bandwidth_per_peer: 1024 * 1024, // 1 MB/s
                    burst_allowance: 10,
                },
            },
            performance: PerformanceConfig {
                message_buffer_size: 1024,
                worker_threads: 4,
                enable_compression: true,
                compression_threshold: 1024,
                connection_pool_size: 100,
            },
        }
    }
}

/// Main signaling manager that coordinates all signaling activities
#[derive(Debug)]
pub struct SignalingManager {
    config: SignalingConfig,
    server: Option<SignalingServer>,
    client: SignalingClient,
    discovery: PeerDiscovery,
    broker: ConnectionBroker,
    registry: PeerRegistry,
}

impl SignalingManager {
    /// Create a new signaling manager
    pub fn new(config: SignalingConfig) -> SignalingResult<Self> {
        let registry = PeerRegistry::new();
        let discovery = PeerDiscovery::new(config.discovery.clone())?;
        let client = SignalingClient::new(config.client.clone())?;
        let broker = ConnectionBroker::new(registry.clone())?;
        
        let server = if config.server.enable_websocket || config.server.enable_rest {
            Some(SignalingServer::new(config.server.clone())?)
        } else {
            None
        };
        
        Ok(Self {
            config,
            server,
            client,
            discovery,
            broker,
            registry,
        })
    }
    
    /// Start the signaling manager
    pub async fn start(&mut self) -> SignalingResult<()> {
        tracing::info!("Starting signaling manager");
        
        // Start server if configured
        if let Some(server) = &mut self.server {
            server.start().await?;
            tracing::info!("Signaling server started");
        }
        
        // Start discovery
        self.discovery.start().await?;
        tracing::info!("Peer discovery started");
        
        // Start connection broker
        self.broker.start().await?;
        tracing::info!("Connection broker started");
        
        // Connect to default signaling servers
        for server_url in &self.config.client.default_servers {
            if let Err(e) = self.client.connect(server_url).await {
                tracing::warn!("Failed to connect to signaling server {}: {}", server_url, e);
            }
        }
        
        tracing::info!("Signaling manager started successfully");
        Ok(())
    }
    
    /// Stop the signaling manager
    pub async fn stop(&mut self) -> SignalingResult<()> {
        tracing::info!("Stopping signaling manager");
        
        // Stop components in reverse order
        self.broker.stop().await?;
        self.discovery.stop().await?;
        
        if let Some(server) = &mut self.server {
            server.stop().await?;
        }
        
        self.client.disconnect_all().await?;
        
        tracing::info!("Signaling manager stopped");
        Ok(())
    }
    
    /// Get peer registry
    pub fn registry(&self) -> &PeerRegistry {
        &self.registry
    }
    
    /// Get connection broker
    pub fn broker(&self) -> &ConnectionBroker {
        &self.broker
    }
    
    /// Get signaling client
    pub fn client(&self) -> &SignalingClient {
        &self.client
    }
    
    /// Get peer discovery
    pub fn discovery(&self) -> &PeerDiscovery {
        &self.discovery
    }
    
    /// Request connection to a peer
    pub async fn connect_to_peer(
        &self,
        peer_id: &PeerId,
        transport_type: TransportType,
    ) -> SignalingResult<()> {
        self.broker.request_connection(peer_id, transport_type).await
    }
    
    /// Announce this peer to the network
    pub async fn announce_peer(&self, peer_info: &PeerInfo) -> SignalingResult<()> {
        // Add to local registry
        self.registry.add_peer(peer_info.clone()).await?;
        
        // Announce via discovery
        self.discovery.announce_peer(peer_info).await?;
        
        // Announce via signaling servers
        self.client.announce_peer(peer_info).await?;
        
        Ok(())
    }
    
    /// Find peers with specific capabilities
    pub async fn find_peers(
        &self,
        capabilities: &PeerCapabilities,
    ) -> SignalingResult<Vec<PeerInfo>> {
        // Search local registry first
        let mut peers = self.registry.find_peers_by_capabilities(capabilities).await?;
        
        // Search via discovery if needed
        if peers.len() < 10 {
            let discovered = self.discovery.find_peers(capabilities).await?;
            peers.extend(discovered);
        }
        
        // Search via signaling servers if still need more
        if peers.len() < 10 {
            let remote = self.client.find_peers(capabilities).await?;
            peers.extend(remote);
        }
        
        // Remove duplicates and sort by score
        peers.sort_by(|a, b| b.routing_score().partial_cmp(&a.routing_score()).unwrap_or(std::cmp::Ordering::Equal));
        peers.dedup_by(|a, b| a.id == b.id);
        
        Ok(peers)
    }
    
    /// Get signaling statistics
    pub async fn get_stats(&self) -> SignalingResult<SignalingStats> {
        Ok(SignalingStats {
            connected_servers: self.client.connected_servers().await?,
            discovered_peers: self.registry.peer_count().await?,
            active_connections: self.broker.active_connections().await?,
            server_stats: if let Some(server) = &self.server {
                Some(server.get_stats().await?)
            } else {
                None
            },
        })
    }
}

/// Signaling statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignalingStats {
    pub connected_servers: usize,
    pub discovered_peers: usize,
    pub active_connections: usize,
    pub server_stats: Option<ServerStats>,
}

/// Server statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerStats {
    pub websocket_connections: usize,
    pub rest_requests: u64,
    pub total_messages: u64,
    pub uptime: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = SignalingConfig::default();
        assert!(config.server.enable_websocket);
        assert!(config.server.enable_rest);
        assert!(config.discovery.enable_local);
        assert!(!config.discovery.enable_dht);
        assert!(config.security.enable_signing);
        assert!(config.security.enable_encryption);
    }
    
    #[tokio::test]
    async fn test_signaling_manager_creation() {
        let config = SignalingConfig::default();
        let manager = SignalingManager::new(config);
        assert!(manager.is_ok());
    }
}