//! # zMesh Onion Routing Module
//!
//! This module implements onion routing with 2-3 configurable hops and Perfect Forward Secrecy (PFS).
//! It provides secure, anonymous communication through multiple relay nodes.
//!
//! ## Features
//!
//! - **Configurable Hops**: Support for 2 or 3 hops as chosen by the user
//! - **Perfect Forward Secrecy**: Each circuit uses ephemeral keys that are destroyed after use
//! - **Multiple Cipher Suites**: Support for AES-256-GCM and ChaCha20-Poly1305
//! - **Key Exchange**: X25519 and P-256 ECDH key exchange
//! - **Circuit Management**: Automatic circuit creation, maintenance, and cleanup
//! - **Path Selection**: Intelligent path selection based on latency, reliability, and diversity
//! - **Traffic Analysis Resistance**: Padding and timing obfuscation (configurable)
//!
//! ## Architecture
//!
//! ```text
//! Client -> Entry Node -> [Middle Node] -> Exit Node -> Destination
//!    |         |              |             |           |
//!    +-- Encrypted with Exit Key -----------+           |
//!    +-- Encrypted with Middle Key --------+             |
//!    +-- Encrypted with Entry Key ---------+             |
//! ```
//!
//! Each layer of encryption is peeled off at each hop, revealing the next destination
//! and the encrypted payload for the next hop.

use zMesh_core::{
    error::zMeshError,
    peer::{PeerId, PeerInfo},
    transport::TransportType,
};

pub mod error;
pub mod crypto;
pub mod circuit;
pub mod path;
pub mod packet;
pub mod router;
pub mod relay;
pub mod exit;
pub mod metrics;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use error::{OnionError, OnionResult};
pub use crypto::{OnionCrypto, CipherSuite, KeyExchange};
pub use circuit::{Circuit, CircuitId, CircuitManager, CircuitStatus};
pub use path::{PathSelector, PathStrategy, OnionPath};
pub use packet::{OnionPacket, OnionLayer, PacketProcessor};
pub use router::OnionRouter;
pub use relay::RelayNode;
pub use exit::ExitNode;

#[cfg(feature = "metrics")]
pub use metrics::OnionMetrics;

/// Re-export commonly used types
pub use zMesh_core::{
    onion::{OnionConfig, CircuitPath},
    crypto::{CryptoConfig, CipherSuite as CoreCipherSuite},
};

/// Onion routing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnionRoutingConfig {
    /// Core onion configuration
    pub onion: OnionConfig,
    
    /// Cryptographic configuration
    pub crypto: CryptoConfig,
    
    /// Path selection configuration
    pub path: PathConfig,
    
    /// Circuit management configuration
    pub circuit: CircuitConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
    
    /// Security settings
    pub security: SecurityConfig,
}

/// Path selection configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PathConfig {
    /// Path selection strategy
    pub strategy: PathStrategy,
    
    /// Minimum path diversity (geographic/network)
    pub min_diversity: f32,
    
    /// Maximum latency per hop (milliseconds)
    pub max_hop_latency: u32,
    
    /// Minimum reliability per hop
    pub min_hop_reliability: f32,
    
    /// Exclude nodes in same country
    pub exclude_same_country: bool,
    
    /// Exclude nodes in same AS
    pub exclude_same_as: bool,
    
    /// Maximum path reuse count
    pub max_path_reuse: u32,
    
    /// Path refresh interval
    pub path_refresh_interval: std::time::Duration,
}

/// Circuit management configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitConfig {
    /// Maximum concurrent circuits
    pub max_circuits: usize,
    
    /// Circuit lifetime
    pub circuit_lifetime: std::time::Duration,
    
    /// Circuit build timeout
    pub build_timeout: std::time::Duration,
    
    /// Circuit extend timeout
    pub extend_timeout: std::time::Duration,
    
    /// Maximum circuit build retries
    pub max_build_retries: u32,
    
    /// Circuit health check interval
    pub health_check_interval: std::time::Duration,
    
    /// Preemptive circuit building
    pub preemptive_circuits: usize,
}

/// Performance configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceConfig {
    /// Packet buffer size
    pub packet_buffer_size: usize,
    
    /// Maximum packet size
    pub max_packet_size: usize,
    
    /// Batch processing size
    pub batch_size: usize,
    
    /// Worker thread count
    pub worker_threads: usize,
    
    /// Enable packet batching
    pub enable_batching: bool,
    
    /// Batching timeout
    pub batch_timeout: std::time::Duration,
}

/// Security configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityConfig {
    /// Enable traffic padding
    pub enable_padding: bool,
    
    /// Padding block size
    pub padding_block_size: usize,
    
    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,
    
    /// Timing variance (milliseconds)
    pub timing_variance: u32,
    
    /// Enable circuit isolation
    pub enable_circuit_isolation: bool,
    
    /// Maximum streams per circuit
    pub max_streams_per_circuit: usize,
    
    /// Enable guard nodes
    pub enable_guard_nodes: bool,
    
    /// Number of guard nodes
    pub guard_node_count: usize,
}

impl Default for OnionRoutingConfig {
    fn default() -> Self {
        Self {
            onion: OnionConfig::default(),
            crypto: CryptoConfig::default(),
            path: PathConfig {
                strategy: PathStrategy::Balanced,
                min_diversity: 0.7,
                max_hop_latency: 500, // 500ms
                min_hop_reliability: 0.95,
                exclude_same_country: true,
                exclude_same_as: true,
                max_path_reuse: 100,
                path_refresh_interval: std::time::Duration::from_secs(300), // 5 minutes
            },
            circuit: CircuitConfig {
                max_circuits: 10,
                circuit_lifetime: std::time::Duration::from_secs(600), // 10 minutes
                build_timeout: std::time::Duration::from_secs(30),
                extend_timeout: std::time::Duration::from_secs(10),
                max_build_retries: 3,
                health_check_interval: std::time::Duration::from_secs(60),
                preemptive_circuits: 2,
            },
            performance: PerformanceConfig {
                packet_buffer_size: 1024,
                max_packet_size: 1024 * 64, // 64KB
                batch_size: 10,
                worker_threads: 4,
                enable_batching: true,
                batch_timeout: std::time::Duration::from_millis(10),
            },
            security: SecurityConfig {
                enable_padding: false, // Disabled by user request
                padding_block_size: 1024,
                enable_timing_obfuscation: false, // Disabled by user request
                timing_variance: 0,
                enable_circuit_isolation: true,
                max_streams_per_circuit: 10,
                enable_guard_nodes: true,
                guard_node_count: 3,
            },
        }
    }
}

/// Main onion routing manager
#[derive(Debug)]
pub struct OnionManager {
    config: OnionRoutingConfig,
    router: OnionRouter,
    circuit_manager: CircuitManager,
    path_selector: PathSelector,
    crypto: Box<dyn OnionCrypto + Send + Sync>,
    
    #[cfg(feature = "metrics")]
    metrics: OnionMetrics,
}

impl OnionManager {
    /// Create a new onion manager
    pub async fn new(
        config: OnionRoutingConfig,
        transport: Box<dyn zMesh_transport::Transport + Send + Sync>,
    ) -> OnionResult<Self> {
        // Initialize cryptographic provider
        let crypto = crypto::create_crypto_provider(&config.crypto)?;
        
        // Initialize path selector
        let path_selector = PathSelector::new(config.path.clone())?;
        
        // Initialize circuit manager
        let circuit_manager = CircuitManager::new(
            config.circuit.clone(),
            crypto.clone(),
        ).await?;
        
        // Initialize router
        let router = OnionRouter::new(
            config.onion.clone(),
            transport,
            circuit_manager.clone(),
        ).await?;
        
        Ok(Self {
            config,
            router,
            circuit_manager,
            path_selector,
            crypto,
            
            #[cfg(feature = "metrics")]
            metrics: OnionMetrics::new()?,
        })
    }
    
    /// Start the onion manager
    pub async fn start(&mut self) -> OnionResult<()> {
        tracing::info!("Starting onion routing manager");
        
        // Start circuit manager
        self.circuit_manager.start().await?;
        
        // Start router
        self.router.start().await?;
        
        // Build initial circuits
        self.build_preemptive_circuits().await?;
        
        tracing::info!("Onion routing manager started");
        Ok(())
    }
    
    /// Stop the onion manager
    pub async fn stop(&mut self) -> OnionResult<()> {
        tracing::info!("Stopping onion routing manager");
        
        // Stop router
        self.router.stop().await?;
        
        // Stop circuit manager
        self.circuit_manager.stop().await?;
        
        tracing::info!("Onion routing manager stopped");
        Ok(())
    }
    
    /// Send data through onion routing
    pub async fn send_data(
        &self,
        destination: &str,
        data: Vec<u8>,
        hops: Option<u8>,
    ) -> OnionResult<()> {
        // Validate hop count
        let hop_count = hops.unwrap_or(self.config.onion.default_hops);
        if hop_count < self.config.onion.min_hops || hop_count > self.config.onion.max_hops {
            return Err(OnionError::InvalidHopCount(hop_count));
        }
        
        // Get or create circuit
        let circuit = self.get_or_create_circuit(hop_count).await?;
        
        // Route data through circuit
        self.router.route_data(circuit, destination, data).await?;
        
        #[cfg(feature = "metrics")]
        self.metrics.record_packet_sent();
        
        Ok(())
    }
    
    /// Receive data from onion routing
    pub async fn receive_data(&self) -> OnionResult<(String, Vec<u8>)> {
        let (source, data) = self.router.receive_data().await?;
        
        #[cfg(feature = "metrics")]
        self.metrics.record_packet_received();
        
        Ok((source, data))
    }
    
    /// Create a new circuit with specified hop count
    pub async fn create_circuit(&self, hops: u8) -> OnionResult<CircuitId> {
        // Validate hop count
        if hops < self.config.onion.min_hops || hops > self.config.onion.max_hops {
            return Err(OnionError::InvalidHopCount(hops));
        }
        
        // Select path
        let path = self.path_selector.select_path(hops as usize).await?;
        
        // Build circuit
        let circuit_id = self.circuit_manager.build_circuit(path).await?;
        
        #[cfg(feature = "metrics")]
        self.metrics.record_circuit_created();
        
        Ok(circuit_id)
    }
    
    /// Close a circuit
    pub async fn close_circuit(&self, circuit_id: CircuitId) -> OnionResult<()> {
        self.circuit_manager.close_circuit(circuit_id).await?;
        
        #[cfg(feature = "metrics")]
        self.metrics.record_circuit_closed();
        
        Ok(())
    }
    
    /// Get circuit statistics
    pub async fn get_circuit_stats(&self) -> OnionResult<CircuitStats> {
        let active_circuits = self.circuit_manager.active_circuit_count().await?;
        let total_circuits = self.circuit_manager.total_circuit_count().await?;
        let failed_circuits = self.circuit_manager.failed_circuit_count().await?;
        
        Ok(CircuitStats {
            active_circuits,
            total_circuits,
            failed_circuits,
            success_rate: if total_circuits > 0 {
                (total_circuits - failed_circuits) as f32 / total_circuits as f32
            } else {
                0.0
            },
        })
    }
    
    /// Update configuration
    pub async fn update_config(&mut self, config: OnionRoutingConfig) -> OnionResult<()> {
        self.config = config.clone();
        
        // Update components
        self.circuit_manager.update_config(config.circuit).await?;
        self.path_selector.update_config(config.path).await?;
        self.router.update_config(config.onion).await?;
        
        Ok(())
    }
    
    // Private methods
    
    async fn get_or_create_circuit(&self, hops: u8) -> OnionResult<CircuitId> {
        // Try to get an existing circuit with the required hop count
        if let Some(circuit_id) = self.circuit_manager.get_available_circuit(hops).await? {
            return Ok(circuit_id);
        }
        
        // Create a new circuit
        self.create_circuit(hops).await
    }
    
    async fn build_preemptive_circuits(&self) -> OnionResult<()> {
        let preemptive_count = self.config.circuit.preemptive_circuits;
        
        for _ in 0..preemptive_count {
            // Build circuits with default hop count
            let hops = self.config.onion.default_hops;
            if let Err(e) = self.create_circuit(hops).await {
                tracing::warn!("Failed to build preemptive circuit: {}", e);
            }
        }
        
        Ok(())
    }
}

/// Circuit statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitStats {
    pub active_circuits: usize,
    pub total_circuits: usize,
    pub failed_circuits: usize,
    pub success_rate: f32,
}

/// Onion routing node types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    /// Entry node (first hop)
    Entry,
    /// Middle node (intermediate hop)
    Middle,
    /// Exit node (last hop)
    Exit,
}

/// Stream identifier for circuit multiplexing
pub type StreamId = u16;

/// Onion routing stream
#[derive(Debug, Clone)]
pub struct OnionStream {
    pub id: StreamId,
    pub circuit_id: CircuitId,
    pub destination: String,
    pub created_at: std::time::Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = OnionRoutingConfig::default();
        
        // Check that user requirements are respected
        assert!(!config.security.enable_padding); // No dummy traffic
        assert!(!config.security.enable_timing_obfuscation); // No time obfuscation
        assert_eq!(config.security.timing_variance, 0);
        
        // Check hop configuration
        assert_eq!(config.onion.min_hops, 2);
        assert_eq!(config.onion.max_hops, 3);
        
        // Check PFS is enabled
        assert!(config.crypto.enable_pfs);
    }
    
    #[test]
    fn test_config_serialization() {
        let config = OnionRoutingConfig::default();
        
        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OnionRoutingConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.onion.min_hops, deserialized.onion.min_hops);
        assert_eq!(config.onion.max_hops, deserialized.onion.max_hops);
    }
    
    #[tokio::test]
    async fn test_circuit_stats() {
        let stats = CircuitStats {
            active_circuits: 5,
            total_circuits: 10,
            failed_circuits: 2,
            success_rate: 0.8,
        };
        
        assert_eq!(stats.active_circuits, 5);
        assert_eq!(stats.success_rate, 0.8);
    }
}