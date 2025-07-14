//! Circuit management for onion routing
//! Supports 2-3 configurable hops with Perfect Forward Secrecy

use crate::crypto::{CircuitKeys, HopKeys, OnionCrypto, OnionEncryptedData, OnionKey};
use crate::error::{CircuitError, OnionResult};
use zMesh_core::peer::PeerId;
use zMesh_transport::{Connection, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Circuit identifier
pub type CircuitId = String;

/// Circuit state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is being built
    Building,
    /// Circuit is ready for use
    Ready,
    /// Circuit is being extended
    Extending,
    /// Circuit is being torn down
    TearingDown,
    /// Circuit is closed
    Closed,
    /// Circuit failed
    Failed(String),
}

/// Circuit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Number of hops (2 or 3)
    pub hop_count: u8,
    /// Circuit build timeout
    pub build_timeout: Duration,
    /// Circuit idle timeout
    pub idle_timeout: Duration,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    /// Maximum circuit lifetime
    pub max_lifetime: Duration,
    /// Enable Perfect Forward Secrecy
    pub enable_pfs: bool,
    /// Maximum concurrent circuits
    pub max_concurrent_circuits: usize,
    /// Circuit retry attempts
    pub retry_attempts: u8,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            hop_count: 3,
            build_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            key_rotation_interval: Duration::from_secs(1800),
            max_lifetime: Duration::from_secs(7200),
            enable_pfs: true,
            max_concurrent_circuits: 100,
            retry_attempts: 3,
        }
    }
}

impl CircuitConfig {
    /// Validate hop count (must be 2 or 3)
    pub fn validate_hop_count(&self) -> OnionResult<()> {
        if self.hop_count < 2 || self.hop_count > 3 {
            return Err(crate::error::OnionError::invalid_hop_count(self.hop_count));
        }
        Ok(())
    }
}

/// Information about a single hop in the circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    /// Hop index (0-based)
    pub index: u8,
    /// Peer ID of the relay
    pub peer_id: PeerId,
    /// Connection to the relay
    pub connection_id: String,
    /// Hop establishment timestamp
    pub established_at: SystemTime,
    /// Hop latency
    pub latency: Option<Duration>,
    /// Hop bandwidth
    pub bandwidth: Option<u64>,
    /// Hop reliability score
    pub reliability: Option<f32>,
}

/// Circuit statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CircuitStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Average latency
    pub avg_latency: Option<Duration>,
    /// Circuit uptime
    pub uptime: Duration,
    /// Number of key rotations
    pub key_rotations: u32,
    /// Last activity timestamp
    pub last_activity: SystemTime,
}

/// Circuit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitEvent {
    /// Circuit build started
    BuildStarted { circuit_id: CircuitId },
    /// Hop extended
    HopExtended { circuit_id: CircuitId, hop_index: u8, peer_id: PeerId },
    /// Circuit ready
    Ready { circuit_id: CircuitId },
    /// Circuit failed
    Failed { circuit_id: CircuitId, reason: String },
    /// Circuit closed
    Closed { circuit_id: CircuitId, reason: String },
    /// Key rotation performed
    KeyRotation { circuit_id: CircuitId },
    /// Data sent through circuit
    DataSent { circuit_id: CircuitId, bytes: usize },
    /// Data received through circuit
    DataReceived { circuit_id: CircuitId, bytes: usize },
}

/// Circuit implementation
pub struct Circuit {
    /// Circuit identifier
    pub id: CircuitId,
    /// Circuit configuration
    pub config: CircuitConfig,
    /// Circuit state
    pub state: CircuitState,
    /// Hops in the circuit
    pub hops: Vec<HopInfo>,
    /// Circuit keys for PFS
    pub keys: CircuitKeys,
    /// Circuit statistics
    pub stats: CircuitStats,
    /// Circuit creation timestamp
    pub created_at: SystemTime,
    /// Last activity timestamp
    pub last_activity: SystemTime,
    /// Event sender
    event_tx: mpsc::UnboundedSender<CircuitEvent>,
    /// Crypto provider
    crypto: Arc<RwLock<OnionCrypto>>,
}

impl Circuit {
    /// Create a new circuit
    pub fn new(
        config: CircuitConfig,
        event_tx: mpsc::UnboundedSender<CircuitEvent>,
        crypto: Arc<RwLock<OnionCrypto>>,
    ) -> OnionResult<Self> {
        config.validate_hop_count()?;
        
        let id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        
        let keys = CircuitKeys::new(id.clone(), config.key_rotation_interval);
        
        Ok(Self {
            id: id.clone(),
            config,
            state: CircuitState::Building,
            hops: Vec::new(),
            keys,
            stats: CircuitStats::default(),
            created_at: now,
            last_activity: now,
            event_tx,
            crypto,
        })
    }
    
    /// Get circuit ID
    pub fn id(&self) -> &str {
        &self.id
    }
    
    /// Get circuit state
    pub fn state(&self) -> &CircuitState {
        &self.state
    }
    
    /// Get number of established hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
    
    /// Check if circuit is ready
    pub fn is_ready(&self) -> bool {
        matches!(self.state, CircuitState::Ready) && 
        self.hops.len() == self.config.hop_count as usize
    }
    
    /// Check if circuit is closed
    pub fn is_closed(&self) -> bool {
        matches!(self.state, CircuitState::Closed | CircuitState::Failed(_))
    }
    
    /// Check if circuit has expired
    pub fn is_expired(&self) -> bool {
        let age = SystemTime::now().duration_since(self.created_at).unwrap_or_default();
        age >= self.config.max_lifetime
    }
    
    /// Check if circuit is idle
    pub fn is_idle(&self) -> bool {
        let idle_time = SystemTime::now().duration_since(self.last_activity).unwrap_or_default();
        idle_time >= self.config.idle_timeout
    }
    
    /// Check if keys need rotation
    pub fn needs_key_rotation(&self) -> bool {
        self.config.enable_pfs && self.keys.needs_rotation()
    }
    
    /// Start building the circuit
    pub async fn build(&mut self, path: Vec<PeerId>) -> OnionResult<()> {
        if path.len() != self.config.hop_count as usize {
            return Err(CircuitError::BuildFailed(
                format!("Path length {} doesn't match hop count {}", path.len(), self.config.hop_count)
            ).into());
        }
        
        self.state = CircuitState::Building;
        self.send_event(CircuitEvent::BuildStarted { circuit_id: self.id.clone() });
        
        // Build circuit hop by hop
        for (index, peer_id) in path.iter().enumerate() {
            self.extend_to_peer(index as u8, peer_id.clone()).await?;
        }
        
        self.state = CircuitState::Ready;
        self.send_event(CircuitEvent::Ready { circuit_id: self.id.clone() });
        
        Ok(())
    }
    
    /// Extend circuit to a new peer
    async fn extend_to_peer(&mut self, hop_index: u8, peer_id: PeerId) -> OnionResult<()> {
        self.state = CircuitState::Extending;
        
        // Generate ephemeral key pair for this hop
        let mut crypto = self.crypto.write().await;
        let (private_key, public_key) = crypto.generate_ephemeral_keypair()?;
        
        // TODO: Send extend request to the peer
        // This would involve:
        // 1. Sending the public key to the peer
        // 2. Receiving the peer's public key
        // 3. Performing key exchange
        // 4. Deriving hop keys
        
        // For now, simulate the key exchange
        let peer_public_key = crypto.generate_ephemeral_keypair()?.1;
        let shared_secret = crypto.key_exchange(&private_key, &peer_public_key)?;
        
        // Generate hop keys with PFS
        let hop_keys = crypto.generate_hop_keys(hop_index, &shared_secret)?;
        
        // Store keys in circuit
        self.keys.add_hop_keys(hop_index, hop_keys);
        
        // Create hop info
        let hop_info = HopInfo {
            index: hop_index,
            peer_id: peer_id.clone(),
            connection_id: format!("conn-{}-{}", self.id, hop_index),
            established_at: SystemTime::now(),
            latency: None,
            bandwidth: None,
            reliability: None,
        };
        
        self.hops.push(hop_info);
        self.update_activity();
        
        self.send_event(CircuitEvent::HopExtended {
            circuit_id: self.id.clone(),
            hop_index,
            peer_id,
        });
        
        Ok(())
    }
    
    /// Send data through the circuit
    pub async fn send_data(&mut self, data: &[u8]) -> OnionResult<()> {
        if !self.is_ready() {
            return Err(CircuitError::NotReady("Circuit not ready for data transmission".to_string()).into());
        }
        
        // Encrypt data layer by layer (onion encryption)
        let encrypted_data = self.encrypt_onion_layers(data).await?;
        
        // TODO: Send encrypted data through the first hop
        // This would involve sending the data to the first relay
        
        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;
        self.update_activity();
        
        self.send_event(CircuitEvent::DataSent {
            circuit_id: self.id.clone(),
            bytes: data.len(),
        });
        
        Ok(())
    }
    
    /// Receive data from the circuit
    pub async fn receive_data(&mut self, encrypted_data: &[u8]) -> OnionResult<Vec<u8>> {
        if !self.is_ready() {
            return Err(CircuitError::NotReady("Circuit not ready for data reception".to_string()).into());
        }
        
        // Decrypt data layer by layer (onion decryption)
        let decrypted_data = self.decrypt_onion_layers(encrypted_data).await?;
        
        self.stats.bytes_received += encrypted_data.len() as u64;
        self.stats.packets_received += 1;
        self.update_activity();
        
        self.send_event(CircuitEvent::DataReceived {
            circuit_id: self.id.clone(),
            bytes: encrypted_data.len(),
        });
        
        Ok(decrypted_data)
    }
    
    /// Encrypt data with onion layers
    async fn encrypt_onion_layers(&self, data: &[u8]) -> OnionResult<Vec<u8>> {
        let mut encrypted_data = data.to_vec();
        let crypto = self.crypto.read().await;
        
        // Encrypt from the last hop to the first (reverse order)
        for hop_index in (0..self.hops.len()).rev() {
            if let Some(hop_keys) = self.keys.get_hop_keys(hop_index as u8) {
                let encrypted = crypto.encrypt(
                    &encrypted_data,
                    &hop_keys.forward_key,
                    None,
                )?;
                
                // Serialize encrypted data for next layer
                encrypted_data = bincode::serialize(&encrypted)
                    .map_err(|e| crate::error::PacketError::InvalidFormat(e.to_string()))?;
            }
        }
        
        Ok(encrypted_data)
    }
    
    /// Decrypt data from onion layers
    async fn decrypt_onion_layers(&self, data: &[u8]) -> OnionResult<Vec<u8>> {
        let mut decrypted_data = data.to_vec();
        let crypto = self.crypto.read().await;
        
        // Decrypt from the first hop to the last
        for hop_index in 0..self.hops.len() {
            if let Some(hop_keys) = self.keys.get_hop_keys(hop_index as u8) {
                // Deserialize encrypted data
                let encrypted: OnionEncryptedData = bincode::deserialize(&decrypted_data)
                    .map_err(|e| crate::error::PacketError::InvalidFormat(e.to_string()))?;
                
                decrypted_data = crypto.decrypt(&encrypted, &hop_keys.backward_key)?;
            }
        }
        
        Ok(decrypted_data)
    }
    
    /// Rotate circuit keys
    pub async fn rotate_keys(&mut self) -> OnionResult<()> {
        if !self.config.enable_pfs {
            return Ok(());
        }
        
        let mut crypto = self.crypto.write().await;
        
        // Rotate keys for each hop
        for hop_index in 0..self.hops.len() {
            // Generate new shared secret
            let (private_key, public_key) = crypto.generate_ephemeral_keypair()?;
            
            // TODO: Perform key exchange with the hop
            // For now, simulate it
            let peer_public_key = crypto.generate_ephemeral_keypair()?.1;
            let shared_secret = crypto.key_exchange(&private_key, &peer_public_key)?;
            
            // Generate new hop keys
            let new_hop_keys = crypto.generate_hop_keys(hop_index as u8, &shared_secret)?;
            
            // Replace old keys
            self.keys.add_hop_keys(hop_index as u8, new_hop_keys);
        }
        
        self.keys.last_rotation = SystemTime::now();
        self.stats.key_rotations += 1;
        
        self.send_event(CircuitEvent::KeyRotation { circuit_id: self.id.clone() });
        
        Ok(())
    }
    
    /// Close the circuit
    pub async fn close(&mut self, reason: String) -> OnionResult<()> {
        if self.is_closed() {
            return Ok(());
        }
        
        self.state = CircuitState::TearingDown;
        
        // TODO: Send close messages to all hops
        // This would involve notifying each relay that the circuit is being torn down
        
        self.state = CircuitState::Closed;
        
        self.send_event(CircuitEvent::Closed {
            circuit_id: self.id.clone(),
            reason,
        });
        
        Ok(())
    }
    
    /// Fail the circuit
    pub fn fail(&mut self, reason: String) {
        self.state = CircuitState::Failed(reason.clone());
        
        self.send_event(CircuitEvent::Failed {
            circuit_id: self.id.clone(),
            reason,
        });
    }
    
    /// Update last activity timestamp
    fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
        self.stats.last_activity = self.last_activity;
        self.stats.uptime = self.last_activity.duration_since(self.created_at).unwrap_or_default();
    }
    
    /// Send circuit event
    fn send_event(&self, event: CircuitEvent) {
        let _ = self.event_tx.send(event);
    }
    
    /// Get circuit statistics
    pub fn get_stats(&self) -> CircuitStats {
        let mut stats = self.stats.clone();
        stats.uptime = SystemTime::now().duration_since(self.created_at).unwrap_or_default();
        stats
    }
    
    /// Get hop information
    pub fn get_hop_info(&self, hop_index: u8) -> Option<&HopInfo> {
        self.hops.get(hop_index as usize)
    }
    
    /// Get all hop information
    pub fn get_all_hops(&self) -> &[HopInfo] {
        &self.hops
    }
    
    /// Calculate circuit latency
    pub fn calculate_latency(&self) -> Option<Duration> {
        let latencies: Vec<Duration> = self.hops
            .iter()
            .filter_map(|hop| hop.latency)
            .collect();
        
        if latencies.is_empty() {
            None
        } else {
            Some(latencies.iter().sum())
        }
    }
    
    /// Calculate circuit reliability
    pub fn calculate_reliability(&self) -> Option<f32> {
        let reliabilities: Vec<f32> = self.hops
            .iter()
            .filter_map(|hop| hop.reliability)
            .collect();
        
        if reliabilities.is_empty() {
            None
        } else {
            // Circuit reliability is the product of hop reliabilities
            Some(reliabilities.iter().product())
        }
    }
    
    /// Update hop statistics
    pub fn update_hop_stats(&mut self, hop_index: u8, latency: Option<Duration>, bandwidth: Option<u64>, reliability: Option<f32>) {
        if let Some(hop) = self.hops.get_mut(hop_index as usize) {
            if let Some(lat) = latency {
                hop.latency = Some(lat);
            }
            if let Some(bw) = bandwidth {
                hop.bandwidth = Some(bw);
            }
            if let Some(rel) = reliability {
                hop.reliability = Some(rel);
            }
        }
    }
}

/// Circuit manager for handling multiple circuits
pub struct CircuitManager {
    /// Active circuits
    circuits: Arc<RwLock<HashMap<CircuitId, Arc<RwLock<Circuit>>>>>,
    /// Circuit configuration
    config: CircuitConfig,
    /// Event receiver
    event_rx: mpsc::UnboundedReceiver<CircuitEvent>,
    /// Event sender
    event_tx: mpsc::UnboundedSender<CircuitEvent>,
    /// Crypto provider
    crypto: Arc<RwLock<OnionCrypto>>,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new(config: CircuitConfig, crypto: Arc<RwLock<OnionCrypto>>) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        Self {
            circuits: Arc::new(RwLock::new(HashMap::new())),
            config,
            event_rx,
            event_tx,
            crypto,
        }
    }
    
    /// Create a new circuit
    pub async fn create_circuit(&self) -> OnionResult<CircuitId> {
        let circuits = self.circuits.read().await;
        if circuits.len() >= self.config.max_concurrent_circuits {
            return Err(crate::error::CircuitError::LimitExceeded {
                current: circuits.len(),
                max: self.config.max_concurrent_circuits,
            }.into());
        }
        drop(circuits);
        
        let circuit = Circuit::new(
            self.config.clone(),
            self.event_tx.clone(),
            self.crypto.clone(),
        )?;
        
        let circuit_id = circuit.id().to_string();
        
        let mut circuits = self.circuits.write().await;
        circuits.insert(circuit_id.clone(), Arc::new(RwLock::new(circuit)));
        
        Ok(circuit_id)
    }
    
    /// Get a circuit by ID
    pub async fn get_circuit(&self, circuit_id: &str) -> Option<Arc<RwLock<Circuit>>> {
        let circuits = self.circuits.read().await;
        circuits.get(circuit_id).cloned()
    }
    
    /// Remove a circuit
    pub async fn remove_circuit(&self, circuit_id: &str) -> OnionResult<()> {
        let mut circuits = self.circuits.write().await;
        if let Some(circuit_arc) = circuits.remove(circuit_id) {
            let mut circuit = circuit_arc.write().await;
            circuit.close("Circuit removed by manager".to_string()).await?;
        }
        Ok(())
    }
    
    /// Get all circuit IDs
    pub async fn get_circuit_ids(&self) -> Vec<CircuitId> {
        let circuits = self.circuits.read().await;
        circuits.keys().cloned().collect()
    }
    
    /// Get circuit count
    pub async fn circuit_count(&self) -> usize {
        let circuits = self.circuits.read().await;
        circuits.len()
    }
    
    /// Cleanup expired and idle circuits
    pub async fn cleanup_circuits(&self) -> OnionResult<usize> {
        let mut circuits_to_remove = Vec::new();
        
        {
            let circuits = self.circuits.read().await;
            for (circuit_id, circuit_arc) in circuits.iter() {
                let circuit = circuit_arc.read().await;
                if circuit.is_expired() || circuit.is_idle() || circuit.is_closed() {
                    circuits_to_remove.push(circuit_id.clone());
                }
            }
        }
        
        let removed_count = circuits_to_remove.len();
        for circuit_id in circuits_to_remove {
            self.remove_circuit(&circuit_id).await?;
        }
        
        Ok(removed_count)
    }
    
    /// Rotate keys for all circuits
    pub async fn rotate_all_keys(&self) -> OnionResult<usize> {
        let mut rotated_count = 0;
        
        let circuits = self.circuits.read().await;
        for circuit_arc in circuits.values() {
            let mut circuit = circuit_arc.write().await;
            if circuit.needs_key_rotation() {
                circuit.rotate_keys().await?;
                rotated_count += 1;
            }
        }
        
        Ok(rotated_count)
    }
    
    /// Get aggregated statistics
    pub async fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        let circuits = self.circuits.read().await;
        
        stats.insert("total_circuits".to_string(), circuits.len() as u64);
        
        let mut ready_count = 0;
        let mut building_count = 0;
        let mut failed_count = 0;
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        
        for circuit_arc in circuits.values() {
            let circuit = circuit_arc.read().await;
            match circuit.state() {
                CircuitState::Ready => ready_count += 1,
                CircuitState::Building | CircuitState::Extending => building_count += 1,
                CircuitState::Failed(_) => failed_count += 1,
                _ => {},
            }
            
            let circuit_stats = circuit.get_stats();
            total_bytes_sent += circuit_stats.bytes_sent;
            total_bytes_received += circuit_stats.bytes_received;
        }
        
        stats.insert("ready_circuits".to_string(), ready_count);
        stats.insert("building_circuits".to_string(), building_count);
        stats.insert("failed_circuits".to_string(), failed_count);
        stats.insert("total_bytes_sent".to_string(), total_bytes_sent);
        stats.insert("total_bytes_received".to_string(), total_bytes_received);
        
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{OnionCipherSuite, OnionKeyExchange};
    use std::time::Duration;
    
    fn create_test_crypto() -> Arc<RwLock<OnionCrypto>> {
        Arc::new(RwLock::new(OnionCrypto::new(
            OnionCipherSuite::ChaCha20Poly1305,
            OnionKeyExchange::X25519,
            Duration::from_secs(3600),
        )))
    }
    
    #[tokio::test]
    async fn test_circuit_creation() {
        let config = CircuitConfig::default();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let crypto = create_test_crypto();
        
        let circuit = Circuit::new(config, event_tx, crypto).unwrap();
        
        assert_eq!(circuit.state(), &CircuitState::Building);
        assert_eq!(circuit.hop_count(), 0);
        assert!(!circuit.is_ready());
        assert!(!circuit.is_closed());
    }
    
    #[tokio::test]
    async fn test_invalid_hop_count() {
        let mut config = CircuitConfig::default();
        config.hop_count = 1; // Invalid
        
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let crypto = create_test_crypto();
        
        let result = Circuit::new(config, event_tx, crypto);
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_circuit_manager() {
        let config = CircuitConfig::default();
        let crypto = create_test_crypto();
        let manager = CircuitManager::new(config, crypto);
        
        assert_eq!(manager.circuit_count().await, 0);
        
        let circuit_id = manager.create_circuit().await.unwrap();
        assert_eq!(manager.circuit_count().await, 1);
        
        let circuit = manager.get_circuit(&circuit_id).await;
        assert!(circuit.is_some());
        
        manager.remove_circuit(&circuit_id).await.unwrap();
        assert_eq!(manager.circuit_count().await, 0);
    }
    
    #[test]
    fn test_circuit_config_validation() {
        let mut config = CircuitConfig::default();
        
        // Valid hop counts
        config.hop_count = 2;
        assert!(config.validate_hop_count().is_ok());
        
        config.hop_count = 3;
        assert!(config.validate_hop_count().is_ok());
        
        // Invalid hop counts
        config.hop_count = 1;
        assert!(config.validate_hop_count().is_err());
        
        config.hop_count = 4;
        assert!(config.validate_hop_count().is_err());
    }
    
    #[test]
    fn test_circuit_stats() {
        let stats = CircuitStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.key_rotations, 0);
    }
}