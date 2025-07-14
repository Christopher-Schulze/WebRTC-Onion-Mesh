//! Mesh networking and peer discovery

use crate::{zmeshError, zmeshResult, PeerId, PeerRegistry};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

/// Exit node types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitType {
    /// Direct peer exit
    Direct,
    /// Cloudflare Worker exit
    Cloudflare,
}

impl Default for ExitType {
    fn default() -> Self {
        ExitType::Direct
    }
}

/// Mesh network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Peer discovery interval
    pub discovery_interval: Duration,
    /// Peer health check interval
    pub health_check_interval: Duration,
    /// Maximum peer age before cleanup
    pub max_peer_age: Duration,
    /// Minimum peers for network operation
    pub min_peers: usize,
    /// Target number of connections
    pub target_connections: usize,
    /// Path selection strategy
    pub path_strategy: PathStrategy,
    /// Enable self-seeding
    pub enable_seeding: bool,
    /// Cache size for chunks
    pub cache_size: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            max_connections: 50,
            discovery_interval: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            max_peer_age: Duration::from_secs(3600), // 1 hour
            min_peers: 3,
            target_connections: 8,
            path_strategy: PathStrategy::LowestLatency,
            enable_seeding: true,
            cache_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Path selection strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathStrategy {
    /// Select path with lowest total latency
    LowestLatency,
    /// Select path with highest reliability
    HighestReliability,
    /// Balance latency and reliability
    Balanced,
    /// Random selection for anonymity
    Random,
}

/// Network path through the mesh
#[derive(Debug, Clone)]
pub struct NetworkPath {
    /// Path identifier
    pub id: PathId,
    /// Ordered list of peer IDs
    pub hops: Vec<PeerId>,
    /// Total estimated latency
    pub total_latency: Duration,
    /// Path reliability score (0.0 to 1.0)
    pub reliability: f64,
    /// Path creation time
    pub created_at: Instant,
    /// Last used time
    pub last_used: Instant,
    /// Usage count
    pub usage_count: u64,
    /// Exit type for this path
    pub exit_type: ExitType,
    /// Country code for Cloudflare exit
    pub country: Option<String>,
}

impl NetworkPath {
    /// Create new network path
    pub fn new(hops: Vec<PeerId>, exit_type: ExitType, country: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            id: PathId::new(),
            hops,
            total_latency: Duration::ZERO,
            reliability: 1.0,
            created_at: now,
            last_used: now,
            usage_count: 0,
            exit_type,
            country,
        }
    }
    
    /// Calculate path score (lower is better)
    pub fn score(&self, strategy: PathStrategy) -> f64 {
        match strategy {
            PathStrategy::LowestLatency => self.total_latency.as_millis() as f64,
            PathStrategy::HighestReliability => 1000.0 * (1.0 - self.reliability),
            PathStrategy::Balanced => {
                let latency_score = self.total_latency.as_millis() as f64;
                let reliability_penalty = 500.0 * (1.0 - self.reliability);
                latency_score + reliability_penalty
            }
            PathStrategy::Random => rand::random::<f64>() * 1000.0,
        }
    }
    
    /// Update path statistics
    pub fn update_stats(&mut self, latency: Duration, success: bool) {
        // Update latency with exponential moving average
        if self.total_latency == Duration::ZERO {
            self.total_latency = latency;
        } else {
            let alpha = 0.3;
            let new_latency_ms = self.total_latency.as_millis() as f64 * (1.0 - alpha) + 
                                latency.as_millis() as f64 * alpha;
            self.total_latency = Duration::from_millis(new_latency_ms as u64);
        }
        
        // Update reliability
        let alpha = 0.1;
        if success {
            self.reliability = self.reliability * (1.0 - alpha) + alpha;
        } else {
            self.reliability = self.reliability * (1.0 - alpha);
        }
        self.reliability = self.reliability.max(0.0).min(1.0);
        
        self.last_used = Instant::now();
        self.usage_count += 1;
    }
    
    /// Check if path is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_used.elapsed() > max_age
    }
}

/// Path identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(u64);

impl PathId {
    /// Generate new random path ID
    pub fn new() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().gen())
    }
}

/// Mesh options for connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshOptions {
    /// Number of hops (2 or 3)
    pub hops: u8,
    /// Exit type
    pub exit: ExitType,
    /// Country code for Cloudflare exit
    pub country: Option<String>,
    /// Enable FEC
    pub enable_fec: bool,
}

impl Default for MeshOptions {
    fn default() -> Self {
        Self {
            hops: 2,
            exit: ExitType::Direct,
            country: None,
            enable_fec: true,
        }
    }
}

/// Chunk identifier for self-seeding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId {
    /// Content hash
    pub hash: [u8; 32],
    /// Chunk index
    pub index: u32,
}

impl ChunkId {
    /// Create new chunk ID
    pub fn new(hash: [u8; 32], index: u32) -> Self {
        Self { hash, index }
    }
}

/// Cached chunk for self-seeding
#[derive(Debug, Clone)]
pub struct CachedChunk {
    /// Chunk identifier
    pub id: ChunkId,
    /// Chunk data
    pub data: bytes::Bytes,
    /// Cache time
    pub cached_at: SystemTime,
    /// Access count
    pub access_count: u64,
    /// Last access time
    pub last_access: SystemTime,
}

impl CachedChunk {
    /// Create new cached chunk
    pub fn new(id: ChunkId, data: bytes::Bytes) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            data,
            cached_at: now,
            access_count: 0,
            last_access: now,
        }
    }
    
    /// Update access statistics
    pub fn access(&mut self) {
        self.access_count += 1;
        self.last_access = SystemTime::now();
    }
    
    /// Check if chunk is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_access.elapsed().unwrap_or(Duration::ZERO) > max_age
    }
}

/// Chunk cache for self-seeding
pub struct ChunkCache {
    chunks: HashMap<ChunkId, CachedChunk>,
    max_size: usize,
    current_size: usize,
}

impl ChunkCache {
    /// Create new chunk cache
    pub fn new(max_size: usize) -> Self {
        Self {
            chunks: HashMap::new(),
            max_size,
            current_size: 0,
        }
    }
    
    /// Add chunk to cache
    pub fn add_chunk(&mut self, chunk: CachedChunk) -> zmeshResult<()> {
        let chunk_size = chunk.data.len();
        
        // Check if we need to evict chunks
        while self.current_size + chunk_size > self.max_size && !self.chunks.is_empty() {
            self.evict_lru();
        }
        
        if chunk_size > self.max_size {
            return Err(zmeshError::Config("Chunk too large for cache".to_string()));
        }
        
        self.current_size += chunk_size;
        self.chunks.insert(chunk.id.clone(), chunk);
        
        Ok(())
    }
    
    /// Get chunk from cache
    pub fn get_chunk(&mut self, id: &ChunkId) -> Option<&mut CachedChunk> {
        if let Some(chunk) = self.chunks.get_mut(id) {
            chunk.access();
            Some(chunk)
        } else {
            None
        }
    }
    
    /// Remove chunk from cache
    pub fn remove_chunk(&mut self, id: &ChunkId) -> Option<CachedChunk> {
        if let Some(chunk) = self.chunks.remove(id) {
            self.current_size -= chunk.data.len();
            Some(chunk)
        } else {
            None
        }
    }
    
    /// Evict least recently used chunk
    fn evict_lru(&mut self) {
        if let Some(lru_id) = self.chunks.iter()
            .min_by_key(|(_, chunk)| chunk.last_access)
            .map(|(id, _)| id.clone()) {
            self.remove_chunk(&lru_id);
        }
    }
    
    /// Clean up stale chunks
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let stale_ids: Vec<_> = self.chunks.iter()
            .filter(|(_, chunk)| chunk.is_stale(max_age))
            .map(|(id, _)| id.clone())
            .collect();
        
        for id in stale_ids {
            self.remove_chunk(&id);
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_chunks: self.chunks.len(),
            total_size: self.current_size,
            max_size: self.max_size,
            hit_rate: 0.0, // TODO: Track hit rate
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_chunks: usize,
    pub total_size: usize,
    pub max_size: usize,
    pub hit_rate: f64,
}

/// Path manager for selecting and maintaining network paths
pub struct PathManager {
    paths: HashMap<PathId, NetworkPath>,
    config: MeshConfig,
    peer_registry: PeerRegistry,
}

impl PathManager {
    /// Create new path manager
    pub fn new(config: MeshConfig, peer_registry: PeerRegistry) -> Self {
        Self {
            paths: HashMap::new(),
            config,
            peer_registry,
        }
    }
    
    /// Select best path for given options
    pub fn select_path(&mut self, options: &MeshOptions) -> zmeshResult<PathId> {
        // Try to find existing suitable path
        if let Some(path_id) = self.find_suitable_path(options) {
            return Ok(path_id);
        }
        
        // Build new path
        self.build_path(options)
    }
    
    /// Build new path
    pub fn build_path(&mut self, options: &MeshOptions) -> zmeshResult<PathId> {
        let hops = self.select_hops(options.hops as usize)?;
        let path = NetworkPath::new(hops, options.exit, options.country.clone());
        let path_id = path.id;
        
        self.paths.insert(path_id, path);
        Ok(path_id)
    }
    
    /// Select hops for path
    fn select_hops(&self, hop_count: usize) -> zmeshResult<Vec<PeerId>> {
        let available_peers = self.peer_registry.best_peers(hop_count * 2); // Get more than needed
        
        if available_peers.len() < hop_count {
            return Err(zmeshError::PathNotAvailable);
        }
        
        // Select diverse hops (avoid using same peer multiple times)
        let mut selected = Vec::new();
        let mut used_peers = HashSet::new();
        
        for peer in available_peers {
            if !used_peers.contains(&peer.id) && selected.len() < hop_count {
                selected.push(peer.id.clone());
                used_peers.insert(peer.id.clone());
            }
        }
        
        if selected.len() < hop_count {
            return Err(zmeshError::PathNotAvailable);
        }
        
        Ok(selected)
    }
    
    /// Find suitable existing path
    fn find_suitable_path(&self, options: &MeshOptions) -> Option<PathId> {
        self.paths.iter()
            .filter(|(_, path)| {
                path.hops.len() == options.hops as usize &&
                path.exit_type == options.exit &&
                path.country == options.country &&
                !path.is_stale(Duration::from_secs(300)) // 5 minutes
            })
            .min_by_key(|(_, path)| path.score(self.config.path_strategy) as u64)
            .map(|(id, _)| *id)
    }
    
    /// Update path statistics
    pub fn update_path_stats(&mut self, path_id: PathId, latency: Duration, success: bool) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.update_stats(latency, success);
        }
    }
    
    /// Get path by ID
    pub fn get_path(&self, path_id: PathId) -> Option<&NetworkPath> {
        self.paths.get(&path_id)
    }
    
    /// Remove path
    pub fn remove_path(&mut self, path_id: PathId) -> Option<NetworkPath> {
        self.paths.remove(&path_id)
    }
    
    /// Clean up stale paths
    pub fn cleanup_stale(&mut self) {
        let max_age = Duration::from_secs(1800); // 30 minutes
        self.paths.retain(|_, path| !path.is_stale(max_age));
    }
    
    /// Get path statistics
    pub fn stats(&self) -> PathStats {
        PathStats {
            total_paths: self.paths.len(),
            active_paths: self.paths.values().filter(|p| !p.is_stale(Duration::from_secs(300))).count(),
            avg_latency: self.calculate_avg_latency(),
            avg_reliability: self.calculate_avg_reliability(),
        }
    }
    
    /// Calculate average latency across all paths
    fn calculate_avg_latency(&self) -> Duration {
        if self.paths.is_empty() {
            return Duration::ZERO;
        }
        
        let total_ms: u64 = self.paths.values()
            .map(|p| p.total_latency.as_millis() as u64)
            .sum();
        
        Duration::from_millis(total_ms / self.paths.len() as u64)
    }
    
    /// Calculate average reliability across all paths
    fn calculate_avg_reliability(&self) -> f64 {
        if self.paths.is_empty() {
            return 0.0;
        }
        
        let total_reliability: f64 = self.paths.values()
            .map(|p| p.reliability)
            .sum();
        
        total_reliability / self.paths.len() as f64
    }
}

/// Path statistics
#[derive(Debug, Clone)]
pub struct PathStats {
    pub total_paths: usize,
    pub active_paths: usize,
    pub avg_latency: Duration,
    pub avg_reliability: f64,
}