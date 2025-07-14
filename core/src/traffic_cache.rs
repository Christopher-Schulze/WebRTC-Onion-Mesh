//! Advanced traffic chunk caching system
//! Implements intelligent caching strategies for network traffic chunks

use crate::{zMeshError, zMeshResult, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Traffic chunk identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrafficChunkId {
    /// Flow identifier (source + destination)
    pub flow_id: u64,
    /// Sequence number within flow
    pub sequence: u32,
    /// Chunk hash for integrity
    pub hash: [u8; 32],
}

impl TrafficChunkId {
    pub fn new(flow_id: u64, sequence: u32, data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().into();
        
        Self {
            flow_id,
            sequence,
            hash,
        }
    }
}

/// Traffic chunk metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficChunkMeta {
    /// Chunk identifier
    pub id: TrafficChunkId,
    /// Chunk size in bytes
    pub size: usize,
    /// Priority level (0-255, higher = more important)
    pub priority: u8,
    /// Traffic type classification
    pub traffic_type: TrafficType,
    /// Expected access pattern
    pub access_pattern: AccessPattern,
    /// Time-to-live for this chunk
    pub ttl: Duration,
    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Traffic type classification for intelligent caching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficType {
    /// Real-time traffic (video calls, gaming)
    RealTime,
    /// Streaming media
    Streaming,
    /// File transfer
    FileTransfer,
    /// Web browsing
    WebBrowsing,
    /// Background sync
    BackgroundSync,
    /// Unknown/other
    Unknown,
}

impl TrafficType {
    /// Get default cache priority for traffic type
    pub fn default_priority(&self) -> u8 {
        match self {
            TrafficType::RealTime => 255,
            TrafficType::Streaming => 200,
            TrafficType::WebBrowsing => 150,
            TrafficType::FileTransfer => 100,
            TrafficType::BackgroundSync => 50,
            TrafficType::Unknown => 75,
        }
    }
    
    /// Get default TTL for traffic type
    pub fn default_ttl(&self) -> Duration {
        match self {
            TrafficType::RealTime => Duration::from_secs(5),
            TrafficType::Streaming => Duration::from_secs(30),
            TrafficType::WebBrowsing => Duration::from_secs(300),
            TrafficType::FileTransfer => Duration::from_secs(600),
            TrafficType::BackgroundSync => Duration::from_secs(1800),
            TrafficType::Unknown => Duration::from_secs(60),
        }
    }
}

/// Expected access pattern for predictive caching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Sequential access (streaming)
    Sequential,
    /// Random access
    Random,
    /// Burst access (file download)
    Burst,
    /// Periodic access
    Periodic,
}

/// Cached traffic chunk
#[derive(Debug, Clone)]
pub struct CachedTrafficChunk {
    /// Chunk metadata
    pub meta: TrafficChunkMeta,
    /// Chunk data
    pub data: bytes::Bytes,
    /// Cache statistics
    pub stats: ChunkStats,
}

/// Chunk access statistics
#[derive(Debug, Clone)]
pub struct ChunkStats {
    /// Number of times accessed
    pub access_count: u64,
    /// Last access time
    pub last_access: Instant,
    /// First cached time
    pub cached_at: Instant,
    /// Number of times served to other peers
    pub serve_count: u64,
    /// Average access interval
    pub avg_access_interval: Duration,
    /// Popularity score (0.0 - 1.0)
    pub popularity: f64,
}

impl Default for ChunkStats {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            access_count: 0,
            last_access: now,
            cached_at: now,
            serve_count: 0,
            avg_access_interval: Duration::ZERO,
            popularity: 0.0,
        }
    }
}

impl ChunkStats {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Update access statistics
    pub fn record_access(&mut self) {
        let now = Instant::now();
        let interval = now.duration_since(self.last_access);
        
        self.access_count += 1;
        self.last_access = now;
        
        // Update average access interval with exponential moving average
        if self.access_count > 1 {
            let alpha = 0.3;
            let new_avg = self.avg_access_interval.as_millis() as f64 * (1.0 - alpha) +
                         interval.as_millis() as f64 * alpha;
            self.avg_access_interval = Duration::from_millis(new_avg as u64);
        } else {
            self.avg_access_interval = interval;
        }
        
        // Update popularity score
        self.update_popularity();
    }
    
    /// Record serving chunk to another peer
    pub fn record_serve(&mut self) {
        self.serve_count += 1;
        self.update_popularity();
    }
    
    /// Update popularity score based on access patterns
    fn update_popularity(&mut self) {
        let age = self.cached_at.elapsed().as_secs() as f64;
        let access_rate = self.access_count as f64 / age.max(1.0);
        let serve_rate = self.serve_count as f64 / age.max(1.0);
        
        // Combine access rate and serve rate with time decay
        let time_decay = (-age / 3600.0).exp(); // Decay over 1 hour
        self.popularity = ((access_rate + serve_rate * 2.0) * time_decay).min(1.0);
    }
    
    /// Check if chunk is stale based on TTL and access patterns
    pub fn is_stale(&self, ttl: Duration) -> bool {
        let age = self.cached_at.elapsed();
        let idle_time = self.last_access.elapsed();
        
        // Chunk is stale if:
        // 1. Exceeded TTL, or
        // 2. Not accessed for long time relative to its access pattern
        age > ttl || (idle_time > self.avg_access_interval * 5 && idle_time > Duration::from_secs(300))
    }
}

/// Cache eviction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvictionStrategy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// Hybrid: LRU + popularity + size
    Hybrid,
    /// Priority-based eviction
    Priority,
}

/// Advanced traffic chunk cache
pub struct TrafficChunkCache {
    /// Cached chunks
    chunks: HashMap<TrafficChunkId, CachedTrafficChunk>,
    /// Access order for LRU
    access_order: VecDeque<TrafficChunkId>,
    /// Current cache size in bytes
    current_size: usize,
    /// Maximum cache size in bytes
    max_size: usize,
    /// Eviction strategy
    eviction_strategy: EvictionStrategy,
    /// Cache statistics
    cache_stats: CacheStatistics,
    /// Predictive cache entries
    predicted_chunks: HashSet<TrafficChunkId>,
}

impl TrafficChunkCache {
    /// Create new traffic chunk cache
    pub fn new(max_size: usize, eviction_strategy: EvictionStrategy) -> Self {
        Self {
            chunks: HashMap::new(),
            access_order: VecDeque::new(),
            current_size: 0,
            max_size,
            eviction_strategy,
            cache_stats: CacheStatistics::default(),
            predicted_chunks: HashSet::new(),
        }
    }
    
    /// Add chunk to cache
    pub fn add_chunk(&mut self, chunk: CachedTrafficChunk) -> zMeshResult<()> {
        let chunk_size = chunk.data.len();
        
        // Check if chunk already exists
        if self.chunks.contains_key(&chunk.meta.id) {
            return Ok(()); // Already cached
        }
        
        // Ensure we have space
        while self.current_size + chunk_size > self.max_size && !self.chunks.is_empty() {
            self.evict_chunk();
        }
        
        if chunk_size > self.max_size {
            return Err(zMeshError::Config("Chunk too large for cache".to_string()));
        }
        
        // Add to cache
        let chunk_id = chunk.meta.id.clone();
        self.current_size += chunk_size;
        self.access_order.push_back(chunk_id.clone());
        self.chunks.insert(chunk_id.clone(), chunk);
        
        // Update statistics
        self.cache_stats.chunks_added += 1;
        self.cache_stats.total_size = self.current_size;
        
        // Remove from predicted if it was predicted
        self.predicted_chunks.remove(&chunk_id);
        
        Ok(())
    }
    
    /// Get chunk from cache
    pub fn get_chunk(&mut self, id: &TrafficChunkId) -> Option<&mut CachedTrafficChunk> {
        let chunk_exists = self.chunks.contains_key(id);
        
        if chunk_exists {
            // Update cache statistics first
            self.cache_stats.cache_hits += 1;
            self.update_hit_rate();
            
            // Update LRU order
            if let Some(pos) = self.access_order.iter().position(|x| x == id) {
                self.access_order.remove(pos);
                self.access_order.push_back(id.clone());
            }
            
            // Get mutable reference and update access statistics
            if let Some(chunk) = self.chunks.get_mut(id) {
                chunk.stats.record_access();
                Some(chunk)
            } else {
                None
            }
        } else {
            // Cache miss
            self.cache_stats.cache_misses += 1;
            self.update_hit_rate();
            None
        }
    }
    
    /// Record chunk being served to another peer
    pub fn record_serve(&mut self, id: &TrafficChunkId) {
        if let Some(chunk) = self.chunks.get_mut(id) {
            chunk.stats.record_serve();
            self.cache_stats.chunks_served += 1;
        }
    }
    
    /// Evict chunk based on strategy
    fn evict_chunk(&mut self) {
        let chunk_to_evict = match self.eviction_strategy {
            EvictionStrategy::LRU => self.find_lru_chunk(),
            EvictionStrategy::LFU => self.find_lfu_chunk(),
            EvictionStrategy::Hybrid => self.find_hybrid_chunk(),
            EvictionStrategy::Priority => self.find_priority_chunk(),
        };
        
        if let Some(chunk_id) = chunk_to_evict {
            self.remove_chunk(&chunk_id);
        }
    }
    
    /// Find LRU chunk for eviction
    fn find_lru_chunk(&self) -> Option<TrafficChunkId> {
        self.access_order.front().cloned()
    }
    
    /// Find LFU chunk for eviction
    fn find_lfu_chunk(&self) -> Option<TrafficChunkId> {
        self.chunks.iter()
            .min_by_key(|(_, chunk)| chunk.stats.access_count)
            .map(|(id, _)| id.clone())
    }
    
    /// Find chunk for hybrid eviction (combines multiple factors)
    fn find_hybrid_chunk(&self) -> Option<TrafficChunkId> {
        self.chunks.iter()
            .min_by(|(_, a), (_, b)| {
                let score_a = self.calculate_eviction_score(a);
                let score_b = self.calculate_eviction_score(b);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id.clone())
    }
    
    /// Find chunk for priority-based eviction
    fn find_priority_chunk(&self) -> Option<TrafficChunkId> {
        self.chunks.iter()
            .min_by_key(|(_, chunk)| chunk.meta.priority)
            .map(|(id, _)| id.clone())
    }
    
    /// Calculate eviction score for hybrid strategy (lower = more likely to evict)
    fn calculate_eviction_score(&self, chunk: &CachedTrafficChunk) -> f64 {
        let age_factor = chunk.stats.cached_at.elapsed().as_secs() as f64 / 3600.0; // Hours
        let access_factor = 1.0 / (chunk.stats.access_count as f64 + 1.0);
        let size_factor = chunk.data.len() as f64 / (1024.0 * 1024.0); // MB
        let priority_factor = (255 - chunk.meta.priority) as f64 / 255.0;
        let popularity_factor = 1.0 - chunk.stats.popularity;
        
        // Weighted combination
        age_factor * 0.2 + access_factor * 0.3 + size_factor * 0.1 + 
        priority_factor * 0.2 + popularity_factor * 0.2
    }
    
    /// Remove chunk from cache
    pub fn remove_chunk(&mut self, id: &TrafficChunkId) -> Option<CachedTrafficChunk> {
        if let Some(chunk) = self.chunks.remove(id) {
            self.current_size -= chunk.data.len();
            
            // Remove from access order
            if let Some(pos) = self.access_order.iter().position(|x| x == id) {
                self.access_order.remove(pos);
            }
            
            // Update statistics
            self.cache_stats.chunks_evicted += 1;
            self.cache_stats.total_size = self.current_size;
            
            Some(chunk)
        } else {
            None
        }
    }
    
    /// Clean up stale chunks
    pub fn cleanup_stale(&mut self) {
        let stale_ids: Vec<_> = self.chunks.iter()
            .filter(|(_, chunk)| chunk.stats.is_stale(chunk.meta.ttl))
            .map(|(id, _)| id.clone())
            .collect();
        
        for id in stale_ids {
            self.remove_chunk(&id);
        }
    }
    
    /// Predict next chunks for proactive caching
    pub fn predict_next_chunks(&mut self, flow_id: u64, current_sequence: u32) -> Vec<TrafficChunkId> {
        let mut predictions = Vec::new();
        
        // For sequential access patterns, predict next few chunks
        for i in 1..=3 {
            let predicted_id = TrafficChunkId {
                flow_id,
                sequence: current_sequence + i,
                hash: [0; 32], // Will be updated when actual chunk arrives
            };
            predictions.push(predicted_id.clone());
            self.predicted_chunks.insert(predicted_id);
        }
        
        predictions
    }
    
    /// Check if chunk is predicted
    pub fn is_predicted(&self, id: &TrafficChunkId) -> bool {
        self.predicted_chunks.contains(id)
    }
    
    /// Update cache hit rate
    fn update_hit_rate(&mut self) {
        let total_requests = self.cache_stats.cache_hits + self.cache_stats.cache_misses;
        if total_requests > 0 {
            self.cache_stats.hit_rate = self.cache_stats.cache_hits as f64 / total_requests as f64;
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> &CacheStatistics {
        &self.cache_stats
    }
    
    /// Get cache utilization (0.0 - 1.0)
    pub fn utilization(&self) -> f64 {
        self.current_size as f64 / self.max_size as f64
    }
    
    /// Get number of cached chunks
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
    
    /// Check if chunk exists in cache
    pub fn contains_chunk(&self, id: &TrafficChunkId) -> bool {
        self.chunks.contains_key(id)
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStatistics {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub hit_rate: f64,
    pub chunks_added: u64,
    pub chunks_evicted: u64,
    pub chunks_served: u64,
    pub total_size: usize,
}

/// Distributed chunk location service
pub struct ChunkLocationService {
    /// Known chunk locations (chunk_id -> set of peer_ids)
    chunk_locations: HashMap<TrafficChunkId, HashSet<PeerId>>,
    /// Peer chunk inventories (peer_id -> set of chunk_ids)
    peer_inventories: HashMap<PeerId, HashSet<TrafficChunkId>>,
    /// Location update timestamps
    location_updates: HashMap<TrafficChunkId, Instant>,
}

impl ChunkLocationService {
    pub fn new() -> Self {
        Self {
            chunk_locations: HashMap::new(),
            peer_inventories: HashMap::new(),
            location_updates: HashMap::new(),
        }
    }
    
    /// Register chunk location
    pub fn register_chunk(&mut self, chunk_id: TrafficChunkId, peer_id: PeerId) {
        self.chunk_locations.entry(chunk_id.clone())
            .or_insert_with(HashSet::new)
            .insert(peer_id.clone());
        
        self.peer_inventories.entry(peer_id)
            .or_insert_with(HashSet::new)
            .insert(chunk_id.clone());
        
        self.location_updates.insert(chunk_id, Instant::now());
    }
    
    /// Find peers that have a specific chunk
    pub fn find_chunk_peers(&self, chunk_id: &TrafficChunkId) -> Vec<PeerId> {
        self.chunk_locations.get(chunk_id)
            .map(|peers| peers.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Get chunks available from a specific peer
    pub fn get_peer_chunks(&self, peer_id: &PeerId) -> Vec<TrafficChunkId> {
        self.peer_inventories.get(peer_id)
            .map(|chunks| chunks.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Remove chunk location
    pub fn remove_chunk_location(&mut self, chunk_id: &TrafficChunkId, peer_id: &PeerId) {
        if let Some(peers) = self.chunk_locations.get_mut(chunk_id) {
            peers.remove(peer_id);
            if peers.is_empty() {
                self.chunk_locations.remove(chunk_id);
                self.location_updates.remove(chunk_id);
            }
        }
        
        if let Some(chunks) = self.peer_inventories.get_mut(peer_id) {
            chunks.remove(chunk_id);
        }
    }
    
    /// Clean up stale location information
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let stale_chunks: Vec<_> = self.location_updates.iter()
            .filter(|(_, &timestamp)| timestamp.elapsed() > max_age)
            .map(|(chunk_id, _)| chunk_id.clone())
            .collect();
        
        for chunk_id in stale_chunks {
            self.chunk_locations.remove(&chunk_id);
            self.location_updates.remove(&chunk_id);
        }
    }
}

/// Proactive seeding manager
pub struct ProactiveSeedingManager {
    /// Cache reference
    cache: Arc<RwLock<TrafficChunkCache>>,
    /// Location service
    location_service: Arc<RwLock<ChunkLocationService>>,
    /// Seeding strategies
    strategies: Vec<SeedingStrategy>,
}

/// Seeding strategy
#[derive(Debug, Clone)]
pub enum SeedingStrategy {
    /// Seed popular chunks to strategic locations
    PopularityBased { threshold: f64 },
    /// Seed chunks along predicted paths
    PathBased { lookahead: usize },
    /// Seed chunks based on geographic distribution
    GeographicBased { target_regions: Vec<String> },
    /// Seed chunks based on traffic patterns
    PatternBased { pattern_window: Duration },
}

impl ProactiveSeedingManager {
    pub fn new(
        cache: Arc<RwLock<TrafficChunkCache>>,
        location_service: Arc<RwLock<ChunkLocationService>>,
    ) -> Self {
        Self {
            cache,
            location_service,
            strategies: vec![
                SeedingStrategy::PopularityBased { threshold: 0.7 },
                SeedingStrategy::PathBased { lookahead: 3 },
            ],
        }
    }
    
    /// Execute proactive seeding
    pub async fn execute_seeding(&self) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        let mut seeding_tasks = Vec::new();
        
        for strategy in &self.strategies {
            let tasks = self.execute_strategy(strategy).await?;
            seeding_tasks.extend(tasks);
        }
        
        Ok(seeding_tasks)
    }
    
    /// Execute specific seeding strategy
    async fn execute_strategy(
        &self,
        strategy: &SeedingStrategy,
    ) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        match strategy {
            SeedingStrategy::PopularityBased { threshold } => {
                self.seed_popular_chunks(*threshold).await
            }
            SeedingStrategy::PathBased { lookahead } => {
                self.seed_path_chunks(*lookahead).await
            }
            SeedingStrategy::GeographicBased { target_regions } => {
                self.seed_geographic_chunks(target_regions).await
            }
            SeedingStrategy::PatternBased { pattern_window } => {
                self.seed_pattern_chunks(*pattern_window).await
            }
        }
    }
    
    /// Seed popular chunks to strategic locations
    async fn seed_popular_chunks(
        &self,
        threshold: f64,
    ) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        // Implementation would identify popular chunks and strategic peers
        // This is a simplified version
        Ok(Vec::new())
    }
    
    /// Seed chunks along predicted paths
    async fn seed_path_chunks(
        &self,
        _lookahead: usize,
    ) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        // Implementation would predict traffic paths and pre-position chunks
        Ok(Vec::new())
    }
    
    /// Seed chunks based on geographic distribution
    async fn seed_geographic_chunks(
        &self,
        _target_regions: &[String],
    ) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        // Implementation would distribute chunks geographically
        Ok(Vec::new())
    }
    
    /// Seed chunks based on traffic patterns
    async fn seed_pattern_chunks(
        &self,
        _pattern_window: Duration,
    ) -> zMeshResult<Vec<(TrafficChunkId, Vec<PeerId>)>> {
        // Implementation would analyze traffic patterns and pre-cache
        Ok(Vec::new())
    }
}