//! Integration layer for enhanced mesh networking with traffic caching and multi-path distribution
//!
//! This module provides the integration between the existing mesh system and the new
//! traffic caching and multi-path distribution capabilities.

use crate::{
    mesh::{PathManager, MeshConfig},
    traffic_cache::{TrafficChunkCache, ChunkLocationService, ProactiveSeedingManager},
    multipath_distribution::{MultiPathDistributor, DistributionStrategy},
    peer::PeerId,
    error::zmeshResult,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Enhanced mesh node that integrates traffic caching and multi-path distribution
pub struct EnhancedMeshNode {
    /// Node identifier
    pub node_id: PeerId,
    
    /// Original mesh configuration
    pub config: MeshConfig,
    
    /// Path manager for network paths
    pub path_manager: Arc<RwLock<PathManager>>,
    
    /// Enhanced traffic cache system
    pub traffic_cache: Arc<RwLock<TrafficChunkCache>>,
    
    /// Multi-path distributor
    pub distributor: Arc<RwLock<MultiPathDistributor>>,
    
    /// Chunk location service for distributed caching
    pub location_service: Arc<RwLock<ChunkLocationService>>,
    
    /// Proactive seeding manager
    pub seeding_manager: Arc<RwLock<ProactiveSeedingManager>>,
    
    /// Performance metrics
    pub metrics: Arc<RwLock<MeshMetrics>>,
    
    /// Background task handles
    task_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Performance metrics for the enhanced mesh system
#[derive(Debug, Clone)]
pub struct MeshMetrics {
    /// Total packets processed
    pub packets_processed: u64,
    
    /// Cache hit rate
    pub cache_hit_rate: f64,
    
    /// Average path latency
    pub avg_path_latency: Duration,
    
    /// Multi-path efficiency
    pub multipath_efficiency: f64,
    
    /// Successful chunk deliveries
    pub successful_deliveries: u64,
    
    /// Failed chunk deliveries
    pub failed_deliveries: u64,
    
    /// Bandwidth utilization per path
    pub path_bandwidth_usage: HashMap<String, f64>,
    
    /// Last updated timestamp
    pub last_updated: Instant,
}

impl Default for MeshMetrics {
    fn default() -> Self {
        Self {
            packets_processed: 0,
            cache_hit_rate: 0.0,
            avg_path_latency: Duration::ZERO,
            multipath_efficiency: 0.0,
            successful_deliveries: 0,
            failed_deliveries: 0,
            path_bandwidth_usage: HashMap::new(),
            last_updated: Instant::now(),
        }
    }
}

/// Configuration for the enhanced mesh system
#[derive(Debug, Clone)]
pub struct EnhancedMeshConfig {
    /// Base mesh configuration
    pub mesh_config: MeshConfig,
    
    /// Traffic cache size in bytes
    pub cache_size: usize,
    
    /// Maximum number of paths for multi-path distribution
    pub max_paths: usize,
    
    /// Default distribution strategy
    pub distribution_strategy: DistributionStrategy,
    
    /// Enable proactive seeding
    pub enable_proactive_seeding: bool,
    
    /// Seeding strategy configuration
    pub seeding_interval: Duration,
    
    /// Path quality thresholds
    pub min_path_reliability: f64,
    pub max_path_latency: Duration,
    
    /// Cache warming configuration
    pub cache_warming_enabled: bool,
    pub cache_warming_threshold: f64,
}

impl Default for EnhancedMeshConfig {
    fn default() -> Self {
        Self {
            mesh_config: MeshConfig::default(),
            cache_size: 100 * 1024 * 1024, // 100MB
            max_paths: 4,
            distribution_strategy: DistributionStrategy::Adaptive,
            enable_proactive_seeding: true,
            seeding_interval: Duration::from_secs(30),
            min_path_reliability: 0.95,
            max_path_latency: Duration::from_millis(200),
            cache_warming_enabled: true,
            cache_warming_threshold: 0.8,
        }
    }
}

impl EnhancedMeshNode {
    /// Create a new enhanced mesh node
    pub fn new(node_id: PeerId, config: EnhancedMeshConfig) -> Self {
        let traffic_cache = Arc::new(RwLock::new(
            TrafficChunkCache::new(config.cache_size, crate::traffic_cache::EvictionStrategy::LRU)
        ));
        
        let distributor = Arc::new(RwLock::new(
            MultiPathDistributor::new(config.distribution_strategy.clone())
        ));
        
        let location_service = Arc::new(RwLock::new(
            ChunkLocationService::new()
        ));
        
        let seeding_manager = Arc::new(RwLock::new(
            ProactiveSeedingManager::new(
                Arc::clone(&traffic_cache),
                Arc::clone(&location_service)
            )
        ));
        
        let peer_registry = crate::peer::PeerRegistry::new();
        let path_manager = Arc::new(RwLock::new(
            PathManager::new(config.mesh_config.clone(), peer_registry)
        ));
        
        Self {
            node_id,
            config: config.mesh_config,
            path_manager,
            traffic_cache,
            distributor,
            location_service,
            seeding_manager,
            metrics: Arc::new(RwLock::new(MeshMetrics::default())),
            task_handles: Vec::new(),
        }
    }
    
    /// Start the enhanced mesh node
    pub async fn start(&mut self) -> zmeshResult<()> {
        // Start background tasks
        self.start_cache_maintenance().await;
        self.start_path_monitoring().await;
        self.start_proactive_seeding().await;
        self.start_metrics_collection().await;
        
        Ok(())
    }
    
    /// Stop the enhanced mesh node
    pub async fn stop(&mut self) {
        // Cancel all background tasks
        for handle in self.task_handles.drain(..) {
            handle.abort();
        }
    }
    
    /// Process incoming traffic chunk
    pub async fn process_chunk(&self, chunk_data: Vec<u8>, flow_id: u64, sequence: u32) -> zmeshResult<()> {
        // Update metrics
        {
            let cache = self.traffic_cache.read().await;
            let mut metrics = self.metrics.write().await;
            metrics.packets_processed += 1;
        }
        
        // Check cache first
        let chunk_id = crate::traffic_cache::TrafficChunkId::new(flow_id, sequence, &chunk_data);
        
        {
            let cache = self.traffic_cache.read().await;
            if cache.contains_chunk(&chunk_id) {
                // Cache hit - update metrics
                let mut metrics = self.metrics.write().await;
                let total_requests = metrics.packets_processed;
                let cache_hits = (metrics.cache_hit_rate * (total_requests - 1) as f64) + 1.0;
                metrics.cache_hit_rate = cache_hits / total_requests as f64;
                return Ok(());
            }
        }
        
        // Cache miss - distribute via multi-path
        // Get available paths from path manager
        let paths = {
            let pm = self.path_manager.read().await;
            pm.stats().active_paths
        };
        
        if paths > 0 {
            let mut distributor = self.distributor.write().await;
            let chunk_meta = crate::traffic_cache::TrafficChunkMeta {
                id: chunk_id.clone(),
                size: chunk_data.len(),
                priority: 128,
                traffic_type: crate::traffic_cache::TrafficType::WebBrowsing,
                access_pattern: crate::traffic_cache::AccessPattern::Sequential,
                ttl: std::time::Duration::from_secs(3600),
                created_at: std::time::SystemTime::now(),
            };
            distributor.distribute_chunk(chunk_id.clone(), &chunk_meta, &chunk_data).await?;
            
            // Cache the chunk
            let mut cache = self.traffic_cache.write().await;
            let chunk_meta = crate::traffic_cache::TrafficChunkMeta {
                id: chunk_id.clone(),
                size: chunk_data.len(),
                priority: 128,
                traffic_type: crate::traffic_cache::TrafficType::WebBrowsing,
                access_pattern: crate::traffic_cache::AccessPattern::Sequential,
                ttl: std::time::Duration::from_secs(3600),
                created_at: std::time::SystemTime::now(),
            };
            let cached_chunk = crate::traffic_cache::CachedTrafficChunk {
                meta: chunk_meta,
                data: bytes::Bytes::from(chunk_data),
                stats: crate::traffic_cache::ChunkStats::default(),
            };
            let _ = cache.add_chunk(cached_chunk);
        }
        
        Ok(())
    }
    
    /// Get current performance metrics
    pub async fn get_metrics(&self) -> MeshMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Start cache maintenance background task
    async fn start_cache_maintenance(&mut self) {
        let cache = Arc::clone(&self.traffic_cache);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean expired chunks
                {
                    let mut cache_guard = cache.write().await;
                    cache_guard.cleanup_stale();
                }
            }
        });
        
        self.task_handles.push(handle);
    }
    
    /// Start path monitoring background task
    async fn start_path_monitoring(&mut self) {
        let path_manager = Arc::clone(&self.path_manager);
        let metrics = Arc::clone(&self.metrics);
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Update path quality metrics
                let path_stats = {
                    let pm = path_manager.read().await;
                    pm.stats()
                };
                
                // Update metrics with path statistics
                {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.avg_path_latency = path_stats.avg_latency;
                    metrics_guard.last_updated = Instant::now();
                }
            }
        });
        
        self.task_handles.push(handle);
    }
    
    /// Start proactive seeding background task
    async fn start_proactive_seeding(&mut self) {
        let seeding_manager = Arc::clone(&self.seeding_manager);
        let cache = Arc::clone(&self.traffic_cache);
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Perform proactive seeding
                {
                    let seeding_guard = seeding_manager.read().await;
                    let _ = seeding_guard.execute_seeding().await;
                }
            }
        });
        
        self.task_handles.push(handle);
    }
    
    /// Start metrics collection background task
    async fn start_metrics_collection(&mut self) {
        let distributor = Arc::clone(&self.distributor);
        let metrics = Arc::clone(&self.metrics);
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Collect distribution metrics
                let dist_stats = {
                    let dist_guard = distributor.read().await;
                    dist_guard.get_distribution_stats()
                };
                
                // Update metrics
                {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.successful_deliveries = dist_stats.successful_chunks as u64;
                    metrics_guard.failed_deliveries = (dist_stats.total_chunks - dist_stats.successful_chunks) as u64;
                    
                    if dist_stats.total_chunks > 0 {
                        metrics_guard.multipath_efficiency = dist_stats.success_rate;
                    }
                }
            }
        });
        
        self.task_handles.push(handle);
    }
}

/// Builder for creating enhanced mesh nodes with custom configuration
pub struct EnhancedMeshBuilder {
    config: EnhancedMeshConfig,
}

impl EnhancedMeshBuilder {
    pub fn new() -> Self {
        Self {
            config: EnhancedMeshConfig::default(),
        }
    }
    
    pub fn cache_size(mut self, size: usize) -> Self {
        self.config.cache_size = size;
        self
    }
    
    pub fn max_paths(mut self, max_paths: usize) -> Self {
        self.config.max_paths = max_paths;
        self
    }
    
    pub fn distribution_strategy(mut self, strategy: DistributionStrategy) -> Self {
        self.config.distribution_strategy = strategy;
        self
    }
    
    pub fn enable_proactive_seeding(mut self, enabled: bool) -> Self {
        self.config.enable_proactive_seeding = enabled;
        self
    }
    
    pub fn build(self, node_id: PeerId) -> EnhancedMeshNode {
        EnhancedMeshNode::new(node_id, self.config)
    }
}

impl Default for EnhancedMeshBuilder {
    fn default() -> Self {
        Self::new()
    }
}