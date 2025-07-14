//! Multi-path chunk distribution system
//! Implements intelligent distribution of traffic chunks across multiple network paths

use crate::traffic_cache::{TrafficChunkId, TrafficChunkMeta, TrafficType};
use crate::{zMeshError, zMeshResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Path quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathQuality {
    /// Path identifier
    pub path_id: u64,
    /// Current latency
    pub latency: Duration,
    /// Bandwidth estimate (bytes/sec)
    pub bandwidth: u64,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Jitter (latency variation)
    pub jitter: Duration,
    /// Path reliability score (0.0 - 1.0)
    pub reliability: f64,
    /// Current congestion level (0.0 - 1.0)
    pub congestion: f64,
    /// Last measurement time
    #[serde(skip, default = "Instant::now")]
    pub last_measured: Instant,
}

impl PathQuality {
    pub fn new(path_id: u64) -> Self {
        Self {
            path_id,
            latency: Duration::from_millis(100),
            bandwidth: 1024 * 1024, // 1 MB/s default
            loss_rate: 0.0,
            jitter: Duration::from_millis(10),
            reliability: 1.0,
            congestion: 0.0,
            last_measured: Instant::now(),
        }
    }
    
    /// Calculate overall path score (higher is better)
    pub fn score(&self) -> f64 {
        let latency_score = 1000.0 / (self.latency.as_millis() as f64 + 1.0);
        let bandwidth_score = (self.bandwidth as f64) / (1024.0 * 1024.0); // Normalize to MB/s
        let loss_score = 1.0 - self.loss_rate;
        let jitter_score = 100.0 / (self.jitter.as_millis() as f64 + 1.0);
        let congestion_score = 1.0 - self.congestion;
        
        // Weighted combination
        latency_score * 0.25 + bandwidth_score * 0.25 + loss_score * 0.2 + 
        jitter_score * 0.15 + self.reliability * 0.1 + congestion_score * 0.05
    }
    
    /// Check if path quality is acceptable
    pub fn is_acceptable(&self) -> bool {
        self.latency < Duration::from_millis(2000) &&
        self.loss_rate < 0.1 &&
        self.reliability > 0.5
    }
    
    /// Update path quality metrics
    pub fn update(&mut self, latency: Duration, success: bool, bytes_sent: u64, duration: Duration) {
        let alpha = 0.3; // Exponential moving average factor
        
        // Update latency
        let new_latency_ms = self.latency.as_millis() as f64 * (1.0 - alpha) + 
                            latency.as_millis() as f64 * alpha;
        self.latency = Duration::from_millis(new_latency_ms as u64);
        
        // Update bandwidth
        if duration > Duration::ZERO {
            let current_bandwidth = (bytes_sent as f64) / duration.as_secs_f64();
            self.bandwidth = (self.bandwidth as f64 * (1.0 - alpha) + current_bandwidth * alpha) as u64;
        }
        
        // Update reliability
        if success {
            self.reliability = self.reliability * (1.0 - alpha) + alpha;
        } else {
            self.reliability = self.reliability * (1.0 - alpha);
            self.loss_rate = self.loss_rate * (1.0 - alpha) + alpha;
        }
        
        self.reliability = self.reliability.clamp(0.0, 1.0);
        self.loss_rate = self.loss_rate.clamp(0.0, 1.0);
        self.last_measured = Instant::now();
    }
}

/// Chunk distribution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionStrategy {
    /// Send all chunks on best path
    SinglePath,
    /// Distribute chunks across multiple paths
    MultiPath,
    /// Duplicate critical chunks on multiple paths
    Redundant,
    /// Adaptive based on traffic type and conditions
    Adaptive,
}

/// Chunk transmission record
#[derive(Debug, Clone)]
pub struct ChunkTransmission {
    /// Chunk identifier
    pub chunk_id: TrafficChunkId,
    /// Path used for transmission
    pub path_id: u64,
    /// Transmission start time
    pub start_time: Instant,
    /// Transmission completion time (if completed)
    pub completion_time: Option<Instant>,
    /// Number of bytes transmitted
    pub bytes_transmitted: u64,
    /// Transmission success
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Multi-path distribution manager
pub struct MultiPathDistributor {
    /// Available paths and their quality metrics
    paths: HashMap<u64, PathQuality>,
    /// Distribution strategy
    strategy: DistributionStrategy,
    /// Active transmissions
    active_transmissions: HashMap<TrafficChunkId, Vec<ChunkTransmission>>,
    /// Transmission history for learning
    transmission_history: VecDeque<ChunkTransmission>,
    /// Maximum history size
    max_history: usize,
    /// Path selection weights
    path_weights: HashMap<u64, f64>,
    /// Congestion control state
    congestion_control: CongestionControl,
}

impl MultiPathDistributor {
    pub fn new(strategy: DistributionStrategy) -> Self {
        Self {
            paths: HashMap::new(),
            strategy,
            active_transmissions: HashMap::new(),
            transmission_history: VecDeque::new(),
            max_history: 1000,
            path_weights: HashMap::new(),
            congestion_control: CongestionControl::new(),
        }
    }
    
    /// Add or update path quality
    pub fn update_path(&mut self, path_quality: PathQuality) {
        let path_id = path_quality.path_id;
        self.paths.insert(path_id, path_quality);
        
        // Initialize weight if new path
        if !self.path_weights.contains_key(&path_id) {
            self.path_weights.insert(path_id, 1.0);
        }
    }
    
    /// Remove path
    pub fn remove_path(&mut self, path_id: u64) {
        self.paths.remove(&path_id);
        self.path_weights.remove(&path_id);
    }
    
    /// Distribute chunk across selected paths
    pub async fn distribute_chunk(
        &mut self,
        chunk_id: TrafficChunkId,
        chunk_meta: &TrafficChunkMeta,
        chunk_data: &[u8],
    ) -> zMeshResult<Vec<u64>> {
        let selected_paths = self.select_paths_for_chunk(chunk_meta)?;
        
        if selected_paths.is_empty() {
            return Err(zMeshError::PathNotAvailable);
        }
        
        let mut transmissions = Vec::new();
        
        for path_id in &selected_paths {
            let transmission = ChunkTransmission {
                chunk_id: chunk_id.clone(),
                path_id: *path_id,
                start_time: Instant::now(),
                completion_time: None,
                bytes_transmitted: chunk_data.len() as u64,
                success: false,
                error: None,
            };
            
            transmissions.push(transmission);
        }
        
        self.active_transmissions.insert(chunk_id, transmissions);
        
        // Update congestion control
        self.congestion_control.on_chunk_sent(chunk_data.len());
        
        Ok(selected_paths)
    }
    
    /// Select paths for chunk distribution
    fn select_paths_for_chunk(&mut self, chunk_meta: &TrafficChunkMeta) -> zMeshResult<Vec<u64>> {
        let available_paths: Vec<_> = self.paths.iter()
            .filter(|(_, quality)| quality.is_acceptable())
            .collect();
        
        if available_paths.is_empty() {
            return Err(zMeshError::PathNotAvailable);
        }
        
        match self.strategy {
            DistributionStrategy::SinglePath => {
                self.select_single_path(&available_paths)
            }
            DistributionStrategy::MultiPath => {
                self.select_multiple_paths(&available_paths, chunk_meta)
            }
            DistributionStrategy::Redundant => {
                self.select_redundant_paths(&available_paths, chunk_meta)
            }
            DistributionStrategy::Adaptive => {
                self.select_adaptive_paths(&available_paths, chunk_meta)
            }
        }
    }
    
    /// Select single best path
    fn select_single_path(&self, available_paths: &[(&u64, &PathQuality)]) -> zMeshResult<Vec<u64>> {
        let best_path = available_paths.iter()
            .max_by(|(_, a), (_, b)| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, _)| **id)
            .ok_or(zMeshError::PathNotAvailable)?;
        
        Ok(vec![best_path])
    }
    
    /// Select multiple paths for load balancing
    fn select_multiple_paths(
        &self,
        available_paths: &[(&u64, &PathQuality)],
        chunk_meta: &TrafficChunkMeta,
    ) -> zMeshResult<Vec<u64>> {
        let num_paths = match chunk_meta.traffic_type {
            TrafficType::RealTime => 1, // Low latency, single path
            TrafficType::Streaming => 2, // Moderate redundancy
            TrafficType::FileTransfer => 3, // High throughput
            TrafficType::WebBrowsing => 2,
            TrafficType::BackgroundSync => 1,
            TrafficType::Unknown => 1,
        }.min(available_paths.len());
        
        let mut selected_paths: Vec<_> = available_paths.iter()
            .map(|(id, quality)| (**id, quality.score()))
            .collect();
        
        // Sort by score (descending)
        selected_paths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(selected_paths.into_iter().take(num_paths).map(|(id, _)| id).collect())
    }
    
    /// Select paths with redundancy for critical chunks
    fn select_redundant_paths(
        &self,
        available_paths: &[(&u64, &PathQuality)],
        chunk_meta: &TrafficChunkMeta,
    ) -> zMeshResult<Vec<u64>> {
        let redundancy_level = match chunk_meta.priority {
            200..=255 => 3, // High priority
            100..=199 => 2, // Medium priority
            _ => 1,         // Low priority
        }.min(available_paths.len());
        
        let mut selected_paths: Vec<_> = available_paths.iter()
            .map(|(id, quality)| (**id, quality.score()))
            .collect();
        
        // Sort by score (descending)
        selected_paths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(selected_paths.into_iter().take(redundancy_level).map(|(id, _)| id).collect())
    }
    
    /// Adaptive path selection based on current conditions
    fn select_adaptive_paths(
        &self,
        available_paths: &[(&u64, &PathQuality)],
        chunk_meta: &TrafficChunkMeta,
    ) -> zMeshResult<Vec<u64>> {
        // Analyze current network conditions
        let avg_congestion: f64 = available_paths.iter()
            .map(|(_, quality)| quality.congestion)
            .sum::<f64>() / available_paths.len() as f64;
        
        let avg_loss_rate: f64 = available_paths.iter()
            .map(|(_, quality)| quality.loss_rate)
            .sum::<f64>() / available_paths.len() as f64;
        
        // Decide strategy based on conditions and traffic type
        if avg_congestion > 0.7 || avg_loss_rate > 0.05 {
            // High congestion/loss: use redundancy
            self.select_redundant_paths(available_paths, chunk_meta)
        } else if chunk_meta.traffic_type == TrafficType::RealTime {
            // Real-time traffic: single best path
            self.select_single_path(available_paths)
        } else {
            // Normal conditions: multi-path
            self.select_multiple_paths(available_paths, chunk_meta)
        }
    }
    
    /// Record transmission completion
    pub fn record_transmission_complete(
        &mut self,
        chunk_id: &TrafficChunkId,
        path_id: u64,
        success: bool,
        error: Option<String>,
    ) {
        if let Some(transmissions) = self.active_transmissions.get_mut(chunk_id) {
            if let Some(transmission) = transmissions.iter_mut().find(|t| t.path_id == path_id) {
                transmission.completion_time = Some(Instant::now());
                transmission.success = success;
                transmission.error = error;
                
                // Update path quality
                if let Some(path_quality) = self.paths.get_mut(&path_id) {
                    let duration = transmission.completion_time.unwrap()
                        .duration_since(transmission.start_time);
                    path_quality.update(
                        duration,
                        success,
                        transmission.bytes_transmitted,
                        duration,
                    );
                }
                
                // Move to history if all transmissions complete
                if transmissions.iter().all(|t| t.completion_time.is_some()) {
                    let completed_transmissions = self.active_transmissions.remove(chunk_id).unwrap();
                    for transmission in completed_transmissions {
                        self.add_to_history(transmission);
                    }
                }
            }
        }
        
        // Update congestion control
        if success {
            self.congestion_control.on_ack_received();
        } else {
            self.congestion_control.on_loss_detected();
        }
    }
    
    /// Add transmission to history
    fn add_to_history(&mut self, transmission: ChunkTransmission) {
        self.transmission_history.push_back(transmission);
        
        // Limit history size
        while self.transmission_history.len() > self.max_history {
            self.transmission_history.pop_front();
        }
    }
    
    /// Get path statistics
    pub fn get_path_stats(&self, path_id: u64) -> Option<PathStats> {
        let path_quality = self.paths.get(&path_id)?;
        
        let transmissions: Vec<_> = self.transmission_history.iter()
            .filter(|t| t.path_id == path_id)
            .collect();
        
        let total_transmissions = transmissions.len();
        let successful_transmissions = transmissions.iter().filter(|t| t.success).count();
        let total_bytes: u64 = transmissions.iter().map(|t| t.bytes_transmitted).sum();
        
        let avg_duration = if !transmissions.is_empty() {
            let total_duration: Duration = transmissions.iter()
                .filter_map(|t| t.completion_time.map(|ct| ct.duration_since(t.start_time)))
                .sum();
            total_duration / transmissions.len() as u32
        } else {
            Duration::ZERO
        };
        
        Some(PathStats {
            path_id,
            quality: path_quality.clone(),
            total_transmissions,
            successful_transmissions,
            success_rate: if total_transmissions > 0 {
                successful_transmissions as f64 / total_transmissions as f64
            } else {
                0.0
            },
            total_bytes,
            avg_duration,
        })
    }
    
    /// Get overall distribution statistics
    pub fn get_distribution_stats(&self) -> DistributionStats {
        let total_chunks = self.transmission_history.len() + self.active_transmissions.len();
        let completed_chunks = self.transmission_history.len();
        let successful_chunks = self.transmission_history.iter().filter(|t| t.success).count();
        
        let total_bytes: u64 = self.transmission_history.iter()
            .map(|t| t.bytes_transmitted)
            .sum();
        
        let avg_paths_per_chunk = if completed_chunks > 0 {
            // Count unique chunks in history
            let unique_chunks: HashSet<_> = self.transmission_history.iter()
                .map(|t| &t.chunk_id)
                .collect();
            self.transmission_history.len() as f64 / unique_chunks.len() as f64
        } else {
            0.0
        };
        
        DistributionStats {
            total_chunks,
            completed_chunks,
            successful_chunks,
            success_rate: if completed_chunks > 0 {
                successful_chunks as f64 / completed_chunks as f64
            } else {
                0.0
            },
            total_bytes,
            avg_paths_per_chunk,
            active_paths: self.paths.len(),
        }
    }
    
    /// Update path weights based on performance
    pub fn update_path_weights(&mut self) {
        for (path_id, quality) in &self.paths {
            let weight = quality.score() * (1.0 - quality.congestion);
            self.path_weights.insert(*path_id, weight);
        }
    }
    
    /// Get recommended chunk size for path
    pub fn get_recommended_chunk_size(&self, path_id: u64) -> Option<usize> {
        let quality = self.paths.get(&path_id)?;
        
        // Adjust chunk size based on path characteristics
        let base_size = 64 * 1024; // 64KB base
        let bandwidth_factor = (quality.bandwidth as f64 / (1024.0 * 1024.0)).min(10.0); // Max 10x
        let loss_factor = 1.0 - quality.loss_rate;
        let congestion_factor = 1.0 - quality.congestion;
        
        let adjusted_size = base_size as f64 * bandwidth_factor * loss_factor * congestion_factor;
        Some(adjusted_size.max(4096.0).min(1024.0 * 1024.0) as usize) // 4KB - 1MB range
    }
}

/// Congestion control state
#[derive(Debug, Clone)]
struct CongestionControl {
    /// Current window size
    window_size: usize,
    /// Slow start threshold
    ssthresh: usize,
    /// Congestion state
    state: CongestionState,
    /// Outstanding bytes
    outstanding_bytes: usize,
    /// Last congestion event
    last_congestion: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
}

impl CongestionControl {
    fn new() -> Self {
        Self {
            window_size: 64 * 1024, // 64KB initial window
            ssthresh: 512 * 1024,   // 512KB threshold
            state: CongestionState::SlowStart,
            outstanding_bytes: 0,
            last_congestion: None,
        }
    }
    
    fn on_chunk_sent(&mut self, bytes: usize) {
        self.outstanding_bytes += bytes;
    }
    
    fn on_ack_received(&mut self) {
        match self.state {
            CongestionState::SlowStart => {
                self.window_size += 1024; // Exponential growth
                if self.window_size >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                self.window_size += 1024 / (self.window_size / 1024); // Linear growth
            }
            CongestionState::FastRecovery => {
                self.state = CongestionState::CongestionAvoidance;
            }
        }
    }
    
    fn on_loss_detected(&mut self) {
        self.ssthresh = self.window_size / 2;
        self.window_size = self.ssthresh;
        self.state = CongestionState::FastRecovery;
        self.last_congestion = Some(Instant::now());
    }
}

/// Path statistics
#[derive(Debug, Clone)]
pub struct PathStats {
    pub path_id: u64,
    pub quality: PathQuality,
    pub total_transmissions: usize,
    pub successful_transmissions: usize,
    pub success_rate: f64,
    pub total_bytes: u64,
    pub avg_duration: Duration,
}

/// Distribution statistics
#[derive(Debug, Clone)]
pub struct DistributionStats {
    pub total_chunks: usize,
    pub completed_chunks: usize,
    pub successful_chunks: usize,
    pub success_rate: f64,
    pub total_bytes: u64,
    pub avg_paths_per_chunk: f64,
    pub active_paths: usize,
}

/// Chunk reassembly manager
pub struct ChunkReassemblyManager {
    /// Pending reassemblies (flow_id -> chunks)
    pending_flows: HashMap<u64, FlowReassembly>,
    /// Completed flows
    completed_flows: VecDeque<u64>,
    /// Maximum pending flows
    max_pending_flows: usize,
}

/// Flow reassembly state
#[derive(Debug)]
struct FlowReassembly {
    /// Expected sequence numbers
    expected_sequences: HashSet<u32>,
    /// Received chunks
    received_chunks: HashMap<u32, Vec<u8>>,
    /// Flow start time
    start_time: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Flow timeout
    timeout: Duration,
}

impl ChunkReassemblyManager {
    pub fn new(max_pending_flows: usize) -> Self {
        Self {
            pending_flows: HashMap::new(),
            completed_flows: VecDeque::new(),
            max_pending_flows,
        }
    }
    
    /// Add chunk for reassembly
    pub fn add_chunk(
        &mut self,
        flow_id: u64,
        sequence: u32,
        data: Vec<u8>,
        is_last: bool,
    ) -> Option<Vec<u8>> {
        let flow = self.pending_flows.entry(flow_id).or_insert_with(|| {
            FlowReassembly {
                expected_sequences: HashSet::new(),
                received_chunks: HashMap::new(),
                start_time: Instant::now(),
                last_activity: Instant::now(),
                timeout: Duration::from_secs(30),
            }
        });
        
        flow.received_chunks.insert(sequence, data);
        flow.last_activity = Instant::now();
        
        if is_last {
            // Mark all sequences up to this one as expected
            for seq in 0..=sequence {
                flow.expected_sequences.insert(seq);
            }
        }
        
        // Check if flow is complete
        if !flow.expected_sequences.is_empty() && 
           flow.expected_sequences.iter().all(|seq| flow.received_chunks.contains_key(seq)) {
            // Flow is complete, reassemble
            let mut sequences: Vec<_> = flow.expected_sequences.iter().cloned().collect();
            sequences.sort();
            
            let mut reassembled = Vec::new();
            for seq in sequences {
                if let Some(chunk_data) = flow.received_chunks.get(&seq) {
                    reassembled.extend_from_slice(chunk_data);
                }
            }
            
            self.pending_flows.remove(&flow_id);
            self.completed_flows.push_back(flow_id);
            
            // Limit completed flows history
            while self.completed_flows.len() > 100 {
                self.completed_flows.pop_front();
            }
            
            return Some(reassembled);
        }
        
        None
    }
    
    /// Clean up timed out flows
    pub fn cleanup_timeouts(&mut self) {
        let timed_out: Vec<_> = self.pending_flows.iter()
            .filter(|(_, flow)| flow.last_activity.elapsed() > flow.timeout)
            .map(|(flow_id, _)| *flow_id)
            .collect();
        
        for flow_id in timed_out {
            self.pending_flows.remove(&flow_id);
        }
    }
    
    /// Get reassembly statistics
    pub fn stats(&self) -> ReassemblyStats {
        let total_pending = self.pending_flows.len();
        let total_completed = self.completed_flows.len();
        
        let avg_chunks_per_flow = if total_pending > 0 {
            self.pending_flows.values()
                .map(|flow| flow.received_chunks.len())
                .sum::<usize>() as f64 / total_pending as f64
        } else {
            0.0
        };
        
        ReassemblyStats {
            pending_flows: total_pending,
            completed_flows: total_completed,
            avg_chunks_per_flow,
        }
    }
}

/// Reassembly statistics
#[derive(Debug, Clone)]
pub struct ReassemblyStats {
    pub pending_flows: usize,
    pub completed_flows: usize,
    pub avg_chunks_per_flow: f64,
}