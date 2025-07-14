//! Metrics collection and monitoring for onion routing
//! Provides comprehensive statistics and performance monitoring

use crate::circuit::{CircuitStats, CircuitState};
use crate::packet::PacketStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Onion routing metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnionMetrics {
    /// Circuit metrics
    pub circuits: CircuitMetrics,
    /// Packet metrics
    pub packets: PacketMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Security metrics
    pub security: SecurityMetrics,
    /// Network metrics
    pub network: NetworkMetrics,
    /// Resource metrics
    pub resources: ResourceMetrics,
    /// Last update timestamp
    pub last_update: Instant,
}

/// Circuit-related metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CircuitMetrics {
    /// Total circuits created
    pub circuits_created: u64,
    /// Circuits currently active
    pub circuits_active: u64,
    /// Circuits destroyed
    pub circuits_destroyed: u64,
    /// Failed circuit attempts
    pub circuits_failed: u64,
    /// Average circuit lifetime
    pub avg_lifetime: Duration,
    /// Circuit success rate (0.0 - 1.0)
    pub success_rate: f64,
    /// Circuits by hop count
    pub circuits_by_hops: HashMap<u8, u64>,
    /// Circuit states distribution
    pub state_distribution: HashMap<String, u64>,
}

/// Packet-related metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketMetrics {
    /// Total packets processed
    pub packets_processed: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Invalid packets
    pub invalid_packets: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Packet drop rate (0.0 - 1.0)
    pub drop_rate: f64,
}

/// Performance-related metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average latency per hop
    pub avg_hop_latency: Duration,
    /// End-to-end latency
    pub avg_e2e_latency: Duration,
    /// Throughput in bytes per second
    pub throughput_bps: u64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Circuit establishment time
    pub avg_circuit_setup_time: Duration,
    /// Key exchange time
    pub avg_key_exchange_time: Duration,
    /// Encryption/decryption time
    pub avg_crypto_time: Duration,
}

/// Security-related metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Key rotations performed
    pub key_rotations: u64,
    /// Authentication failures
    pub auth_failures: u64,
    /// Replay attacks detected
    pub replay_attacks: u64,
    /// Invalid signatures
    pub invalid_signatures: u64,
    /// Encryption failures
    pub encryption_failures: u64,
    /// Decryption failures
    pub decryption_failures: u64,
    /// Security events
    pub security_events: u64,
}

/// Network-related metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Connected peers
    pub connected_peers: u64,
    /// Peer connections established
    pub peer_connections_established: u64,
    /// Peer connections lost
    pub peer_connections_lost: u64,
    /// Network errors
    pub network_errors: u64,
    /// Bandwidth usage in bytes
    pub bandwidth_usage: u64,
    /// Connection timeouts
    pub connection_timeouts: u64,
    /// DNS resolution failures
    pub dns_failures: u64,
}

/// Resource usage metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetrics {
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// CPU usage percentage (0.0 - 100.0)
    pub cpu_usage: f64,
    /// Active threads
    pub active_threads: u64,
    /// Open file descriptors
    pub open_fds: u64,
    /// Network sockets
    pub network_sockets: u64,
    /// Cache hit rate (0.0 - 1.0)
    pub cache_hit_rate: f64,
}

/// Metrics collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Collection interval
    pub collection_interval: Duration,
    /// Enable detailed metrics
    pub enable_detailed: bool,
    /// Enable performance metrics
    pub enable_performance: bool,
    /// Enable security metrics
    pub enable_security: bool,
    /// Enable resource metrics
    pub enable_resources: bool,
    /// Metrics retention period
    pub retention_period: Duration,
    /// Export metrics to external systems
    pub enable_export: bool,
    /// Export endpoint
    pub export_endpoint: Option<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(10),
            enable_detailed: true,
            enable_performance: true,
            enable_security: true,
            enable_resources: false, // Disabled by default for performance
            retention_period: Duration::from_secs(3600), // 1 hour
            enable_export: false,
            export_endpoint: None,
        }
    }
}

/// Historical metrics data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Timestamp of the snapshot
    pub timestamp: Instant,
    /// Metrics at this point in time
    pub metrics: OnionMetrics,
}

/// Metrics collector for onion routing
pub struct MetricsCollector {
    /// Configuration
    config: MetricsConfig,
    /// Current metrics
    current_metrics: Arc<RwLock<OnionMetrics>>,
    /// Historical metrics
    history: Arc<RwLock<Vec<MetricsSnapshot>>>,
    /// Performance counters
    counters: Arc<RwLock<HashMap<String, u64>>>,
    /// Timing measurements
    timings: Arc<RwLock<HashMap<String, Vec<Duration>>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            current_metrics: Arc::new(RwLock::new(OnionMetrics::default())),
            history: Arc::new(RwLock::new(Vec::new())),
            counters: Arc::new(RwLock::new(HashMap::new())),
            timings: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start metrics collection
    pub async fn start(&self) {
        let current_metrics = Arc::clone(&self.current_metrics);
        let history = Arc::clone(&self.history);
        let counters = Arc::clone(&self.counters);
        let timings = Arc::clone(&self.timings);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(config.collection_interval);
            
            loop {
                interval.tick().await;
                
                // Collect current metrics
                let mut metrics = current_metrics.write().await;
                metrics.last_update = Instant::now();
                
                // Update counters-based metrics
                let counters_guard = counters.read().await;
                metrics.circuits.circuits_created = *counters_guard.get("circuits_created").unwrap_or(&0);
                metrics.circuits.circuits_destroyed = *counters_guard.get("circuits_destroyed").unwrap_or(&0);
                metrics.circuits.circuits_failed = *counters_guard.get("circuits_failed").unwrap_or(&0);
                metrics.packets.packets_processed = *counters_guard.get("packets_processed").unwrap_or(&0);
                metrics.packets.packets_sent = *counters_guard.get("packets_sent").unwrap_or(&0);
                metrics.packets.packets_received = *counters_guard.get("packets_received").unwrap_or(&0);
                metrics.packets.packets_dropped = *counters_guard.get("packets_dropped").unwrap_or(&0);
                metrics.security.key_rotations = *counters_guard.get("key_rotations").unwrap_or(&0);
                metrics.security.auth_failures = *counters_guard.get("auth_failures").unwrap_or(&0);
                drop(counters_guard);
                
                // Calculate rates
                if metrics.packets.packets_processed > 0 {
                    metrics.packets.drop_rate = 
                        metrics.packets.packets_dropped as f64 / metrics.packets.packets_processed as f64;
                }
                
                if metrics.circuits.circuits_created > 0 {
                    metrics.circuits.success_rate = 
                        (metrics.circuits.circuits_created - metrics.circuits.circuits_failed) as f64 / 
                        metrics.circuits.circuits_created as f64;
                }
                
                // Update timing-based metrics
                if config.enable_performance {
                    let timings_guard = timings.read().await;
                    
                    if let Some(hop_latencies) = timings_guard.get("hop_latency") {
                        if !hop_latencies.is_empty() {
                            let total: Duration = hop_latencies.iter().sum();
                            metrics.performance.avg_hop_latency = total / hop_latencies.len() as u32;
                        }
                    }
                    
                    if let Some(setup_times) = timings_guard.get("circuit_setup") {
                        if !setup_times.is_empty() {
                            let total: Duration = setup_times.iter().sum();
                            metrics.performance.avg_circuit_setup_time = total / setup_times.len() as u32;
                        }
                    }
                }
                
                // Create snapshot
                let snapshot = MetricsSnapshot {
                    timestamp: Instant::now(),
                    metrics: metrics.clone(),
                };
                
                drop(metrics);
                
                // Store in history
                let mut history_guard = history.write().await;
                history_guard.push(snapshot);
                
                // Clean old history
                let cutoff = Instant::now() - config.retention_period;
                history_guard.retain(|snapshot| snapshot.timestamp > cutoff);
                
                // Export metrics if enabled
                if config.enable_export {
                    // TODO: Implement metrics export
                }
            }
        });
    }
    
    /// Increment a counter
    pub async fn increment_counter(&self, name: &str) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += 1;
    }
    
    /// Add a counter value
    pub async fn add_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }
    
    /// Record a timing measurement
    pub async fn record_timing(&self, name: &str, duration: Duration) {
        let mut timings = self.timings.write().await;
        timings.entry(name.to_string()).or_insert_with(Vec::new).push(duration);
        
        // Keep only recent measurements
        let entry = timings.get_mut(name).unwrap();
        if entry.len() > 1000 {
            entry.drain(0..500); // Remove oldest half
        }
    }
    
    /// Get current metrics
    pub async fn get_metrics(&self) -> OnionMetrics {
        let metrics = self.current_metrics.read().await;
        metrics.clone()
    }
    
    /// Get metrics history
    pub async fn get_history(&self, duration: Duration) -> Vec<MetricsSnapshot> {
        let history = self.history.read().await;
        let cutoff = Instant::now() - duration;
        
        history.iter()
            .filter(|snapshot| snapshot.timestamp > cutoff)
            .cloned()
            .collect()
    }
    
    /// Update circuit metrics
    pub async fn update_circuit_metrics(&self, stats: &CircuitStats) {
        let mut metrics = self.current_metrics.write().await;
        
        metrics.circuits.circuits_active = stats.active_circuits as u64;
        metrics.circuits.avg_lifetime = stats.avg_lifetime;
        
        // Update hop distribution
        metrics.circuits.circuits_by_hops.clear();
        for (hops, count) in &stats.circuits_by_hops {
            metrics.circuits.circuits_by_hops.insert(*hops, *count as u64);
        }
    }
    
    /// Update packet metrics
    pub async fn update_packet_metrics(&self, stats: &PacketStats) {
        let mut metrics = self.current_metrics.write().await;
        
        metrics.packets.packets_processed = stats.packets_processed;
        metrics.packets.packets_sent = stats.packets_sent;
        metrics.packets.packets_received = stats.packets_received;
        metrics.packets.packets_forwarded = stats.packets_forwarded;
        metrics.packets.packets_dropped = stats.packets_dropped;
        metrics.packets.invalid_packets = stats.invalid_packets;
        metrics.packets.avg_packet_size = stats.avg_packet_size;
        metrics.packets.total_bytes = stats.total_bytes;
        
        // Calculate drop rate
        if stats.packets_processed > 0 {
            metrics.packets.drop_rate = 
                stats.packets_dropped as f64 / stats.packets_processed as f64;
        }
    }
    
    /// Update performance metrics
    pub async fn update_performance_metrics(
        &self,
        throughput: u64,
        packets_per_second: f64,
    ) {
        let mut metrics = self.current_metrics.write().await;
        metrics.performance.throughput_bps = throughput;
        metrics.performance.packets_per_second = packets_per_second;
    }
    
    /// Update security metrics
    pub async fn record_security_event(&self, event_type: &str) {
        self.increment_counter(&format!("security_{}", event_type)).await;
        
        let mut metrics = self.current_metrics.write().await;
        metrics.security.security_events += 1;
    }
    
    /// Update network metrics
    pub async fn update_network_metrics(
        &self,
        connected_peers: u64,
        bandwidth_usage: u64,
    ) {
        let mut metrics = self.current_metrics.write().await;
        metrics.network.connected_peers = connected_peers;
        metrics.network.bandwidth_usage = bandwidth_usage;
    }
    
    /// Update resource metrics
    pub async fn update_resource_metrics(
        &self,
        memory_usage: u64,
        cpu_usage: f64,
    ) {
        if !self.config.enable_resources {
            return;
        }
        
        let mut metrics = self.current_metrics.write().await;
        metrics.resources.memory_usage = memory_usage;
        metrics.resources.cpu_usage = cpu_usage;
    }
    
    /// Reset all metrics
    pub async fn reset_metrics(&self) {
        let mut metrics = self.current_metrics.write().await;
        *metrics = OnionMetrics::default();
        
        let mut counters = self.counters.write().await;
        counters.clear();
        
        let mut timings = self.timings.write().await;
        timings.clear();
        
        let mut history = self.history.write().await;
        history.clear();
    }
    
    /// Get summary statistics
    pub async fn get_summary(&self) -> MetricsSummary {
        let metrics = self.get_metrics().await;
        
        MetricsSummary {
            circuits_active: metrics.circuits.circuits_active,
            circuits_success_rate: metrics.circuits.success_rate,
            packets_per_second: metrics.performance.packets_per_second,
            avg_latency: metrics.performance.avg_hop_latency,
            drop_rate: metrics.packets.drop_rate,
            throughput_mbps: (metrics.performance.throughput_bps as f64) / (1024.0 * 1024.0),
            security_events: metrics.security.security_events,
            connected_peers: metrics.network.connected_peers,
        }
    }
    
    /// Export metrics to string format
    pub async fn export_metrics(&self, format: MetricsFormat) -> String {
        let metrics = self.get_metrics().await;
        
        match format {
            MetricsFormat::Json => {
                serde_json::to_string_pretty(&metrics).unwrap_or_default()
            }
            MetricsFormat::Prometheus => {
                self.to_prometheus_format(&metrics)
            }
            MetricsFormat::InfluxDB => {
                self.to_influxdb_format(&metrics)
            }
        }
    }
    
    /// Convert metrics to Prometheus format
    fn to_prometheus_format(&self, metrics: &OnionMetrics) -> String {
        let mut output = String::new();
        
        // Circuit metrics
        output.push_str(&format!("onion_circuits_created_total {}\n", metrics.circuits.circuits_created));
        output.push_str(&format!("onion_circuits_active {}\n", metrics.circuits.circuits_active));
        output.push_str(&format!("onion_circuits_success_rate {}\n", metrics.circuits.success_rate));
        
        // Packet metrics
        output.push_str(&format!("onion_packets_processed_total {}\n", metrics.packets.packets_processed));
        output.push_str(&format!("onion_packets_dropped_total {}\n", metrics.packets.packets_dropped));
        output.push_str(&format!("onion_packet_drop_rate {}\n", metrics.packets.drop_rate));
        
        // Performance metrics
        output.push_str(&format!("onion_throughput_bps {}\n", metrics.performance.throughput_bps));
        output.push_str(&format!("onion_latency_seconds {}\n", metrics.performance.avg_hop_latency.as_secs_f64()));
        
        // Security metrics
        output.push_str(&format!("onion_security_events_total {}\n", metrics.security.security_events));
        output.push_str(&format!("onion_auth_failures_total {}\n", metrics.security.auth_failures));
        
        output
    }
    
    /// Convert metrics to InfluxDB line protocol format
    fn to_influxdb_format(&self, metrics: &OnionMetrics) -> String {
        let timestamp = metrics.last_update.elapsed().as_nanos();
        
        format!(
            "onion_metrics circuits_created={},circuits_active={},packets_processed={},throughput_bps={} {}\n",
            metrics.circuits.circuits_created,
            metrics.circuits.circuits_active,
            metrics.packets.packets_processed,
            metrics.performance.throughput_bps,
            timestamp
        )
    }
}

/// Metrics summary for quick overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Active circuits
    pub circuits_active: u64,
    /// Circuit success rate
    pub circuits_success_rate: f64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Average latency
    pub avg_latency: Duration,
    /// Packet drop rate
    pub drop_rate: f64,
    /// Throughput in Mbps
    pub throughput_mbps: f64,
    /// Security events
    pub security_events: u64,
    /// Connected peers
    pub connected_peers: u64,
}

/// Metrics export formats
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsFormat {
    /// JSON format
    Json,
    /// Prometheus format
    Prometheus,
    /// InfluxDB line protocol
    InfluxDB,
}

/// Timing helper for measuring durations
pub struct TimingHelper {
    start_time: Instant,
    name: String,
    collector: Arc<MetricsCollector>,
}

impl TimingHelper {
    /// Start timing measurement
    pub fn start(name: String, collector: Arc<MetricsCollector>) -> Self {
        Self {
            start_time: Instant::now(),
            name,
            collector,
        }
    }
    
    /// Finish timing measurement and record
    pub async fn finish(self) {
        let duration = self.start_time.elapsed();
        self.collector.record_timing(&self.name, duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_collector() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        
        // Test counter increment
        collector.increment_counter("test_counter").await;
        collector.add_counter("test_counter", 5).await;
        
        // Test timing recording
        collector.record_timing("test_timing", Duration::from_millis(100)).await;
        
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.last_update.elapsed().as_secs(), 0); // Should be recent
    }
    
    #[tokio::test]
    async fn test_timing_helper() {
        let config = MetricsConfig::default();
        let collector = Arc::new(MetricsCollector::new(config));
        
        let timer = TimingHelper::start("test_operation".to_string(), collector.clone());
        
        // Simulate some work
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        timer.finish().await;
        
        // Verify timing was recorded
        let timings = collector.timings.read().await;
        assert!(timings.contains_key("test_operation"));
    }
    
    #[test]
    fn test_metrics_summary() {
        let summary = MetricsSummary {
            circuits_active: 10,
            circuits_success_rate: 0.95,
            packets_per_second: 1000.0,
            avg_latency: Duration::from_millis(50),
            drop_rate: 0.01,
            throughput_mbps: 10.0,
            security_events: 0,
            connected_peers: 5,
        };
        
        assert_eq!(summary.circuits_active, 10);
        assert!((summary.circuits_success_rate - 0.95).abs() < f64::EPSILON);
    }
    
    #[tokio::test]
    async fn test_metrics_export() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        
        // Add some test data
        collector.increment_counter("circuits_created").await;
        collector.add_counter("packets_processed", 100).await;
        
        let json_export = collector.export_metrics(MetricsFormat::Json).await;
        assert!(!json_export.is_empty());
        
        let prometheus_export = collector.export_metrics(MetricsFormat::Prometheus).await;
        assert!(prometheus_export.contains("onion_circuits_created_total"));
    }
    
    #[test]
    fn test_metrics_config() {
        let config = MetricsConfig::default();
        
        assert_eq!(config.collection_interval, Duration::from_secs(10));
        assert!(config.enable_detailed);
        assert!(config.enable_performance);
        assert!(config.enable_security);
        assert!(!config.enable_resources);
        assert!(!config.enable_export);
    }
}