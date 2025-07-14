//! Configuration management for zMesh

use crate::{
    crypto::CryptoConfig,
    fec::FecConfig,
    mesh::MeshConfig,
    transport::TransportConfig,
    onion::OnionConfig,
    zMeshError, zMeshResult,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Main zMesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct zMeshConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Transport layer configuration
    pub transport: TransportConfig,
    /// Onion routing configuration
    pub onion: OnionConfig,
    /// Forward Error Correction configuration
    pub fec: FecConfig,
    /// Mesh networking configuration
    pub mesh: MeshConfig,
    /// Cryptographic configuration
    pub crypto: CryptoConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Performance tuning
    pub performance: PerformanceConfig,
    /// Development/debug options
    pub debug: DebugConfig,
}

impl Default for zMeshConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            transport: TransportConfig::default(),
            onion: OnionConfig::default(),
            fec: FecConfig::default(),
            mesh: MeshConfig::default(),
            crypto: CryptoConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
            debug: DebugConfig::default(),
        }
    }
}

impl zMeshConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> zMeshResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| zMeshError::Config(format!("Failed to read config file: {}", e)))?;
        
        let config: Self = toml::from_str(&content)
            .map_err(|e| zMeshError::Config(format!("Failed to parse config: {}", e)))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> zMeshResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| zMeshError::Config(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, content)
            .map_err(|e| zMeshError::Config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load configuration from environment variables
    pub fn from_env() -> zMeshResult<Self> {
        let mut config = Self::default();
        
        // Network settings
        if let Ok(node_id) = std::env::var("zMesh_NODE_ID") {
            config.network.node_id = Some(node_id);
        }
        
        if let Ok(listen_port) = std::env::var("zMesh_LISTEN_PORT") {
            config.network.listen_port = listen_port.parse()
                .map_err(|e| zMeshError::Config(format!("Invalid listen port: {}", e)))?;
        }
        
        // Bootstrap peers
        if let Ok(bootstrap) = std::env::var("zMesh_BOOTSTRAP_PEERS") {
            config.network.bootstrap_peers = bootstrap
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        
        // Debug mode
        if let Ok(debug) = std::env::var("zMesh_DEBUG") {
            config.debug.enabled = debug.parse().unwrap_or(false);
        }
        
        // Log level
        if let Ok(log_level) = std::env::var("zMesh_LOG_LEVEL") {
            config.logging.level = log_level.parse().unwrap_or(LogLevel::Info);
        }
        
        config.validate()?;
        Ok(config)
    }
    
    /// Validate configuration
    pub fn validate(&self) -> zMeshResult<()> {
        // Validate network settings
        if self.network.listen_port == 0 {
            return Err(zMeshError::Config("Invalid listen port".to_string()));
        }
        
        // Validate onion settings
        if self.onion.hops < 2 || self.onion.hops > 3 {
            return Err(zMeshError::Config("Onion hops must be 2 or 3".to_string()));
        }
        
        // Validate FEC settings
        self.fec.validate()?;
        
        // Validate mesh settings
        if self.mesh.min_peers == 0 {
            return Err(zMeshError::Config("Minimum peers must be > 0".to_string()));
        }
        
        if self.mesh.target_connections < self.mesh.min_peers {
            return Err(zMeshError::Config("Target connections must be >= min peers".to_string()));
        }
        
        // Validate performance settings
        if self.performance.max_memory_mb == 0 {
            return Err(zMeshError::Config("Max memory must be > 0".to_string()));
        }
        
        Ok(())
    }
    
    /// Create configuration for development
    pub fn development() -> Self {
        let mut config = Self::default();
        
        // Enable debug features
        config.debug.enabled = true;
        config.debug.verbose_logging = true;
        config.debug.metrics_enabled = true;
        
        // Faster intervals for development
        config.mesh.discovery_interval = Duration::from_secs(10);
        config.mesh.health_check_interval = Duration::from_secs(30);
        
        // More verbose logging
        config.logging.level = LogLevel::Debug;
        config.logging.log_to_console = true;
        
        // Lower resource limits
        config.performance.max_memory_mb = 256;
        config.performance.max_connections = 20;
        
        config
    }
    
    /// Create configuration for production
    pub fn production() -> Self {
        let mut config = Self::default();
        
        // Disable debug features
        config.debug.enabled = false;
        config.debug.verbose_logging = false;
        
        // Production logging
        config.logging.level = LogLevel::Info;
        config.logging.log_to_console = false;
        config.logging.log_to_file = true;
        
        // Higher resource limits
        config.performance.max_memory_mb = 1024;
        config.performance.max_connections = 100;
        
        // Longer intervals for stability
        config.mesh.discovery_interval = Duration::from_secs(60);
        config.mesh.health_check_interval = Duration::from_secs(120);
        
        config
    }
}

/// Network-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Node identifier (auto-generated if None)
    pub node_id: Option<String>,
    /// Listen port for incoming connections
    pub listen_port: u16,
    /// Bootstrap peer addresses
    pub bootstrap_peers: Vec<String>,
    /// Network name/identifier
    pub network_name: String,
    /// Protocol version
    pub protocol_version: String,
    /// User agent string
    pub user_agent: String,
    /// Enable IPv6 support
    pub enable_ipv6: bool,
    /// Bind to specific interface (None = all interfaces)
    pub bind_interface: Option<String>,
    /// External IP address (for NAT traversal)
    pub external_ip: Option<String>,
    /// Enable UPnP for port forwarding
    pub enable_upnp: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            listen_port: 8080,
            bootstrap_peers: vec![
                "wss://bootstrap1.zMesh.example.com".to_string(),
                "wss://bootstrap2.zMesh.example.com".to_string(),
            ],
            network_name: "zMesh".to_string(),
            protocol_version: "1.0".to_string(),
            user_agent: format!("zMesh/{}", env!("CARGO_PKG_VERSION")),
            enable_ipv6: true,
            bind_interface: None,
            external_ip: None,
            enable_upnp: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log to console
    pub log_to_console: bool,
    /// Log to file
    pub log_to_file: bool,
    /// Log file path
    pub log_file_path: String,
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    /// Number of log files to keep
    pub max_files: u32,
    /// Log format
    pub format: LogFormat,
    /// Enable structured logging (JSON)
    pub structured: bool,
    /// Include source location in logs
    pub include_location: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            log_to_console: true,
            log_to_file: false,
            log_file_path: "zMesh.log".to_string(),
            max_file_size_mb: 100,
            max_files: 5,
            format: LogFormat::Human,
            structured: false,
            include_location: false,
        }
    }
}

/// Log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::str::FromStr for LogLevel {
    type Err = zMeshError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err(zMeshError::Config(format!("Invalid log level: {}", s))),
        }
    }
}

/// Log formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Human-readable format
    Human,
    /// JSON format
    Json,
    /// Compact format
    Compact,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum memory usage in MB
    pub max_memory_mb: usize,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Worker thread pool size (0 = auto)
    pub worker_threads: usize,
    /// I/O thread pool size (0 = auto)
    pub io_threads: usize,
    /// Buffer sizes
    pub buffer_sizes: BufferConfig,
    /// Timeout settings
    pub timeouts: TimeoutConfig,
    /// Rate limiting
    pub rate_limits: RateLimitConfig,
    /// Enable performance metrics
    pub enable_metrics: bool,
    /// Metrics collection interval
    pub metrics_interval: Duration,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_connections: 50,
            worker_threads: 0, // Auto-detect
            io_threads: 0, // Auto-detect
            buffer_sizes: BufferConfig::default(),
            timeouts: TimeoutConfig::default(),
            rate_limits: RateLimitConfig::default(),
            enable_metrics: true,
            metrics_interval: Duration::from_secs(60),
        }
    }
}

/// Buffer size configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Send buffer size in bytes
    pub send_buffer: usize,
    /// Receive buffer size in bytes
    pub recv_buffer: usize,
    /// Channel buffer size (number of messages)
    pub channel_buffer: usize,
    /// Chunk buffer size in bytes
    pub chunk_buffer: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            send_buffer: 64 * 1024, // 64KB
            recv_buffer: 64 * 1024, // 64KB
            channel_buffer: 1000,
            chunk_buffer: 1024 * 1024, // 1MB
        }
    }
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Circuit build timeout
    pub circuit_timeout: Duration,
    /// Peer discovery timeout
    pub discovery_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            circuit_timeout: Duration::from_secs(60),
            discovery_timeout: Duration::from_secs(30),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum messages per second per peer
    pub max_messages_per_sec: u32,
    /// Maximum bytes per second per peer
    pub max_bytes_per_sec: u64,
    /// Maximum concurrent requests per peer
    pub max_concurrent_requests: u32,
    /// Rate limit window duration
    pub window_duration: Duration,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_messages_per_sec: 100,
            max_bytes_per_sec: 1024 * 1024, // 1MB/s
            max_concurrent_requests: 10,
            window_duration: Duration::from_secs(60),
            enabled: true,
        }
    }
}

/// Debug and development configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugConfig {
    /// Enable debug mode
    pub enabled: bool,
    /// Enable verbose logging
    pub verbose_logging: bool,
    /// Enable metrics collection
    pub metrics_enabled: bool,
    /// Enable tracing
    pub tracing_enabled: bool,
    /// Simulate network conditions
    pub simulate_network: Option<NetworkSimulation>,
    /// Enable test mode features
    pub test_mode: bool,
    /// Disable certain security features for testing
    pub unsafe_mode: bool,
    /// Enable profiling
    pub profiling_enabled: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verbose_logging: false,
            metrics_enabled: false,
            tracing_enabled: false,
            simulate_network: None,
            test_mode: false,
            unsafe_mode: false,
            profiling_enabled: false,
        }
    }
}

/// Network simulation for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSimulation {
    /// Simulate packet loss (0.0 to 1.0)
    pub packet_loss: f64,
    /// Simulate latency (additional delay)
    pub latency: Duration,
    /// Simulate jitter (random delay variation)
    pub jitter: Duration,
    /// Simulate bandwidth limit (bytes per second)
    pub bandwidth_limit: Option<u64>,
}

/// Configuration builder for fluent API
pub struct ConfigBuilder {
    config: zMeshConfig,
}

impl ConfigBuilder {
    /// Create new config builder
    pub fn new() -> Self {
        Self {
            config: zMeshConfig::default(),
        }
    }
    
    /// Set node ID
    pub fn node_id<S: Into<String>>(mut self, node_id: S) -> Self {
        self.config.network.node_id = Some(node_id.into());
        self
    }
    
    /// Set listen port
    pub fn listen_port(mut self, port: u16) -> Self {
        self.config.network.listen_port = port;
        self
    }
    
    /// Add bootstrap peer
    pub fn bootstrap_peer<S: Into<String>>(mut self, peer: S) -> Self {
        self.config.network.bootstrap_peers.push(peer.into());
        self
    }
    
    /// Set log level
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.config.logging.level = level;
        self
    }
    
    /// Enable debug mode
    pub fn debug(mut self, enabled: bool) -> Self {
        self.config.debug.enabled = enabled;
        self
    }
    
    /// Set onion hops
    pub fn onion_hops(mut self, hops: u8) -> Self {
        self.config.onion.hops = hops;
        self
    }
    
    /// Enable FEC
    pub fn enable_fec(mut self, enabled: bool) -> Self {
        self.config.fec.enabled = enabled;
        self
    }
    
    /// Set cache size
    pub fn cache_size(mut self, size: usize) -> Self {
        self.config.mesh.cache_size = size;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> zMeshResult<zMeshConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}