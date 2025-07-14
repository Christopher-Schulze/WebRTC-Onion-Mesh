//! Transport layer abstractions for WebRTC and WebSocket

use crate::{zMeshError, zMeshResult, PeerId};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Transport layer abstraction
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote peer
    async fn connect(&mut self, address: &str) -> zMeshResult<Box<dyn Connection>>;
    
    /// Listen for incoming connections
    async fn listen(&mut self, address: &str) -> zMeshResult<Box<dyn Listener>>;
    
    /// Get the transport type
    fn transport_type(&self) -> TransportType;
    
    /// Check if transport is available in current environment
    fn is_available(&self) -> bool;
}

/// Connection abstraction
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send data to the remote peer
    async fn send(&mut self, data: Bytes) -> zMeshResult<()>;
    
    /// Receive data from the remote peer
    async fn recv(&mut self) -> zMeshResult<Option<Bytes>>;
    
    /// Close the connection
    async fn close(&mut self) -> zMeshResult<()>;
    
    /// Get the remote peer address
    fn remote_addr(&self) -> Option<SocketAddr>;
    
    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;
    
    /// Check if connection is still alive
    fn is_connected(&self) -> bool;
    
    /// Set connection timeout
    fn set_timeout(&mut self, timeout: Duration);
}

/// Listener abstraction for incoming connections
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept an incoming connection
    async fn accept(&mut self) -> zMeshResult<Box<dyn Connection>>;
    
    /// Get the local address
    fn local_addr(&self) -> zMeshResult<SocketAddr>;
    
    /// Close the listener
    async fn close(&mut self) -> zMeshResult<()>;
}

/// Transport protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// WebRTC DataChannel (preferred)
    WebRtc,
    /// WebSocket over HTTPS (fallback)
    WebSocket,
}

impl TransportType {
    /// Get default port for transport type
    pub fn default_port(&self) -> u16 {
        match self {
            TransportType::WebRtc => 0, // Dynamic port assignment
            TransportType::WebSocket => 443, // HTTPS
        }
    }
    
    /// Check if transport requires TLS
    pub fn requires_tls(&self) -> bool {
        match self {
            TransportType::WebRtc => true, // WebRTC has built-in encryption
            TransportType::WebSocket => true, // We only use WSS
        }
    }
    
    /// Get transport priority (lower is better)
    pub fn priority(&self) -> u8 {
        match self {
            TransportType::WebRtc => 1, // Preferred
            TransportType::WebSocket => 2, // Fallback
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::WebRtc => write!(f, "webrtc"),
            TransportType::WebSocket => write!(f, "websocket"),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets lost
    pub packets_lost: u64,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Connection uptime
    pub uptime: Duration,
}

impl ConnectionStats {
    /// Calculate packet loss rate (0.0 to 1.0)
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_lost as f64 / self.packets_sent as f64
    }
    
    /// Calculate throughput in bytes per second
    pub fn throughput(&self) -> f64 {
        if self.uptime.as_secs() == 0 {
            return 0.0;
        }
        (self.bytes_sent + self.bytes_received) as f64 / self.uptime.as_secs_f64()
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Preferred transport types in order of preference
    pub preferred_transports: Vec<TransportType>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive interval
    pub keepalive_interval: Duration,
    /// Maximum message size
    pub max_message_size: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// WebRTC specific configuration
    pub webrtc: WebRtcConfig,
    /// WebSocket specific configuration
    pub websocket: WebSocketConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            preferred_transports: vec![TransportType::WebRtc, TransportType::WebSocket],
            connect_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(60),
            max_message_size: 1024 * 1024, // 1MB
            enable_compression: true,
            webrtc: WebRtcConfig::default(),
            websocket: WebSocketConfig::default(),
        }
    }
}

/// WebRTC specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcConfig {
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// TURN servers for relay (if needed)
    pub turn_servers: Vec<TurnServer>,
    /// ICE gathering timeout
    pub ice_timeout: Duration,
    /// Enable ordered delivery
    pub ordered: bool,
    /// Maximum retransmits
    pub max_retransmits: Option<u16>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: Vec::new(), // Peers act as TURN relays
            ice_timeout: Duration::from_secs(10),
            ordered: false, // Unordered for better performance
            max_retransmits: Some(3),
        }
    }
}

/// TURN server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

/// WebSocket specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Use secure WebSocket (WSS)
    pub use_tls: bool,
    /// Additional headers
    pub headers: std::collections::HashMap<String, String>,
    /// Subprotocols
    pub subprotocols: Vec<String>,
    /// Ping interval for keep-alive
    pub ping_interval: Duration,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            use_tls: true, // Always use WSS
            headers: std::collections::HashMap::new(),
            subprotocols: vec!["zMesh".to_string()],
            ping_interval: Duration::from_secs(30),
        }
    }
}

/// Message types for transport layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportMessage {
    /// Data payload
    Data(Bytes),
    /// Keep-alive ping
    Ping,
    /// Pong response
    Pong,
    /// Connection close
    Close,
    /// Error notification
    Error(String),
}

/// Transport manager for handling multiple transport types
pub struct TransportManager {
    transports: Vec<Box<dyn Transport>>,
    config: TransportConfig,
}

impl TransportManager {
    /// Create new transport manager
    pub fn new(config: TransportConfig) -> Self {
        Self {
            transports: Vec::new(),
            config,
        }
    }
    
    /// Add a transport implementation
    pub fn add_transport(&mut self, transport: Box<dyn Transport>) {
        self.transports.push(transport);
    }
    
    /// Get available transports
    pub fn available_transports(&self) -> Vec<TransportType> {
        self.transports
            .iter()
            .filter(|t| t.is_available())
            .map(|t| t.transport_type())
            .collect()
    }
    
    /// Get preferred transport for connection
    pub fn preferred_transport(&self) -> Option<TransportType> {
        let available = self.available_transports();
        self.config
            .preferred_transports
            .iter()
            .find(|t| available.contains(t))
            .copied()
    }
}

/// Connection pool for managing multiple connections
pub struct ConnectionPool {
    connections: std::collections::HashMap<PeerId, Box<dyn Connection>>,
    max_connections: usize,
}

impl ConnectionPool {
    /// Create new connection pool
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: std::collections::HashMap::new(),
            max_connections,
        }
    }
    
    /// Add connection to pool
    pub fn add_connection(&mut self, peer_id: PeerId, connection: Box<dyn Connection>) -> zMeshResult<()> {
        if self.connections.len() >= self.max_connections {
            return Err(zMeshError::Transport("Connection pool full".to_string()));
        }
        self.connections.insert(peer_id, connection);
        Ok(())
    }
    
    /// Get connection by peer ID
    pub fn get_connection(&mut self, peer_id: &PeerId) -> Option<&mut Box<dyn Connection>> {
        self.connections.get_mut(peer_id)
    }
    
    /// Remove connection
    pub fn remove_connection(&mut self, peer_id: &PeerId) -> Option<Box<dyn Connection>> {
        self.connections.remove(peer_id)
    }
    
    /// Get all connected peer IDs
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.keys().cloned().collect()
    }
    
    /// Clean up disconnected connections
    pub fn cleanup_disconnected(&mut self) {
        self.connections.retain(|_, conn| conn.is_connected());
    }
}